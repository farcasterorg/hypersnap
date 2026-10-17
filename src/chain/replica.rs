//! Shards 1 and 2 after the pivot: the replica of the shard-0 records (FIP
//! §17.7), the signer check of a user message against it (FIP §16.8), and
//! the fee gate with the unsettled charges (FIP §12).

use crate::chain::shard0::auth::{self, falcon_key_hash, Scheme};
use crate::chain::shard0::keys;
use crate::chain::shard0::Shard0Error;
use crate::proto::{self, FalconSignerRecord, FeeCharge, FidCustodyRecord, MessageType};
use crate::storage::constants::RootPrefix;
use crate::storage::db::{PageOptions, RocksDB, RocksDbTransactionBatch};
use crate::storage::store::account::get_from_db_or_txn;
use prost::Message as _;

fn get(
    db: &RocksDB,
    txn: &RocksDbTransactionBatch,
    key: &[u8],
) -> Result<Option<Vec<u8>>, Shard0Error> {
    get_from_db_or_txn(db, txn, key).map_err(|e| Shard0Error::Internal(e.to_string()))
}

fn get_u64(db: &RocksDB, txn: &RocksDbTransactionBatch, key: &[u8]) -> Result<u64, Shard0Error> {
    Ok(get(db, txn, key)?
        .map(|v| keys::decode_u64(&v))
        .unwrap_or(0))
}

fn put_u64(txn: &mut RocksDbTransactionBatch, key: Vec<u8>, v: u64) {
    if v == 0 {
        txn.delete(key);
    } else {
        txn.put(key, keys::u64_value(v));
    }
}

/// A Falcon-512 signer with a `ttl`, and its last use before the message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignerUse {
    pub fid: u64,
    pub key_hash: [u8; 32],
    pub last_use: u64,
}

/// How the signer of a message was checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignerCheck {
    /// The FID is not migrated and the message is Ed25519: the snapchain
    /// rules apply (on-chain and gasless signers).
    Snapchain,
    /// The FID is migrated, and the signature verified against the replica.
    /// A signer with a `ttl` has its last use, which the message moves on.
    Verified(Option<SignerUse>),
}

/// `[146][fid][keccak256(falcon_key)]` → the last use of the signer.
pub fn last_use_key(fid: u64, key_hash: &[u8]) -> Vec<u8> {
    keys::prefix(
        RootPrefix::HyperFalconSignerLastUse,
        &[&fid.to_be_bytes(), key_hash],
    )
}

/// The last-use key of the signer record at `key`, if `key` is the key of a
/// Falcon-512 signer record.
pub fn last_use_key_of_signer(key: &[u8]) -> Option<Vec<u8>> {
    (key.first() == Some(&(RootPrefix::HyperFalconSigner as u8)) && key.len() == 41).then(|| {
        let mut k = key.to_vec();
        k[0] = RootPrefix::HyperFalconSignerLastUse as u8;
        k
    })
}

/// Record the use of a signer by a message at `message_timestamp`, as the
/// snapchain sliding TTL does: only if it moves the last use on by more than
/// `SLIDING_TTL_THROTTLE_SECONDS`.
pub fn record_use(txn: &mut RocksDbTransactionBatch, used: &SignerUse, message_timestamp: u64) {
    use crate::storage::store::account::SLIDING_TTL_THROTTLE_SECONDS;
    if message_timestamp > used.last_use + SLIDING_TTL_THROTTLE_SECONDS {
        txn.put(
            last_use_key(used.fid, &used.key_hash),
            keys::u64_value(message_timestamp),
        );
    }
}

/// The FIP §16.8 acceptance rules on shard 1 or 2.
pub fn check_signer(
    db: &RocksDB,
    txn: &RocksDbTransactionBatch,
    message: &proto::Message,
    network: proto::FarcasterNetwork,
    block_timestamp: u64,
) -> Result<SignerCheck, Shard0Error> {
    let fid = message.fid();
    let custody: Option<FidCustodyRecord> = get(db, txn, &keys::custody(fid))?
        .map(|v| FidCustodyRecord::decode(v.as_slice()))
        .transpose()
        .map_err(|e| Shard0Error::Internal(e.to_string()))?;
    let scheme = message.signature_scheme;
    if custody.is_none() {
        return if scheme == proto::SignatureScheme::Ed25519 as i32 {
            Ok(SignerCheck::Snapchain)
        } else {
            Err(Shard0Error::invalid(
                "an FID that is not migrated has no Falcon-512 keys",
            ))
        };
    }
    let env = auth::open(message, network, block_timestamp)?;
    let hash = env
        .falcon_key_hash
        .ok_or_else(|| Shard0Error::invalid("a migrated FID signs with a Falcon-512 signer"))?;
    match env.scheme {
        Scheme::Dual => {
            let ed = env.ed25519_key.unwrap();
            let paired = get(db, txn, &keys::signer_pair(fid, &ed))?
                .ok_or_else(|| Shard0Error::invalid("the Ed25519 key is not a registered pair"))?;
            if paired.as_slice() != hash {
                return Err(Shard0Error::invalid(
                    "the pair names a different Falcon-512 key",
                ));
            }
        }
        Scheme::Falcon => {}
        _ => {
            return Err(Shard0Error::invalid(
                "a migrated FID cannot use Ed25519-only messages",
            ))
        }
    }
    let record: FalconSignerRecord = get(db, txn, &keys::falcon_signer(fid, &hash))?
        .map(|v| FalconSignerRecord::decode(v.as_slice()))
        .transpose()
        .map_err(|e| Shard0Error::Internal(e.to_string()))?
        .ok_or_else(|| Shard0Error::invalid("the key is not a signer of the FID"))?;
    if !record.scopes.is_empty() && !record.scopes.contains(&(env.msg_type as i32)) {
        return Err(Shard0Error::invalid(
            "message type is not in the signer scopes",
        ));
    }
    env.verify_falcon(&record.falcon_key)?;
    debug_assert_eq!(falcon_key_hash(&record.falcon_key), hash);
    if record.ttl == 0 {
        return Ok(SignerCheck::Verified(None));
    }
    // The snapchain sliding TTL (FIP §16.10): the last use starts at the
    // KEY_ADD, and the signer expires `ttl` seconds after it.
    let last_use = get_u64(db, txn, &last_use_key(fid, &hash))?.max(record.added_at_time);
    if last_use + u64::from(record.ttl) < block_timestamp {
        return Err(Shard0Error::invalid("the signer expired"));
    }
    Ok(SignerCheck::Verified(Some(SignerUse {
        fid,
        key_hash: hash,
        last_use,
    })))
}

// ---- Fees (§12) ----

const CHARGE_BY_HEIGHT: u8 = 0x00;
const UNSETTLED_BY_FID: u8 = 0x01;

/// `[138][0][height][fid]` → the charges of FID in the shard block.
pub fn charge_key(height: u64, fid: u64) -> Vec<u8> {
    keys::prefix(
        RootPrefix::HyperUnsettledCharge,
        &[
            &[CHARGE_BY_HEIGHT],
            &height.to_be_bytes(),
            &fid.to_be_bytes(),
        ],
    )
}

fn charges_of_height(height: u64) -> Vec<u8> {
    keys::prefix(
        RootPrefix::HyperUnsettledCharge,
        &[&[CHARGE_BY_HEIGHT], &height.to_be_bytes()],
    )
}

/// `[138][1][fid]` → the sum of the unsettled charges of the FID.
pub fn unsettled_key(fid: u64) -> Vec<u8> {
    keys::prefix(
        RootPrefix::HyperUnsettledCharge,
        &[&[UNSETTLED_BY_FID], &fid.to_be_bytes()],
    )
}

/// The base fee of a message type (FIP §12 table).
pub fn base_fee(t: MessageType) -> u64 {
    match t {
        MessageType::CastAdd => 1_000_000,
        MessageType::LinkAdd | MessageType::ReactionAdd => 100_000,
        MessageType::UserDataAdd | MessageType::VerificationAddEthAddress => 500_000,
        _ => 0,
    }
}

/// Charge the fee of `message` in the shard block at `height`, if the
/// replica fee balance less the unsettled charges covers it (FIP §12).
/// Returns the fee.
pub fn charge_fee(
    db: &std::sync::Arc<RocksDB>,
    txn: &mut RocksDbTransactionBatch,
    message: &proto::Message,
    height: u64,
) -> Result<u64, Shard0Error> {
    let Some(data) = message.data.as_ref() else {
        return Ok(0);
    };
    let fid = data.fid;
    let t = MessageType::try_from(data.r#type).unwrap_or(MessageType::None);
    let base = base_fee(t);
    if base == 0 || fid == 0 {
        return Ok(0);
    }
    let trust_fp = get(db, txn, &keys::trust_score(fid))?
        .and_then(|v| <[u8; 4]>::try_from(v.as_slice()).ok())
        .map(u32::from_be_bytes)
        .unwrap_or(0);
    // Only CastAdd has a calculated uniqueness; the merge stores remove
    // other duplicates by identity.
    let uniqueness = if t == MessageType::CastAdd {
        let canonical = crate::chain::fingerprint_store::canonical_cast_content(data);
        crate::chain::fingerprint_store::FingerprintStore::new(db.clone())
            .uniqueness_score(&canonical, data.timestamp as u64, txn)
            .map_err(|e| Shard0Error::Internal(e.to_string()))?
    } else {
        proof_of_quality::fees::UNIQUENESS_ENC_FULL
    };
    let fee = proof_of_quality::fees::compute_effective_fee_micro(base, trust_fp, uniqueness);
    if fee == 0 {
        return Ok(0);
    }
    let balance = get_u64(db, txn, &keys::fee_balance(fid))?;
    let unsettled = get_u64(db, txn, &unsettled_key(fid))?;
    if balance.saturating_sub(unsettled) < fee {
        return Err(Shard0Error::invalid(format!(
            "fee balance of FID {} is {} with {} unsettled; the fee is {}",
            fid, balance, unsettled, fee
        )));
    }
    let k = charge_key(height, fid);
    let v = get_u64(db, txn, &k)? + fee;
    put_u64(txn, k, v);
    put_u64(txn, unsettled_key(fid), unsettled + fee);
    Ok(fee)
}

/// The charges of the shard block at `height`, sorted by FID (for the
/// `FeeSettlement` of shard 0).
pub fn charges_of_block(db: &RocksDB, height: u64) -> Result<Vec<FeeCharge>, Shard0Error> {
    let prefix = charges_of_height(height);
    let stop = crate::storage::util::increment_vec_u8(&prefix);
    let mut out = Vec::new();
    db.for_each_iterator_by_prefix(
        Some(prefix.clone()),
        Some(stop),
        &PageOptions::default(),
        |k, v| {
            out.push(FeeCharge {
                fid: u64::from_be_bytes(k[prefix.len()..].try_into().unwrap()),
                amount: keys::decode_u64(v),
            });
            Ok(false)
        },
    )
    .map_err(|e| Shard0Error::Internal(e.to_string()))?;
    Ok(out)
}

/// Shard 0 settled the blocks up to `settled` (a replica write of its
/// settlement point): drop their charges from the unsettled sums.
pub fn prune_settled(
    db: &RocksDB,
    txn: &mut RocksDbTransactionBatch,
    from_exclusive: u64,
    settled: u64,
) -> Result<(), Shard0Error> {
    for height in from_exclusive + 1..=settled {
        for c in charges_of_block(db, height)? {
            let u = get_u64(db, txn, &unsettled_key(c.fid))?.saturating_sub(c.amount);
            put_u64(txn, unsettled_key(c.fid), u);
            txn.delete(charge_key(height, c.fid));
        }
    }
    Ok(())
}

/// The trie operations of the replica writes of `entries` (FIP §16.13: shards
/// 1 and 2 contain the replica records).
pub fn write_ops(entries: &[proto::OutboxEntry]) -> Vec<(Vec<u8>, Option<Vec<u8>>)> {
    entries
        .iter()
        .flat_map(|e| e.writes.iter())
        .map(|w| (w.key.clone(), (!w.delete).then(|| w.value.clone())))
        .collect()
}

pub fn encode_fid(fid: u64) -> Vec<u8> {
    fid.to_be_bytes().to_vec()
}

#[allow(unused)]
fn _uses() {
    let _ = proto::OutboxEntry::default().encode_to_vec();
}
