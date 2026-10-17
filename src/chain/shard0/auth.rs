//! Message envelopes and signer roles on shard 0 (FIP §14.1, §14.2, §16.7,
//! §16.8).
//!
//! [`open`] checks what needs no state: the hash, the Ed25519 signature, the
//! form of the extension and the size. [`resolve`] finds the role of the
//! signing key from the shard-0 state and verifies the Falcon-512 signature
//! with the stored key. Each message type then accepts only its roles.

use super::keys::{self, KeyHash};
use super::state::MsgTxn;
use super::Shard0Error;
use crate::core::util::FarcasterTime;
use crate::proto::{
    self, message_data::Body, FalconSignerRecord, FidCustodyRecord, HyperSignatureExtension,
    MessageData, MessageType, NodeAttestationState, SignatureScheme, SpendKeyRecord,
};
use crate::storage::store::account::{get_active_key, ActiveKey, OnchainEventStore};
use alloy_primitives::Address;
use ed25519_dalek::{Signature as EdSignature, VerifyingKey};
use hypersnap_falcon::domains::{self, Domain};
use prost::Message as _;

pub use hypersnap_messages::{
    blake3_20, eip712_hash, EIP712_CUSTODY_MIGRATION, EIP712_TOKEN_ESCROW_BRIDGE,
    EIP712_TOKEN_ESCROW_CLAIM,
};

/// Snapchain's limit on `data_bytes`; Hypersnap types may use up to
/// `MAX_MESSAGE_BYTES` (FIP §4.2).
const MAX_FARCASTER_DATA_BYTES: usize = 2048;
/// How far a message timestamp may be after the block (snapchain rule).
const MAX_FUTURE_SECONDS: u64 = 10 * 60;

pub fn falcon_key_hash(key: &[u8]) -> KeyHash {
    hypersnap_messages::falcon_key_hash(key)
}

/// The signature scheme of a message (FIP §16.8).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scheme {
    /// `SIGNATURE_SCHEME_NONE`: only for the types whose body signature
    /// authorizes them (§14.2).
    None,
    Ed25519,
    Dual,
    Falcon,
}

/// A message after the stateless checks.
#[derive(Clone, Debug)]
pub struct Envelope {
    pub data: MessageData,
    pub data_bytes: Vec<u8>,
    pub msg_type: MessageType,
    pub scheme: Scheme,
    /// The Ed25519 key (`ED25519` and `ED25519_FALCON512`).
    pub ed25519_key: Option<[u8; 32]>,
    /// `keccak256` of the Falcon-512 key that signed the message.
    pub falcon_key_hash: Option<KeyHash>,
    pub extension: Option<HyperSignatureExtension>,
    falcon_signature: Vec<u8>,
}

impl Envelope {
    pub fn fid(&self) -> u64 {
        self.data.fid
    }

    pub fn body(&self) -> Option<&Body> {
        self.data.body.as_ref()
    }

    /// Verify the Falcon-512 message signature (`"hypersnap-msg-v1" ||
    /// data_bytes`) with `key`, which must hash to the signer.
    pub fn verify_falcon(&self, key: &[u8]) -> Result<(), Shard0Error> {
        if self.falcon_key_hash != Some(falcon_key_hash(key)) {
            return Err(Shard0Error::invalid(
                "Falcon-512 key does not match the signer",
            ));
        }
        hypersnap_falcon::verify_bytes(key, domains::MSG, &self.data_bytes, &self.falcon_signature)
            .map_err(|_| Shard0Error::invalid("invalid Falcon-512 message signature"))
    }

    /// The payload of a second signature: `data_bytes` with the
    /// second-signature fields of the body empty (FIP §14.1), in canonical
    /// encoding. `clear` is one of the `hypersnap_messages::clear_*`
    /// functions.
    pub fn second_signature_payload(&self, clear: impl FnOnce(&mut Body)) -> Vec<u8> {
        hypersnap_messages::second_signature_payload(&self.data, clear)
    }
}

/// Stateless checks of a message (FIP §16.8).
pub fn open(
    message: &proto::Message,
    network: proto::FarcasterNetwork,
    block_timestamp: u64,
) -> Result<Envelope, Shard0Error> {
    let (data, data_bytes) = match &message.data_bytes {
        Some(bytes) if !bytes.is_empty() => (
            MessageData::decode(bytes.as_slice())
                .map_err(|_| Shard0Error::invalid("data_bytes do not decode"))?,
            bytes.clone(),
        ),
        _ => {
            let data = message
                .data
                .clone()
                .ok_or_else(|| Shard0Error::invalid("message has no data"))?;
            let bytes = data.encode_to_vec();
            (data, bytes)
        }
    };
    let msg_type = MessageType::try_from(data.r#type)
        .map_err(|_| Shard0Error::invalid("unknown message type"))?;
    let limit = if msg_type.is_hypersnap() {
        crate::chain::block::MAX_MESSAGE_BYTES
    } else {
        MAX_FARCASTER_DATA_BYTES
    };
    if data_bytes.len() > limit {
        return Err(Shard0Error::invalid("data_bytes too long"));
    }
    let msg_network = proto::FarcasterNetwork::try_from(data.network)
        .map_err(|_| Shard0Error::invalid("invalid network"))?;
    if msg_network == proto::FarcasterNetwork::None
        || (network == proto::FarcasterNetwork::Mainnet && msg_network != network)
    {
        return Err(Shard0Error::invalid("wrong network"));
    }
    if message.hash_scheme != proto::HashScheme::Blake3 as i32
        || message.hash != blake3_20(&data_bytes)
    {
        return Err(Shard0Error::invalid("bad message hash"));
    }
    let ts = FarcasterTime::new(data.timestamp as u64).to_u64();
    if ts > block_timestamp.saturating_add(MAX_FUTURE_SECONDS) {
        return Err(Shard0Error::invalid("timestamp too far in the future"));
    }

    let scheme = SignatureScheme::try_from(message.signature_scheme)
        .map_err(|_| Shard0Error::invalid("unknown signature scheme"))?;
    let mut env = Envelope {
        data,
        data_bytes,
        msg_type,
        scheme: Scheme::None,
        ed25519_key: None,
        falcon_key_hash: None,
        extension: None,
        falcon_signature: vec![],
    };
    match scheme {
        SignatureScheme::None => {
            if !message.signature.is_empty() || !message.signer.is_empty() || env.fid() != 0 {
                return Err(Shard0Error::invalid(
                    "an unsigned message has no signer, no signature and fid 0",
                ));
            }
        }
        SignatureScheme::Ed25519 => {
            env.scheme = Scheme::Ed25519;
            env.ed25519_key = Some(verify_ed25519(
                &message.signer,
                &message.hash,
                &message.signature,
            )?);
        }
        SignatureScheme::Ed25519Falcon512 => {
            env.scheme = Scheme::Dual;
            if message.signature.len() <= 64 {
                return Err(Shard0Error::invalid("dual signature has no extension"));
            }
            env.ed25519_key = Some(verify_ed25519(
                &message.signer,
                &message.hash,
                &message.signature[..64],
            )?);
            let ext = HyperSignatureExtension::decode(&message.signature[64..])
                .map_err(|_| Shard0Error::invalid("extension does not decode"))?;
            if ext.version != 1 {
                return Err(Shard0Error::invalid("unknown extension version"));
            }
            env.falcon_key_hash = Some(
                ext.falcon_signer_key_hash
                    .as_slice()
                    .try_into()
                    .map_err(|_| Shard0Error::invalid("falcon_signer_key_hash is not 32 bytes"))?,
            );
            env.falcon_signature = ext.falcon_signature.clone();
            env.extension = Some(ext);
        }
        SignatureScheme::Falcon512 => {
            env.scheme = Scheme::Falcon;
            env.falcon_key_hash = Some(
                message
                    .signer
                    .as_slice()
                    .try_into()
                    .map_err(|_| Shard0Error::invalid("Falcon-512 signer is not 32 bytes"))?,
            );
            env.falcon_signature = message.signature.clone();
        }
        SignatureScheme::Eip712 => return Err(Shard0Error::invalid("EIP-712 message signature")),
    }
    Ok(env)
}

fn verify_ed25519(signer: &[u8], hash: &[u8], signature: &[u8]) -> Result<[u8; 32], Shard0Error> {
    let key: [u8; 32] = signer
        .try_into()
        .map_err(|_| Shard0Error::invalid("Ed25519 signer is not 32 bytes"))?;
    let sig = EdSignature::from_slice(signature)
        .map_err(|_| Shard0Error::invalid("bad Ed25519 signature"))?;
    VerifyingKey::from_bytes(&key)
        .map_err(|_| Shard0Error::invalid("bad Ed25519 signer"))?
        .verify_strict(hash, &sig)
        .map_err(|_| Shard0Error::invalid("invalid Ed25519 signature"))?;
    Ok(key)
}

/// The role of the key that signed a message (FIP §14.1).
#[derive(Clone, Debug, PartialEq)]
pub enum Role {
    /// No signature (`MessageData.fid = 0`); the body signature authorizes it.
    Unsigned,
    /// The Falcon-512 custody key of a migrated FID.
    AccountKey,
    /// The Falcon-512 recovery key of a migrated FID.
    RecoveryKey,
    SpendKey {
        key_hash: KeyHash,
        record: SpendKeyRecord,
    },
    /// An app signer: an Ed25519 signer of an FID that is not migrated, a
    /// signer pair, or a Falcon-512 signer of a migrated FID.
    AppSigner,
    /// The node key of a node that the FID attested (FIP §3).
    NodeKey {
        key_hash: KeyHash,
        attestation: NodeAttestationState,
    },
}

pub fn custody_of(txn: &MsgTxn, fid: u64) -> Result<Option<FidCustodyRecord>, Shard0Error> {
    txn.get_proto(&keys::custody(fid))
}

/// Find the role of the signer of `env` and verify its signature (FIP
/// §16.8 acceptance rules). `KEY_ADD`, `KEY_REMOVE` and `CUSTODY_MIGRATION`
/// prove their own keys; their handlers call [`open`]-level checks only.
pub fn resolve(
    txn: &MsgTxn,
    onchain: &OnchainEventStore,
    env: &Envelope,
) -> Result<Role, Shard0Error> {
    let fid = env.fid();
    if env.scheme == Scheme::None {
        return Ok(Role::Unsigned);
    }
    let custody = custody_of(txn, fid)?;
    match (env.scheme, &custody) {
        (Scheme::Ed25519, None) => {
            let key = env.ed25519_key.unwrap();
            let db = txn.base().db().clone();
            let active = get_active_key(onchain, &db, txn.base().batch(), fid, &key)
                .map_err(|e| Shard0Error::Internal(e.to_string()))?
                .ok_or_else(|| Shard0Error::invalid("signer is not active for the FID"))?;
            if let ActiveKey::Gasless { .. } = active {
                if !active.admits(env.msg_type) {
                    return Err(Shard0Error::invalid(
                        "message type is not in the signer scopes",
                    ));
                }
            }
            Ok(Role::AppSigner)
        }
        (Scheme::Ed25519, Some(_)) => Err(Shard0Error::invalid(
            "a migrated FID cannot use Ed25519-only messages",
        )),
        // An FID that is not migrated has no Falcon-512 keys of its own, but
        // a signer of it can attest a node key (FIP §3).
        (Scheme::Falcon, None)
            if txn.exists(&keys::node_attestation(&env.falcon_key_hash.unwrap()))? =>
        {
            node_key_role(txn, env)
        }
        (Scheme::Dual | Scheme::Falcon, None) => Err(Shard0Error::invalid(
            "an FID that is not migrated has no Falcon-512 keys",
        )),
        (Scheme::Dual, Some(_)) => {
            let ed = env.ed25519_key.unwrap();
            let hash = env.falcon_key_hash.unwrap();
            let paired = txn
                .get(&keys::signer_pair(fid, &ed))?
                .ok_or_else(|| Shard0Error::invalid("the Ed25519 key is not a registered pair"))?;
            if paired.as_slice() != hash {
                return Err(Shard0Error::invalid(
                    "the pair names a different Falcon-512 key",
                ));
            }
            let record: FalconSignerRecord = txn
                .get_proto(&keys::falcon_signer(fid, &hash))?
                .ok_or_else(|| Shard0Error::invalid("paired Falcon-512 signer is missing"))?;
            check_scopes(&record, env.msg_type)?;
            env.verify_falcon(&record.falcon_key)?;
            Ok(Role::AppSigner)
        }
        (Scheme::Falcon, Some(custody)) => {
            let hash = env.falcon_key_hash.unwrap();
            if falcon_key_hash(&custody.falcon_custody_key) == hash {
                env.verify_falcon(&custody.falcon_custody_key)?;
                return Ok(Role::AccountKey);
            }
            if !custody.falcon_recovery_key.is_empty()
                && falcon_key_hash(&custody.falcon_recovery_key) == hash
            {
                env.verify_falcon(&custody.falcon_recovery_key)?;
                return Ok(Role::RecoveryKey);
            }
            if let Some(record) = txn.get_proto::<SpendKeyRecord>(&keys::spend_key(fid, &hash))? {
                env.verify_falcon(&record.spend_key)?;
                return Ok(Role::SpendKey {
                    key_hash: hash,
                    record,
                });
            }
            if let Some(record) =
                txn.get_proto::<FalconSignerRecord>(&keys::falcon_signer(fid, &hash))?
            {
                check_scopes(&record, env.msg_type)?;
                env.verify_falcon(&record.falcon_key)?;
                return Ok(Role::AppSigner);
            }
            node_key_role(txn, env)
        }
        (Scheme::None, _) => unreachable!(),
    }
}

/// A node key signs for its FID whether or not the FID is migrated (FIP §3,
/// §5.2).
pub fn node_key_role(txn: &MsgTxn, env: &Envelope) -> Result<Role, Shard0Error> {
    let hash = env
        .falcon_key_hash
        .ok_or_else(|| Shard0Error::invalid("a node key signs with Falcon-512"))?;
    let attestation: NodeAttestationState = txn
        .get_proto(&keys::node_attestation(&hash))?
        .ok_or_else(|| Shard0Error::invalid("the key has no role for the FID"))?;
    if attestation.fid != env.fid() {
        return Err(Shard0Error::invalid(
            "the node key belongs to a different FID",
        ));
    }
    env.verify_falcon(&attestation.node_public_key)?;
    Ok(Role::NodeKey {
        key_hash: hash,
        attestation,
    })
}

fn check_scopes(record: &FalconSignerRecord, msg_type: MessageType) -> Result<(), Shard0Error> {
    if record.scopes.is_empty() || record.scopes.contains(&(msg_type as i32)) {
        Ok(())
    } else {
        Err(Shard0Error::invalid(
            "message type is not in the signer scopes",
        ))
    }
}

/// Verify a body signature by a Falcon-512 key over `domain || payload`.
pub fn verify_falcon_body(
    key: &[u8],
    domain: Domain,
    payload: &[u8],
    signature: &[u8],
) -> Result<(), Shard0Error> {
    hypersnap_falcon::verify_bytes(key, domain, payload, signature)
        .map_err(|_| Shard0Error::invalid(format!("invalid {} signature", domain.name())))
}

// ---- EIP-712 (FIP §16.7) ----

/// The address that signed `eip712_hash(domain, payload)`.
pub fn recover_eip712(
    domain: &[u8],
    payload: &[u8],
    signature: &[u8],
) -> Result<Address, Shard0Error> {
    hypersnap_messages::recover_eip712(domain, payload, signature)
        .map_err(|e| Shard0Error::invalid(e.to_string()))
}

#[cfg(test)]
pub(crate) mod test_keys {
    //! Keys and signed messages for shard-0 tests, over the shared encoders
    //! of `hypersnap_messages`. Each Falcon-512 signature uses a fresh seeded
    //! RNG, so the signatures are deterministic.
    use super::*;
    use crate::proto::{Message, MessageData};
    use ed25519_dalek::SigningKey;
    use hypersnap_falcon::FalconSecretKey;
    use rand::SeedableRng;

    fn rng() -> rand_chacha::ChaCha20Rng {
        rand_chacha::ChaCha20Rng::from_seed([7u8; 32])
    }

    pub fn falcon(seed: u8) -> FalconSecretKey {
        hypersnap_falcon::keygen_from_seed([seed; 32])
    }

    pub fn falcon_public(sk: &FalconSecretKey) -> Vec<u8> {
        hypersnap_messages::falcon_public(sk)
    }

    pub fn falcon_sign(sk: &FalconSecretKey, domain: Domain, payload: &[u8]) -> Vec<u8> {
        hypersnap_messages::falcon_sign(sk, domain, payload, &mut rng()).unwrap()
    }

    /// A `SIGNATURE_SCHEME_FALCON512` message signed by `sk`.
    pub fn falcon_message(sk: &FalconSecretKey, data: MessageData) -> Message {
        hypersnap_messages::falcon_message(sk, data, &mut rng()).unwrap()
    }

    /// A `SIGNATURE_SCHEME_ED25519` message.
    pub fn ed25519_message(sk: &SigningKey, data: MessageData) -> Message {
        hypersnap_messages::ed25519_message(sk, data)
    }

    /// A dual-signed message with `ext` (the Falcon signature is added).
    pub fn dual_message(
        ed: &SigningKey,
        falcon_sk: &FalconSecretKey,
        data: MessageData,
        ext: HyperSignatureExtension,
    ) -> Message {
        hypersnap_messages::dual_message(ed, falcon_sk, data, ext, &mut rng()).unwrap()
    }

    /// An unsigned (`SIGNATURE_SCHEME_NONE`, fid 0) message.
    pub fn unsigned_message(data: MessageData) -> Message {
        hypersnap_messages::unsigned_message(data)
    }

    pub fn eip712_sign(
        signer: &alloy_signer_local::PrivateKeySigner,
        domain: &[u8],
        payload: &[u8],
    ) -> Vec<u8> {
        hypersnap_messages::eip712_sign(signer, domain, payload).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::test_keys::*;
    use super::*;
    use crate::proto::{FarcasterNetwork, MessageData};

    fn data(fid: u64, t: MessageType) -> MessageData {
        MessageData {
            r#type: t as i32,
            fid,
            timestamp: 10,
            network: FarcasterNetwork::Devnet as i32,
            body: Some(Body::FeeDepositBody(proto::FeeDepositBody {
                amount: 5,
                nonce: 1,
            })),
        }
    }

    #[test]
    fn falcon_envelope_verifies_with_its_key_only() {
        let sk = falcon(1);
        let m = falcon_message(&sk, data(7, MessageType::FeeDeposit));
        let env = open(&m, FarcasterNetwork::Devnet, 1_000_000_000).unwrap();
        assert_eq!(env.scheme, Scheme::Falcon);
        env.verify_falcon(&falcon_public(&sk)).unwrap();
        assert!(env.verify_falcon(&falcon_public(&falcon(2))).is_err());

        // A changed body breaks the hash.
        let mut bad = m.clone();
        bad.data_bytes = Some(data(8, MessageType::FeeDeposit).encode_to_vec());
        assert!(open(&bad, FarcasterNetwork::Devnet, 1_000_000_000).is_err());
    }

    #[test]
    fn dual_envelope_checks_both_halves() {
        let ed = ed25519_dalek::SigningKey::from_bytes(&[3u8; 32]);
        let sk = falcon(4);
        let m = dual_message(
            &ed,
            &sk,
            data(7, MessageType::FeeDeposit),
            Default::default(),
        );
        let env = open(&m, FarcasterNetwork::Devnet, 1_000_000_000).unwrap();
        assert_eq!(env.scheme, Scheme::Dual);
        env.verify_falcon(&falcon_public(&sk)).unwrap();

        // The relay form (first 64 bytes, ED25519) is a valid Ed25519 message
        // with the same hash.
        let mut relayed = m.clone();
        relayed.signature.truncate(64);
        relayed.signature_scheme = SignatureScheme::Ed25519 as i32;
        let env2 = open(&relayed, FarcasterNetwork::Devnet, 1_000_000_000).unwrap();
        assert_eq!(env2.scheme, Scheme::Ed25519);
        assert_eq!(relayed.hash, m.hash);
    }

    #[test]
    fn unsigned_needs_fid_zero() {
        let m = unsigned_message(data(0, MessageType::TokenEscrowClaim));
        assert_eq!(
            open(&m, FarcasterNetwork::Devnet, 1_000_000_000)
                .unwrap()
                .scheme,
            Scheme::None
        );
        let m = unsigned_message(data(5, MessageType::TokenEscrowClaim));
        assert!(open(&m, FarcasterNetwork::Devnet, 1_000_000_000).is_err());
    }

    #[test]
    fn eip712_round_trip() {
        let signer = alloy_signer_local::PrivateKeySigner::from_bytes(&[9u8; 32].into()).unwrap();
        let sig = eip712_sign(&signer, EIP712_CUSTODY_MIGRATION, b"payload");
        let who = recover_eip712(EIP712_CUSTODY_MIGRATION, b"payload", &sig).unwrap();
        assert_eq!(who, signer.address());
        let other = recover_eip712(EIP712_TOKEN_ESCROW_CLAIM, b"payload", &sig).unwrap();
        assert_ne!(other, signer.address());
    }
}
