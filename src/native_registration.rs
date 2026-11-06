//! Selective port of pow's native registration: hashcash, custody EIP-712,
//! validator-assigned high FIDs and deterministic registry replication only.
use crate::{
    core::error::HubError,
    proto,
    storage::{
        constants::RootPrefix,
        db::{RocksDB, RocksDbTransactionBatch},
        store::account::{get_from_db_or_txn, StoreEventHandler},
        trie::merkle_trie::TrieKey,
    },
};
use alloy_dyn_abi::TypedData;
use alloy_primitives::{Address, Signature};
use prost::Message as _;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub const FIRST_NATIVE_FID: u64 = 1 << 32;
// Mobile onboarding target: at 500k nonce attempts/s, mean ~8.4s,
// 95th percentile ~25.1s. Actual device performance still needs benchmarking.
pub const MIN_DIFFICULTY_BITS: u32 = 22;
pub const ANCHOR_WINDOW: u64 = 1024;
/// The fork starts a separate cross-shard event stream. This is well above
/// legacy sequence numbers while remaining exactly representable in JSON numbers.
pub const FORK_EVENT_BASE: u64 = 1 << 48;
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub activation_heights: BTreeMap<String, u64>,
    #[serde(skip, default = "minimum_difficulty")]
    pub min_difficulty_bits: u32,
}
fn minimum_difficulty() -> u32 {
    MIN_DIFFICULTY_BITS
}
impl Default for Config {
    fn default() -> Self {
        Self {
            activation_heights: BTreeMap::new(),
            min_difficulty_bits: MIN_DIFFICULTY_BITS,
        }
    }
}
impl Config {
    pub fn validate(
        &self,
        num_shards: u32,
        gossip: &BTreeMap<String, u64>,
        sets: &[crate::consensus::consensus::ValidatorSetConfig],
    ) -> Result<(), String> {
        if self.activation_heights.is_empty() {
            return Ok(());
        }
        if self.activation_heights != *gossip
            || self.activation_heights.len() != num_shards as usize + 1
            || !(1..=256).contains(&self.min_difficulty_bits)
        {
            return Err("native registration requires the same complete per-shard fork schedule as gossip, and difficulty 1..=256".into());
        }
        for shard in 0..=num_shards {
            let height = self
                .activation_heights
                .get(&shard.to_string())
                .ok_or("native registration is missing a shard fork height")?;
            if !sets
                .iter()
                .any(|s| s.effective_at == *height && s.shard_ids.contains(&shard))
            {
                return Err(format!("native registration cutoff for shard {shard} must match a validator transition"));
            }
        }
        Ok(())
    }
    pub fn event_watermark(&self, shard: u32, height: u64, persisted: u64) -> u64 {
        if self.active(shard, height) {
            persisted.max(FORK_EVENT_BASE)
        } else {
            persisted
        }
    }
    pub fn active(&self, shard: u32, height: u64) -> bool {
        self.activation_heights
            .get(&shard.to_string())
            .is_some_and(|h| height >= *h)
    }
}
pub fn is_native_fid(fid: u64) -> bool {
    fid >= FIRST_NATIVE_FID
}

thread_local! {
    // API reads understand both formats. Consensus execution explicitly selects
    // the format at its candidate height, including when replaying old blocks.
    static NATIVE_FID_ENCODING: std::cell::Cell<Option<bool>> = const { std::cell::Cell::new(None) };
}

pub(crate) fn native_fid_encoding() -> bool {
    NATIVE_FID_ENCODING.with(|mode| mode.get().unwrap_or(true))
}

/// A synchronous execution scope: never retain this guard across an await.
/// The !Send marker prevents moving a scope to another executor thread.
pub(crate) struct FidEncodingScope {
    previous: Option<bool>,
    _thread: std::marker::PhantomData<std::rc::Rc<()>>,
}
impl FidEncodingScope {
    pub(crate) fn enter(enabled: bool) -> Self {
        Self {
            previous: NATIVE_FID_ENCODING.with(|mode| mode.replace(Some(enabled))),
            _thread: std::marker::PhantomData,
        }
    }

    /// Standalone admission/simulation uses the next height; nested execution
    /// keeps the exact height selected by proposal or block replay.
    pub(crate) fn or_next(config: &Config, shard: u32, next_height: u64) -> Self {
        let enabled = NATIVE_FID_ENCODING
            .with(|mode| mode.get())
            .unwrap_or_else(|| config.active(shard, next_height));
        Self::enter(enabled)
    }
}
impl Drop for FidEncodingScope {
    fn drop(&mut self) {
        NATIVE_FID_ENCODING.with(|mode| mode.set(self.previous));
    }
}
fn invalid(message: &str) -> HubError {
    HubError::validation_failure(message)
}
fn sequence_key() -> Vec<u8> {
    vec![RootPrefix::NativeFidSequence as u8]
}
pub fn account_key(fid: u64) -> Vec<u8> {
    [
        vec![RootPrefix::NativeAccount as u8],
        fid.to_be_bytes().to_vec(),
    ]
    .concat()
}
fn custody_key(address: &[u8]) -> Vec<u8> {
    [vec![RootPrefix::NativeCustodyToFid as u8], address.to_vec()].concat()
}
pub fn account(
    db: &RocksDB,
    txn: &RocksDbTransactionBatch,
    fid: u64,
) -> Result<Option<proto::NativeRegistrationRecord>, HubError> {
    get_from_db_or_txn(db, txn, &account_key(fid))?
        .map(|b| proto::NativeRegistrationRecord::decode(b.as_slice()).map_err(Into::into))
        .transpose()
}
pub fn fid_by_custody(db: &RocksDB, address: &[u8]) -> Result<Option<u64>, HubError> {
    if address.len() != 20 {
        return Err(invalid("custody must be 20 bytes"));
    }
    db.get(&custody_key(address))?
        .map(|b| {
            b.as_slice()
                .try_into()
                .map(u64::from_be_bytes)
                .map_err(|_| HubError::invalid_internal_state("corrupt native custody index"))
        })
        .transpose()
}
pub fn body(message: &proto::Message) -> Result<proto::HyperNativeOnboardBody, HubError> {
    let data = message
        .data
        .as_ref()
        .ok_or_else(|| invalid("native registration data missing"))?;
    if message.msg_type() != proto::MessageType::NativeOnboard || data.body.is_some() {
        return Err(invalid("native registration type/body mismatch"));
    }
    let bytes = data
        .native_onboard_body
        .as_ref()
        .ok_or_else(|| invalid("native registration body missing"))?;
    proto::HyperNativeOnboardBody::decode(bytes.as_slice())
        .map_err(|_| invalid("invalid native registration body"))
}

pub fn pow_gate_commitment(nonce: &[u8], difficulty: u32) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"hyper.onboard.pow.commitment:");
    h.update(nonce);
    h.update(difficulty.to_be_bytes());
    h.finalize().into()
}
pub fn pow_hash(custody: &[u8; 20], anchor: &[u8; 32], nonce: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"hyper.onboard.pow:");
    h.update(custody);
    h.update(anchor);
    h.update(nonce);
    h.finalize().into()
}
pub fn pow_target_met(hash: &[u8; 32], difficulty: u32) -> bool {
    if difficulty > 256 {
        return false;
    }
    let full = (difficulty / 8) as usize;
    let rest = difficulty % 8;
    hash[..full].iter().all(|b| *b == 0) && (rest == 0 || hash[full] < (1u8 << (8 - rest)))
}

pub fn onboard_typed_data(
    custody: &[u8; 20],
    height: u64,
    anchor: &[u8; 32],
    commitment: &[u8; 32],
) -> serde_json::Value {
    json!({"types": {
        "EIP712Domain": [{"name":"name","type":"string"},{"name":"version","type":"string"},{"name":"chainId","type":"uint256"}],
        "HyperNativeOnboard": [{"name":"custody","type":"address"},{"name":"anchor_block_height","type":"uint64"},{"name":"anchor_block_hash","type":"bytes32"},{"name":"gate_commitment","type":"bytes32"}]
    }, "primaryType":"HyperNativeOnboard", "domain":{"name":"HypersnapNativeOnboard","version":"1","chainId":"10"},
    "message":{"custody":format!("0x{}",hex::encode(custody)),"anchor_block_height":height.to_string(),"anchor_block_hash":format!("0x{}",hex::encode(anchor)),"gate_commitment":format!("0x{}",hex::encode(commitment))}})
}
pub fn precheck(message: &proto::Message) -> Result<(), HubError> {
    precheck_with_difficulty(message, 1)
}
fn precheck_with_difficulty(message: &proto::Message, minimum: u32) -> Result<(), HubError> {
    let b = body(message)?;
    let data = message
        .data
        .as_ref()
        .ok_or_else(|| invalid("missing registration data"))?;
    let bytes = if let Some(bytes) = &message.data_bytes {
        if proto::MessageData::decode(bytes.as_slice())
            .map_err(|_| invalid("invalid registration data"))?
            != *data
        {
            return Err(invalid("registration data does not match signed bytes"));
        }
        bytes.clone()
    } else {
        data.encode_to_vec()
    };
    if message.hash_scheme != proto::HashScheme::Blake3 as i32
        || message.hash != crate::storage::util::blake3_20(&bytes)
    {
        return Err(invalid("registration message hash mismatch"));
    }
    if message.fid() != 0
        || message.signature_scheme != proto::SignatureScheme::None as i32
        || !message.signature.is_empty()
        || !message.signer.is_empty()
    {
        return Err(invalid(
            "native registration has fid 0 and custody authorization only",
        ));
    }
    let custody: [u8; 20] = b
        .custody_address
        .as_slice()
        .try_into()
        .map_err(|_| invalid("custody must be 20 bytes"))?;
    if custody == [0; 20] {
        return Err(invalid("zero custody address"));
    }
    let anchor: [u8; 32] = b
        .anchor_block_hash
        .as_slice()
        .try_into()
        .map_err(|_| invalid("anchor hash must be 32 bytes"))?;
    let Some(proto::hyper_native_onboard_body::GateProof::Pow(pow)) = &b.gate_proof else {
        return Err(invalid("registration requires proof of work"));
    };
    if pow.difficulty_bits < minimum
        || !pow_target_met(
            &pow_hash(&custody, &anchor, &pow.nonce),
            pow.difficulty_bits,
        )
    {
        return Err(invalid(
            "registration proof of work does not meet its difficulty",
        ));
    }
    let typed: TypedData = serde_json::from_value(onboard_typed_data(
        &custody,
        b.anchor_block_height,
        &anchor,
        &pow_gate_commitment(&pow.nonce, pow.difficulty_bits),
    ))
    .map_err(|_| invalid("invalid custody payload"))?;
    let digest = typed
        .eip712_signing_hash()
        .map_err(|_| invalid("invalid custody payload"))?;
    if b.custody_signature.len() != 65 || !matches!(b.custody_signature[64], 0 | 1 | 27 | 28) {
        return Err(invalid("invalid custody signature"));
    }
    let parity = matches!(b.custody_signature[64], 1 | 28);
    let signature = Signature::from_bytes_and_parity(&b.custody_signature[..64], parity);
    if signature.normalize_s().is_some()
        || signature
            .recover_address_from_prehash(&digest)
            .map_err(|_| invalid("invalid custody signature"))?
            != Address::from(custody)
    {
        return Err(invalid("custody signature mismatch"));
    }
    Ok(())
}
/// Validate against the candidate block's actual height and committed anchor.
pub fn validate(
    config: &Config,
    stores: &crate::storage::store::block_engine::BlockStores,
    txn: &RocksDbTransactionBatch,
    message: &proto::Message,
    height: u64,
) -> Result<(), HubError> {
    if !config.active(0, height) {
        return Err(invalid(
            "native registration is not active before the validator fork",
        ));
    }
    precheck_with_difficulty(message, config.min_difficulty_bits)?;
    validate_state(stores, txn, message, height)
}
fn validate_state(
    stores: &crate::storage::store::block_engine::BlockStores,
    txn: &RocksDbTransactionBatch,
    message: &proto::Message,
    height: u64,
) -> Result<(), HubError> {
    let b = body(message)?;
    if message
        .data
        .as_ref()
        .is_none_or(|d| d.network != stores.network as i32)
    {
        return Err(invalid("registration belongs to another Farcaster network"));
    }
    if b.anchor_block_height >= height || height - b.anchor_block_height > ANCHOR_WINDOW {
        return Err(invalid("registration anchor is outside the recent window"));
    }
    let block = stores
        .block_store
        .get_block_by_height(b.anchor_block_height)
        .map_err(|e| HubError::internal_db_error(&e.to_string()))?
        .ok_or_else(|| invalid("registration anchor block is unavailable"))?;
    if block.hash != b.anchor_block_hash {
        return Err(invalid("registration anchor hash does not match"));
    }
    if get_from_db_or_txn(&stores.db, txn, &custody_key(&b.custody_address))?.is_some() {
        return Err(invalid("custody already has a native FID"));
    }
    Ok(())
}
pub fn merge(
    stores: &crate::storage::store::block_engine::BlockStores,
    txn: &mut RocksDbTransactionBatch,
    message: &proto::Message,
    height: u64,
) -> Result<proto::HubEvent, HubError> {
    validate(&stores.native_registration, stores, txn, message, height)?;
    let fid = get_from_db_or_txn(&stores.db, txn, &sequence_key())?
        .map(|b| {
            b.as_slice()
                .try_into()
                .map(u64::from_be_bytes)
                .map_err(|_| HubError::invalid_internal_state("corrupt native FID counter"))
        })
        .transpose()?
        .unwrap_or(FIRST_NATIVE_FID);
    if !is_native_fid(fid) {
        return Err(HubError::invalid_internal_state(
            "native FID counter out of range",
        ));
    }
    let next = fid
        .checked_add(1)
        .ok_or_else(|| invalid("native FID namespace exhausted"))?;
    let record = proto::NativeRegistrationRecord {
        fid,
        registration: Some(message.clone()),
        block_number: height,
    };
    apply_record(&stores.db, txn, &record)?;
    txn.put(sequence_key(), next.to_be_bytes().to_vec());
    event(&stores.event_handler, txn, &record)
}
pub fn validate_record_proof(
    config: &Config,
    record: &proto::NativeRegistrationRecord,
    network: proto::FarcasterNetwork,
) -> Result<(), HubError> {
    let message = record
        .registration
        .as_ref()
        .ok_or_else(|| invalid("native registration missing message"))?;
    precheck_with_difficulty(message, config.min_difficulty_bits)?;
    let body = body(message)?;
    if !is_native_fid(record.fid)
        || message
            .data
            .as_ref()
            .is_none_or(|d| d.network != network as i32)
        || body.anchor_block_height >= record.block_number
        || record.block_number - body.anchor_block_height > ANCHOR_WINDOW
    {
        return Err(invalid("invalid native registration receipt"));
    }
    if let Some(cutoff) = config.activation_heights.get("0") {
        if record.block_number < *cutoff {
            return Err(invalid("native registration receipt predates fork"));
        }
    }
    Ok(())
}

pub fn apply_record(
    db: &RocksDB,
    txn: &mut RocksDbTransactionBatch,
    record: &proto::NativeRegistrationRecord,
) -> Result<(), HubError> {
    if !is_native_fid(record.fid) {
        return Err(invalid("invalid native FID"));
    }
    let message = record
        .registration
        .as_ref()
        .ok_or_else(|| invalid("native registration missing message"))?;
    let b = body(message)?;
    if let Some(existing) = account(db, txn, record.fid)? {
        if existing == *record {
            return Ok(());
        }
        return Err(invalid("native FID already assigned"));
    }
    if get_from_db_or_txn(db, txn, &custody_key(&b.custody_address))?.is_some() {
        return Err(invalid("custody already has a native FID"));
    }
    let next = record
        .fid
        .checked_add(1)
        .ok_or_else(|| invalid("native FID namespace exhausted"))?;
    let current = get_from_db_or_txn(db, txn, &sequence_key())?
        .map(|b| {
            b.as_slice()
                .try_into()
                .map(u64::from_be_bytes)
                .map_err(|_| HubError::invalid_internal_state("corrupt native sequence"))
        })
        .transpose()?
        .unwrap_or(FIRST_NATIVE_FID);
    txn.put(sequence_key(), current.max(next).to_be_bytes().to_vec());
    txn.put(account_key(record.fid), record.encode_to_vec());
    txn.put(
        custody_key(&b.custody_address),
        record.fid.to_be_bytes().to_vec(),
    );
    Ok(())
}
pub fn event(
    handler: &StoreEventHandler,
    txn: &mut RocksDbTransactionBatch,
    record: &proto::NativeRegistrationRecord,
) -> Result<proto::HubEvent, HubError> {
    let mut event = proto::HubEvent {
        r#type: proto::HubEventType::MergeMessage as i32,
        body: Some(proto::hub_event::Body::MergeMessageBody(
            proto::MergeMessageBody {
                message: record.registration.clone(),
                deleted_messages: vec![],
                native_registration: Some(record.clone()),
            },
        )),
        ..Default::default()
    };
    handler.commit_transaction(txn, &mut event)?;
    Ok(event)
}
pub fn trie_key(record: &proto::NativeRegistrationRecord) -> Vec<u8> {
    let mut key = TrieKey::for_message_type(record.fid, proto::MessageType::NativeOnboard as u8);
    key.extend_from_slice(&crate::storage::util::blake3_20(&record.encode_to_vec()));
    key
}

pub fn normalize_data(data: &mut proto::MessageData, native_enabled: bool) {
    if !native_enabled || data.r#type != proto::MessageType::NativeOnboard as i32 {
        data.native_onboard_body = None;
    }
}
pub fn transactions_for_root(
    transactions: &[proto::Transaction],
    native_enabled: bool,
) -> std::borrow::Cow<'_, [proto::Transaction]> {
    let needs = transactions
        .iter()
        .flat_map(|t| &t.user_messages)
        .filter_map(|m| m.data.as_ref())
        .any(|d| {
            d.native_onboard_body.is_some()
                && (!native_enabled || d.r#type != proto::MessageType::NativeOnboard as i32)
        });
    if !needs {
        return std::borrow::Cow::Borrowed(transactions);
    }
    let mut transactions = transactions.to_vec();
    for data in transactions
        .iter_mut()
        .flat_map(|t| &mut t.user_messages)
        .filter_map(|m| m.data.as_mut())
    {
        normalize_data(data, native_enabled);
    }
    std::borrow::Cow::Owned(transactions)
}

pub fn is_registration_event(event: &proto::BlockEvent) -> bool {
    matches!(event.data.as_ref().and_then(|d| d.body.as_ref()), Some(proto::block_event_data::Body::MergeMessageEventBody(m)) if m.message.as_ref().is_some_and(|m| m.msg_type() == proto::MessageType::NativeOnboard))
}

/// Native IDs follow legacy IDs in enumeration, independently of the compact
/// account-key escape encoding. Tokens are full native registry keys.
pub fn list_accounts(
    db: &RocksDB,
    options: &crate::storage::db::PageOptions,
) -> Result<(Vec<u64>, Option<Vec<u8>>), HubError> {
    let prefix = vec![RootPrefix::NativeAccount as u8];
    let mut fids = vec![];
    let mut last = None;
    let limit = options
        .page_size
        .unwrap_or(crate::storage::constants::PAGE_SIZE_MAX);
    let complete = db.for_each_iterator_by_prefix(
        Some(prefix.clone()),
        Some(crate::storage::util::increment_vec_u8(&prefix)),
        options,
        |key, value| {
            let record = proto::NativeRegistrationRecord::decode(value)?;
            fids.push(record.fid);
            last = Some(key.to_vec());
            Ok(fids.len() >= limit)
        },
    )?;
    Ok((fids, if complete { None } else { last }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::util::FarcasterTime;
    use crate::{
        proto::Height,
        storage::store::{
            account::{encoded_fid_len, make_fid_key, read_fid_key},
            block_engine_test_helpers as blocks,
            mempool_poller::MempoolMessage,
        },
    };
    use alloy_signer::SignerSync;
    use alloy_signer_local::PrivateKeySigner;
    fn config() -> Config {
        Config {
            activation_heights: [("0".into(), 2), ("1".into(), 1), ("2".into(), 1)].into(),
            min_difficulty_bits: 4,
        }
    }
    fn registration(
        custody: &PrivateKeySigner,
        anchor: &proto::Block,
        bits: u32,
    ) -> proto::Message {
        let address: [u8; 20] = custody.address().into();
        let hash: [u8; 32] = anchor.hash.as_slice().try_into().unwrap();
        let nonce = (0u64..)
            .find(|n| pow_target_met(&pow_hash(&address, &hash, &n.to_be_bytes()), bits))
            .unwrap()
            .to_be_bytes()
            .to_vec();
        let height = anchor.header.as_ref().unwrap().height.unwrap().block_number;
        let typed: TypedData = serde_json::from_value(onboard_typed_data(
            &address,
            height,
            &hash,
            &pow_gate_commitment(&nonce, bits),
        ))
        .unwrap();
        let signature = custody
            .sign_hash_sync(&typed.eip712_signing_hash().unwrap())
            .unwrap();
        let data = proto::MessageData {
            r#type: proto::MessageType::NativeOnboard as i32,
            fid: 0,
            timestamp: FarcasterTime::current().to_u64() as u32,
            network: proto::FarcasterNetwork::Devnet as i32,
            body: None,
            native_onboard_body: Some(
                proto::HyperNativeOnboardBody {
                    custody_address: address.to_vec(),
                    custody_signature: signature.as_bytes().to_vec(),
                    anchor_block_height: height,
                    anchor_block_hash: hash.to_vec(),
                    gate_proof: Some(proto::hyper_native_onboard_body::GateProof::Pow(
                        proto::PowSolution {
                            nonce,
                            difficulty_bits: bits,
                        },
                    )),
                }
                .encode_to_vec(),
            ),
        };
        let bytes = data.encode_to_vec();
        proto::Message {
            data: Some(data),
            data_bytes: Some(bytes.clone()),
            hash: crate::storage::util::blake3_20(&bytes).to_vec(),
            hash_scheme: proto::HashScheme::Blake3 as i32,
            ..Default::default()
        }
    }
    fn setup() -> (
        crate::storage::store::block_engine::BlockEngine,
        tempfile::TempDir,
        proto::Block,
    ) {
        let (engine, dir) = blocks::setup();
        let engine = engine.with_native_registration(config());
        let mut anchor = blocks::default_block();
        anchor.hash = vec![42; 32];
        engine.stores().block_store.put_block(&anchor).unwrap();
        (engine, dir, anchor)
    }
    #[test]
    fn native_fids_and_legacy_keys_are_disjoint_and_round_trip() {
        assert_eq!(FIRST_NATIVE_FID, u32::MAX as u64 + 1);
        assert!(!is_native_fid(u32::MAX as u64));
        assert!(is_native_fid(FIRST_NATIVE_FID));
        for fid in [1, 42, u32::MAX as u64] {
            assert_eq!(make_fid_key(fid), (fid as u32).to_be_bytes());
            assert_eq!(read_fid_key(&make_fid_key(fid), 0), fid);
        }
        for fid in [FIRST_NATIVE_FID, FIRST_NATIVE_FID + 1, 1u64 << 63, u64::MAX] {
            let key = make_fid_key(fid);
            assert_eq!(key.len(), 12);
            assert_eq!(encoded_fid_len(&key, 0), Some(12));
            assert_eq!(read_fid_key(&key, 0), fid);
            assert_ne!(key, make_fid_key(fid as u32 as u64));
            let trie = TrieKey::for_message_type(fid, 160);
            let decoded = TrieKey::decode(&trie).unwrap();
            assert_eq!(decoded.fid, fid);
            assert_eq!(decoded.message_type, Some(160));
        }
    }
    #[test]
    fn historical_high_fid_encoding_and_nested_scopes_are_preserved() {
        let fid = FIRST_NATIVE_FID + 42;
        let native_key = TrieKey::for_fid(fid);
        {
            let _legacy = FidEncodingScope::enter(false);
            assert_eq!(make_fid_key(fid), 42u32.to_be_bytes());
            assert_eq!(crate::storage::store::account::fid_key_len(fid), 4);
            assert_eq!(TrieKey::for_fid(fid), TrieKey::for_fid(42));
            let _nested = FidEncodingScope::or_next(&config(), 0, 10);
            assert_eq!(make_fid_key(fid), 42u32.to_be_bytes());
        }
        assert_eq!(TrieKey::for_fid(fid), native_key);
        assert_eq!(make_fid_key(fid).len(), 12);
    }

    #[test]
    fn pre_fork_block_replay_keeps_legacy_high_fid_rent_keys() {
        use crate::utils::factory::events_factory;
        let (engine, _dir, _) = setup();
        // Leave the candidate (height 2) before activation.
        let mut schedule = config();
        schedule.activation_heights.insert("0".into(), 3);
        let mut engine = engine.with_native_registration(schedule);
        let rent = events_factory::create_rent_event_with_timestamp(
            FIRST_NATIVE_FID + 42,
            1,
            1_790_000_000,
        );
        let state = engine.propose_state_change(
            vec![MempoolMessage::OnchainEvent(rent.clone())],
            Height::new(0, 2),
            None,
        );
        assert_eq!(state.transactions.len(), 1);
        blocks::validate_and_commit_state_change(&mut engine, &state);
        let legacy_key = {
            let _scope = FidEncodingScope::enter(false);
            TrieKey::for_onchain_event(&rent)
        };
        assert!(engine.trie_key_exists(
            &crate::storage::trie::merkle_trie::Context::new(),
            &legacy_key
        ));
        assert!(!engine.trie_key_exists(
            &crate::storage::trie::merkle_trie::Context::new(),
            &TrieKey::for_onchain_event(&rent)
        ));
    }
    #[test]
    fn pow_target_checks_every_bit() {
        assert!(pow_target_met(&[0; 32], 256));
        assert!(!pow_target_met(&[0; 32], 257));
        let mut hash = [0; 32];
        hash[3] = 0x02;
        assert!(pow_target_met(&hash, 30));
        assert!(!pow_target_met(&hash, 31));
    }
    #[test]
    fn fork_boundary_pow_signature_anchor_and_replay_checks() {
        let (engine, _dir, anchor) = setup();
        let stores = engine.stores();
        let custody = PrivateKeySigner::random();
        let message = registration(&custody, &anchor, 4);
        let txn = RocksDbTransactionBatch::new();
        assert!(validate(&config(), &stores, &txn, &message, 1).is_err());
        validate(&config(), &stores, &txn, &message, 2).unwrap();
        assert!(validate(&config(), &stores, &txn, &message, 1026).is_err());
        let mut strict = config();
        strict.min_difficulty_bits = MIN_DIFFICULTY_BITS;
        assert!(validate(&strict, &stores, &txn, &message, 2).is_err());
        let mut tampered = message.clone();
        tampered.data.as_mut().unwrap().fid = 1;
        assert!(precheck(&tampered).is_err());
        let mut wrong_anchor = anchor.clone();
        wrong_anchor.hash = vec![43; 32];
        let bad = registration(&custody, &wrong_anchor, 4);
        assert!(validate(&config(), &stores, &txn, &bad, 2).is_err());
        let mut txn = RocksDbTransactionBatch::new();
        let event = merge(&stores, &mut txn, &message, 2).unwrap();
        assert!(validate(&config(), &stores, &txn, &message, 2).is_err());
        assert!(account(
            &stores.db,
            &RocksDbTransactionBatch::new(),
            FIRST_NATIVE_FID
        )
        .unwrap()
        .is_none());
        stores.db.commit(txn).unwrap();
        let record = account(
            &stores.db,
            &RocksDbTransactionBatch::new(),
            FIRST_NATIVE_FID,
        )
        .unwrap()
        .unwrap();
        assert_eq!(record.registration, Some(message));
        assert_eq!(
            fid_by_custody(&stores.db, custody.address().as_slice()).unwrap(),
            Some(FIRST_NATIVE_FID)
        );
        assert_eq!(
            stores
                .onchain_event_store
                .get_custody_address(FIRST_NATIVE_FID, None)
                .unwrap(),
            Some(custody.address().to_vec())
        );
        assert!(stores
            .onchain_event_store
            .get_id_register_event_by_fid(FIRST_NATIVE_FID, None)
            .unwrap()
            .is_none());
        let (insert, _) = TrieKey::for_hub_event(&event);
        assert_eq!(insert, vec![trie_key(&record)]);
    }
    #[tokio::test]
    async fn registration_proposal_commit_and_replica_are_deterministic() {
        let (mut engine, _dir, anchor) = setup();
        let custody = PrivateKeySigner::random();
        let message = registration(&custody, &anchor, 4);
        let state = engine.propose_state_change(
            vec![MempoolMessage::UserMessage(message.clone())],
            Height::new(0, 2),
            None,
        );
        assert_eq!(state.transactions.len(), 1);
        assert!(account(
            &engine.stores().db,
            &RocksDbTransactionBatch::new(),
            FIRST_NATIVE_FID
        )
        .unwrap()
        .is_none());
        let block = blocks::validate_and_commit_state_change(&mut engine, &state);
        let record = account(
            &engine.stores().db,
            &RocksDbTransactionBatch::new(),
            FIRST_NATIVE_FID,
        )
        .unwrap()
        .unwrap();
        assert!(engine.trie_key_exists(
            &crate::storage::trie::merkle_trie::Context::new(),
            &trie_key(&record)
        ));
        let native = block
            .events
            .iter()
            .find(|e| is_registration_event(e))
            .unwrap();
        let (shard, _dir2) = crate::storage::store::test_helper::new_engine().await;
        let mut shard = shard.with_native_registration(config(), engine.stores().db.clone());
        let event = native.clone();
        let mut old_stream = RocksDbTransactionBatch::new();
        shard
            .get_stores()
            .block_event_store
            .put_block_event(
                &crate::utils::factory::events_factory::create_heartbeat_event(1001),
                &mut old_stream,
            )
            .unwrap();
        shard.db.commit(old_stream).unwrap();
        crate::storage::store::test_helper::commit_block_events(&mut shard, vec![&event]).await;
        assert_eq!(
            account(&shard.db, &RocksDbTransactionBatch::new(), FIRST_NATIVE_FID).unwrap(),
            Some(record)
        );
        // Retrying an already-issued custody cannot consume another FID.
        assert!(validate(
            &config(),
            &engine.stores(),
            &RocksDbTransactionBatch::new(),
            &message,
            3
        )
        .is_err());
        assert!(account(
            &engine.stores().db,
            &RocksDbTransactionBatch::new(),
            FIRST_NATIVE_FID + 1
        )
        .unwrap()
        .is_none());
        // Existing gasless keys and storage lending make the new identity usable,
        // without inventing an IdRegistry event or changing the storage policy.
        use crate::storage::store::account::{get_gasless_key_owner_fid, list_gasless_keys_by_fid};
        use crate::utils::factory::{messages_factory as messages, signers::generate_signer};
        let app_custody = PrivateKeySigner::random();
        let app_signer = generate_signer();
        blocks::register_user(
            1,
            app_signer.clone(),
            app_custody.address().to_vec(),
            1000,
            &mut engine,
        );
        let signer = generate_signer();
        let now = FarcasterTime::current().to_u64() as u32;
        let key = messages::keys::create_key_add(
            FIRST_NATIVE_FID,
            &custody,
            1,
            &app_custody,
            &signer,
            vec![proto::MessageType::CastAdd],
            3600,
            1,
            now + 86_400,
            Some(now),
        );
        blocks::commit_message(&mut engine, &key, blocks::Validity::Valid);
        let lend = messages::storage_lend::create_storage_lend(
            1,
            FIRST_NATIVE_FID,
            1,
            proto::StorageUnitType::UnitType2025,
            None,
            Some(&app_signer),
        );
        blocks::commit_message(&mut engine, &lend, blocks::Validity::Valid);
        // Several cross-shard events from different authors arrive in one batch.
        let from = shard.get_stores().block_event_store.max_seqnum().unwrap() + 1;
        let to = engine.stores().block_event_store.max_seqnum().unwrap();
        let mut pending: Vec<_> = (from..=to)
            .map(|n| {
                engine
                    .stores()
                    .block_event_store
                    .get_block_event_by_seqnum(n)
                    .unwrap()
                    .unwrap()
            })
            .collect();
        pending.reverse(); // replay normalizes their committed sequence order
        crate::storage::store::test_helper::commit_block_events(
            &mut shard,
            pending.iter().collect(),
        )
        .await;
        assert_eq!(
            get_gasless_key_owner_fid(
                &shard.db,
                &RocksDbTransactionBatch::new(),
                &signer.verifying_key().to_bytes()
            )
            .unwrap(),
            Some(FIRST_NATIVE_FID)
        );
        let keys =
            list_gasless_keys_by_fid(&shard.db, FIRST_NATIVE_FID, &Default::default()).unwrap();
        assert_eq!(keys.records[0].0, signer.verifying_key().to_bytes());
        let cast = messages::casts::create_cast_add(
            FIRST_NATIVE_FID,
            "native account without an IdRegistry transaction",
            None,
            Some(&signer),
        );
        crate::storage::store::test_helper::commit_message(&mut shard, &cast).await;
        assert!(shard
            .get_stores()
            .onchain_event_store
            .get_id_register_event_by_fid(FIRST_NATIVE_FID, None)
            .unwrap()
            .is_none());
        let remove = messages::keys::create_key_remove_custody(
            FIRST_NATIVE_FID,
            &custody,
            &signer,
            &signer.verifying_key().to_bytes(),
            2,
            now + 86_400,
            Some(now),
        );
        let removed = blocks::commit_message(&mut engine, &remove, blocks::Validity::Valid);
        crate::storage::store::test_helper::commit_block_events(
            &mut shard,
            removed.events.iter().collect(),
        )
        .await;
        let rejected = messages::casts::create_cast_add(
            FIRST_NATIVE_FID,
            "revoked signer must fail",
            None,
            Some(&signer),
        );
        assert!(shard.simulate_message(&rejected).is_err());
    }
    #[test]
    fn authentication_and_pending_registration_deduplication() {
        use crate::mempool::mempool::MessageMempoolExt;
        let (_, _dir, anchor) = setup();
        let original = registration(&PrivateKeySigner::random(), &anchor, 4);
        let mut changed = original.clone();
        changed.data.as_mut().unwrap().timestamp += 1;
        assert_eq!(original.mempool_key(), changed.mempool_key());
        let mut body = body(&changed).unwrap();
        body.custody_signature[0] ^= 1;
        changed.data.as_mut().unwrap().native_onboard_body = Some(body.encode_to_vec());
        let bytes = changed.data.as_ref().unwrap().encode_to_vec();
        changed.data_bytes = Some(bytes.clone());
        changed.hash = crate::storage::util::blake3_20(&bytes).to_vec();
        assert!(precheck(&changed).is_err());
    }
    #[test]
    fn registration_schedule_is_the_validator_and_topic_fork_schedule() {
        let file: toml::Value = toml::from_str(include_str!("../validators.toml")).unwrap();
        let config: Config = file["consensus"]["native_registration"]
            .clone()
            .try_into()
            .unwrap();
        let gossip: BTreeMap<String, u64> =
            file["gossip"]["topic_cutovers"].clone().try_into().unwrap();
        let sets: Vec<crate::consensus::consensus::ValidatorSetConfig> = file["consensus"]
            ["validator_sets"]
            .clone()
            .try_into()
            .unwrap();
        config.validate(2, &gossip, &sets).unwrap();
        for (shard, height) in &config.activation_heights {
            let shard = shard.parse().unwrap();
            assert!(!config.active(shard, height - 1));
            assert!(config.active(shard, *height));
        }
        let mut wrong = config.clone();
        *wrong.activation_heights.get_mut("1").unwrap() += 1;
        assert!(wrong.validate(2, &gossip, &sets).is_err());
        assert_eq!(config.min_difficulty_bits, MIN_DIFFICULTY_BITS);
        assert_eq!(
            MIN_DIFFICULTY_BITS, 22,
            "pin the consensus registration difficulty"
        );
    }
    #[test]
    fn native_ids_remain_lossless_in_json() {
        #[derive(Serialize, Deserialize)]
        struct Data {
            #[serde(with = "super::serde_fid")]
            fid: u64,
            #[serde(with = "super::serde_fid::vec")]
            fids: Vec<u64>,
            #[serde(with = "super::serde_fid::option")]
            requester: Option<u64>,
        }
        let data = Data {
            fid: FIRST_NATIVE_FID + 7,
            fids: vec![42, FIRST_NATIVE_FID + 9],
            requester: Some(FIRST_NATIVE_FID),
        };
        let json = serde_json::to_value(&data).unwrap();
        assert_eq!(json["fid"], (FIRST_NATIVE_FID + 7).to_string());
        assert_eq!(json["fids"][0], 42);
        let decoded: Data = serde_json::from_value(json).unwrap();
        assert_eq!(decoded.fid, data.fid);
        assert_eq!(decoded.fids, data.fids);
        assert_eq!(decoded.requester, data.requester);
    }
    #[test]
    fn legacy_messages_ignore_registration_extensions_without_losing_their_body() {
        use crate::storage::store::account::decode_message_data;
        use crate::utils::factory::messages_factory;
        use prost::encoding::{encode_key, encode_varint, WireType};
        let cast = messages_factory::casts::create_cast_add(42, "legacy body survives", None, None);
        let data = cast.data.unwrap();
        let mut bytes = data.encode_to_vec();
        // Wrong wire type was valid as an unknown field on Snapchain.
        encode_key(1160, WireType::Varint, &mut bytes);
        encode_varint(123, &mut bytes);
        let decoded = decode_message_data(&bytes, None).unwrap();
        assert_eq!(decoded, data);
        let mut with_extension = data.clone();
        with_extension.native_onboard_body = Some(vec![0xff, 0xff]);
        let decoded = decode_message_data(&with_extension.encode_to_vec(), None).unwrap();
        assert_eq!(decoded, data);
        let tx = proto::Transaction {
            fid: 42,
            user_messages: vec![proto::Message {
                data: Some(with_extension),
                ..Default::default()
            }],
            ..Default::default()
        };
        let normalized = transactions_for_root(&[tx], false).into_owned();
        assert_eq!(normalized[0].user_messages[0].data.as_ref().unwrap(), &data);
    }
    #[test]
    fn aborted_registration_does_not_consume_sequence_and_assignment_is_monotonic() {
        let (engine, _dir, anchor) = setup();
        let stores = engine.stores();
        let first = registration(&PrivateKeySigner::random(), &anchor, 4);
        let second = registration(&PrivateKeySigner::random(), &anchor, 4);
        {
            let mut discarded = RocksDbTransactionBatch::new();
            merge(&stores, &mut discarded, &first, 2).unwrap();
        }
        let mut txn = RocksDbTransactionBatch::new();
        merge(&stores, &mut txn, &second, 2).unwrap();
        merge(&stores, &mut txn, &first, 2).unwrap();
        stores.db.commit(txn).unwrap();
        assert_eq!(
            account(
                &stores.db,
                &RocksDbTransactionBatch::new(),
                FIRST_NATIVE_FID
            )
            .unwrap()
            .unwrap()
            .registration,
            Some(second)
        );
        assert_eq!(
            account(
                &stores.db,
                &RocksDbTransactionBatch::new(),
                FIRST_NATIVE_FID + 1
            )
            .unwrap()
            .unwrap()
            .registration,
            Some(first)
        );
        let fids: Vec<_> =
            crate::storage::store::account::FIDIterator::new(stores.db.clone(), 0).collect();
        assert_eq!(fids, vec![FIRST_NATIVE_FID, FIRST_NATIVE_FID + 1]);
        let (page, token) = stores
            .onchain_event_store
            .get_fids(&crate::storage::db::PageOptions {
                page_size: Some(1),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(page, vec![FIRST_NATIVE_FID]);
        let (page, _) = stores
            .onchain_event_store
            .get_fids(&crate::storage::db::PageOptions {
                page_size: Some(1),
                page_token: token,
                ..Default::default()
            })
            .unwrap();
        assert_eq!(page, vec![FIRST_NATIVE_FID + 1]);
        // Reverse enumeration starts with native IDs, then continues into
        // legacy registrations without dropping or repeating an account.
        let legacy = crate::utils::factory::events_factory::create_id_register_event(
            42,
            proto::IdRegisterEventType::Register,
            vec![42; 20],
            None,
        );
        let mut txn = RocksDbTransactionBatch::new();
        stores
            .onchain_event_store
            .merge_onchain_event(legacy, &mut txn)
            .unwrap();
        stores.db.commit(txn).unwrap();
        let mut token = None;
        let mut reverse = vec![];
        for _ in 0..5 {
            let (page, next) = stores
                .onchain_event_store
                .get_fids(&crate::storage::db::PageOptions {
                    page_size: Some(1),
                    reverse: true,
                    page_token: token,
                })
                .unwrap();
            reverse.extend(page);
            token = next;
            if token.is_none() {
                break;
            }
        }
        assert!(token.is_none());
        assert_eq!(reverse, vec![FIRST_NATIVE_FID + 1, FIRST_NATIVE_FID, 42]);
    }
    #[tokio::test]
    async fn native_receipts_survive_snapshot_replay_and_reject_forged_assignments() {
        let (mut engine, _dir, anchor) = setup();
        let message = registration(&PrivateKeySigner::random(), &anchor, 4);
        let state = engine.propose_state_change(
            vec![MempoolMessage::UserMessage(message)],
            Height::new(0, 2),
            None,
        );
        blocks::validate_and_commit_state_change(&mut engine, &state);
        let record = account(
            &engine.stores().db,
            &RocksDbTransactionBatch::new(),
            FIRST_NATIVE_FID,
        )
        .unwrap()
        .unwrap();
        let (shard, _dir2) = crate::storage::store::test_helper::new_engine().await;
        let shard = shard.with_native_registration(config(), engine.stores().db.clone());
        let entry = proto::ShardTrieEntryWithMessage {
            trie_key: trie_key(&record),
            trie_message: Some(
                proto::shard_trie_entry_with_message::TrieMessage::NativeRegistration(
                    record.clone(),
                ),
            ),
        };
        let mut txn = RocksDbTransactionBatch::new();
        let result = shard
            .replay_replicator_message(&mut txn, &entry, true)
            .unwrap();
        assert_eq!(result.trie_keys, vec![trie_key(&record)]);
        shard.db.commit(txn).unwrap();
        assert_eq!(
            account(&shard.db, &RocksDbTransactionBatch::new(), FIRST_NATIVE_FID).unwrap(),
            Some(record.clone())
        );
        let mut forged = record;
        forged.fid += 1;
        let wrong = proto::ShardTrieEntryWithMessage {
            trie_message: Some(
                proto::shard_trie_entry_with_message::TrieMessage::NativeRegistration(forged),
            ),
            ..entry
        };
        assert!(shard
            .replay_replicator_message(&mut RocksDbTransactionBatch::new(), &wrong, true)
            .is_err());
    }
}

pub mod serde_fid {
    use serde::{ser::SerializeSeq, Deserialize, Deserializer, Serialize, Serializer};
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Id {
        Number(u64),
        Text(String),
    }
    impl Id {
        fn parse<E: serde::de::Error>(self) -> Result<u64, E> {
            match self {
                Self::Number(n) => Ok(n),
                Self::Text(s) => s.parse().map_err(E::custom),
            }
        }
    }
    struct Fid(u64);
    impl Serialize for Fid {
        fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            serialize(&self.0, s)
        }
    }
    pub fn serialize<S: Serializer>(fid: &u64, serializer: S) -> Result<S::Ok, S::Error> {
        if crate::native_registration::is_native_fid(*fid) {
            fid.to_string().serialize(serializer)
        } else {
            fid.serialize(serializer)
        }
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
        Id::deserialize(deserializer)?.parse()
    }
    pub mod option {
        use super::*;
        pub fn serialize<S: Serializer>(fid: &Option<u64>, s: S) -> Result<S::Ok, S::Error> {
            fid.map(Fid).serialize(s)
        }
        pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<u64>, D::Error> {
            Option::<Id>::deserialize(d)?.map(Id::parse).transpose()
        }
    }
    pub mod vec {
        use super::*;
        pub fn serialize<S: Serializer>(fids: &[u64], s: S) -> Result<S::Ok, S::Error> {
            let mut seq = s.serialize_seq(Some(fids.len()))?;
            for fid in fids {
                seq.serialize_element(&Fid(*fid))?;
            }
            seq.end()
        }
        pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u64>, D::Error> {
            Vec::<Id>::deserialize(d)?
                .into_iter()
                .map(Id::parse)
                .collect()
        }
    }
}
