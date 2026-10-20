//! `/hyper/v1` reads over the shard-0 state: the routes of the old hyper
//! node that keep a meaning after the pivot, with their JSON shapes. All are
//! `GET`. The full API is plan WS13.
//!
//!  - `head`, `epoch`: the certified shard-0 tip.
//!  - `block/{height}`: a summary of a shard-0 block.
//!  - `rewards/{fid}`, `nonce/{fid}`: the token balance and the account-key
//!    nonce.
//!  - `custody/{address}`: the hyper-native FID of a custody address.
//!  - `lock/{fid}/{lock_id}`, `lock-tree/root`, `lock-tree/proof/{lock_id}`:
//!    the bridge locks, their leaves, and OpenZeppelin proofs against the
//!    `bridge_lock_root` of the state (FIP §13.3).
//!  - `trust/{fid}`, `staked/{fid}`, `unstake-queue/{fid}`.
//!  - `bridge/inbound-burn/{chain_id}/{burn_id}`, `bridge/observed-burns`.
//!  - `nullifier/{hex}`: a spent QCT3 nullifier.

use crate::chain::bridge_burn_store::BridgeBurnStore;
use crate::chain::shard0::keys;
use crate::chain::shard0::ledger;
use crate::chain::shard0::state::BlockState;
use crate::chain::shard_blocks::HypersnapBlockStore;
use crate::proto::{HyperInboundBurn, StakeType, TokenLockState};
use crate::storage::constants::RootPrefix;
use crate::storage::db::RocksDB;
use alloy_primitives::{Address, B256, U256};
use http_body_util::{combinators::BoxBody, BodyExt, Full};
use hyper::body::Bytes;
use hyper::{Method, Response, StatusCode};
use prost::Message as _;
use serde_json::{json, Value};
use std::convert::Infallible;
use std::sync::Arc;

#[derive(Debug, PartialEq, Eq)]
pub enum ReadError {
    NotFound,
    BadRequest(String),
    Internal(String),
}

fn internal(e: impl std::fmt::Display) -> ReadError {
    ReadError::Internal(e.to_string())
}

fn hex0x(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

fn parse_u64(s: &str, what: &str) -> Result<u64, ReadError> {
    s.parse()
        .map_err(|_| ReadError::BadRequest(format!("invalid {}: {}", what, s)))
}

fn parse_hex32(s: &str, what: &str) -> Result<[u8; 32], ReadError> {
    let bytes = hex::decode(s.trim_start_matches("0x"))
        .map_err(|e| ReadError::BadRequest(format!("invalid {} hex: {}", what, e)))?;
    let len = bytes.len();
    bytes
        .try_into()
        .map_err(|_| ReadError::BadRequest(format!("{} must be 32 bytes (got {})", what, len)))
}

fn stake_type_name(t: u8) -> &'static str {
    match StakeType::try_from(t as i32) {
        Ok(StakeType::Validator) => "validator",
        Ok(StakeType::Vouch) => "vouch",
        Ok(StakeType::Credibility) => "credibility",
        _ => "unknown",
    }
}

/// The bridge leaf of a lock (`HypersnapBridge.sol` `MerkleProof`).
fn lock_leaf(state: &TokenLockState) -> Option<[u8; 32]> {
    let lock_id: [u8; 32] = state.lock_id.as_slice().try_into().ok()?;
    let address: [u8; 20] = state.destination_address.as_slice().try_into().ok()?;
    Some(
        hypersnap_crypto::bridge_payload::lock_leaf_evm(
            B256::from(lock_id),
            state.destination_chain_id,
            Address::from(address),
            U256::from(state.amount),
        )
        .0,
    )
}

#[derive(Clone)]
pub struct HyperV1 {
    shard0: Arc<RocksDB>,
    /// The burns that this node's watcher observed (node-local).
    burns: Option<BridgeBurnStore>,
}

impl HyperV1 {
    pub fn new(shard0: Arc<RocksDB>, burns: Option<BridgeBurnStore>) -> Self {
        HyperV1 { shard0, burns }
    }

    pub fn can_handle(&self, method: &Method, path: &str) -> bool {
        method == Method::GET && path.starts_with("/hyper/v1/")
    }

    pub async fn handle(
        &self,
        _method: &Method,
        path: &str,
        _body: Bytes,
    ) -> Response<BoxBody<Bytes, Infallible>> {
        let (status, body) = match self.read(path) {
            Ok(v) => (StatusCode::OK, v),
            Err(ReadError::NotFound) => (StatusCode::NOT_FOUND, json!({"error": "not found"})),
            Err(ReadError::BadRequest(e)) => (StatusCode::BAD_REQUEST, json!({ "error": e })),
            Err(ReadError::Internal(e)) => {
                (StatusCode::INTERNAL_SERVER_ERROR, json!({ "error": e }))
            }
        };
        Response::builder()
            .status(status)
            .header("content-type", "application/json")
            .body(Full::new(Bytes::from(body.to_string())).boxed())
            .unwrap()
    }

    pub fn read(&self, path: &str) -> Result<Value, ReadError> {
        let segments: Vec<&str> = path
            .strip_prefix("/hyper/v1/")
            .ok_or(ReadError::NotFound)?
            .trim_end_matches('/')
            .split('/')
            .collect();
        let state = BlockState::new(self.shard0.clone());
        let txn = state.txn();
        let fid = |s: &str| parse_u64(s, "fid");
        match segments.as_slice() {
            ["head"] => {
                let tip = HypersnapBlockStore::new(self.shard0.clone()).last();
                let header = tip.and_then(|b| b.header);
                Ok(json!({
                    "height": header.as_ref().map(|h| h.height),
                    "hash": header.as_ref().map(|h| hex0x(&crate::chain::block::block_hash(h))),
                }))
            }
            ["epoch"] => {
                let tip = HypersnapBlockStore::new(self.shard0.clone()).last();
                let epoch = tip.and_then(|b| b.header).map_or(0, |h| h.epoch);
                let seed = crate::chain::shard0::validators::epoch_seed(&txn, epoch)
                    .map_err(internal)?
                    .map(|s| hex0x(&s));
                Ok(json!({ "epoch": epoch, "seed": seed }))
            }
            ["block", height] => {
                let block = HypersnapBlockStore::new(self.shard0.clone())
                    .get(parse_u64(height, "height")?)
                    .ok_or(ReadError::NotFound)?;
                let h = block.header.clone().unwrap_or_default();
                Ok(json!({
                    "height": h.height,
                    "hash": hex0x(&crate::chain::block::block_hash(&h)),
                    "parent_hash": hex0x(&h.parent_hash),
                    "epoch": h.epoch,
                    "timestamp": h.timestamp,
                    "state_root": hex0x(&h.state_root),
                    "bridge_lock_root": hex0x(&h.bridge_lock_root),
                    "bridge_action_hash": hex0x(&h.bridge_action_hash),
                    "messages": block.messages.len(),
                    "system_messages": block.system_messages.len(),
                }))
            }
            ["rewards", f] => {
                let f = fid(f)?;
                let balance = txn.get_u64(&keys::balance(f)).map_err(internal)?;
                Ok(json!({ "fid": f, "balance": balance }))
            }
            ["nonce", f] => {
                let f = fid(f)?;
                let nonce = txn.get_u64(&keys::account_nonce(f)).map_err(internal)?;
                Ok(json!({ "fid": f, "nonce": nonce }))
            }
            ["custody", address] => {
                let custody = hex::decode(address.trim_start_matches("0x")).map_err(|_| {
                    ReadError::BadRequest(format!("invalid custody hex: {}", address))
                })?;
                let key = keys::prefix(RootPrefix::HyperNativeCustodyToFid, &[&custody]);
                let f = txn
                    .get(&key)
                    .map_err(internal)?
                    .map(|v| keys::decode_u64(&v));
                Ok(json!({ "custody": hex0x(&custody), "fid": f }))
            }
            ["lock", f, lock_id] => {
                let f = fid(f)?;
                let lock_id = parse_hex32(lock_id, "lock_id")?;
                let state: Option<TokenLockState> = txn
                    .get_proto(&keys::token_lock(f, &lock_id))
                    .map_err(internal)?;
                Ok(json!({
                    "fid": f,
                    "lock_id_hex": hex0x(&lock_id),
                    "state": state.as_ref().map(|s| json!({
                        "sender_fid": s.sender_fid,
                        "amount": s.amount,
                        "destination_chain_id": s.destination_chain_id,
                        "destination_address_hex": hex0x(&s.destination_address),
                    })),
                    "leaf_hex": state.as_ref().and_then(lock_leaf).map(|l| hex0x(&l)),
                }))
            }
            ["lock-tree", "root"] => {
                let root = ledger::bridge_lock_root(&txn).map_err(internal)?;
                Ok(json!({ "root_hex": hex0x(&root) }))
            }
            ["lock-tree", "proof", lock_id] => {
                let lock_id = parse_hex32(lock_id, "lock_id")?;
                let leaf = txn
                    .scan(&[RootPrefix::HyperTokenLocked as u8])
                    .map_err(internal)?
                    .values()
                    .filter_map(|v| TokenLockState::decode(v.as_slice()).ok())
                    .find(|s| s.lock_id == lock_id)
                    .and_then(|s| lock_leaf(&s));
                // The leaves in lock order (`[130][index BE]`).
                let leaves: Vec<B256> = txn
                    .scan(&[RootPrefix::HyperBridgeLockTree as u8])
                    .map_err(internal)?
                    .values()
                    .filter_map(|v| <[u8; 32]>::try_from(v.as_slice()).ok().map(B256::from))
                    .collect();
                let index = leaf.and_then(|l| leaves.iter().position(|x| x.0 == l));
                let proof = index.map(|i| {
                    hypersnap_crypto::merkle::Tree::build(leaves.clone())
                        .proof_for(i)
                        .iter()
                        .map(|h| hex0x(h.as_slice()))
                        .collect::<Vec<_>>()
                });
                Ok(json!({
                    "lock_id_hex": hex0x(&lock_id),
                    "leaf_hex": index.and(leaf).map(|l| hex0x(&l)),
                    "proof_hex": proof.clone().unwrap_or_default(),
                    "included": proof.is_some(),
                }))
            }
            ["trust", f] => {
                let f = fid(f)?;
                let score = txn
                    .get(&keys::trust_score(f))
                    .map_err(internal)?
                    .and_then(|v| <[u8; 4]>::try_from(v.as_slice()).ok())
                    .map(|b| u32::from_be_bytes(b) as f64 / 1e6);
                Ok(json!({ "fid": f, "score": score }))
            }
            ["staked", f] => {
                let f = fid(f)?;
                let get = |t: u8| txn.get_u64(&keys::staked(f, t)).map_err(internal);
                let validator = get(StakeType::Validator as u8)?;
                let vouch_out = get(StakeType::Vouch as u8)?;
                let credibility = get(StakeType::Credibility as u8)?;
                let vouch_in = get(keys::STAKE_VOUCH_RECEIVED)?;
                Ok(json!({
                    "fid": f,
                    "validator_atoms": validator,
                    "vouch_outgoing_atoms": vouch_out,
                    "vouch_incoming_atoms": vouch_in,
                    "credibility_atoms": credibility,
                    // The received vouch stake is other FIDs' tokens.
                    "total_atoms": validator.saturating_add(vouch_out).saturating_add(credibility),
                }))
            }
            ["unstake-queue", f] => {
                let f = fid(f)?;
                let prefix = keys::unstakes_of(f);
                // `[69][fid][release_epoch][stake_type]` → amount.
                let entries: Vec<(u64, u8, u64)> = txn
                    .scan(&prefix)
                    .map_err(internal)?
                    .iter()
                    .filter_map(|(k, v)| {
                        let rest = k.get(prefix.len()..)?;
                        let release = u64::from_be_bytes(rest.get(..8)?.try_into().ok()?);
                        Some((release, *rest.get(8)?, keys::decode_u64(v)))
                    })
                    .collect();
                Ok(json!({
                    "fid": f,
                    "count": entries.len(),
                    "total_pending_atoms": entries.iter().map(|e| e.2).sum::<u64>(),
                    "entries": entries.iter().map(|(release, t, amount)| json!({
                        "maturation_epoch": release,
                        "stake_type": stake_type_name(*t),
                        "amount": amount,
                    })).collect::<Vec<_>>(),
                }))
            }
            ["bridge", "inbound-burn", chain, burn_id] => {
                let chain: u32 = chain
                    .parse()
                    .map_err(|_| ReadError::BadRequest(format!("invalid chain_id: {}", chain)))?;
                let burn_id = parse_hex32(burn_id, "burn_id")?;
                let record: Option<HyperInboundBurn> = txn
                    .get_proto(&keys::inbound_burn(chain, &burn_id))
                    .map_err(internal)?;
                let b = record.clone().unwrap_or_default();
                Ok(json!({
                    "source_chain_id": chain,
                    "burn_id_hex": hex0x(&burn_id),
                    "processed": record.is_some(),
                    "recipient_fid": b.recipient_fid,
                    "amount": b.amount,
                    "source_block_number": b.source_block_number,
                    "source_tx_hash_hex": hex0x(&b.source_tx_hash),
                }))
            }
            ["bridge", "observed-burns"] => {
                let observed = match &self.burns {
                    Some(store) => store.iter_all().map_err(internal)?,
                    None => vec![],
                };
                Ok(json!({
                    "count": observed.len(),
                    "burns": observed.iter().map(|b| json!({
                        "source_chain_id": b.source_chain_id,
                        "burn_id_hex": hex0x(&b.burn_id),
                        "recipient_fid": b.recipient_fid,
                        "amount": b.amount,
                        "source_block_number": b.source_block_number,
                        "source_tx_hash_hex": hex0x(&b.source_tx_hash),
                        "observed_at_unix": b.observed_at_unix,
                    })).collect::<Vec<_>>(),
                }))
            }
            ["nullifier", nullifier] => {
                let n = parse_hex32(nullifier, "nullifier")?;
                let key = keys::prefix(RootPrefix::HyperQctNullifier, &[&n]);
                Ok(json!({ "spent": txn.exists(&key).map_err(internal)? }))
            }
            _ => Err(ReadError::NotFound),
        }
    }
}
