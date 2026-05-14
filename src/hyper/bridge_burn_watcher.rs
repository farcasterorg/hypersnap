//! FIP-proof-of-work-tokenization §13.6 inbound bridge: watcher
//! for `HypersnapBridge.Burned` events on a destination chain.
//!
//! Runs alongside `recovery_watcher` (or any other per-chain
//! observer). Subscribes to the bridge contract's `Burned` event
//! at the given RPC, waits for `BRIDGE_FINALITY_CONFIRMATIONS`
//! before recording, and persists each observed burn to a local
//! `BridgeBurnStore` for the threshold-signing flow to consume.
//!
//! ## Why finality-wait inline
//!
//! L1 reorgs can drop a burn that the watcher already recorded —
//! producing a phantom credit on hypersnap. Waiting
//! `BRIDGE_FINALITY_CONFIRMATIONS` blocks (default 64 on Optimism
//! per FIP §13.8) before persisting bounds this risk: any reorg
//! deeper than the confirmation depth is treated as a consensus
//! failure on the source chain and is the operator's problem to
//! detect.
//!
//! ## Decoded fields
//!
//! - `burn_id`: contract's `uint256 burnId`, 32 bytes BE.
//! - `recipient_fid`: decoded from `bytes32 hypersnapRecipient`.
//!   The hypersnap-side encoding writes the FID as 8 BE bytes at
//!   the FRONT of bytes32 with the remaining 24 bytes zero. Any
//!   non-zero trailing bytes mean the burn was routed via a
//!   different scheme this watcher doesn't understand — skip with
//!   a warning rather than guess.
//! - `amount`: contract's `uint256 amount`, validated to fit u64
//!   (the protocol-side balance store is u64). Burns above
//!   u64::MAX atoms are skipped with a warning — this should not
//!   happen because the contract uses 6 decimals and a sane total
//!   supply, but it's a guardrail against bugs in a future contract
//!   that uses different decimals.
//!
//! ## Restart resume
//!
//! Reads `highest_observed_block(source_chain_id)` from the store
//! on startup and resumes from `last + 1 - REORG_GUARD` (so we
//! re-scan a small window in case the most-recently-persisted
//! burns were in a block that's near the finality horizon and got
//! a deeper reorg below the watermark). `REORG_GUARD = 32` blocks
//! is enough headroom for typical OP reorg depths.

use crate::hyper::bridge_burn_store::{BridgeBurnStore, BridgeBurnStoreError};
use crate::proto;
use alloy_primitives::{Address, FixedBytes, U256};
use alloy_provider::{Provider, ProviderBuilder};
use alloy_rpc_types::{BlockNumberOrTag, Filter};
use alloy_sol_types::{sol, SolEvent};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::time;
use tracing::{error, info, warn};

sol! {
    /// Subset of `HypersnapBridge.sol` — just the Burned event.
    /// Layout must match the on-chain emit exactly.
    #[allow(missing_docs)]
    event Burned(
        uint256 indexed burnId,
        address indexed sender,
        bytes32 indexed hypersnapRecipient,
        uint256 amount,
        uint32  sourceChainId
    );
}

/// Block-batch size per `eth_getLogs` call. 8K leaves headroom
/// under the common 10K cap; lower via config for stricter RPCs.
const DEFAULT_BLOCK_BATCH: u64 = 8_000;

/// Finality depth (in source-chain blocks) the watcher waits
/// before persisting a burn. Matches `BRIDGE_FINALITY_CONFIRMATIONS`
/// in FIP §13.8 (default 64 — about 2 minutes on Optimism).
pub const DEFAULT_FINALITY_CONFIRMATIONS: u64 = 64;

/// On restart, re-scan this many blocks below the highest-observed
/// watermark in case a near-finality reorg moved earlier burns.
const REORG_GUARD: u64 = 32;

#[derive(Debug, Clone)]
pub struct BridgeBurnWatcherConfig {
    /// Destination-chain RPC URL. Empty disables the watcher.
    pub rpc_url: String,
    /// EIP-155 chain id of the source chain (= the chain the
    /// bridge contract is deployed on).
    pub source_chain_id: u32,
    /// Bridge contract address on the source chain.
    pub bridge_contract_address: Address,
    /// First block to scan if the store is empty (usually the
    /// bridge deployment block).
    pub start_block: u64,
    /// Poll cadence once we're caught up to head.
    pub poll_interval: Duration,
    /// Block-batch size override.
    pub block_batch: u64,
    /// Confirmations to wait before persisting a burn.
    pub finality_confirmations: u64,
}

impl Default for BridgeBurnWatcherConfig {
    fn default() -> Self {
        Self {
            rpc_url: String::new(),
            source_chain_id: 10, // OP mainnet
            bridge_contract_address: Address::ZERO,
            start_block: 0,
            poll_interval: Duration::from_secs(30),
            block_batch: DEFAULT_BLOCK_BATCH,
            finality_confirmations: DEFAULT_FINALITY_CONFIRMATIONS,
        }
    }
}

#[derive(thiserror::Error, Debug)]
pub enum BridgeBurnWatcherError {
    #[error(transparent)]
    Store(#[from] BridgeBurnStoreError),
    #[error("rpc / transport: {0}")]
    Rpc(String),
    #[error("watcher misconfigured: {0}")]
    Config(String),
}

/// Long-running watcher task. Returns `Err` only on configuration
/// errors; transient RPC errors are logged + retried.
pub async fn run(
    cfg: BridgeBurnWatcherConfig,
    store: BridgeBurnStore,
) -> Result<(), BridgeBurnWatcherError> {
    if cfg.rpc_url.is_empty() {
        info!(
            "bridge burn watcher (chain {}): rpc_url empty, watcher not started",
            cfg.source_chain_id
        );
        return Ok(());
    }
    if cfg.bridge_contract_address == Address::ZERO {
        return Err(BridgeBurnWatcherError::Config(
            "bridge_contract_address is zero — refusing to subscribe to the zero address".into(),
        ));
    }
    let provider =
        ProviderBuilder::new().on_http(cfg.rpc_url.parse().map_err(|e: url::ParseError| {
            BridgeBurnWatcherError::Rpc(format!("invalid rpc url: {}", e))
        })?);

    let resume_from = match store
        .highest_observed_block(cfg.source_chain_id)
        .map_err(BridgeBurnWatcherError::Store)?
    {
        Some(b) => b.saturating_sub(REORG_GUARD).max(cfg.start_block),
        None => cfg.start_block,
    };
    info!(
        "bridge burn watcher (chain {}): starting; resume_from = {}, finality = {}",
        cfg.source_chain_id, resume_from, cfg.finality_confirmations
    );

    let mut next_block = resume_from;
    loop {
        let head = match provider.get_block_number().await {
            Ok(h) => h,
            Err(e) => {
                warn!(
                    "bridge burn watcher (chain {}): get_block_number failed: {}; retrying in {:?}",
                    cfg.source_chain_id, e, cfg.poll_interval
                );
                time::sleep(cfg.poll_interval).await;
                continue;
            }
        };
        // Only scan up to `head - finality_confirmations`.
        let finalized_head = head.saturating_sub(cfg.finality_confirmations);
        if next_block > finalized_head {
            time::sleep(cfg.poll_interval).await;
            continue;
        }
        let stop = (next_block + cfg.block_batch - 1).min(finalized_head);
        if let Err(e) = scan_range(&provider, &cfg, &store, next_block, stop).await {
            error!(
                "bridge burn watcher (chain {}): scan {}..={} failed: {}; retrying in {:?}",
                cfg.source_chain_id, next_block, stop, e, cfg.poll_interval
            );
            time::sleep(cfg.poll_interval).await;
            continue;
        }
        next_block = stop.saturating_add(1);
    }
}

async fn scan_range<P>(
    provider: &P,
    cfg: &BridgeBurnWatcherConfig,
    store: &BridgeBurnStore,
    from: u64,
    to: u64,
) -> Result<(), BridgeBurnWatcherError>
where
    P: Provider<alloy_transport_http::Http<reqwest::Client>>,
{
    let filter = Filter::new()
        .address(cfg.bridge_contract_address)
        .from_block(BlockNumberOrTag::Number(from))
        .to_block(BlockNumberOrTag::Number(to))
        .event_signature(Burned::SIGNATURE_HASH);

    let logs = provider
        .get_logs(&filter)
        .await
        .map_err(|e| BridgeBurnWatcherError::Rpc(e.to_string()))?;

    if logs.is_empty() {
        return Ok(());
    }

    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    for log in logs {
        let block_number = match log.block_number {
            Some(b) => b,
            None => continue,
        };
        let tx_hash = log.transaction_hash.map(|h| h.to_vec()).unwrap_or_default();

        // Decode topics: [signature_hash, burnId, sender, hypersnapRecipient].
        let topics = log.topics();
        let burn_id = match topics.get(1) {
            Some(t) => t.as_slice().to_vec(),
            None => continue,
        };
        // topics[2] = sender — not used for credit, but cross-checked
        // (optional) by the threshold-signing flow if it wants.
        let hypersnap_recipient = match topics.get(3) {
            Some(t) => *t,
            None => continue,
        };
        let recipient_fid = match decode_hypersnap_recipient(hypersnap_recipient) {
            Some(fid) => fid,
            None => {
                warn!(
                    "bridge burn watcher (chain {}): skipping burn at block {} with non-FID recipient: 0x{}",
                    cfg.source_chain_id,
                    block_number,
                    hex::encode(hypersnap_recipient.as_slice())
                );
                continue;
            }
        };

        // Decode non-indexed data: amount (uint256) || sourceChainId (uint32).
        let data = log.data().data.as_ref();
        if data.len() < 32 {
            warn!(
                "bridge burn watcher (chain {}): malformed event data at block {} (len {})",
                cfg.source_chain_id,
                block_number,
                data.len()
            );
            continue;
        }
        let amount_u256 = U256::from_be_slice(&data[..32]);
        let amount = match amount_u256.try_into() {
            Ok(a) => a,
            Err(_) => {
                warn!(
                    "bridge burn watcher (chain {}): burn amount overflows u64 at block {}",
                    cfg.source_chain_id, block_number
                );
                continue;
            }
        };

        let burn = proto::HyperObservedBurn {
            source_chain_id: cfg.source_chain_id,
            burn_id,
            recipient_fid,
            amount,
            source_block_number: block_number,
            source_tx_hash: tx_hash,
            observed_at_unix: now_unix,
        };
        store.record(&burn)?;
    }

    Ok(())
}

/// Decode the contract's `bytes32 hypersnapRecipient` into a u64
/// FID. Convention: the FID is BE-encoded into the FIRST 8 bytes,
/// trailing 24 bytes must be zero. Any other shape returns `None`
/// so the watcher skips the event rather than guessing.
fn decode_hypersnap_recipient(bytes: FixedBytes<32>) -> Option<u64> {
    let raw = bytes.as_slice();
    // Trailing 24 bytes must be all zero.
    if raw[8..].iter().any(|&b| b != 0) {
        return None;
    }
    let mut fid_bytes = [0u8; 8];
    fid_bytes.copy_from_slice(&raw[..8]);
    let fid = u64::from_be_bytes(fid_bytes);
    if fid == 0 {
        return None;
    }
    Some(fid)
}

/// Inverse of `decode_hypersnap_recipient` — produces the bytes32
/// a user (or a relayer SDK) should pass to
/// `HypersnapBridge.burn(amount, hypersnapRecipient)` when they
/// want to credit FID `fid` on hypersnap. Documented so SDKs in
/// other languages have one canonical reference.
pub fn encode_hypersnap_recipient(fid: u64) -> FixedBytes<32> {
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&fid.to_be_bytes());
    FixedBytes::from(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_defaults_disable_watcher() {
        let cfg = BridgeBurnWatcherConfig::default();
        assert!(cfg.rpc_url.is_empty());
        assert_eq!(cfg.source_chain_id, 10);
        assert_eq!(cfg.bridge_contract_address, Address::ZERO);
        assert_eq!(cfg.finality_confirmations, 64);
    }

    #[tokio::test]
    async fn empty_rpc_url_returns_immediately() {
        let dir = tempfile::TempDir::new().unwrap();
        let db = crate::storage::db::RocksDB::new(dir.path().to_str().unwrap());
        db.open().unwrap();
        let store = BridgeBurnStore::new(std::sync::Arc::new(db));
        let cfg = BridgeBurnWatcherConfig::default();
        let result = tokio::time::timeout(Duration::from_secs(1), run(cfg, store)).await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_ok());
    }

    #[tokio::test]
    async fn zero_contract_address_is_config_error() {
        let dir = tempfile::TempDir::new().unwrap();
        let db = crate::storage::db::RocksDB::new(dir.path().to_str().unwrap());
        db.open().unwrap();
        let store = BridgeBurnStore::new(std::sync::Arc::new(db));
        let cfg = BridgeBurnWatcherConfig {
            rpc_url: "http://localhost:8545".into(),
            ..BridgeBurnWatcherConfig::default()
        };
        let r = run(cfg, store).await;
        assert!(matches!(r, Err(BridgeBurnWatcherError::Config(_))));
    }

    #[test]
    fn encode_decode_recipient_round_trips() {
        for fid in [1u64, 42, 1_000_000, u64::MAX] {
            let bytes = encode_hypersnap_recipient(fid);
            assert_eq!(decode_hypersnap_recipient(bytes), Some(fid));
        }
    }

    #[test]
    fn decode_rejects_non_zero_trailing_bytes() {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&42u64.to_be_bytes());
        bytes[15] = 0xff; // garbage in middle
        let r = decode_hypersnap_recipient(FixedBytes::from(bytes));
        assert!(r.is_none());
    }

    #[test]
    fn decode_rejects_zero_fid() {
        let bytes = FixedBytes::from([0u8; 32]);
        assert!(decode_hypersnap_recipient(bytes).is_none());
    }
}
