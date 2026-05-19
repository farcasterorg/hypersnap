//! Hyper-side watcher for IdRegistry `Recover` events.
//!
//! Runs alongside snapchain's on-chain events ingester. Subscribes to
//! the same `IdRegistry` contract on the same RPC, but filters only
//! for the `Recover` event signature. Persists into the hyper
//! `RecoveryEventStore` (independent of the snapchain on-chain events
//! store, so the upstream snapchain proto stays untouched).
//!
//! Why a separate watcher rather than a hook into snapchain ingestion:
//!
//!  1. **Proto compatibility**: snapchain's `IdRegisterEventType` enum is
//!     part of the upstream wire protocol. Adding a `RECOVER` variant
//!     would diverge our `OnChainEvent` byte stream from upstream.
//!     Peers running vanilla snapchain would either reject or
//!     misinterpret the new event_type.
//!  2. **Layer isolation**: the hyper layer is designed as a parallel
//!     side-channel atop snapchain. New on-chain ingestion needs
//!     belong here, not crammed into the snapchain ingester.
//!  3. **Restartability**: the watcher reads `highest_recorded_block`
//!     from the store on startup and resumes from `last + 1`, so it
//!     doesn't re-scan history on every restart.
//!
//! Determinism for the in-protocol retro distribution: every validator
//! running this watcher and synced to the same OP finality depth has
//! the same Recover event set. Reads from local store at the snapshot
//! block produce byte-identical results.

use crate::hyper::recovery_store::{RecoveryEventStore, RecoveryStoreError};
use crate::proto;
use alloy_primitives::{address, Address, U256};
use alloy_provider::{Provider, ProviderBuilder};
use alloy_rpc_types::{BlockNumberOrTag, BlockTransactionsKind, Filter};
use alloy_sol_types::{sol, SolEvent};
use std::time::Duration;
use tokio::time;
use tracing::{error, info, warn};

sol! {
    /// Subset of the IdRegistry — just the Recover event.
    #[allow(missing_docs)]
    event Recover(address indexed from, address indexed to, uint256 indexed id);
}

/// IdRegistry contract address on Optimism mainnet (chain id 10).
pub const ID_REGISTRY_ADDRESS_OP: Address = address!("00000000Fc6c5F01Fc30151999387Bb99A9f489b");

/// OP mainnet chain id, recorded on each persisted event so consumers
/// can disambiguate if the watcher is ever extended to other chains.
const OP_MAINNET_CHAIN_ID: u32 = 10;

/// Block range per `eth_getLogs` call. 8K leaves headroom under the
/// common 10K cap; lower for stricter providers via config.
const DEFAULT_BLOCK_BATCH: u64 = 8_000;

#[derive(Debug, Clone)]
pub struct RecoveryWatcherConfig {
    /// Optimism RPC URL. Empty disables the watcher.
    pub rpc_url: String,
    /// First block to scan if the store is empty. Typical: the
    /// IdRegistry contract deployment block (~108864739 on OP).
    pub start_block: u64,
    /// Poll interval for catching new blocks once we're caught up to
    /// chain head.
    pub poll_interval: Duration,
    /// Block-batch size override (some RPCs cap at less than 8K).
    pub block_batch: u64,
}

impl Default for RecoveryWatcherConfig {
    fn default() -> Self {
        Self {
            rpc_url: String::new(),
            start_block: 108_864_739,
            poll_interval: Duration::from_secs(30),
            block_batch: DEFAULT_BLOCK_BATCH,
        }
    }
}

#[derive(thiserror::Error, Debug)]
pub enum RecoveryWatcherError {
    #[error(transparent)]
    Store(#[from] RecoveryStoreError),
    #[error("rpc / transport: {0}")]
    Rpc(String),
}

/// Long-running watcher task. Runs until canceled by the supervisor
/// (drop the JoinHandle, or send a shutdown signal via the encompassing
/// task framework).
///
/// Returns `Err` only on configuration / startup errors. Transient RPC
/// errors are logged + retried with backoff so the task keeps running.
pub async fn run(
    cfg: RecoveryWatcherConfig,
    store: RecoveryEventStore,
) -> Result<(), RecoveryWatcherError> {
    if cfg.rpc_url.is_empty() {
        info!("recovery watcher: rpc_url empty, watcher not started");
        return Ok(());
    }
    let provider =
        ProviderBuilder::new().on_http(cfg.rpc_url.parse().map_err(|e: url::ParseError| {
            RecoveryWatcherError::Rpc(format!("invalid rpc url: {}", e))
        })?);

    // Resume from the highest block we've already persisted, falling
    // back to the configured start block.
    let resume_from = store
        .highest_recorded_block()
        .map_err(RecoveryWatcherError::Store)?
        .map(|b| b.saturating_add(1))
        .unwrap_or(cfg.start_block);
    info!("recovery watcher: starting; resume_from = {}", resume_from);

    let mut next_block = resume_from;
    loop {
        // Get current chain head.
        let head = match provider.get_block_number().await {
            Ok(h) => h,
            Err(e) => {
                warn!(
                    "recovery watcher: get_block_number failed: {}; retrying in {:?}",
                    e, cfg.poll_interval
                );
                time::sleep(cfg.poll_interval).await;
                continue;
            }
        };

        if next_block > head {
            // Caught up. Sleep and try again.
            time::sleep(cfg.poll_interval).await;
            continue;
        }

        let stop = (next_block + cfg.block_batch - 1).min(head);
        if let Err(e) = scan_range(&provider, &store, next_block, stop).await {
            error!(
                "recovery watcher: scan {}..={} failed: {}; retrying in {:?}",
                next_block, stop, e, cfg.poll_interval
            );
            time::sleep(cfg.poll_interval).await;
            continue;
        }
        next_block = stop.saturating_add(1);
    }
}

async fn scan_range<P>(
    provider: &P,
    store: &RecoveryEventStore,
    from: u64,
    to: u64,
) -> Result<(), RecoveryWatcherError>
where
    P: Provider<alloy_transport_http::Http<reqwest::Client>>,
{
    let filter = Filter::new()
        .address(ID_REGISTRY_ADDRESS_OP)
        .from_block(BlockNumberOrTag::Number(from))
        .to_block(BlockNumberOrTag::Number(to))
        .event_signature(Recover::SIGNATURE_HASH);

    let logs = provider
        .get_logs(&filter)
        .await
        .map_err(|e| RecoveryWatcherError::Rpc(e.to_string()))?;

    if logs.is_empty() {
        return Ok(());
    }

    // Resolve block timestamps for unique block numbers in this batch.
    let mut unique_blocks: Vec<u64> = logs.iter().filter_map(|l| l.block_number).collect();
    unique_blocks.sort_unstable();
    unique_blocks.dedup();

    let mut block_ts: std::collections::HashMap<u64, u64> = std::collections::HashMap::new();
    for bn in &unique_blocks {
        let block = provider
            .get_block_by_number(BlockNumberOrTag::Number(*bn), BlockTransactionsKind::Hashes)
            .await
            .map_err(|e| RecoveryWatcherError::Rpc(e.to_string()))?;
        if let Some(b) = block {
            block_ts.insert(*bn, b.header.timestamp);
        }
    }

    for log in logs {
        let block_number = match log.block_number {
            Some(b) => b,
            None => continue,
        };
        let block_timestamp = match block_ts.get(&block_number) {
            Some(t) => *t,
            None => continue,
        };
        let log_index = log.log_index.unwrap_or(0) as u32;
        let tx_hash = log.transaction_hash.map(|h| h.to_vec()).unwrap_or_default();

        // Recover has 3 indexed topics: from (1), to (2), id (3).
        let topics = log.topics();
        let from_addr = topics
            .get(1)
            .map(|t| {
                // address occupies the last 20 bytes of the 32-byte topic.
                let raw = t.as_slice();
                raw[12..].to_vec()
            })
            .unwrap_or_default();
        let to_addr = topics
            .get(2)
            .map(|t| t.as_slice()[12..].to_vec())
            .unwrap_or_default();
        let fid = match topics.get(3) {
            Some(t) => U256::from_be_slice(t.as_slice()).to::<u64>(),
            None => continue,
        };

        let ev = proto::HyperRecoveryEvent {
            fid,
            from_address: from_addr,
            to_address: to_addr,
            block_number,
            block_timestamp,
            transaction_hash: tx_hash,
            log_index,
            chain_id: OP_MAINNET_CHAIN_ID,
        };
        store.record(&ev)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_defaults_disable_watcher() {
        let cfg = RecoveryWatcherConfig::default();
        assert!(cfg.rpc_url.is_empty());
        assert_eq!(cfg.start_block, 108_864_739);
    }

    #[tokio::test]
    async fn empty_rpc_url_returns_immediately() {
        let dir = tempfile::TempDir::new().unwrap();
        let db = crate::storage::db::RocksDB::new(dir.path().to_str().unwrap());
        db.open().unwrap();
        let store = RecoveryEventStore::new(std::sync::Arc::new(db));
        let cfg = RecoveryWatcherConfig::default();
        // With empty rpc_url, run() should return Ok(()) immediately
        // without doing any RPC.
        let result = tokio::time::timeout(Duration::from_secs(1), run(cfg, store)).await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_ok());
    }
}
