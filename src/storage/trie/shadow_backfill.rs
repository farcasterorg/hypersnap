//! Backfill of the shadow Keccak trie (plan R0).
//!
//! A shard that has no shadow trie gets one in three steps:
//!
//! 1. **Build.** From a read-only snapshot of the shard DB at chunk height
//!    `H0`, walk every key of the blake3 sync trie (virtual shard by virtual
//!    shard, in key order), resolve the object behind it (`key_resolver`), and
//!    insert `(key, value)` into the Keccak trie. Records are written to the
//!    live DB under `RootPrefix::KeccakTrieNode`; the engine does not touch
//!    them while the status is `Building`.
//! 2. **Catch up.** Replay the persisted hub events of chunks `H0+1 ..= H1`,
//!    where `H1` is the committed height when the step starts, and record
//!    `Built { height }` after each step. Repeat until the gap is small, then
//!    stop.
//! 3. **Hand-off.** At its next commit, the shard engine sees `Built`, replays
//!    the few chunks after `height`, applies its own chunk, and marks the trie
//!    `Live` (see `ShardEngine::stage_shadow_trie`).
//!
//! While the status is not `Live`, event pruning must not remove events above
//! the recorded height (`event_prune_floor`), or step 2 or 3 cannot finish.

use super::key_resolver::TrieKeyResolver;
use super::merkle_trie::{self, TRIE_SHARD_SIZE};
use super::shadow_trie::{RocksNodeStore, ShadowStatus, ShadowTrie, ShadowTrieError};
use crate::proto;
use crate::storage::constants::RootPrefix;
use crate::storage::db::{PageOptions, RocksDB, RocksDbTransactionBatch};
use crate::storage::store::account::{HubEventStorageExt, SEQUENCE_BITS};
use crate::storage::store::stores::Stores;
use hypersnap_ktrie::KTrie;
use std::sync::Arc;
use tracing::{info, warn};

/// Keys resolved per trie commit during the build.
pub const BUILD_BATCH_KEYS: usize = 50_000;
/// Sync-trie keys fetched per page.
const PAGE_KEYS: usize = 10_000;
/// The catch-up stops and hands off when the gap is at most this many chunks.
pub const HANDOFF_GAP: u64 = 50;

#[derive(Clone, Debug, Default)]
pub struct BackfillOutcome {
    pub snapshot_height: u64,
    pub leaf_count: u64,
    pub unresolved_keys: u64,
    pub root: [u8; 32],
}

/// Lowest chunk height whose events must be kept, if a backfill needs them.
pub fn event_prune_floor(db: &RocksDB) -> Option<u64> {
    match ShadowStatus::read(db) {
        ShadowStatus::Building { snapshot_height } => Some(snapshot_height),
        ShadowStatus::Built { height } => Some(height),
        ShadowStatus::Absent | ShadowStatus::Live { .. } => None,
    }
}

/// Remove every Keccak-trie record of a shard (an interrupted build leaves
/// partial records behind).
pub fn clear_trie_records(db: &RocksDB) -> Result<u64, ShadowTrieError> {
    let start = vec![RootPrefix::KeccakTrieNode as u8];
    let stop = vec![RootPrefix::KeccakTrieNode as u8 + 1];
    let mut removed = 0u64;
    loop {
        let mut keys: Vec<Vec<u8>> = Vec::new();
        db.for_each_iterator_by_prefix_paged(
            Some(start.clone()),
            Some(stop.clone()),
            &PageOptions::default(),
            |key, _| {
                keys.push(key.to_vec());
                Ok(keys.len() >= PAGE_KEYS)
            },
        )
        .map_err(|e| ShadowTrieError::Trie(e.to_string()))?;
        if keys.is_empty() {
            return Ok(removed);
        }
        let mut txn = RocksDbTransactionBatch::new();
        for key in keys {
            txn.delete(key);
            removed += 1;
        }
        db.commit(txn)
            .map_err(|e| ShadowTrieError::Trie(e.to_string()))?;
    }
}

/// Step 1. `snapshot` is a read-only view of the shard at `snapshot_height`;
/// `live_db` is the writable shard DB that receives the trie records.
pub fn build_from_snapshot(
    snapshot: &Stores,
    live_db: Arc<RocksDB>,
    snapshot_height: u64,
) -> Result<BackfillOutcome, ShadowTrieError> {
    let mut trie = KTrie::open(RocksNodeStore::new(live_db))?;
    let mut sync_trie = snapshot.trie.clone();
    let ctx = merkle_trie::Context::new();
    let mut resolver = TrieKeyResolver::new(snapshot);

    let mut ops: Vec<(Vec<u8>, Option<Vec<u8>>)> = Vec::with_capacity(BUILD_BATCH_KEYS);
    let mut resolved = 0u64;
    let mut unresolved = 0u64;

    for virtual_shard in 0..TRIE_SHARD_SIZE {
        let prefix = [virtual_shard as u8];
        let mut page_token: Option<String> = None;
        loop {
            let mut keys = Vec::with_capacity(PAGE_KEYS);
            page_token = sync_trie
                .get_paged_values_of_subtree(
                    &ctx,
                    &snapshot.db,
                    &prefix,
                    &mut keys,
                    PAGE_KEYS,
                    page_token,
                )
                .map_err(|e| ShadowTrieError::Trie(e.to_string()))?;
            for key in keys {
                match resolver.resolve(&key) {
                    Ok(Some(object)) => {
                        ops.push((key, Some(object.state_value())));
                        resolved += 1;
                    }
                    Ok(None) | Err(_) => {
                        if unresolved < 20 {
                            warn!(
                                shard_id = snapshot.shard_id,
                                key = hex::encode(&key),
                                "shadow backfill: no object for sync-trie key"
                            );
                        }
                        unresolved += 1;
                    }
                }
                if ops.len() >= BUILD_BATCH_KEYS {
                    trie.apply(std::mem::take(&mut ops))?;
                    trie.commit_to_store()?;
                }
            }
            if page_token.is_none() {
                break;
            }
        }
        // Keys of the next virtual shard start again at low FIDs.
        resolver.evict_below(u64::MAX);
        info!(
            shard_id = snapshot.shard_id,
            virtual_shard, resolved, unresolved, "shadow backfill: virtual shard done"
        );
    }
    if !ops.is_empty() {
        trie.apply(ops)?;
    }
    let batch = trie.commit_to_store()?;

    Ok(BackfillOutcome {
        snapshot_height,
        leaf_count: batch.len,
        unresolved_keys: unresolved,
        root: batch.root,
    })
}

/// Add the gasless-key nonces and last-use times of `db` to its built trie,
/// as their storage key and stored bytes (`shadow_entries::GASLESS_STATE`).
/// The content replay keeps them in its trie; a build from the state of a
/// replay DB needs this step to give the same root. The R0 backfill does not
/// do it: its trie follows the hub events only. Returns the root.
pub fn add_gasless_state(db: Arc<RocksDB>) -> Result<[u8; 32], ShadowTrieError> {
    let mut trie = KTrie::open(RocksNodeStore::new(db.clone()))?;
    let prefix = RootPrefix::GaslessKey as u8;
    let mut ops: Vec<(Vec<u8>, Option<Vec<u8>>)> = Vec::with_capacity(BUILD_BATCH_KEYS);
    for postfix in super::shadow_entries::GASLESS_STATE {
        let mut from = vec![prefix, postfix];
        loop {
            let mut page = Vec::with_capacity(PAGE_KEYS);
            db.for_each_iterator_by_prefix_paged(
                Some(from.clone()),
                Some(vec![prefix, postfix + 1]),
                &PageOptions::default(),
                |key, value| {
                    page.push((key.to_vec(), Some(value.to_vec())));
                    Ok(page.len() >= PAGE_KEYS)
                },
            )
            .map_err(|e| ShadowTrieError::Trie(e.to_string()))?;
            let full = page.len() == PAGE_KEYS;
            if let Some((key, _)) = page.last() {
                from = key.clone();
                from.push(0);
            }
            ops.extend(page);
            if ops.len() >= BUILD_BATCH_KEYS {
                trie.apply(std::mem::take(&mut ops))?;
                trie.commit_to_store()?;
            }
            if !full {
                break;
            }
        }
    }
    if !ops.is_empty() {
        trie.apply(ops)?;
    }
    Ok(trie.commit_to_store()?.root)
}

/// All hub events of chunks `from ..= to`, in order.
pub fn events_for_heights(
    db: &Arc<RocksDB>,
    from: u64,
    to: u64,
) -> Result<Vec<proto::HubEvent>, ShadowTrieError> {
    let mut out = Vec::new();
    if from > to {
        return Ok(out);
    }
    let start_id = from << SEQUENCE_BITS;
    let stop_id = (to + 1) << SEQUENCE_BITS;
    let mut page_token: Option<Vec<u8>> = None;
    loop {
        let page_options = PageOptions {
            page_token: page_token.clone(),
            ..PageOptions::default()
        };
        let page =
            proto::HubEvent::get_events(db.clone(), start_id, Some(stop_id), Some(page_options))
                .map_err(|e| ShadowTrieError::Trie(e.to_string()))?;
        out.extend(page.events);
        match page.next_page_token {
            Some(token) => page_token = Some(token),
            None => return Ok(out),
        }
    }
}

/// Step 2. Replays the events after the trie's height until the gap to the
/// committed height `committed_height()` is at most `HANDOFF_GAP`, then writes
/// `Built { height }`. Returns that height.
pub fn catch_up(
    live_db: Arc<RocksDB>,
    from_height: u64,
    committed_height: impl Fn() -> u64,
) -> Result<u64, ShadowTrieError> {
    let mut shadow = ShadowTrie::open(live_db.clone())?;
    let mut height = from_height;
    loop {
        let target = committed_height();
        if target <= height + HANDOFF_GAP {
            let mut txn = RocksDbTransactionBatch::new();
            ShadowStatus::Built { height }.stage(&mut txn);
            live_db
                .commit(txn)
                .map_err(|e| ShadowTrieError::Trie(e.to_string()))?;
            return Ok(height);
        }
        // Bounded steps keep memory flat when the gap is large.
        let step_to = target.min(height + 1_000);
        let events = events_for_heights(&live_db, height + 1, step_to)?;
        shadow.apply_events(&events)?;
        shadow.trie_mut().commit_to_store()?;
        height = step_to;
        // Persist progress: the records are complete at `height`, so a
        // restart resumes the catch-up here instead of rebuilding.
        let mut txn = RocksDbTransactionBatch::new();
        ShadowStatus::Built { height }.stage(&mut txn);
        live_db
            .commit(txn)
            .map_err(|e| ShadowTrieError::Trie(e.to_string()))?;
    }
}
