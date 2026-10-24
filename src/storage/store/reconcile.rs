//! Hyper reconciliation: merges into the hyper stores every message the legacy
//! stores hold that the hyper stores lack, and records each FID's hyper casts
//! in the cast hash index.
//!
//! Chunk replay ([`super::hyper_backfill`]) and the engine's dual write fill the
//! hyper stores, but neither surfaces merge failures, and a message that
//! reached legacy storage outside the local chunk history never reaches hyper
//! at all. This pass walks each FID's legacy messages once, checkpointed per
//! shard by FID. Merging goes through the hyper stores' CRDT rules, so a legacy
//! message that hyper has since superseded (for example, a cast hyper holds a
//! remove for) is rejected rather than resurrected.
//!
//! The cast hash index is otherwise fed from events and chunk replay, so it
//! misses the same messages; recording every hyper cast-adds key per FID
//! completes it.

use crate::api::cast_hash_index::CastHashIndexer;
use crate::mempool::routing::{MessageRouter, ShardRouter};
use crate::proto::Message;
use crate::storage::constants::{RootPrefix, UserPostfix};
use crate::storage::db::{PageOptions, RocksDB, RocksDbTransactionBatch};
use crate::storage::store::account::{make_user_key_with_prefix, message_decode, HASH_LENGTH};
use crate::storage::store::stores::Stores;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tracing::{info, warn};

/// Bump to run the pass again over every FID.
const CHECKPOINT_NAME: &str = "hyper_reconcile_v1";
/// FIDs between checkpoint writes and progress logs.
const FIDS_PER_CHECKPOINT: u64 = 10_000;
/// Legacy messages checked against hyper per multi-get.
const KEY_BATCH: usize = 512;
/// Messages this recent are left to the engine's dual write, so the pass does
/// not race a block that is merging them right now.
const RECENT_SECS: u64 = 600;
/// Message records occupy user postfixes below this value; index records
/// (add/remove sets and so on) start at it.
const FIRST_INDEX_POSTFIX: u8 = 86;

#[derive(Default)]
struct PassStats {
    scanned: u64,
    merged: u64,
    casts_indexed: u64,
}

/// Run the reconciliation pass for every shard, resuming from each shard's
/// checkpoint. Blocking; run it on a blocking thread.
pub fn run_hyper_reconcile(
    api_db: &Arc<RocksDB>,
    shard_stores: &HashMap<u32, Stores>,
    hyper_shard_stores: &HashMap<u32, Stores>,
    cast_hash: &CastHashIndexer,
) {
    let num_shards = shard_stores.len() as u32;
    let router = ShardRouter {};
    let mut shard_ids: Vec<_> = shard_stores.keys().cloned().collect();
    shard_ids.sort();

    for shard_id in shard_ids {
        let (Some(legacy), Some(hyper)) = (
            shard_stores.get(&shard_id),
            hyper_shard_stores.get(&shard_id),
        ) else {
            continue;
        };
        let Some(max_fid) = max_registered_fid(legacy) else {
            continue;
        };
        let start_fid =
            crate::api::backfill::load_shard_checkpoint(api_db, CHECKPOINT_NAME, shard_id).max(1);
        if start_fid > max_fid {
            info!(
                shard_id,
                max_fid, "Hyper reconciliation already complete for shard"
            );
            continue;
        }
        info!(
            shard_id,
            from = start_fid,
            to = max_fid,
            "Starting hyper reconciliation"
        );

        let started = Instant::now();
        let cutoff = crate::core::util::get_farcaster_time()
            .unwrap_or(0)
            .saturating_sub(RECENT_SECS);
        let mut stats = PassStats::default();
        for fid in start_fid..=max_fid {
            if router.route_fid(fid, num_shards) == shard_id {
                reconcile_fid(legacy, hyper, cast_hash, fid, cutoff, &mut stats);
            }
            if fid % FIDS_PER_CHECKPOINT == 0 || fid == max_fid {
                crate::api::backfill::save_shard_checkpoint(
                    api_db,
                    CHECKPOINT_NAME,
                    shard_id,
                    fid + 1,
                )
                .unwrap_or_else(
                    |e| warn!(shard_id, error = %e, "Failed to save reconcile checkpoint"),
                );
                info!(
                    shard_id,
                    fid,
                    max_fid,
                    scanned = stats.scanned,
                    merged = stats.merged,
                    casts_indexed = stats.casts_indexed,
                    elapsed_secs = started.elapsed().as_secs(),
                    "Hyper reconciliation progress"
                );
            }
        }
        info!(
            shard_id,
            scanned = stats.scanned,
            merged = stats.merged,
            casts_indexed = stats.casts_indexed,
            elapsed_secs = started.elapsed().as_secs(),
            "Hyper reconciliation complete for shard"
        );
    }
}

/// The highest registered FID, from the last IdRegister events in key order.
pub(crate) fn max_registered_fid(stores: &Stores) -> Option<u64> {
    stores
        .onchain_event_store
        .get_fids(&PageOptions {
            page_size: Some(64),
            page_token: None,
            reverse: true,
        })
        .ok()
        .and_then(|(fids, _)| fids.into_iter().max())
}

fn reconcile_fid(
    legacy: &Stores,
    hyper: &Stores,
    cast_hash: &CastHashIndexer,
    fid: u64,
    cutoff: u64,
    stats: &mut PassStats,
) {
    let legacy_user = make_user_key_with_prefix(RootPrefix::User as u8, fid);
    let hyper_root = RootPrefix::HyperUser as u8;
    let db = &legacy.db;

    let mut batch: Vec<(Vec<u8>, Vec<u8>)> = Vec::with_capacity(KEY_BATCH);
    let start = [&legacy_user[..], &[UserPostfix::CastMessage as u8]].concat();
    let stop = [&legacy_user[..], &[FIRST_INDEX_POSTFIX]].concat();
    let result = db.for_each_iterator_by_prefix(
        Some(start),
        Some(stop),
        &PageOptions::default(),
        |key, value| {
            batch.push((key.to_vec(), value.to_vec()));
            if batch.len() >= KEY_BATCH {
                merge_missing(hyper, hyper_root, &mut batch, cutoff, stats);
            }
            Ok(false)
        },
    );
    if let Err(e) = result {
        warn!(fid, error = %e, "Failed to scan legacy messages");
    }
    merge_missing(hyper, hyper_root, &mut batch, cutoff, stats);

    index_hyper_casts(hyper, cast_hash, fid, stats);
}

/// Merge the messages in `batch` whose hyper primary key is absent, then
/// clear `batch`.
fn merge_missing(
    hyper: &Stores,
    hyper_root: u8,
    batch: &mut Vec<(Vec<u8>, Vec<u8>)>,
    cutoff: u64,
    stats: &mut PassStats,
) {
    if batch.is_empty() {
        return;
    }
    stats.scanned += batch.len() as u64;
    let hyper_keys: Vec<Vec<u8>> = batch
        .iter()
        .map(|(key, _)| [&[hyper_root][..], &key[1..]].concat())
        .collect();
    let present = match hyper.db.get_many(&hyper_keys) {
        Ok(values) => values,
        Err(e) => {
            warn!(error = %e, "Failed to check hyper keys");
            batch.clear();
            return;
        }
    };

    let mut txn = RocksDbTransactionBatch::new();
    for ((_, value), hyper_value) in batch.iter().zip(present.iter()) {
        if !hyper_value.is_empty() {
            continue;
        }
        let Ok(message) = message_decode(value) else {
            continue;
        };
        if is_recent(&message, cutoff) {
            continue;
        }
        if super::hyper_backfill::merge_message_to_hyper(hyper, &message, &mut txn) {
            stats.merged += 1;
        }
    }
    if txn.len() > 0 {
        if let Err(e) = hyper.db.commit(txn) {
            warn!(error = %e, "Failed to commit reconciled messages");
        }
    }
    batch.clear();
}

fn is_recent(message: &Message, cutoff: u64) -> bool {
    message
        .data
        .as_ref()
        .is_some_and(|data| data.timestamp as u64 >= cutoff)
}

/// Record every cast in the FID's hyper cast-adds set in the cast hash index.
fn index_hyper_casts(hyper: &Stores, cast_hash: &CastHashIndexer, fid: u64, stats: &mut PassStats) {
    let user = make_user_key_with_prefix(RootPrefix::HyperUser as u8, fid);
    let start = [&user[..], &[UserPostfix::CastAdds as u8]].concat();
    let stop = [&user[..], &[UserPostfix::CastAdds as u8 + 1]].concat();
    let hash_offset = start.len();

    let mut hashes: Vec<Vec<u8>> = Vec::new();
    let result = hyper.db.for_each_iterator_by_prefix(
        Some(start),
        Some(stop),
        &PageOptions::default(),
        |key, _| {
            if key.len() == hash_offset + HASH_LENGTH {
                hashes.push(key[hash_offset..].to_vec());
            }
            Ok(false)
        },
    );
    if let Err(e) = result {
        warn!(fid, error = %e, "Failed to scan hyper cast adds");
        return;
    }
    stats.casts_indexed += hashes.len() as u64;
    cast_hash.record_many(fid, &hashes);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::config::FeatureConfig;
    use crate::storage::store::account::CastStore;
    use crate::storage::store::test_helper;
    use crate::utils::factory::messages_factory;

    #[tokio::test]
    async fn test_reconcile_merges_legacy_only_messages_and_indexes_casts() {
        let (mut engine, _dir) = test_helper::new_engine().await;
        let fid = test_helper::FID_FOR_TEST;
        test_helper::register_user(
            fid,
            test_helper::default_signer(),
            test_helper::default_custody_address(),
            &mut engine,
        )
        .await;

        // One cast through the engine (dual-written), one into legacy only.
        let both = messages_factory::casts::create_cast_add(fid, "both", None, None);
        test_helper::commit_message(&mut engine, &both).await;
        let legacy_only = messages_factory::casts::create_cast_add(
            fid,
            "legacy only",
            Some(both.data.as_ref().unwrap().timestamp - 3600),
            None,
        );
        let legacy = engine.get_stores();
        let hyper = engine.get_hyper_stores().unwrap();
        let mut txn = RocksDbTransactionBatch::new();
        legacy
            .cast_store
            .merge(&legacy_only, &mut txn, &test_helper::default_merge_ctx())
            .unwrap();
        legacy.db.commit(txn).unwrap();
        assert!(
            CastStore::get_cast_add(&hyper.cast_store, fid, legacy_only.hash.clone())
                .unwrap()
                .is_none()
        );

        let api_dir = tempfile::tempdir().unwrap();
        let api_db = Arc::new(RocksDB::new(api_dir.path().to_str().unwrap()));
        api_db.open().unwrap();
        let cast_hash = CastHashIndexer::new(
            FeatureConfig {
                enabled: true,
                ..Default::default()
            },
            api_db.clone(),
        );
        let shard_stores = HashMap::from([(1u32, legacy.clone())]);
        let hyper_stores = HashMap::from([(1u32, hyper.clone())]);
        run_hyper_reconcile(&api_db, &shard_stores, &hyper_stores, &cast_hash);

        assert!(
            CastStore::get_cast_add(&hyper.cast_store, fid, legacy_only.hash.clone())
                .unwrap()
                .is_some()
        );
        assert_eq!(cast_hash.get_fid_by_hash(&legacy_only.hash), Some(fid));
        assert_eq!(cast_hash.get_fid_by_hash(&both.hash), Some(fid));

        // A finished pass resumes past the last FID and leaves hyper unchanged.
        run_hyper_reconcile(&api_db, &shard_stores, &hyper_stores, &cast_hash);
        let casts =
            CastStore::get_cast_adds_by_fid(&hyper.cast_store, fid, &PageOptions::default())
                .unwrap();
        assert_eq!(casts.messages.len(), 2);
    }
}
