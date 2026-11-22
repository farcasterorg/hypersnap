//! Blocks whose live index events a bridge lost while the node kept running.
//!
//! A bridge drops an event when the index channel is full and misses events
//! when it lags behind the engine's broadcast. Until now both waited for the
//! next restart's block backfill, so on a busy node some casts stayed missing
//! from the hash index (and unfindable by hash) for as long as it ran.
//!
//! The bridges record the heights here; a repair task reads those blocks back
//! from the shard store, which keeps every committed block, and replays them
//! into the indexers that can take a message twice and in any order.

use crate::api::events::IndexEvent;
use crate::api::indexer::Indexer;
use crate::storage::store::stores::Stores;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::broadcast;

/// Blocks read from the shard store per replayed batch.
const REPAIR_BATCH_BLOCKS: u64 = 100;
/// How often the repair task looks for lost blocks.
const REPAIR_INTERVAL: Duration = Duration::from_secs(10);

/// Inclusive block ranges with lost events, per shard.
#[derive(Default)]
pub struct IndexGaps(Mutex<Gaps>);

#[derive(Default)]
struct Gaps {
    /// Ranges waiting for the next repair pass.
    pending: HashMap<u32, Vec<(u64, u64)>>,
    /// Per shard, the lowest block a running repair pass hasn't replayed yet.
    replaying: HashMap<u32, u64>,
}

impl IndexGaps {
    /// Record that events from blocks `from..=to` of `shard_id` were lost.
    pub fn lost(&self, shard_id: u32, from: u64, to: u64) {
        let (from, to) = (from.min(to), from.max(to));
        let mut gaps = self.0.lock().unwrap();
        let ranges = gaps.pending.entry(shard_id).or_default();
        // Drops come in runs of the same or next block; extend the last range.
        if let Some(last) = ranges.last_mut() {
            if from <= last.1.saturating_add(1) && to.saturating_add(1) >= last.0 {
                *last = (last.0.min(from), last.1.max(to));
                return;
            }
        }
        ranges.push((from, to));
    }

    /// Take every recorded range, merged and sorted per shard, for a repair
    /// pass. They count towards [`Self::floor`] until the pass moves past them.
    pub(crate) fn take(&self) -> HashMap<u32, Vec<(u64, u64)>> {
        let mut gaps = self.0.lock().unwrap();
        let mut taken = std::mem::take(&mut gaps.pending);
        for (&shard_id, ranges) in taken.iter_mut() {
            ranges.sort_unstable();
            let mut merged: Vec<(u64, u64)> = Vec::with_capacity(ranges.len());
            for &(from, to) in ranges.iter() {
                match merged.last_mut() {
                    Some(last) if from <= last.1.saturating_add(1) => last.1 = last.1.max(to),
                    _ => merged.push((from, to)),
                }
            }
            *ranges = merged;
            if let Some(&(from, _)) = ranges.first() {
                gaps.replaying.insert(shard_id, from);
            }
        }
        taken
    }

    /// A repair pass has replayed `shard_id` up to `next` (exclusive), or all
    /// of it with `None`.
    fn replayed(&self, shard_id: u32, next: Option<u64>) {
        let mut gaps = self.0.lock().unwrap();
        match next {
            Some(next) => gaps.replaying.insert(shard_id, next),
            None => gaps.replaying.remove(&shard_id),
        };
    }

    /// The lowest block of `shard_id` whose lost events haven't been replayed
    /// yet, recorded or in a running pass. A block mark kept at or below it
    /// replays them after a restart, as this map doesn't survive one.
    pub fn floor(&self, shard_id: u32) -> Option<u64> {
        let gaps = self.0.lock().unwrap();
        let pending = gaps
            .pending
            .get(&shard_id)
            .and_then(|ranges| ranges.iter().map(|r| r.0).min());
        let replaying = gaps.replaying.get(&shard_id).copied();
        pending.into_iter().chain(replaying).min()
    }

    pub fn is_empty(&self) -> bool {
        let gaps = self.0.lock().unwrap();
        gaps.replaying.is_empty() && gaps.pending.values().all(|r| r.is_empty())
    }
}

/// Replay lost blocks into `indexers` every few seconds until shutdown.
///
/// Only indexers whose writes are idempotent and order-free belong here
/// (puts keyed by the message itself, like the cast hash and quote indexes):
/// a replayed block also carries the events that did arrive, and it lands
/// after newer live events.
pub fn spawn_repair(
    gaps: Arc<IndexGaps>,
    stores: HashMap<u32, Stores>,
    indexers: Vec<Arc<dyn Indexer>>,
    mut shutdown: broadcast::Receiver<()>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = tokio::time::sleep(REPAIR_INTERVAL) => {}
                _ = shutdown.recv() => return,
            }
            repair(&gaps, &stores, &indexers).await;
        }
    })
}

/// One pass over the recorded gaps. A range that fails is recorded again
/// from the failed batch on, for the next pass.
pub(crate) async fn repair(
    gaps: &IndexGaps,
    stores: &HashMap<u32, Stores>,
    indexers: &[Arc<dyn Indexer>],
) {
    for (shard_id, ranges) in gaps.take() {
        let Some(store) = stores.get(&shard_id) else {
            gaps.replayed(shard_id, None);
            continue;
        };
        // The engine sends a block's events before it stores the block, so a
        // range can end in a block the store doesn't have yet: that part waits
        // for the next pass, rather than being read as empty and let go.
        let stored = store.shard_store.max_block_number().unwrap_or_else(|e| {
            tracing::warn!(shard_id, error = %e, "Can't read the latest stored block; retrying lost index events next pass");
            0
        });
        for (from, to) in ranges {
            if to > stored {
                gaps.lost(shard_id, from.max(stored + 1), to);
            }
            let to = to.min(stored);
            if from > to {
                continue;
            }
            tracing::info!(
                shard_id,
                from,
                to,
                "Replaying blocks with lost index events"
            );
            let mut next = from;
            while next <= to {
                let end = (next + REPAIR_BATCH_BLOCKS - 1).min(to);
                // ponytail: reads the shard store on the async runtime; the
                // ranges are the few blocks a bridge lost, not a full backfill.
                let messages: Vec<_> = match store.shard_store.get_shard_chunks(next, Some(end + 1))
                {
                    Ok(chunks) => chunks
                        .into_iter()
                        .flat_map(|chunk| chunk.transactions)
                        .flat_map(|txn| txn.user_messages)
                        .collect(),
                    Err(e) => {
                        tracing::warn!(shard_id, error = %e, "Lost-block replay read failed");
                        gaps.lost(shard_id, next, to);
                        break;
                    }
                };
                if !messages.is_empty() {
                    let events = [IndexEvent::messages(messages, shard_id, end)];
                    for indexer in indexers.iter().filter(|i| i.is_enabled()) {
                        if let Err(e) = indexer.process_batch(&events).await {
                            tracing::warn!(shard_id, indexer = indexer.name(), error = %e,
                                "Lost-block replay failed");
                            gaps.lost(shard_id, next, to);
                            next = to + 1;
                            break;
                        }
                    }
                }
                next = next.max(end + 1);
                gaps.replayed(shard_id, Some(next));
            }
        }
        gaps.replayed(shard_id, None);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lost_blocks_merge_into_ranges() {
        let gaps = IndexGaps::default();
        gaps.lost(1, 10, 10);
        gaps.lost(1, 10, 10);
        gaps.lost(1, 11, 11);
        gaps.lost(1, 20, 18);
        gaps.lost(1, 5, 9);
        gaps.lost(2, 7, 7);
        let mut taken: Vec<_> = gaps.take().into_iter().collect();
        taken.sort();
        assert_eq!(taken, vec![(1, vec![(5, 11), (18, 20)]), (2, vec![(7, 7)])]);
        // Taken ranges count until a repair pass has replayed them.
        assert_eq!(gaps.floor(1), Some(5));
        gaps.lost(1, 3, 3);
        assert_eq!(gaps.floor(1), Some(3));
        gaps.replayed(2, None);
        assert_eq!(gaps.floor(2), None);
        gaps.take();
        gaps.replayed(1, Some(12));
        assert_eq!(gaps.floor(1), Some(12));
        gaps.replayed(1, None);
        assert!(gaps.is_empty());
    }

    #[tokio::test]
    async fn a_lost_block_is_replayed_into_the_hash_index() {
        use crate::api::cast_hash_index::CastHashIndexer;
        use crate::api::config::FeatureConfig;
        use crate::proto::{self, Height, ShardChunk, ShardHeader, Transaction};
        use crate::storage::db::RocksDB;
        use crate::storage::store::stores::StoreLimits;
        use crate::storage::trie::merkle_trie::MerkleTrie;
        use crate::utils::factory::messages_factory::casts;
        use crate::utils::statsd_wrapper::StatsdClientWrapper;

        let dir = tempfile::tempdir().unwrap();
        let db = RocksDB::open_shard_db(dir.path().to_str().unwrap(), 0);
        let store = Stores::new(
            RocksDB::open_shard_db(dir.path().to_str().unwrap(), 1),
            1,
            MerkleTrie::new().unwrap(),
            StoreLimits::default(),
            proto::FarcasterNetwork::Devnet,
            StatsdClientWrapper::new(
                cadence::StatsdClient::builder("test", cadence::NopMetricSink).build(),
                false,
            ),
        );
        let cast = casts::create_cast_add(42, "lost", None, None);
        store
            .shard_store
            .put_shard_chunk(&ShardChunk {
                header: Some(ShardHeader {
                    height: Some(Height {
                        shard_index: 1,
                        block_number: 7,
                    }),
                    ..Default::default()
                }),
                transactions: vec![Transaction {
                    user_messages: vec![cast.clone()],
                    ..Default::default()
                }],
                ..Default::default()
            })
            .unwrap();
        let index = Arc::new(CastHashIndexer::new(
            FeatureConfig {
                enabled: true,
                ..Default::default()
            },
            db,
        ));
        let gaps = IndexGaps::default();
        // Blocks 8 and 9 aren't stored yet.
        gaps.lost(1, 7, 9);

        repair(
            &gaps,
            &HashMap::from([(1, store)]),
            &[index.clone() as Arc<dyn Indexer>],
        )
        .await;
        assert_eq!(index.get_fid_by_hash(&cast.hash), Some(42));
        assert_eq!(gaps.floor(1), Some(8));
    }
}
