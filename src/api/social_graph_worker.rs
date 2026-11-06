//! One writer owns social graph deletion, historical replay and live indexing.
//! Committed shard blocks are the durable queue, so a long rebuild never has to
//! buffer live follows in RAM or pause the other API indexers.
//!
//! A schema rebuild doesn't take the index away: readers keep the generation
//! they have, which this worker keeps current with new blocks, while the other
//! generation is rebuilt a few batches at a time in between. Once it reaches
//! the tip, readers switch to it in one write and the old one is deleted the
//! same way, a batch at a time.

use super::social_graph::cursor_name;
use super::{backfill, IndexEvent, Indexer, IndexerError, SocialGraphIndexer};
use crate::storage::db::RocksDB;
use crate::storage::store::stores::Stores;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::broadcast;

const BLOCKS_PER_BATCH: u64 = 100;
/// Blocks per shard the rebuilding generation replays between live updates.
const REBUILD_BLOCKS_PER_STEP: u64 = 1_000;
/// Old-generation keys deleted between live updates.
const DELETE_KEYS_PER_STEP: usize = 50_000;
/// Pause between steps while a rebuild or deletion has more to do, so it
/// yields disk and CPU to the node's own block processing.
const BUSY_PAUSE: Duration = Duration::from_millis(10);

struct StopOnDrop(Arc<AtomicBool>);

impl Drop for StopOnDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Relaxed);
    }
}

pub(super) fn spawn(
    indexer: Arc<SocialGraphIndexer>,
    db: Arc<RocksDB>,
    stores: HashMap<u32, Stores>,
    backfill_on_startup: bool,
    mut shutdown: broadcast::Receiver<()>,
) -> tokio::task::JoinHandle<()> {
    let stop = Arc::new(AtomicBool::new(false));
    // Own the guard before spawning: aborting an unpolled task must stop its
    // blocking work too. Every delete/replay batch checks this flag.
    let guard = StopOnDrop(stop.clone());
    // Capture the opt-out boundary before returning to the node's dispatch
    // loop. Blocks arriving during deletion must still be indexed afterward.
    let initial_tips: Result<HashMap<_, _>, _> = stores
        .iter()
        .map(|(&id, store)| store.shard_store.max_block_number().map(|tip| (id, tip)))
        .collect();
    let initial_tips = initial_tips.map_err(|e| e.to_string());
    tokio::spawn(async move {
        let _guard = guard;
        let mut prepared = false;
        loop {
            let worker_indexer = indexer.clone();
            let worker_db = db.clone();
            let worker_stores = stores.clone();
            let worker_stop = stop.clone();
            let worker_initial_tips = initial_tips.clone();
            let runtime = tokio::runtime::Handle::current();
            let mut job = tokio::task::spawn_blocking(move || {
                runtime.block_on(async {
                    if !prepared {
                        worker_indexer.prepare(&worker_stop)?;
                        if !backfill_on_startup {
                            // Explicit opt-out: seed only missing cursors, then
                            // keep indexing new blocks (including after restart).
                            let tips = worker_initial_tips.map_err(storage_error)?;
                            for (&shard_id, &height) in &tips {
                                let name = cursor_name(worker_indexer.generation());
                                if backfill::try_load_shard_checkpoint(&worker_db, &name, shard_id)?
                                    == 0
                                {
                                    backfill::save_shard_checkpoint(
                                        &worker_db,
                                        &name,
                                        shard_id,
                                        height + 1,
                                    )?;
                                }
                            }
                        }
                    }
                    step(&worker_indexer, &worker_db, &worker_stores, &worker_stop).await
                })
            });
            let result = tokio::select! {
                result = &mut job => result,
                _ = shutdown.recv() => {
                    stop.store(true, Ordering::Relaxed);
                    let _ = job.await;
                    return;
                }
            };
            let delay = match result {
                Ok(Ok(Step { rebuilding, busy })) => {
                    if !prepared && !rebuilding {
                        tracing::info!("Social graph rebuild complete; following committed blocks");
                    }
                    prepared = true;
                    indexer.set_caught_up(!rebuilding);
                    if busy {
                        BUSY_PAUSE
                    } else {
                        Duration::from_millis(250)
                    }
                }
                other => {
                    indexer.set_caught_up(false);
                    tracing::error!(error = ?other,
                        "Social graph indexing failed; retrying without advancing failed batch");
                    Duration::from_secs(5)
                }
            };
            tokio::select! {
                _ = tokio::time::sleep(delay) => {},
                _ = shutdown.recv() => return,
            }
        }
    })
}

fn storage_error(error: impl std::fmt::Display) -> IndexerError {
    IndexerError::Storage(error.to_string())
}

#[derive(Debug)]
/// What one worker step left: whether a rebuild is still under way (readers
/// are on the old generation), and whether there's more to do right away.
struct Step {
    rebuilding: bool,
    busy: bool,
}

/// Bring the generation readers use up to the tip, then advance a rebuild or
/// an old generation's deletion by one bounded step.
async fn step(
    indexer: &SocialGraphIndexer,
    db: &RocksDB,
    stores: &HashMap<u32, Stores>,
    stop: &AtomicBool,
) -> Result<Step, IndexerError> {
    catch_up(indexer, db, stores, stop, None).await?;
    if let Some(old) = indexer.deleting_generation()? {
        let done = indexer.delete_some(old, DELETE_KEYS_PER_STEP)?;
        // A rebuild into the generation still being deleted waits for it.
        let rebuilding = indexer.building_generation()?.is_some();
        return Ok(Step {
            rebuilding,
            busy: !done || rebuilding,
        });
    }
    let Some(building) = indexer.building_generation()? else {
        return Ok(Step {
            rebuilding: false,
            busy: false,
        });
    };
    let view = indexer.view(building);
    if catch_up(&view, db, stores, stop, Some(REBUILD_BLOCKS_PER_STEP)).await? {
        indexer.switch_to(building)?;
        return Ok(Step {
            rebuilding: false,
            busy: true,
        });
    }
    Ok(Step {
        rebuilding: true,
        busy: true,
    })
}

/// Each shard's next block is persisted only after its index writes succeed.
/// A new pass snapshots a new tip, catching everything committed during replay.
/// With a `budget`, at most that many blocks per shard are replayed; returns
/// whether every shard reached its tip.
async fn catch_up(
    indexer: &SocialGraphIndexer,
    db: &RocksDB,
    stores: &HashMap<u32, Stores>,
    stop: &AtomicBool,
    budget: Option<u64>,
) -> Result<bool, IndexerError> {
    let checkpoint_name = cursor_name(indexer.generation());
    let mut shards: Vec<_> = stores.iter().collect();
    shards.sort_by_key(|(&id, _)| id);
    let mut all_at_tip = true;
    for (&shard_id, store) in shards {
        let tip = store
            .shard_store
            .max_block_number()
            .map_err(storage_error)?;
        let mut next = backfill::try_load_shard_checkpoint(db, &checkpoint_name, shard_id)?;
        let limit = budget.map_or(tip, |b| tip.min(next.saturating_add(b).saturating_sub(1)));
        let started = Instant::now();
        let mut last_log = started;
        while next <= limit {
            if stop.load(Ordering::Relaxed) {
                return Err(IndexerError::Internal(
                    "Social graph worker stopping".into(),
                ));
            }
            let end = (next + BLOCKS_PER_BATCH).min(limit + 1);
            let chunks = store
                .shard_store
                .get_shard_chunks(next, Some(end))
                .map_err(storage_error)?;
            let messages = chunks
                .into_iter()
                .flat_map(|chunk| chunk.transactions)
                .flat_map(|txn| txn.user_messages)
                .collect::<Vec<_>>();
            if !messages.is_empty() {
                indexer
                    .process_batch(&[IndexEvent::messages(messages, shard_id, end - 1)])
                    .await?;
            }
            backfill::save_shard_checkpoint(db, &checkpoint_name, shard_id, end)
                .map_err(storage_error)?;
            next = end;
            if last_log.elapsed().as_secs() >= 5 {
                tracing::info!(
                    shard_id,
                    next_block = next,
                    tip,
                    elapsed_secs = started.elapsed().as_secs(),
                    "Social graph block replay progress"
                );
                last_log = Instant::now();
            }
        }
        if next <= tip {
            all_at_tip = false;
        } else {
            indexer.save_checkpoint(tip).await?;
        }
    }
    Ok(all_at_tip)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::backfill_checkpoint_name;
    use crate::api::config::{ApiConfig, FeatureConfig};
    use crate::api::social_graph::SOCIAL_GRAPH_SCHEMA_VERSION_FOR_TEST;
    use crate::proto::{
        self, message_data::Body, Height, LinkBody, Message, MessageData, MessageType, ShardChunk,
        ShardHeader, Transaction,
    };
    use crate::storage::store::stores::StoreLimits;
    use crate::storage::trie::merkle_trie::MerkleTrie;
    use crate::utils::statsd_wrapper::StatsdClientWrapper;

    fn stores(db: Arc<RocksDB>) -> Stores {
        Stores::new(
            db,
            1,
            MerkleTrie::new().unwrap(),
            StoreLimits::default(),
            proto::FarcasterNetwork::Devnet,
            StatsdClientWrapper::new(
                cadence::StatsdClient::builder("test", cadence::NopMetricSink).build(),
                false,
            ),
        )
    }

    fn put_follow(store: &Stores, height: u64, add: bool) {
        store
            .shard_store
            .put_shard_chunk(&ShardChunk {
                header: Some(ShardHeader {
                    height: Some(Height {
                        shard_index: 1,
                        block_number: height,
                    }),
                    timestamp: height,
                    ..Default::default()
                }),
                transactions: vec![Transaction {
                    user_messages: vec![Message {
                        data: Some(MessageData {
                            fid: 1,
                            timestamp: height as u32,
                            r#type: if add {
                                MessageType::LinkAdd
                            } else {
                                MessageType::LinkRemove
                            } as i32,
                            body: Some(Body::LinkBody(LinkBody {
                                r#type: "follow".into(),
                                target: Some(proto::link_body::Target::TargetFid(2)),
                                ..Default::default()
                            })),
                            ..Default::default()
                        }),
                        ..Default::default()
                    }],
                    ..Default::default()
                }],
                ..Default::default()
            })
            .unwrap();
    }

    #[tokio::test]
    async fn committed_blocks_queue_during_clear_and_resume_after_restart() {
        let dir = tempfile::tempdir().unwrap();
        let db = RocksDB::open_shard_db(dir.path().to_str().unwrap(), 0);
        let shard_db = RocksDB::open_shard_db(dir.path().to_str().unwrap(), 1);
        let store = stores(shard_db);
        let config = FeatureConfig {
            enabled: true,
            backfill_on_startup: true,
            ..Default::default()
        };
        let indexer = SocialGraphIndexer::open(config.clone(), db.clone());
        // Both blocks arrive before the old index has even been cleared.
        put_follow(&store, 1, true);
        put_follow(&store, 2, false);
        indexer.prepare(&AtomicBool::new(false)).unwrap();
        let all_stores = HashMap::from([(1, store.clone())]);
        catch_up(&indexer, &db, &all_stores, &AtomicBool::new(false), None)
            .await
            .unwrap();
        assert_eq!(indexer.get_follower_count(2).unwrap(), 0);
        let name = backfill_checkpoint_name("social_graph");
        assert_eq!(backfill::load_shard_checkpoint(&db, &name, 1), 3);

        // A restarted worker sees a block committed during downtime and uses
        // the saved cursor rather than erasing/replaying the index again.
        let resumed = SocialGraphIndexer::open(config, db.clone());
        resumed.prepare(&AtomicBool::new(false)).unwrap();
        put_follow(&store, 3, true);
        catch_up(&resumed, &db, &all_stores, &AtomicBool::new(false), None)
            .await
            .unwrap();
        catch_up(&resumed, &db, &all_stores, &AtomicBool::new(false), None)
            .await
            .unwrap();
        assert_eq!(resumed.get_follower_count(2).unwrap(), 1);
        assert_eq!(resumed.get_following_count(1).unwrap(), 1);
        assert_eq!(backfill::load_shard_checkpoint(&db, &name, 1), 4);
    }

    #[tokio::test]
    async fn schema_rebuild_keeps_serving_the_old_index_until_the_new_one_is_ready() {
        let dir = tempfile::tempdir().unwrap();
        let db = RocksDB::open_shard_db(dir.path().to_str().unwrap(), 0);
        let store = stores(RocksDB::open_shard_db(dir.path().to_str().unwrap(), 1));
        let all_stores = HashMap::from([(1, store.clone())]);
        let config = FeatureConfig {
            enabled: true,
            backfill_on_startup: true,
            ..Default::default()
        };
        let no_stop = AtomicBool::new(false);
        // A node on the previous schema: 1 follows 2, with a drifted count of 7.
        put_follow(&store, 1, true);
        let old = SocialGraphIndexer::open(config.clone(), db.clone());
        old.prepare(&no_stop).unwrap();
        catch_up(&old, &db, &all_stores, &no_stop, None)
            .await
            .unwrap();
        let count_key = old.view(0).follower_count_key_for_test(2);
        db.put(&count_key, &7u64.to_be_bytes()).unwrap();
        old.set_schema_version_for_test(SOCIAL_GRAPH_SCHEMA_VERSION_FOR_TEST - 1);

        // The upgraded node starts a rebuild and readers keep the old index.
        let indexer = SocialGraphIndexer::open(config.clone(), db.clone());
        indexer.prepare(&no_stop).unwrap();
        assert_eq!(indexer.building_generation().unwrap(), Some(0x10));
        put_follow(&store, 2, true);
        put_follow(&store, 3, true);
        let rebuilt = indexer.view(0x10);
        assert!(!catch_up(&rebuilt, &db, &all_stores, &no_stop, Some(2))
            .await
            .unwrap());
        assert_eq!(indexer.get_follower_count(2).unwrap(), 7);

        // Restarted mid-rebuild: nothing is cleared, the rebuild resumes.
        let restarted = SocialGraphIndexer::open(config, db.clone());
        restarted.prepare(&no_stop).unwrap();
        assert_eq!(restarted.building_generation().unwrap(), Some(0x10));
        assert_eq!(restarted.get_follower_count(2).unwrap(), 7);
        let name = backfill_checkpoint_name("social_graph");
        assert_eq!(
            backfill::load_shard_checkpoint(&db, &format!("{name}:g1"), 1),
            2
        );

        // It catches up, readers switch to the rebuilt index, the old one goes.
        let first = step(&restarted, &db, &all_stores, &no_stop).await.unwrap();
        assert!(!first.rebuilding);
        assert_eq!(restarted.generation(), 0x10);
        assert_eq!(restarted.get_follower_count(2).unwrap(), 1);
        assert_eq!(restarted.get_following_count(1).unwrap(), 1);
        while restarted.deleting_generation().unwrap().is_some() {
            step(&restarted, &db, &all_stores, &no_stop).await.unwrap();
        }
        assert_eq!(db.get(&count_key).unwrap(), None);
        assert_eq!(backfill::load_shard_checkpoint(&db, &name, 1), 0);

        // And a node opened later reads the rebuilt generation.
        let reopened = SocialGraphIndexer::open(FeatureConfig::default(), db.clone());
        assert_eq!(reopened.get_follower_count(2).unwrap(), 1);
    }

    #[tokio::test]
    async fn failed_batch_does_not_advance_cursor() {
        let dir = tempfile::tempdir().unwrap();
        let db = RocksDB::open_shard_db(dir.path().to_str().unwrap(), 0);
        let store = stores(RocksDB::open_shard_db(dir.path().to_str().unwrap(), 1));
        let indexer = SocialGraphIndexer::new(FeatureConfig::default(), db.clone());
        put_follow(&store, 1, true);
        let mut chunk = store
            .shard_store
            .get_shard_chunks(1, Some(2))
            .unwrap()
            .remove(0);
        chunk.transactions[0].user_messages[0].data = None;
        store.shard_store.put_shard_chunk(&chunk).unwrap();
        let name = backfill_checkpoint_name("social_graph");
        backfill::save_shard_checkpoint(&db, &name, 1, 1).unwrap();
        let all_stores = HashMap::from([(1, store.clone())]);
        assert!(
            catch_up(&indexer, &db, &all_stores, &AtomicBool::new(false), None)
                .await
                .is_err()
        );
        assert_eq!(backfill::load_shard_checkpoint(&db, &name, 1), 1);
        put_follow(&store, 1, true);
        catch_up(&indexer, &db, &all_stores, &AtomicBool::new(false), None)
            .await
            .unwrap();
        assert_eq!(indexer.get_follower_count(2).unwrap(), 1);
    }

    #[tokio::test]
    async fn background_worker_keeps_tailing_without_startup_backfill() {
        let dir = tempfile::tempdir().unwrap();
        let db = RocksDB::open_shard_db(dir.path().to_str().unwrap(), 0);
        let store = stores(RocksDB::open_shard_db(dir.path().to_str().unwrap(), 1));
        put_follow(&store, 1, true);
        let indexer = Arc::new(SocialGraphIndexer::open(
            FeatureConfig {
                enabled: true,
                ..Default::default()
            },
            db.clone(),
        ));
        let (shutdown, _) = broadcast::channel(1);
        let worker = spawn(
            indexer.clone(),
            db,
            HashMap::from([(1, store.clone())]),
            false,
            shutdown.subscribe(),
        );
        // This block arrives after spawn's captured startup tip and must be
        // included even though historical replay was explicitly disabled.
        put_follow(&store, 2, true);
        tokio::time::timeout(Duration::from_secs(3), async {
            while indexer.get_follower_count(2).unwrap() != 1 || !indexer.stats().backfill_complete
            {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        put_follow(&store, 3, false);
        tokio::time::timeout(Duration::from_secs(3), async {
            while indexer.get_follower_count(2).unwrap() != 0 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        shutdown.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(2), worker)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn api_initializes_while_social_graph_delete_is_blocked() {
        let dir = tempfile::tempdir().unwrap();
        let db = RocksDB::open_shard_db(dir.path().to_str().unwrap(), 0);
        // Keep the first delete locked: an accidental synchronous constructor
        // would block here for the database's five-second lock timeout.
        let key = vec![0xE0, 0x01, 0, 0, 0, 0, 0, 0, 0, 2];
        db.put(&key, &7u64.to_be_bytes()).unwrap();
        let guard = db.db();
        let crate::storage::db::DBProvider::Transaction(raw) = guard.as_ref().unwrap() else {
            panic!("expected TransactionDB")
        };
        let lock = raw.transaction();
        lock.get_for_update(&key, true).unwrap();
        let config = ApiConfig {
            enabled: true,
            social_graph: FeatureConfig {
                enabled: true,
                backfill_on_startup: true,
                ..Default::default()
            },
            ..Default::default()
        };
        let started = Instant::now();
        let (hub_tx, _) = broadcast::channel(32);
        let api = crate::api::initialize(
            &config,
            db.clone(),
            vec![(1, hub_tx.clone())],
            HashMap::new(),
            None,
            None,
            None,
        )
        .unwrap();
        assert!(started.elapsed() < Duration::from_secs(2));
        let sg = api.http_handler.social_graph_indexer().unwrap();
        assert_eq!(sg.get_follower_count(2).unwrap(), 7);
        assert!(!sg.stats().backfill_complete);
        // Other live API indexes must keep consuming events while the graph
        // writer is blocked on deletion of its own key space.
        let hash = vec![11; 20];
        hub_tx
            .send(proto::HubEvent {
                r#type: proto::HubEventType::MergeMessage as i32,
                body: Some(proto::hub_event::Body::MergeMessageBody(
                    proto::MergeMessageBody {
                        native_registration: None,
                        message: Some(Message {
                            hash: hash.clone(),
                            data: Some(MessageData {
                                fid: 123,
                                r#type: MessageType::CastAdd as i32,
                                body: Some(Body::CastAddBody(proto::CastAddBody::default())),
                                ..Default::default()
                            }),
                            ..Default::default()
                        }),
                        ..Default::default()
                    },
                )),
                ..Default::default()
            })
            .unwrap();
        let cast_hashes = crate::api::CastHashIndexer::new(FeatureConfig::default(), db.clone());
        tokio::time::timeout(Duration::from_secs(2), async {
            while cast_hashes.get_fid_by_hash(&hash) != Some(123) {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(sg.get_follower_count(2).unwrap(), 7);
        drop(lock);
        drop(guard);
        drop(hub_tx);
        tokio::time::timeout(Duration::from_secs(2), api.shutdown())
            .await
            .unwrap();
    }
}
