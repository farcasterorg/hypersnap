//! Live daily stats have their own queue and worker. Neither startup backfills
//! nor a slow search commit may hold up client attribution.

use super::{
    create_index_channel, ApiConfig, DailyStatsIndexer, HubEventBridge, IndexWorkerPool,
    DEFAULT_CHANNEL_CAPACITY,
};
use crate::proto::HubEvent;
use crate::storage::db::RocksDB;
use std::sync::Arc;
use tokio::sync::broadcast;
use tokio::task::JoinHandle;

pub(super) fn spawn(
    config: &ApiConfig,
    indexer: Arc<DailyStatsIndexer>,
    db: Arc<RocksDB>,
    hub_events: &[(u32, broadcast::Sender<HubEvent>)],
    shutdown: &broadcast::Sender<()>,
) -> (JoinHandle<()>, Vec<JoinHandle<()>>) {
    let (tx, rx) = create_index_channel(DEFAULT_CHANNEL_CAPACITY);
    let mut pool = IndexWorkerPool::new(config.clone(), rx, db).with_shutdown(shutdown.clone());
    pool.register_arc(indexer);
    tracing::info!("Starting dedicated daily stats live worker");
    let worker = tokio::spawn(pool.run());
    let bridges = hub_events
        .iter()
        .map(|(shard_id, sender)| {
            // Subscribe now, before initialization returns and node dispatch can
            // commit new messages. There is deliberately no backfill readiness gate.
            let bridge =
                HubEventBridge::from_sender(sender, tx.clone(), *shard_id).with_backpressure();
            let mut stop = shutdown.subscribe();
            tokio::spawn(async move {
                tokio::select! {
                    _ = bridge.run() => {},
                    _ = stop.recv() => {},
                }
            })
        })
        .collect();
    (worker, bridges)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::{
        config::{DailyStatsConfig, SearchConfig},
        daily_stats::today,
        IndexEvent, Indexer,
    };
    use crate::proto::{self, message_data::Body, Message, MessageData, MessageType};
    use crate::storage::store::stores::{StoreLimits, Stores};
    use crate::storage::trie::merkle_trie::MerkleTrie;
    use crate::utils::statsd_wrapper::StatsdClientWrapper;
    use std::collections::HashMap;
    use std::time::Duration;

    fn cast(fid: u64, byte: u8) -> Message {
        Message {
            hash: vec![byte; 20],
            signer: vec![byte; 32],
            data: Some(MessageData {
                fid,
                timestamp: crate::core::util::get_farcaster_time().unwrap() as u32,
                r#type: MessageType::CastAdd as i32,
                body: Some(Body::CastAddBody(proto::CastAddBody {
                    text: "daily stats isolation".into(),
                    ..Default::default()
                })),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    fn merge_event(message: Message) -> HubEvent {
        HubEvent {
            r#type: proto::HubEventType::MergeMessage as i32,
            body: Some(proto::hub_event::Body::MergeMessageBody(
                proto::MergeMessageBody {
                    message: Some(message),
                    ..Default::default()
                },
            )),
            ..Default::default()
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn live_stats_ignore_search_gate_and_are_not_counted_again_when_it_opens() {
        let dir = tempfile::tempdir().unwrap();
        let db = RocksDB::open_shard_db(dir.path().to_str().unwrap(), 0);
        let stores = Stores::new(
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
        let old = cast(99, 7);
        stores
            .shard_store
            .put_shard_chunk(&proto::ShardChunk {
                header: Some(proto::ShardHeader {
                    height: Some(proto::Height {
                        shard_index: 1,
                        block_number: 1,
                    }),
                    ..Default::default()
                }),
                transactions: vec![proto::Transaction {
                    user_messages: vec![old.clone()],
                    ..Default::default()
                }],
                ..Default::default()
            })
            .unwrap();
        let daily_config = DailyStatsConfig {
            enabled: true,
            repair_on_startup: false,
            flush_every_events: 1,
            ..Default::default()
        };
        // Existing totals have no per-message provenance. They must survive;
        // neither startup replay nor the second live bridge may fold them again.
        let reader = DailyStatsIndexer::new(daily_config.clone(), db.clone());
        reader
            .process_event(&IndexEvent::message(old.clone(), 1, 1))
            .await
            .unwrap();
        let mut hash_key = vec![0xE4, 0x01];
        hash_key.extend_from_slice(&old.hash);
        let db_guard = db.db();
        let crate::storage::db::DBProvider::Transaction(raw) = db_guard.as_ref().unwrap() else {
            panic!("expected TransactionDB")
        };
        let lock = raw.transaction();
        lock.get_for_update(&hash_key, true).unwrap();
        let (hub_tx, _) = broadcast::channel(32);
        let config = ApiConfig {
            enabled: true,
            daily_stats: daily_config.clone(),
            search: SearchConfig {
                enabled: true,
                backfill_on_startup: true,
                memory_budget_mb: 50,
                index_path: dir.path().join("search").to_str().unwrap().to_owned(),
                ..Default::default()
            },
            ..Default::default()
        };
        // Without hyper stores search uses the startup gate. The locked hash
        // write prevents that gate opening until we explicitly release it.
        let api = crate::api::initialize(
            &config,
            db.clone(),
            vec![(1, hub_tx.clone())],
            HashMap::from([(1, stores)]),
            None,
            None,
            None,
        )
        .unwrap();
        let live = cast(123, 8);
        hub_tx.send(merge_event(live.clone())).unwrap();
        let reader = DailyStatsIndexer::new(daily_config, db.clone());
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let row = reader
                    .range_with_clients(today(), today(), Some(10))
                    .unwrap()
                    .remove(0);
                if row.clients.as_ref().is_some_and(|c| c.active_fids == 1) {
                    assert_eq!(row.casts.total, 2);
                    assert_eq!(
                        row.clients
                            .unwrap()
                            .by_client
                            .iter()
                            .find(|c| c.client == "unresolved")
                            .unwrap()
                            .messages_by_action["cast"],
                        1
                    );
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        assert!(
            !api.search_indexer
                .as_ref()
                .unwrap()
                .stats()
                .backfill_complete
        );
        let hashes =
            crate::api::CastHashIndexer::new(crate::api::FeatureConfig::default(), db.clone());
        assert_eq!(hashes.get_fid_by_hash(&live.hash), None);
        drop(lock);
        drop(db_guard);
        tokio::time::timeout(Duration::from_secs(3), async {
            while hashes.get_fid_by_hash(&live.hash) != Some(123) {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        drop(hub_tx);
        tokio::time::timeout(Duration::from_secs(3), api.shutdown())
            .await
            .unwrap();
        assert_eq!(reader.range(today(), today()).unwrap()[0].casts.total, 2);
    }

    #[tokio::test]
    async fn shutdown_flushes_stats_and_stops_bridges_while_engine_channels_stay_open() {
        let dir = tempfile::tempdir().unwrap();
        let db = RocksDB::open_shard_db(dir.path().to_str().unwrap(), 0);
        let indexer = Arc::new(DailyStatsIndexer::new(
            DailyStatsConfig {
                enabled: true,
                flush_every_events: usize::MAX,
                flush_interval_secs: u64::MAX,
                ..Default::default()
            },
            db.clone(),
        ));
        let config = ApiConfig {
            enabled: true,
            ..Default::default()
        };
        let (hub_tx, _) = broadcast::channel(32);
        let (shutdown, _) = broadcast::channel(1);
        let (worker, bridges) = spawn(
            &config,
            indexer.clone(),
            db,
            &[(1, hub_tx.clone())],
            &shutdown,
        );
        hub_tx.send(merge_event(cast(123, 8))).unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            while indexer.stats().items_indexed == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(indexer.range(today(), today()).unwrap()[0].casts.total, 0);
        shutdown.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            worker.await.unwrap();
            for bridge in bridges {
                bridge.await.unwrap();
            }
        })
        .await
        .unwrap();
        assert_eq!(indexer.range(today(), today()).unwrap()[0].casts.total, 1);
        assert_eq!(hub_tx.receiver_count(), 0);
    }
}
