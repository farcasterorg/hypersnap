//! Durable metrics replay with an online replacement generation. The readable
//! generation tails new blocks while the replacement advances in bounded steps.
//! Broadcast events give low latency (including revocations); committed blocks
//! and retained hub events recover missed deliveries and restarts.
use super::{
    backfill, create_index_channel, HubEventBridge, IndexEvent, Indexer, IndexerError,
    MetricsIndexer, DEFAULT_CHANNEL_CAPACITY,
};
use crate::proto::{self, hub_event, HubEvent, HubEventType, Message, MessageType};
use crate::storage::db::{PageOptions, RocksDB};
use crate::storage::store::account::HubEventIdGenerator;
use crate::storage::store::account::{CastStore, ReactionStore};
use crate::storage::store::stores::Stores;
use std::collections::HashMap;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::{Duration, Instant};
use tokio::sync::broadcast;
use tokio::task::JoinHandle;

const BATCH: u64 = 100;
const STEP: u64 = 1000;

fn cursor(generation: u8) -> String {
    format!("metrics_replacement_v1:{generation}")
}
fn storage(e: impl std::fmt::Display) -> IndexerError {
    IndexerError::Storage(e.to_string())
}

struct Stop(Arc<AtomicBool>);
impl Drop for Stop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Relaxed);
    }
}

pub(super) fn spawn(
    indexer: Arc<MetricsIndexer>,
    db: Arc<RocksDB>,
    stores: HashMap<u32, Stores>,
    canonical: HashMap<u32, Stores>,
    hub_events: &[(u32, broadcast::Sender<HubEvent>)],
    shutdown: &broadcast::Sender<()>,
) -> (JoinHandle<()>, Vec<JoinHandle<()>>) {
    let (tx, mut rx) = create_index_channel(DEFAULT_CHANNEL_CAPACITY);
    let mut live_stop = shutdown.subscribe();
    let live_indexer = indexer.clone();
    let mut handles = vec![tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = live_stop.recv() => break,
                event = rx.recv() => match event {
                    Some(event) => {
                        if let Err(e) = live_indexer.process_event(&event).await {
                            tracing::error!(error = %e, "Metrics live write failed; durable replay will retry");
                        }
                    }
                    None => break,
                }
            }
        }
    })];
    for (id, sender) in hub_events {
        let bridge = HubEventBridge::from_sender(sender, tx.clone(), *id).with_backpressure();
        let mut stop = shutdown.subscribe();
        handles.push(tokio::spawn(async move {
            tokio::select! { _ = bridge.run() => {}, _ = stop.recv() => {} }
        }));
    }
    let initial_tips: Result<HashMap<_, _>, _> = stores
        .iter()
        .map(|(&id, s)| s.shard_store.max_block_number().map(|tip| (id, tip)))
        .collect();
    let initial_tips = initial_tips.map_err(storage);
    let flag = Arc::new(AtomicBool::new(false));
    let guard = Stop(flag.clone());
    let mut shutdown = shutdown.subscribe();
    let handle = tokio::spawn(async move {
        let _guard = guard;
        let mut prepared = false;
        let mut last_log = Instant::now();
        loop {
            if last_log.elapsed() >= Duration::from_secs(5) {
                let generation = indexer
                    .building_generation()
                    .ok()
                    .flatten()
                    .unwrap_or_else(|| indexer.generation());
                for (&shard_id, store) in &stores {
                    if let (Ok(next_block), Ok(tip)) = (
                        backfill::try_load_shard_checkpoint(&db, &cursor(generation), shard_id),
                        store.shard_store.max_block_number(),
                    ) {
                        tracing::info!(
                            generation,
                            shard_id,
                            next_block,
                            tip,
                            percent = (next_block as f64 / (tip + 1) as f64 * 100.0).min(100.0),
                            "Metrics replacement replay progress"
                        );
                    }
                }
                last_log = Instant::now();
            }
            let (indexer, db, stores, canonical, flag) = (
                indexer.clone(),
                db.clone(),
                stores.clone(),
                canonical.clone(),
                flag.clone(),
            );
            let tips = initial_tips
                .as_ref()
                .map(Clone::clone)
                .map_err(|e| storage(e.to_string()));
            let runtime = tokio::runtime::Handle::current();
            let worker_flag = flag.clone();
            let mut task = tokio::task::spawn_blocking(move || {
                runtime.block_on(async {
                    if !prepared {
                        // Legacy counts already include live history: seed their new
                        // cursor at startup, never replay old blocks on top of them.
                        let tips = tips?;
                        indexer.prepare()?;
                        if indexer.building_generation()?.is_some() {
                            for (id, tip) in tips {
                                if backfill::try_load_shard_checkpoint(
                                    &db,
                                    &cursor(indexer.generation()),
                                    id,
                                )? == 0
                                {
                                    backfill::save_shard_checkpoint(
                                        &db,
                                        &cursor(indexer.generation()),
                                        id,
                                        tip + 1,
                                    )
                                    .map_err(storage)?;
                                }
                            }
                        }
                    }
                    step(&indexer, &db, &stores, &canonical, &worker_flag).await
                })
            });
            let result = tokio::select! {
                result = &mut task => result,
                _ = shutdown.recv() => { flag.store(true, Ordering::Relaxed); let _ = task.await; return; }
            };
            let delay = match result {
                Ok(Ok(busy)) => {
                    prepared = true;
                    if busy {
                        Duration::from_millis(10)
                    } else {
                        Duration::from_millis(250)
                    }
                }
                other => {
                    tracing::error!(error = ?other, "Metrics replay failed; preserving readable data and retrying");
                    Duration::from_secs(5)
                }
            };
            tokio::select! { _ = tokio::time::sleep(delay) => {}, _ = shutdown.recv() => return }
        }
    });
    (handle, handles)
}

async fn step(
    indexer: &MetricsIndexer,
    db: &RocksDB,
    stores: &HashMap<u32, Stores>,
    canonical: &HashMap<u32, Stores>,
    stop: &AtomicBool,
) -> Result<bool, IndexerError> {
    if stores.is_empty() {
        return Err(storage("No shard stores available for metrics rebuild"));
    }
    let tips: HashMap<_, _> = stores
        .iter()
        .map(|(&id, s)| s.shard_store.max_block_number().map(|tip| (id, tip)))
        .collect::<Result<_, _>>()
        .map_err(storage)?;
    let active_ready = catch_up(
        &indexer.view(indexer.generation()),
        db,
        stores,
        canonical,
        &tips,
        stop,
    )
    .await?;
    if let Some(generation) = indexer.building_generation()? {
        let ready = catch_up(
            &indexer.view(generation),
            db,
            stores,
            canonical,
            &tips,
            stop,
        )
        .await?;
        if ready && active_ready {
            indexer.switch_to(generation)?;
        }
        return Ok(true);
    }
    let deleted = indexer.delete_retired(10_000)?;
    Ok(!active_ready || !deleted)
}

async fn catch_up(
    indexer: &MetricsIndexer,
    db: &RocksDB,
    stores: &HashMap<u32, Stores>,
    canonical: &HashMap<u32, Stores>,
    tips: &HashMap<u32, u64>,
    stop: &AtomicBool,
) -> Result<bool, IndexerError> {
    let name = cursor(indexer.generation());
    let mut ready = true;
    let mut shards: Vec<_> = stores.iter().collect();
    shards.sort_by_key(|(&id, _)| id);
    for (&id, store) in shards {
        let tip = tips[&id];
        let mut next = backfill::try_load_shard_checkpoint(db, &name, id)?;
        let limit = (next.saturating_add(STEP)).min(tip + 1);
        while next < limit {
            if stop.load(Ordering::Relaxed) {
                return Err(IndexerError::Internal("Metrics worker stopping".into()));
            }
            let end = (next + BATCH).min(limit);
            let messages: Vec<_> = store
                .shard_store
                .get_shard_chunks(next, Some(end))
                .map_err(storage)?
                .into_iter()
                .flat_map(|c| c.transactions)
                .flat_map(|t| t.user_messages)
                .collect();
            // Rebuild only canonical retained adds. Historical replaced or
            // revoked adds must not reappear just because their block remains.
            let source = canonical
                .get(&id)
                .ok_or_else(|| storage("Missing metrics source shard"))?;
            let mut events = vec![];
            for message in messages {
                if current(&message, source)? {
                    events.push(IndexEvent::message(message, id, end - 1));
                }
            }
            // Revocations are engine events, not user messages in a block.
            // Recover those still in the durable log, including during downtime.
            let mut options = PageOptions {
                page_size: Some(1000),
                ..Default::default()
            };
            loop {
                let page = store
                    .get_events(
                        HubEventIdGenerator::make_event_id_for_block_number(next),
                        Some(HubEventIdGenerator::make_event_id_for_block_number(end)),
                        Some(options),
                    )
                    .map_err(storage)?;
                for event in page.events {
                    if event.r#type == HubEventType::RevokeMessage as i32 {
                        if let Some(hub_event::Body::RevokeMessageBody(body)) = event.body {
                            if let Some(message) = body.message {
                                events.push(IndexEvent::message_of_kind(
                                    message,
                                    id,
                                    end - 1,
                                    super::events::MessageEventKind::Revoke,
                                ));
                            }
                        }
                    }
                }
                let Some(token) = page.next_page_token else {
                    break;
                };
                options = PageOptions {
                    page_size: Some(1000),
                    page_token: Some(token),
                    ..Default::default()
                };
            }
            indexer.process_batch(&events).await?;
            // Replaying after a crash between these commits is safe: membership
            // transitions, counts and scores were committed together.
            backfill::save_shard_checkpoint(db, &name, id, end).map_err(storage)?;
            next = end;
        }
        if next <= tip {
            ready = false;
        }
        tracing::debug!(
            generation = indexer.generation(),
            shard_id = id,
            next_block = next,
            tip,
            "Metrics block replay progress"
        );
    }
    Ok(ready)
}

fn current(message: &Message, stores: &Stores) -> Result<bool, IndexerError> {
    let Some(data) = &message.data else {
        return Ok(false);
    };
    match (MessageType::try_from(data.r#type), &data.body) {
        (Ok(MessageType::CastAdd), Some(proto::message_data::Body::CastAddBody(body)))
            if matches!(
                &body.parent,
                Some(proto::cast_add_body::Parent::ParentCastId(_))
            ) =>
        {
            Ok(
                CastStore::get_cast_add(&stores.cast_store, data.fid, message.hash.clone())
                    .map_err(storage)?
                    .is_some(),
            )
        }
        (Ok(MessageType::ReactionAdd), Some(proto::message_data::Body::ReactionBody(body))) => {
            Ok(ReactionStore::get_reaction_add(
                &stores.reaction_store,
                data.fid,
                body.r#type,
                body.target.clone(),
            )
            .map_err(storage)?
            .is_some_and(|m| m.hash == message.hash))
        }
        (Ok(MessageType::CastRemove | MessageType::ReactionRemove), _) => Ok(true),
        _ => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::config::MetricsConfig;
    use crate::proto::{message_data::Body, CastId, MessageData, ReactionBody, ReactionType};
    use crate::storage::db::RocksDbTransactionBatch;
    use crate::storage::store::account::MergeContext;
    use crate::storage::store::stores::StoreLimits;
    use crate::storage::trie::merkle_trie::MerkleTrie;
    use crate::utils::statsd_wrapper::StatsdClientWrapper;
    use crate::version::version::EngineVersion;

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
    fn like(fid: u64, byte: u8, timestamp: u32) -> Message {
        Message {
            hash: vec![byte; 20],
            signature_scheme: proto::SignatureScheme::Ed25519 as i32,
            data: Some(MessageData {
                fid,
                timestamp,
                network: proto::FarcasterNetwork::Devnet as i32,
                r#type: MessageType::ReactionAdd as i32,
                body: Some(Body::ReactionBody(ReactionBody {
                    r#type: ReactionType::Like as i32,
                    target: Some(proto::reaction_body::Target::TargetCastId(CastId {
                        fid: 99,
                        hash: vec![9; 20],
                    })),
                })),
                ..Default::default()
            }),
            ..Default::default()
        }
    }
    fn commit(store: &Stores, height: u64, messages: Vec<Message>) {
        for message in &messages {
            let mut txn = RocksDbTransactionBatch::new();
            store
                .reaction_store
                .merge(
                    message,
                    &mut txn,
                    &MergeContext {
                        version: EngineVersion::latest(),
                    },
                )
                .unwrap();
            store.db.commit(txn).unwrap();
        }
        put_block(store, height, messages);
    }
    fn put_block(store: &Stores, height: u64, messages: Vec<Message>) {
        store
            .shard_store
            .put_shard_chunk(&proto::ShardChunk {
                header: Some(proto::ShardHeader {
                    height: Some(proto::Height {
                        shard_index: 1,
                        block_number: height,
                    }),
                    ..Default::default()
                }),
                transactions: vec![proto::Transaction {
                    user_messages: messages,
                    ..Default::default()
                }],
                ..Default::default()
            })
            .unwrap();
    }
    fn indexer(db: Arc<RocksDB>) -> MetricsIndexer {
        MetricsIndexer::new(
            MetricsConfig {
                enabled: true,
                backfill_on_startup: true,
                ..Default::default()
            },
            db,
        )
    }
    fn legacy(db: &RocksDB) {
        let key = [
            vec![0xE2, 1],
            99u64.to_be_bytes().to_vec(),
            vec![20],
            vec![9; 20],
        ]
        .concat();
        db.put(&key, br#"{"likes":20,"recasts":0,"replies":4}"#)
            .unwrap();
    }

    #[tokio::test]
    async fn rebuild_resumes_and_publishes_only_after_every_shard_catches_up() {
        let dir = tempfile::tempdir().unwrap();
        let db = RocksDB::open_shard_db(dir.path().to_str().unwrap(), 0);
        let store = stores(RocksDB::open_shard_db(dir.path().to_str().unwrap(), 1));
        let source = HashMap::from([(1, store.clone())]);
        commit(&store, 1, vec![like(1, 1, 100)]);
        commit(&store, 1005, vec![like(2, 2, 101)]);
        legacy(&db);
        let reader = indexer(db.clone());
        reader.prepare().unwrap();
        let gen = reader.building_generation().unwrap().unwrap();
        backfill::save_shard_checkpoint(&db, &cursor(reader.generation()), 1, 1006).unwrap();
        step(&reader, &db, &source, &source, &AtomicBool::new(false))
            .await
            .unwrap();
        assert_eq!(reader.get_cast_metrics(99, &[9; 20]).unwrap().likes, 20);
        assert_eq!(reader.building_generation().unwrap(), Some(gen));
        assert_eq!(backfill::load_shard_checkpoint(&db, &cursor(gen), 1), 1000);
        // New activity while rebuilding survives both restart and the switch.
        commit(&store, 1006, vec![like(3, 3, 102)]);
        let resumed = indexer(db.clone());
        resumed.prepare().unwrap();
        step(&resumed, &db, &source, &source, &AtomicBool::new(false))
            .await
            .unwrap();
        assert_eq!(resumed.building_generation().unwrap(), None);
        assert_eq!(resumed.get_cast_metrics(99, &[9; 20]).unwrap().likes, 3);
        // Force a checkpoint retry: provenance prevents any double count.
        backfill::save_shard_checkpoint(&db, &cursor(gen), 1, 0).unwrap();
        while !catch_up(
            &resumed.view(gen),
            &db,
            &source,
            &source,
            &HashMap::from([(1, 1006)]),
            &AtomicBool::new(false),
        )
        .await
        .unwrap()
        {}
        assert_eq!(resumed.get_cast_metrics(99, &[9; 20]).unwrap().likes, 3);
    }

    #[tokio::test]
    async fn canonical_rebuild_excludes_superseded_and_revoked_adds() {
        let dir = tempfile::tempdir().unwrap();
        let db = RocksDB::open_shard_db(dir.path().to_str().unwrap(), 0);
        let store = stores(RocksDB::open_shard_db(dir.path().to_str().unwrap(), 1));
        commit(&store, 1, vec![like(1, 1, 100)]);
        commit(&store, 2, vec![like(1, 2, 200)]);
        let revoked = like(2, 3, 100);
        commit(&store, 3, vec![revoked.clone()]);
        let mut txn = RocksDbTransactionBatch::new();
        store.reaction_store.revoke(&revoked, &mut txn).unwrap();
        store.db.commit(txn).unwrap();
        let source = HashMap::from([(1, store)]);
        let reader = indexer(db.clone());
        reader.prepare().unwrap();
        backfill::save_shard_checkpoint(&db, &cursor(reader.generation()), 1, 4).unwrap();
        step(&reader, &db, &source, &source, &AtomicBool::new(false))
            .await
            .unwrap();
        assert_eq!(reader.get_cast_metrics(99, &[9; 20]).unwrap().likes, 1);
    }

    #[tokio::test]
    async fn missing_source_does_not_publish_or_advance_rebuild() {
        let dir = tempfile::tempdir().unwrap();
        let db = RocksDB::open_shard_db(dir.path().to_str().unwrap(), 0);
        let store = stores(RocksDB::open_shard_db(dir.path().to_str().unwrap(), 1));
        commit(&store, 1, vec![like(1, 1, 100)]);
        let source = HashMap::from([(1, store)]);
        legacy(&db);
        let reader = indexer(db.clone());
        reader.prepare().unwrap();
        let gen = reader.building_generation().unwrap().unwrap();
        backfill::save_shard_checkpoint(&db, &cursor(reader.generation()), 1, 2).unwrap();
        assert!(step(
            &reader,
            &db,
            &source,
            &HashMap::new(),
            &AtomicBool::new(false)
        )
        .await
        .is_err());
        assert_eq!(reader.get_cast_metrics(99, &[9; 20]).unwrap().likes, 20);
        assert_eq!(reader.building_generation().unwrap(), Some(gen));
        assert_eq!(backfill::load_shard_checkpoint(&db, &cursor(gen), 1), 0);
    }
}
