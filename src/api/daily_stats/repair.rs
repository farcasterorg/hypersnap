//! One-time repair of days whose live events were held behind startup backfill.
//! Rebuild in a separate persistent DB, then replace rows and a replay boundary
//! in one primary-DB commit. Live collection continues until the short handoff.

use super::*;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};
use tokio::sync::broadcast;

const VERSION: u32 = 1;
const META: [u8; 2] = [keys::DAILY_STATS_PREFIX, 0xF7];
const BATCH: u64 = 500;
const HANDOFF_BLOCKS: u64 = 100;
// Messages may be ten minutes ahead of the block clock (validation/message.rs).
const CLOCK_SKEW: u64 = crate::core::validations::message::ALLOWED_CLOCK_SKEW_SECONDS;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RepairShardProgress {
    pub shard_id: u32,
    pub next_block: u64,
    pub tip: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RepairProgress {
    pub phase: String,
    pub complete: bool,
    pub from: String,
    pub to: String,
    pub messages_replayed: u64,
    pub shards: Vec<RepairShardProgress>,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct RepairFence {
    from_day: u32,
    to_day: u32,
    heights: BTreeMap<u32, u64>,
}

#[derive(Clone, Serialize, Deserialize)]
struct Manifest {
    version: u32,
    from_day: u32,
    to_day: u32,
    progress: RepairProgress,
    fence: Option<RepairFence>,
}

fn storage(error: impl std::fmt::Display) -> IndexerError {
    IndexerError::Storage(error.to_string())
}

fn load(db: &RocksDB) -> Result<Option<Manifest>, IndexerError> {
    db.get(&META)
        .map_err(storage)?
        .map(|bytes| serde_json::from_slice(&bytes).map_err(storage))
        .transpose()
}

fn put(manifest: &Manifest, txn: &mut RocksDbTransactionBatch) -> Result<(), IndexerError> {
    txn.put(
        META.to_vec(),
        serde_json::to_vec(manifest).map_err(storage)?,
    );
    Ok(())
}

fn save(db: &RocksDB, manifest: &Manifest) -> Result<(), IndexerError> {
    let mut txn = RocksDbTransactionBatch::new();
    put(manifest, &mut txn)?;
    db.commit(txn).map_err(storage)
}

pub(super) fn load_fence(db: &RocksDB) -> Result<Option<RepairFence>, IndexerError> {
    let Some(manifest) = load(db)? else {
        return Ok(None);
    };
    if manifest.progress.complete && manifest.fence.is_none() {
        return Err(storage(
            "Completed daily stats repair has no replay boundary",
        ));
    }
    Ok(manifest.fence)
}

struct StopOnDrop(Arc<AtomicBool>);
impl Drop for StopOnDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Relaxed);
    }
}

impl DailyStatsIndexer {
    pub fn repair_progress(&self) -> Option<RepairProgress> {
        match load(&self.db) {
            Ok(manifest) => manifest.map(|m| m.progress),
            Err(error) => Some(RepairProgress {
                phase: "failed".into(),
                complete: false,
                from: day_to_date_string(self.clients_from_day().unwrap_or_else(today)),
                to: day_to_date_string(today()),
                messages_replayed: 0,
                shards: Vec::new(),
                error: Some(error.to_string()),
            }),
        }
    }

    pub(super) fn check_repair_boundary(&self) -> Result<(), IndexerError> {
        let mut error = self.repair_boundary_error.lock().unwrap();
        if error.is_some() {
            // Serve old rows until the published skip boundary can be read.
            let fence = load_fence(&self.db)?;
            *self.repair_fence.lock().unwrap() = fence;
            *error = None;
        }
        Ok(())
    }

    pub(super) fn repaired_day(&self, day: u32) -> bool {
        self.repair_fence
            .lock()
            .unwrap()
            .as_ref()
            .is_some_and(|f| (f.from_day..=f.to_day).contains(&day))
    }

    pub(super) fn accept_message(&self, message: &Message, shard: u32, height: u64) -> bool {
        let fence = self.repair_fence.lock().unwrap();
        let Some(fence) = fence.as_ref() else {
            return true;
        };
        let Some(data) = &message.data else {
            return true;
        };
        let day = day_from_farcaster_seconds(data.timestamp as u64);
        !((fence.from_day..=fence.to_day).contains(&day)
            && fence.heights.get(&shard).is_some_and(|tip| height <= *tip))
    }

    pub(crate) fn spawn_gap_repair(
        self: &Arc<Self>,
        stores: HashMap<u32, Stores>,
        mut shutdown: broadcast::Receiver<()>,
    ) -> tokio::task::JoinHandle<()> {
        let indexer = self.clone();
        let stop = Arc::new(AtomicBool::new(false));
        let guard = StopOnDrop(stop.clone());
        tokio::spawn(async move {
            let _guard = guard;
            loop {
                let worker = indexer.clone();
                let sources = stores.clone();
                let stopping = stop.clone();
                let mut task =
                    tokio::task::spawn_blocking(move || run(&worker, &sources, &stopping));
                let result = tokio::select! {
                    result = &mut task => result,
                    _ = shutdown.recv() => {
                        stop.store(true, Ordering::Relaxed);
                        let _ = task.await;
                        return;
                    }
                };
                match result {
                    Ok(Ok(())) => return,
                    error => {
                        let error = format!("{error:?}");
                        tracing::error!(%error, "Daily stats block repair failed; existing rows remain available");
                        if let Ok(Some(mut m)) = load(&indexer.db) {
                            m.progress.phase = "failed".into();
                            m.progress.error = Some(error);
                            let _ = save(&indexer.db, &m);
                        }
                    }
                }
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(5)) => {},
                    _ = shutdown.recv() => return,
                }
            }
        })
    }
}

struct Job {
    manifest: Manifest,
    stage: DailyStatsIndexer,
}

fn start(
    primary: &DailyStatsIndexer,
    stores: &HashMap<u32, Stores>,
) -> Result<Option<Job>, IndexerError> {
    let manifest = match load(&primary.db)? {
        Some(m) if m.progress.complete => return Ok(None),
        Some(m) => m,
        None => {
            let Some(from) = primary.clients_from_day() else {
                return Ok(None);
            };
            let to = today();
            if from > to || to - from >= MAX_RANGE_DAYS {
                return Err(storage(
                    "Daily stats repair date range is invalid or exceeds 400 days",
                ));
            }
            let m = Manifest {
                version: VERSION,
                from_day: from,
                to_day: to,
                progress: RepairProgress {
                    phase: "planning".into(),
                    complete: false,
                    from: day_to_date_string(from),
                    to: day_to_date_string(to),
                    messages_replayed: 0,
                    shards: Vec::new(),
                    error: None,
                },
                fence: None,
            };
            save(&primary.db, &m)?;
            m
        }
    };
    if manifest.version != VERSION {
        return Err(storage("Unsupported daily stats repair version"));
    }
    if stores.is_empty() {
        return Err(storage("No shard blocks available for daily stats repair"));
    }
    let path = PathBuf::from(primary.db.location());
    let name = path
        .file_name()
        .ok_or_else(|| storage("API database has no directory name"))?
        .to_string_lossy();
    let path = path.with_file_name(format!(
        "{name}.daily-stats-repair-{}-{}",
        manifest.from_day, manifest.to_day
    ));
    let db = Arc::new(RocksDB::new(
        path.to_str()
            .ok_or_else(|| storage("Invalid repair DB path"))?,
    ));
    db.open().map_err(storage)?;
    let stage = DailyStatsIndexer::new(primary.config.clone(), db);
    stage
        .clients_from_day
        .store(manifest.from_day, Ordering::Relaxed);
    let mut stage = stage;
    stage.signer_lookup = primary.signer_lookup.clone();
    let manifest = match load(&stage.db)? {
        Some(m) => {
            if (m.from_day, m.to_day, m.version) != (manifest.from_day, manifest.to_day, VERSION)
                || m.progress.shards.len() != stores.len()
                || m.progress
                    .shards
                    .iter()
                    .any(|s| !stores.contains_key(&s.shard_id))
            {
                return Err(storage("Repair staging plan does not match this node"));
            }
            m
        }
        None => {
            let mut m = manifest;
            let cutoff = (m.from_day as u64 * SECONDS_PER_DAY)
                .saturating_sub(crate::core::types::FARCASTER_EPOCH / 1000)
                .saturating_sub(CLOCK_SKEW);
            for (&id, store) in stores {
                let first = store
                    .shard_store
                    .get_first_shard_chunk()
                    .map_err(storage)?
                    .ok_or_else(|| storage(format!("Shard {id} has no retained blocks")))?;
                let header = first
                    .header
                    .ok_or_else(|| storage("Retained block has no header"))?;
                let min = header
                    .height
                    .ok_or_else(|| storage("Retained block has no height"))?
                    .block_number;
                if min > 1 && header.timestamp > cutoff {
                    return Err(storage(format!("Shard {id} retention does not cover repair start (including clock skew); refusing to replace partial days")));
                }
                let tip = store.shard_store.max_block_number().map_err(storage)?;
                let low = store
                    .shard_store
                    .min_height_since_timestamp(cutoff, min, tip)
                    .map_err(storage)?;
                if low.is_none()
                    && store.shard_store.max_block_timestamp().map_err(storage)? >= cutoff
                {
                    return Err(storage(format!(
                        "Shard {id} is missing its timestamp index for the repair window"
                    )));
                }
                m.progress.shards.push(RepairShardProgress {
                    shard_id: id,
                    next_block: low.unwrap_or(tip + 1),
                    tip,
                });
            }
            m.progress.shards.sort_by_key(|s| s.shard_id);
            m.progress.phase = "replaying".into();
            save(&stage.db, &m)?;
            m
        }
    };
    Ok(Some(Job { manifest, stage }))
}

fn run(
    primary: &DailyStatsIndexer,
    stores: &HashMap<u32, Stores>,
    stop: &AtomicBool,
) -> Result<(), IndexerError> {
    let Some(mut job) = start(primary, stores)? else {
        return Ok(());
    };
    let mut logged = Instant::now();
    save(&primary.db, &job.manifest)?;
    tracing::info!(from = %job.manifest.progress.from, to = %job.manifest.progress.to,
        "Starting resumable daily stats block repair");
    loop {
        check_stop(stop)?;
        let tips = tips(stores)?;
        for (&id, &tip) in &tips {
            replay(&mut job, &stores[&id], id, tip, BATCH, stop)?;
        }
        if publish(primary, &mut job, stores, stop)? {
            tracing::info!(
                messages_replayed = job.manifest.progress.messages_replayed,
                "Daily stats block repair complete"
            );
            if let Err(error) = job.stage.db.destroy() {
                tracing::warn!(%error, "Could not remove completed daily stats repair staging DB");
            }
            return Ok(());
        }
        if logged.elapsed() >= Duration::from_secs(5) {
            save(&primary.db, &job.manifest)?;
            tracing::info!(progress = ?job.manifest.progress, "Daily stats block repair progress");
            logged = Instant::now();
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn check_stop(stop: &AtomicBool) -> Result<(), IndexerError> {
    if stop.load(Ordering::Relaxed) {
        Err(storage("Daily stats repair stopping"))
    } else {
        Ok(())
    }
}

fn tips(stores: &HashMap<u32, Stores>) -> Result<BTreeMap<u32, u64>, IndexerError> {
    stores
        .iter()
        .map(|(&id, s)| {
            s.shard_store
                .max_block_number()
                .map(|n| (id, n))
                .map_err(storage)
        })
        .collect()
}

fn replay(
    job: &mut Job,
    store: &Stores,
    id: u32,
    tip: u64,
    budget: u64,
    stop: &AtomicBool,
) -> Result<(), IndexerError> {
    check_stop(stop)?;
    let shard = job
        .manifest
        .progress
        .shards
        .iter()
        .find(|s| s.shard_id == id)
        .unwrap();
    let next = shard.next_block;
    if next > tip + 1 {
        return Err(storage("Source shard tip regressed behind repair cursor"));
    }
    if next == tip + 1 {
        return Ok(());
    }
    let end = (next + budget).min(tip + 1);
    let chunks = store
        .shard_store
        .get_shard_chunks(next, Some(end))
        .map_err(storage)?;
    if chunks.len() as u64 != end - next {
        return Err(storage(format!(
            "Missing retained blocks in shard {id}, range {next}..{end}"
        )));
    }
    let mut days = BTreeMap::new();
    let mut count = 0;
    for (height, chunk) in (next..end).zip(chunks) {
        let actual = chunk
            .header
            .and_then(|h| h.height)
            .ok_or_else(|| storage("Block has no height"))?;
        if actual.shard_index != id || actual.block_number != height {
            return Err(storage("Out-of-order repair source blocks"));
        }
        for message in chunk.transactions.into_iter().flat_map(|t| t.user_messages) {
            let data = message
                .data
                .as_ref()
                .ok_or_else(|| storage("Committed message has no data"))?;
            let day = day_from_farcaster_seconds(data.timestamp as u64);
            if (job.manifest.from_day..=job.manifest.to_day).contains(&day) {
                let attribution = job.stage.attribute(id, &message);
                job.stage.fold_message(&message, attribution, &mut days);
                count += 1;
            }
        }
    }
    let mut candidate = job.manifest.clone();
    let shard = candidate
        .progress
        .shards
        .iter_mut()
        .find(|s| s.shard_id == id)
        .unwrap();
    shard.next_block = end;
    shard.tip = tip;
    candidate.progress.messages_replayed += count;
    candidate.progress.error = None;
    let mut txn = RocksDbTransactionBatch::new();
    put(&candidate, &mut txn)?;
    job.stage
        .write_days_with_extra(days.into_iter().collect(), txn)?;
    job.manifest = candidate;
    Ok(())
}

fn day_keys(day: u32) -> Vec<Vec<u8>> {
    let mut keys = vec![
        DailyStatsIndexer::counters_key(day),
        DailyStatsIndexer::client_profile_key(day),
        DailyStatsIndexer::client_counters_key(day),
    ];
    keys.extend((1..=5).map(|kind| DailyStatsIndexer::set_key(kind, day)));
    keys.extend((1..=2).map(|kind| DailyStatsIndexer::hll_key(kind, day)));
    keys
}

/// The gate is held only for a bounded final replay and the atomic replacement.
fn publish(
    primary: &DailyStatsIndexer,
    job: &mut Job,
    stores: &HashMap<u32, Stores>,
    stop: &AtomicBool,
) -> Result<bool, IndexerError> {
    let _gate = primary.mutation_gate.lock().unwrap();
    check_stop(stop)?;
    let tips = tips(stores)?;
    for (&id, &tip) in &tips {
        let next = job
            .manifest
            .progress
            .shards
            .iter()
            .find(|s| s.shard_id == id)
            .unwrap()
            .next_block;
        if tip + 1 > next.saturating_add(HANDOFF_BLOCKS) {
            return Ok(false);
        }
        // HubEvents can be broadcast before their shard chunk is persisted.
        // Never replace a live contribution whose block is not replayable yet.
        if primary
            .live_heights
            .lock()
            .unwrap()
            .get(&id)
            .is_some_and(|h| *h > tip)
        {
            return Ok(false);
        }
        if let Some(chunk) = stores[&id]
            .shard_store
            .get_last_shard_chunk()
            .map_err(storage)?
        {
            let ts = chunk
                .header
                .ok_or_else(|| storage("Last block has no header"))?
                .timestamp;
            if day_from_farcaster_seconds(ts) < job.manifest.to_day {
                return Ok(false);
            }
        }
    }
    for (&id, &tip) in &tips {
        replay(job, &stores[&id], id, tip, HANDOFF_BLOCKS, stop)?;
    }
    let fence = RepairFence {
        from_day: job.manifest.from_day,
        to_day: job.manifest.to_day,
        heights: tips,
    };
    let mut complete = job.manifest.clone();
    complete.progress.phase = "complete".into();
    complete.progress.complete = true;
    complete.progress.error = None;
    complete.fence = Some(fence.clone());
    let mut txn = RocksDbTransactionBatch::new();
    for day in complete.from_day..=complete.to_day {
        for key in day_keys(day) {
            match job.stage.db.get(&key).map_err(storage)? {
                Some(value) => txn.put(key, value),
                None => txn.delete(key),
            }
        }
    }
    put(&complete, &mut txn)?;
    let _writer = primary.write_lock.lock().unwrap();
    primary.db.commit(txn).map_err(storage)?;
    // Everything pending at/below the published tips is already in the staged
    // rows. Remove those deltas only after the replacement commit succeeds.
    primary
        .pending
        .lock()
        .unwrap()
        .retain(|day, _| !(*day >= complete.from_day && *day <= complete.to_day));
    *primary.repair_fence.lock().unwrap() = Some(fence);
    *primary.repair_boundary_error.lock().unwrap() = None;
    job.manifest = complete;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{self, CastAddBody, MessageData};
    use crate::storage::store::stores::StoreLimits;
    use crate::storage::trie::merkle_trie::MerkleTrie;
    use crate::utils::statsd_wrapper::StatsdClientWrapper;

    struct App;
    impl SignerRequesterLookup for App {
        fn requester_fid(&self, _: u32, _: u64, _: &[u8]) -> Option<u64> {
            Some(9152)
        }
    }

    fn ts(day: u32) -> u64 {
        day as u64 * SECONDS_PER_DAY + SECONDS_PER_DAY / 2
            - crate::core::types::FARCASTER_EPOCH / 1000
    }

    fn cast(fid: u64, day: u32) -> Message {
        Message {
            signer: vec![1; 32],
            hash: fid.to_be_bytes().to_vec(),
            data: Some(MessageData {
                fid,
                timestamp: ts(day) as u32,
                r#type: MessageType::CastAdd as i32,
                body: Some(Body::CastAddBody(CastAddBody::default())),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    fn setup(
        from: u32,
    ) -> (
        tempfile::TempDir,
        Arc<DailyStatsIndexer>,
        HashMap<u32, Stores>,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let db = RocksDB::open_shard_db(dir.path().to_str().unwrap(), 0);
        let indexer = DailyStatsIndexer::new(
            crate::api::config::DailyStatsConfig {
                enabled: true,
                flush_every_events: u64::MAX as usize,
                flush_interval_secs: u64::MAX,
                ..Default::default()
            },
            db,
        )
        .with_signer_lookup(Arc::new(App));
        indexer.set_clients_from_day(from);
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
        (dir, Arc::new(indexer), HashMap::from([(1, stores)]))
    }

    fn block(stores: &HashMap<u32, Stores>, height: u64, day: u32, messages: Vec<Message>) {
        stores[&1]
            .shard_store
            .put_shard_chunk(&proto::ShardChunk {
                header: Some(proto::ShardHeader {
                    height: Some(proto::Height {
                        shard_index: 1,
                        block_number: height,
                    }),
                    timestamp: ts(day),
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

    fn row(indexer: &DailyStatsIndexer, day: u32) -> DailyStatsRow {
        indexer
            .range_with_clients(day, day, Some(10))
            .unwrap()
            .remove(0)
    }

    #[tokio::test]
    async fn replaces_partial_days_preserves_other_days_and_hands_live_events_over_once() {
        let from = today() - 1;
        let (_dir, primary, stores) = setup(from);
        let old = cast(10, from);
        let missing = cast(11, from);
        let current = cast(12, today());
        block(&stores, 1, from, vec![old.clone()]);
        block(&stores, 2, from, vec![missing.clone()]);
        block(&stores, 3, today(), vec![current.clone()]);
        primary
            .process_event(&IndexEvent::message(cast(99, from - 1), 1, 1))
            .await
            .unwrap();
        primary
            .process_event(&IndexEvent::message(old, 1, 1))
            .await
            .unwrap();
        primary.flush_all().unwrap();
        primary
            .process_event(&IndexEvent::message(current, 1, 3))
            .await
            .unwrap();
        let mut job = start(&primary, &stores).unwrap().unwrap();
        replay(&mut job, &stores[&1], 1, 3, BATCH, &AtomicBool::new(false)).unwrap();
        assert_eq!(
            row(&primary, from).casts.total,
            1,
            "staging must not change served rows"
        );

        // Broadcast may precede chunk persistence. Publication must wait for
        // the already-observed live event to become available for replay.
        let ahead = cast(13, today());
        primary
            .process_event(&IndexEvent::message(ahead.clone(), 1, 4))
            .await
            .unwrap();
        assert!(!publish(&primary, &mut job, &stores, &AtomicBool::new(false)).unwrap());
        block(&stores, 4, today(), vec![ahead]);
        assert!(publish(&primary, &mut job, &stores, &AtomicBool::new(false)).unwrap());
        assert_eq!(row(&primary, from - 1).casts.total, 1);
        assert_eq!(row(&primary, from).casts.total, 2);
        assert_eq!(
            row(&primary, today()).casts.total,
            2,
            "pending live deltas must not be added twice"
        );
        let clients = row(&primary, from).clients.unwrap();
        assert_eq!(clients.active_fids, 2);
        assert!(!clients.partial);
        assert_eq!(
            clients
                .by_client
                .iter()
                .find(|c| c.client == "9152")
                .unwrap()
                .messages_by_action["cast"],
            2
        );

        // Buffered old live events and an overlapping store walk are already
        // represented by the replacement, while genuinely new blocks still fold.
        primary
            .process_event(&IndexEvent::message(missing.clone(), 1, 2))
            .await
            .unwrap();
        primary
            .process_batch(&[IndexEvent::messages(vec![missing], 1, 0)])
            .await
            .unwrap();
        let new = cast(14, today());
        block(&stores, 5, today(), vec![new.clone()]);
        primary
            .process_event(&IndexEvent::message(new, 1, 5))
            .await
            .unwrap();
        primary.flush_all().unwrap();
        assert_eq!(row(&primary, from).casts.total, 2);
        assert_eq!(row(&primary, today()).casts.total, 3);

        // The skip boundary survives restart and completion is a one-time stamp.
        let reopened = DailyStatsIndexer::new(primary.config.clone(), primary.db.clone())
            .with_signer_lookup(Arc::new(App));
        reopened
            .process_event(&IndexEvent::message(cast(10, from), 1, 1))
            .await
            .unwrap();
        reopened.flush_all().unwrap();
        assert_eq!(row(&reopened, from).casts.total, 2);
        assert!(start(&reopened, &stores).unwrap().is_none());
        assert!(reopened.repair_progress().unwrap().complete);
    }

    #[test]
    fn resumes_staging_without_counting_a_committed_batch_twice() {
        let (_dir, primary, stores) = setup(today());
        for height in 1..=3 {
            block(&stores, height, today(), vec![cast(height, today())]);
        }
        let mut job = start(&primary, &stores).unwrap().unwrap();
        replay(&mut job, &stores[&1], 1, 3, 1, &AtomicBool::new(false)).unwrap();
        assert_eq!(job.manifest.progress.shards[0].next_block, 2);
        assert_eq!(row(&job.stage, today()).casts.total, 1);
        drop(job);
        let mut resumed = start(&primary, &stores).unwrap().unwrap();
        assert_eq!(resumed.manifest.progress.shards[0].next_block, 2);
        replay(
            &mut resumed,
            &stores[&1],
            1,
            3,
            BATCH,
            &AtomicBool::new(false),
        )
        .unwrap();
        assert!(publish(&primary, &mut resumed, &stores, &AtomicBool::new(false)).unwrap());
        assert_eq!(row(&primary, today()).casts.total, 3);
        assert_eq!(primary.repair_progress().unwrap().messages_replayed, 3);
    }

    #[tokio::test]
    async fn missing_retention_preserves_existing_totals() {
        let (_dir, primary, stores) = setup(today());
        primary
            .process_event(&IndexEvent::message(cast(10, today()), 1, 50))
            .await
            .unwrap();
        primary.flush_all().unwrap();
        block(&stores, 50, today(), vec![cast(10, today())]);
        assert!(start(&primary, &stores).is_err());
        assert_eq!(row(&primary, today()).casts.total, 1);
        assert!(!primary.repair_progress().unwrap().complete);
    }

    #[test]
    fn failed_replay_batch_does_not_advance_the_durable_cursor() {
        let (_dir, primary, stores) = setup(today());
        for height in 1..=3 {
            block(&stores, height, today(), vec![cast(height, today())]);
        }
        let mut job = start(&primary, &stores).unwrap().unwrap();
        replay(&mut job, &stores[&1], 1, 3, 1, &AtomicBool::new(false)).unwrap();
        let mut malformed = cast(2, today());
        malformed.data = None;
        block(&stores, 2, today(), vec![malformed]);
        assert!(replay(&mut job, &stores[&1], 1, 3, 1, &AtomicBool::new(false)).is_err());
        assert_eq!(
            load(&job.stage.db).unwrap().unwrap().progress.shards[0].next_block,
            2
        );
        assert_eq!(row(&primary, today()).casts.total, 0);
        block(&stores, 2, today(), vec![cast(2, today())]);
        replay(&mut job, &stores[&1], 1, 3, BATCH, &AtomicBool::new(false)).unwrap();
        assert!(publish(&primary, &mut job, &stores, &AtomicBool::new(false)).unwrap());
        assert_eq!(row(&primary, today()).casts.total, 3);
    }

    #[tokio::test]
    async fn publication_failure_keeps_old_rows_pending_deltas_and_the_old_boundary() {
        let (_dir, primary, stores) = setup(today());
        block(&stores, 1, today(), vec![cast(10, today())]);
        let mut job = start(&primary, &stores).unwrap().unwrap();
        replay(&mut job, &stores[&1], 1, 1, BATCH, &AtomicBool::new(false)).unwrap();
        let read_only = Arc::new(primary.db.open_read_only().unwrap());
        let reader = DailyStatsIndexer::new(primary.config.clone(), read_only);
        reader
            .process_event(&IndexEvent::message(cast(99, today()), 1, 1))
            .await
            .unwrap();
        assert!(publish(&reader, &mut job, &stores, &AtomicBool::new(false)).is_err());
        assert!(reader.repair_fence.lock().unwrap().is_none());
        assert_eq!(reader.pending.lock().unwrap()[&today()].counters.casts, 1);
        assert_eq!(row(&primary, today()).casts.total, 0);
        assert!(publish(&primary, &mut job, &stores, &AtomicBool::new(false)).unwrap());
        assert_eq!(row(&primary, today()).casts.total, 1);
    }

    #[test]
    fn cancelled_repair_does_not_publish_or_advance_a_batch() {
        let (_dir, primary, stores) = setup(today());
        block(&stores, 1, today(), vec![cast(10, today())]);
        let mut job = start(&primary, &stores).unwrap().unwrap();
        assert!(replay(&mut job, &stores[&1], 1, 1, BATCH, &AtomicBool::new(true)).is_err());
        assert!(publish(&primary, &mut job, &stores, &AtomicBool::new(true)).is_err());
        assert_eq!(
            load(&job.stage.db).unwrap().unwrap().progress.shards[0].next_block,
            1
        );
        assert_eq!(row(&primary, today()).casts.total, 0);
    }

    #[tokio::test]
    async fn background_job_repairs_once_and_cleans_staging() {
        let (_dir, primary, stores) = setup(today());
        for height in 1..=2 {
            block(&stores, height, today(), vec![cast(height, today())]);
        }
        primary
            .process_event(&IndexEvent::message(cast(1, today()), 1, 1))
            .await
            .unwrap();
        primary.flush_all().unwrap();
        let (stop, _) = broadcast::channel(1);
        let worker = primary.spawn_gap_repair(stores.clone(), stop.subscribe());
        tokio::time::timeout(Duration::from_secs(5), worker)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row(&primary, today()).casts.total, 2);
        assert_eq!(row(&primary, today()).clients.unwrap().active_fids, 2);
        assert_eq!(primary.repair_progress().unwrap().phase, "complete");
        assert!(start(&primary, &stores).unwrap().is_none());
    }

    #[tokio::test]
    async fn repair_combines_shards_and_keeps_independent_skip_boundaries() {
        let (dir, primary, mut stores) = setup(today());
        block(&stores, 1, today(), vec![cast(10, today())]);
        let second = Stores::new(
            RocksDB::open_shard_db(dir.path().to_str().unwrap(), 2),
            2,
            MerkleTrie::new().unwrap(),
            StoreLimits::default(),
            proto::FarcasterNetwork::Devnet,
            StatsdClientWrapper::new(
                cadence::StatsdClient::builder("test", cadence::NopMetricSink).build(),
                false,
            ),
        );
        second
            .shard_store
            .put_shard_chunk(&proto::ShardChunk {
                header: Some(proto::ShardHeader {
                    height: Some(proto::Height {
                        shard_index: 2,
                        block_number: 1,
                    }),
                    timestamp: ts(today()),
                    ..Default::default()
                }),
                transactions: vec![proto::Transaction {
                    user_messages: vec![cast(11, today())],
                    ..Default::default()
                }],
                ..Default::default()
            })
            .unwrap();
        stores.insert(2, second);
        let mut job = start(&primary, &stores).unwrap().unwrap();
        assert!(publish(&primary, &mut job, &stores, &AtomicBool::new(false)).unwrap());
        assert_eq!(row(&primary, today()).casts.total, 2);
        assert_eq!(row(&primary, today()).clients.unwrap().active_fids, 2);
        primary
            .process_event(&IndexEvent::message(cast(11, today()), 2, 1))
            .await
            .unwrap();
        primary
            .process_event(&IndexEvent::message(cast(12, today()), 1, 2))
            .await
            .unwrap();
        primary.flush_all().unwrap();
        assert_eq!(row(&primary, today()).casts.total, 3);
        assert_eq!(primary.repair_progress().unwrap().shards.len(), 2);
    }

    #[test]
    fn seek_includes_clock_skew_across_midnight() {
        let (_dir, primary, stores) = setup(today());
        block(&stores, 1, today() - 3, vec![]);
        block(&stores, 2, today() - 1, vec![]);
        let midnight = ts(today()) - SECONDS_PER_DAY / 2;
        for (height, offset) in [(3, CLOCK_SKEW + 1), (4, CLOCK_SKEW - 1)] {
            let mut message = cast(height, today());
            message.data.as_mut().unwrap().timestamp = midnight as u32;
            stores[&1]
                .shard_store
                .put_shard_chunk(&proto::ShardChunk {
                    header: Some(proto::ShardHeader {
                        height: Some(proto::Height {
                            shard_index: 1,
                            block_number: height,
                        }),
                        timestamp: midnight - offset,
                        ..Default::default()
                    }),
                    transactions: vec![proto::Transaction {
                        user_messages: if height == 4 { vec![message] } else { vec![] },
                        ..Default::default()
                    }],
                    ..Default::default()
                })
                .unwrap();
        }
        block(&stores, 5, today(), vec![cast(5, today())]);
        let mut job = start(&primary, &stores).unwrap().unwrap();
        assert_eq!(job.manifest.progress.shards[0].next_block, 4);
        replay(&mut job, &stores[&1], 1, 5, BATCH, &AtomicBool::new(false)).unwrap();
        assert!(publish(&primary, &mut job, &stores, &AtomicBool::new(false)).unwrap());
        assert_eq!(row(&primary, today()).casts.total, 2);
    }

    #[tokio::test]
    async fn corrupt_boundary_does_not_crash_readers_or_allow_unsafe_writes() {
        let (_dir, primary, _stores) = setup(today());
        primary
            .process_event(&IndexEvent::message(cast(10, today()), 1, 1))
            .await
            .unwrap();
        primary.flush_all().unwrap();
        primary.db.put(&META, b"invalid").unwrap();
        let reopened = DailyStatsIndexer::new(primary.config.clone(), primary.db.clone());
        assert_eq!(row(&reopened, today()).casts.total, 1);
        assert!(reopened
            .process_event(&IndexEvent::message(cast(11, today()), 1, 2))
            .await
            .is_err());
        assert_eq!(reopened.repair_progress().unwrap().phase, "failed");
        assert_eq!(row(&reopened, today()).casts.total, 1);
        primary.db.del(&META).unwrap();
        reopened
            .process_event(&IndexEvent::message(cast(11, today()), 1, 2))
            .await
            .unwrap();
        reopened.flush_all().unwrap();
        assert_eq!(row(&reopened, today()).casts.total, 2);
    }

    #[test]
    fn timestamp_seek_handles_leader_clocks_that_go_backwards() {
        let (_dir, primary, stores) = setup(today());
        block(&stores, 1, today() - 1, vec![]);
        let midnight = ts(today()) - SECONDS_PER_DAY / 2;
        for (height, timestamp) in [
            (2, midnight - CLOCK_SKEW + 10),
            (3, midnight - CLOCK_SKEW - 10),
        ] {
            let mut message = cast(height, today());
            message.data.as_mut().unwrap().timestamp = midnight as u32;
            stores[&1]
                .shard_store
                .put_shard_chunk(&proto::ShardChunk {
                    header: Some(proto::ShardHeader {
                        height: Some(proto::Height {
                            shard_index: 1,
                            block_number: height,
                        }),
                        timestamp,
                        ..Default::default()
                    }),
                    transactions: vec![proto::Transaction {
                        user_messages: if height == 2 { vec![message] } else { vec![] },
                        ..Default::default()
                    }],
                    ..Default::default()
                })
                .unwrap();
        }
        block(&stores, 4, today(), vec![cast(4, today())]);
        let mut job = start(&primary, &stores).unwrap().unwrap();
        assert_eq!(job.manifest.progress.shards[0].next_block, 2);
        replay(&mut job, &stores[&1], 1, 4, BATCH, &AtomicBool::new(false)).unwrap();
        assert!(publish(&primary, &mut job, &stores, &AtomicBool::new(false)).unwrap());
        assert_eq!(row(&primary, today()).casts.total, 2);
    }

    #[test]
    fn staging_write_failure_does_not_commit_counters_or_cursor() {
        let (_dir, primary, stores) = setup(today());
        for height in 1..=2 {
            block(&stores, height, today(), vec![cast(height, today())]);
        }
        let mut job = start(&primary, &stores).unwrap().unwrap();
        let writable = job.stage.db.clone();
        job.stage.db = Arc::new(writable.open_read_only().unwrap());
        assert!(replay(&mut job, &stores[&1], 1, 2, BATCH, &AtomicBool::new(false)).is_err());
        assert_eq!(job.manifest.progress.shards[0].next_block, 1);
        assert_eq!(
            load(&writable).unwrap().unwrap().progress.shards[0].next_block,
            1
        );
        assert_eq!(row(&job.stage, today()).casts.total, 0);
        job.stage.db = writable;
        replay(&mut job, &stores[&1], 1, 2, BATCH, &AtomicBool::new(false)).unwrap();
        assert!(publish(&primary, &mut job, &stores, &AtomicBool::new(false)).unwrap());
        assert_eq!(row(&primary, today()).casts.total, 2);
    }
}
