use crate::storage::constants::{OnChainEventPostfix, RootPrefix};
use crate::storage::db::RocksDB;
use crate::utils::statsd_wrapper::StatsdClientWrapper;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{oneshot, watch};
use tokio::task::JoinHandle;
use tokio::time::{self, Instant};
use tonic::Status;

const INITIAL_WAIT: Duration = Duration::from_secs(2);

pub(super) type CollectError = Box<dyn std::error::Error + Send + Sync>;

#[derive(Default)]
pub(super) struct ShardStats {
    pub approx_size: u64,
    pub num_fid_registrations: u64,
}

pub(super) struct InfoStats {
    pub block_size: u64,
    pub shards: HashMap<u32, ShardStats>,
    pub totals: ShardStats,
}

impl InfoStats {
    pub fn collect(
        block_db: &RocksDB,
        shard_dbs: &HashMap<u32, Arc<RocksDB>>,
    ) -> Result<Self, CollectError> {
        let block_size = block_db.approximate_size()?;
        let mut shards = HashMap::with_capacity(shard_dbs.len());
        let mut totals = ShardStats::default();
        for (&id, db) in shard_dbs {
            let approx_size = db.approximate_size()?;
            let num_fid_registrations = u64::from(db.count_keys_at_prefix(vec![
                RootPrefix::OnChainEvent as u8,
                OnChainEventPostfix::IdRegisterByFid as u8,
            ])?);
            totals.approx_size += approx_size;
            totals.num_fid_registrations += num_fid_registrations;
            shards.insert(
                id,
                ShardStats {
                    approx_size,
                    num_fid_registrations,
                },
            );
        }
        Ok(Self {
            block_size,
            shards,
            totals,
        })
    }
}

struct Snapshot {
    stats: Arc<InfoStats>,
    refreshed_at: Instant,
}

enum State {
    Warming,
    Ready(Snapshot),
    Failed,
}

pub(super) struct InfoStatsCache {
    receiver: watch::Receiver<State>,
    metrics: StatsdClientWrapper,
}

#[must_use]
pub struct InfoStatsTask {
    stop: oneshot::Sender<()>,
    join: JoinHandle<()>,
}

impl InfoStatsTask {
    /// Stop scheduling refreshes and drain any submitted collection.
    /// Tokio cannot abort a running blocking closure. Timing out this join
    /// would let collection keep using the databases during node teardown.
    pub async fn shutdown(self) {
        let _ = self.stop.send(());
        if let Err(error) = self.join.await {
            tracing::error!(%error, "GetInfo statistics task stopped unexpectedly");
        }
    }
}

impl InfoStatsCache {
    pub fn start(
        refresh_interval: Duration,
        metrics: StatsdClientWrapper,
        collect: impl Fn() -> Result<InfoStats, CollectError> + Send + Sync + 'static,
    ) -> (Self, InfoStatsTask) {
        assert!(
            !refresh_interval.is_zero(),
            "GetInfo refresh interval must be positive"
        );
        let (sender, receiver) = watch::channel(State::Warming);
        let (stop, mut stopped) = oneshot::channel();
        let task_metrics = metrics.clone();
        let collect = Arc::new(collect);
        let join = tokio::spawn(async move {
            // A single task owns the schedule and awaits each blocking job to completion.
            let mut delay = Duration::ZERO;
            loop {
                tokio::select! {
                    biased;
                    _ = &mut stopped => break,
                    _ = time::sleep(delay) => {}
                }

                let started = Instant::now();
                let collect = Arc::clone(&collect);
                let result = match tokio::task::spawn_blocking(move || collect()).await {
                    Ok(result) => result,
                    Err(error) => Err(Box::new(error) as CollectError),
                };
                let finished = Instant::now();
                task_metrics.time(
                    "get_info.stats_refresh_ms",
                    (finished - started).as_millis() as u64,
                );
                match result {
                    Ok(stats) => {
                        sender.send_replace(State::Ready(Snapshot {
                            stats: Arc::new(stats),
                            refreshed_at: finished,
                        }));
                    }
                    Err(error) => {
                        task_metrics.incr("get_info.stats_refresh_failed");
                        tracing::warn!(%error, "GetInfo statistics refresh failed");
                        sender.send_if_modified(|state| {
                            if matches!(state, State::Warming) {
                                *state = State::Failed;
                                true
                            } else {
                                false
                            }
                        });
                    }
                }
                if let State::Ready(snapshot) = &*sender.borrow() {
                    task_metrics.gauge(
                        "get_info.stats_cache_age_seconds",
                        snapshot.refreshed_at.elapsed().as_secs(),
                        vec![],
                    );
                }
                delay = refresh_interval;
            }
        });
        (Self { receiver, metrics }, InfoStatsTask { stop, join })
    }

    pub async fn get(&self) -> Result<Arc<InfoStats>, Status> {
        let mut receiver = self.receiver.clone();
        let state = time::timeout(
            INITIAL_WAIT,
            receiver.wait_for(|state| !matches!(state, State::Warming)),
        )
        .await
        .map_err(|_| Status::unavailable("GetInfo statistics are warming up"))?
        .map_err(|_| Status::unavailable("GetInfo statistics task stopped"))?;

        match &*state {
            State::Ready(snapshot) => {
                let stats = Arc::clone(&snapshot.stats);
                let age = snapshot.refreshed_at.elapsed().as_secs();
                drop(state);
                self.metrics
                    .gauge("get_info.stats_cache_age_seconds", age, vec![]);
                Ok(stats)
            }
            _ => Err(Status::unavailable("GetInfo statistics are unavailable")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::mpsc;

    fn stats(size: u64) -> InfoStats {
        InfoStats {
            block_size: size,
            shards: HashMap::new(),
            totals: ShardStats::default(),
        }
    }

    #[tokio::test]
    async fn concurrent_startup_and_shutdown_share_one_collection() {
        let (started, running) = oneshot::channel();
        let (release, blocked) = mpsc::channel();
        let gate = std::sync::Mutex::new(Some((started, blocked)));
        let calls = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&calls);
        let (cache, task) = InfoStatsCache::start(
            Duration::from_millis(1),
            crate::storage::store::test_helper::statsd_client(),
            move || {
                count.fetch_add(1, Ordering::SeqCst);
                if let Some((started, blocked)) = gate.lock().unwrap().take() {
                    started.send(()).unwrap();
                    blocked.recv().unwrap();
                }
                Ok(stats(0))
            },
        );
        running.await.unwrap();

        let mut requests = tokio::task::JoinSet::new();
        let cache = Arc::new(cache);
        for _ in 0..16 {
            let cache = Arc::clone(&cache);
            requests.spawn(async move { cache.get().await.unwrap() });
        }
        tokio::task::yield_now().await;
        assert!(requests.try_join_next().is_none());
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        // Signal shutdown before the first job completes. A refresh interval
        // shorter than this collection cannot lead to a second job.
        let InfoStatsTask { stop, join } = task;
        stop.send(()).unwrap();
        assert!(!join.is_finished());
        release.send(()).unwrap();

        let snapshot = requests.join_next().await.unwrap().unwrap();
        assert_eq!(snapshot.block_size, 0);
        while let Some(result) = requests.join_next().await {
            assert!(Arc::ptr_eq(&snapshot, &result.unwrap()));
        }
        join.await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn cold_wait_times_out_without_cancelling_collection() {
        let (started, running) = oneshot::channel();
        let (release, blocked) = mpsc::channel();
        let gate = std::sync::Mutex::new(Some((started, blocked)));
        let (cache, task) = InfoStatsCache::start(
            Duration::from_secs(60),
            crate::storage::store::test_helper::statsd_client(),
            move || {
                let (started, blocked) = gate.lock().unwrap().take().unwrap();
                started.send(()).unwrap();
                blocked.recv().unwrap();
                Ok(stats(5))
            },
        );
        running.await.unwrap();
        assert_eq!(
            cache.get().await.err().unwrap().code(),
            tonic::Code::Unavailable
        );
        release.send(()).unwrap();
        let mut state = cache.receiver.clone();
        state
            .wait_for(|state| matches!(state, State::Ready(_)))
            .await
            .unwrap();
        assert_eq!(cache.get().await.unwrap().block_size, 5);
        task.shutdown().await;
    }

    #[tokio::test]
    async fn failure_keeps_last_snapshot_and_refresh_recovers() {
        let (retry, retry_gate) = mpsc::channel();
        let retry_gate = std::sync::Mutex::new(retry_gate);
        let (recovering, recovery_started) = oneshot::channel();
        let (release, blocked) = mpsc::channel();
        let gate = std::sync::Mutex::new(Some((recovering, blocked)));
        let calls = AtomicUsize::new(0);
        let (packets, sink) = cadence::SpyMetricSink::new();
        let metrics =
            StatsdClientWrapper::new(cadence::StatsdClient::builder("test", sink).build(), false);
        let (cache, task) = InfoStatsCache::start(Duration::from_millis(10), metrics, move || {
            match calls.fetch_add(1, Ordering::SeqCst) {
                0 => Err(std::io::Error::other("first refresh failed").into()),
                1 => {
                    retry_gate.lock().unwrap().recv().unwrap();
                    Ok(stats(10))
                }
                2 | 3 => Err(std::io::Error::other("later refresh failed").into()),
                _ => {
                    if let Some((recovering, blocked)) = gate.lock().unwrap().take() {
                        recovering.send(()).unwrap();
                        blocked.recv().unwrap();
                    }
                    Ok(stats(20))
                }
            }
        });

        let mut state = cache.receiver.clone();
        state
            .wait_for(|state| matches!(state, State::Failed))
            .await
            .unwrap();
        assert_eq!(
            cache.get().await.err().unwrap().code(),
            tonic::Code::Unavailable
        );
        retry.send(()).unwrap();
        state
            .wait_for(|state| matches!(state, State::Ready(_)))
            .await
            .unwrap();
        let first = cache.get().await.unwrap();
        assert_eq!(first.block_size, 10);

        recovery_started.await.unwrap();
        let emitted: Vec<_> = packets
            .try_iter()
            .map(|packet| String::from_utf8(packet).unwrap())
            .collect();
        assert_eq!(
            emitted
                .iter()
                .filter(|metric| metric.starts_with("test.get_info.stats_refresh_failed:"))
                .count(),
            3
        );
        assert_eq!(
            emitted
                .iter()
                .filter(|metric| metric.starts_with("test.get_info.stats_refresh_ms:"))
                .count(),
            4
        );
        assert_eq!(
            emitted
                .iter()
                .filter(|metric| metric.starts_with("test.get_info.stats_cache_age_seconds:"))
                .count(),
            4
        );
        assert!(Arc::ptr_eq(&first, &cache.get().await.unwrap()));
        release.send(()).unwrap();
        state
            .wait_for(
                |state| matches!(state, State::Ready(snapshot) if snapshot.stats.block_size == 20),
            )
            .await
            .unwrap();
        assert_eq!(cache.get().await.unwrap().block_size, 20);
        task.shutdown().await;
    }
}
