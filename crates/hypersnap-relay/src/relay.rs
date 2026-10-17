//! Wires the configuration into pools, sources, submitters and shard workers.

use crate::classify::Classifier;
use crate::config::{HypersnapBlockSourceKind, PivotConfig, RelayConfig};
use crate::endpoints::{EndpointError, EndpointOptions, EndpointPool};
use crate::filter::{SnapchainAllowlist, SnapchainVersion};
use crate::metrics::{NoopMetrics, RelayMetrics};
use crate::retry::{Backoff, RetryPolicy, Shutdown};
use crate::source::chunks::ChunkSource;
use crate::source::hypersnap::{CertifiedSource, GrpcHypersnapBlockSource, HypersnapBlockSource};
use crate::source::{BlockSource, SourceError};
use crate::store::{DeferredQueue, StateDir};
use crate::submit::{SubmitConfig, Submitter};
use crate::types::{Direction, Network};
use crate::worker::{AllowlistHandle, MessageFilter, ShardWorker, WorkerConfig, WorkerError};
use std::io;
use std::sync::Arc;
use std::time::Duration;
use tokio::task::JoinSet;
use tracing::{error, info, warn};

#[derive(Debug, thiserror::Error)]
pub enum RelayError {
    #[error("config: {0}")]
    Config(String),
    #[error("state: {0}")]
    State(#[from] io::Error),
    #[error(transparent)]
    Endpoint(#[from] EndpointError),
    #[error("outbound source: {0}")]
    Source(#[from] SourceError),
    #[error("{direction} shard {shard}: {source}")]
    Worker {
        direction: Direction,
        shard: u32,
        source: WorkerError,
    },
}

pub struct RelayBuilder {
    config: RelayConfig,
    metrics: Arc<dyn RelayMetrics>,
    outbound_source: Option<Arc<dyn BlockSource>>,
}

impl RelayBuilder {
    pub fn new(config: RelayConfig) -> Self {
        Self {
            config,
            metrics: Arc::new(NoopMetrics),
            outbound_source: None,
        }
    }

    pub fn metrics(mut self, metrics: Arc<dyn RelayMetrics>) -> Self {
        self.metrics = metrics;
        self
    }

    /// Uses `source` for the outbound path instead of the configured one.
    pub fn hypersnap_block_source<S: HypersnapBlockSource>(mut self, source: S) -> Self {
        self.outbound_source = Some(Arc::new(CertifiedSource::new(source)));
        self
    }

    /// Runs until `shutdown` or until a worker fails (storage errors are fatal:
    /// the relay must not advance without durable state).
    pub async fn run(self, shutdown: Shutdown) -> Result<(), RelayError> {
        let mut cfg = self.config;
        cfg.validate()
            .map_err(|e| RelayError::Config(e.to_string()))?;
        let metrics = self.metrics;
        let state = StateDir::open(&cfg.state_dir, cfg.network, cfg.seen_set_capacity)?;
        info!(state_dir = %state.root().display(), network = cfg.network.as_str(), "state opened");

        let pool = |network: Network, urls: &[String], auth: &Option<String>, rpm: u32| {
            EndpointPool::new(
                network,
                urls,
                EndpointOptions {
                    connect_timeout: Duration::from_millis(cfg.connect_timeout_ms),
                    request_timeout: Duration::from_millis(cfg.request_timeout_ms),
                    max_message_bytes: cfg.max_grpc_message_bytes,
                    auth: auth.clone(),
                    rpcs_per_minute: rpm,
                },
                metrics.clone(),
            )
            .map(Arc::new)
        };
        let snapchain = pool(
            Network::Snapchain,
            &cfg.snapchain_endpoints,
            &cfg.snapchain_auth,
            cfg.rate_limits.snapchain_rpcs_per_minute,
        )?;
        let hypersnap = pool(
            Network::Hypersnap,
            &cfg.hypersnap_endpoints,
            &cfg.hypersnap_auth,
            cfg.rate_limits.hypersnap_rpcs_per_minute,
        )?;
        // The fork points come from the Hypersnap node's `PivotRecord` when
        // the config does not set them (FIP A.8).
        if cfg.pivot.is_none() {
            match hypersnap.get_pivot_record().await {
                Ok(record) if record.pivot_height > 0 => {
                    let pivot = PivotConfig::from_record(&record);
                    info!(
                        pivot_height = pivot.pivot_height,
                        fork_heights = ?pivot.fork_heights,
                        "fork points from the node's PivotRecord"
                    );
                    cfg.pivot = Some(pivot);
                }
                Ok(_) => {}
                Err(e) => warn!(error = %e, "no PivotRecord from the Hypersnap nodes"),
            }
        }

        let classifier = Arc::new(Classifier::new(&cfg.deferred.error_patterns));
        let retry = RetryPolicy::new(cfg.retry_initial(), cfg.retry_max());
        let submit_cfg = SubmitConfig {
            retry,
            max_attempts: cfg.max_message_attempts,
        };
        let poll = Duration::from_millis(cfg.poll_interval_ms);
        let farcaster_network = cfg.network.farcaster_network();

        let (internal_trigger, internal) = Shutdown::new();
        {
            let mut external = shutdown.clone();
            let trigger = internal_trigger.clone();
            tokio::spawn(async move {
                external.wait().await;
                trigger.trigger();
            });
        }

        let mut workers: Vec<ShardWorker> = Vec::new();
        let mut background: JoinSet<()> = JoinSet::new();

        let worker_cfg = |network: Network, shard: u32| WorkerConfig {
            start_height: cfg.start_height(network, shard),
            batch_size: cfg.submit_batch_size,
            retry,
            tip_interval: Duration::from_millis(cfg.tip_interval_ms),
            deferred_retry: Duration::from_millis(cfg.deferred.retry_ms),
            deferred_max_attempts: cfg.deferred.max_attempts,
            deferred_check_interval: Duration::from_millis(cfg.deferred.retry_ms.clamp(10, 1_000)),
        };

        if cfg.inbound_enabled {
            let source: Arc<dyn BlockSource> = Arc::new(ChunkSource::new(
                snapchain.clone(),
                cfg.fetch_page_size,
                poll,
            ));
            let submitter = Arc::new(Submitter::new(
                Direction::Inbound,
                hypersnap.clone(),
                classifier.clone(),
                submit_cfg,
                cfg.rate_limits.hypersnap_messages_per_second,
                metrics.clone(),
            ));
            for &shard in &cfg.inbound_shards {
                workers.push(ShardWorker::new(
                    Direction::Inbound,
                    shard,
                    source.clone(),
                    submitter.clone(),
                    MessageFilter::Inbound {
                        network: farcaster_network,
                    },
                    state.seen.clone(),
                    state.cursors.clone(),
                    DeferredQueue::open(
                        &state.deferred_path(Direction::Inbound, shard),
                        cfg.deferred.capacity,
                    )?,
                    metrics.clone(),
                    worker_cfg(Network::Snapchain, shard),
                ));
            }
        }

        if cfg.outbound_enabled {
            let source: Arc<dyn BlockSource> = match self.outbound_source {
                Some(source) => source,
                None => {
                    match cfg.hypersnap_block_source {
                        HypersnapBlockSourceKind::ShardChunks => {
                            warn!("outbound uses the interim shard_chunks source (devnet/testing only)");
                            Arc::new(ChunkSource::new(
                                hypersnap.clone(),
                                cfg.fetch_page_size,
                                poll,
                            ))
                        }
                        HypersnapBlockSourceKind::Certified => Arc::new(CertifiedSource::new(
                            GrpcHypersnapBlockSource::new(hypersnap.clone()),
                        )),
                    }
                }
            };
            let allowlist = Arc::new(AllowlistHandle::new(
                resolve_allowlist(
                    &cfg.snapchain_version,
                    &snapchain,
                    retry,
                    &mut internal.clone(),
                )
                .await?,
            ));
            info!(
                snapchain_version = %allowlist.get().version(),
                types = ?allowlist.get().types().collect::<Vec<_>>(),
                "outbound allowlist"
            );
            if cfg.snapchain_version == "auto" && cfg.version_refresh_secs > 0 {
                let (allowlist, snapchain) = (allowlist.clone(), snapchain.clone());
                let every = Duration::from_secs(cfg.version_refresh_secs);
                let mut stop = internal.clone();
                background.spawn(async move {
                    while stop.sleep(every).await.is_ok() {
                        if let Ok(info) = snapchain.get_info().await {
                            if let Some(v) = SnapchainVersion::parse(&info.version) {
                                if v != allowlist.get().version() {
                                    info!(old = %allowlist.get().version(), new = %v, "snapchain version changed");
                                    allowlist.set(SnapchainAllowlist::for_version(v));
                                }
                            }
                        }
                    }
                });
            }
            let submitter = Arc::new(Submitter::new(
                Direction::Outbound,
                snapchain.clone(),
                classifier.clone(),
                submit_cfg,
                cfg.rate_limits.snapchain_messages_per_second,
                metrics.clone(),
            ));
            for &shard in &cfg.outbound_shards {
                workers.push(ShardWorker::new(
                    Direction::Outbound,
                    shard,
                    source.clone(),
                    submitter.clone(),
                    MessageFilter::Outbound {
                        network: farcaster_network,
                        allowlist: allowlist.clone(),
                    },
                    state.seen.clone(),
                    state.cursors.clone(),
                    DeferredQueue::open(
                        &state.deferred_path(Direction::Outbound, shard),
                        cfg.deferred.capacity,
                    )?,
                    metrics.clone(),
                    worker_cfg(Network::Hypersnap, shard),
                ));
            }
        }

        let mut tasks = JoinSet::new();
        for worker in workers {
            let stop = internal.clone();
            let id = worker.id();
            tasks.spawn(async move { (id, worker.run(stop).await) });
        }
        let mut first_error = None;
        while let Some(joined) = tasks.join_next().await {
            match joined {
                Ok((_, Ok(()))) => {}
                Ok(((direction, shard), Err(source))) => {
                    error!(direction = %direction, shard, error = %source, "worker failed; stopping relay");
                    internal_trigger.trigger();
                    first_error.get_or_insert(RelayError::Worker {
                        direction,
                        shard,
                        source,
                    });
                }
                Err(join_error) => {
                    error!(error = %join_error, "worker task panicked; stopping relay");
                    internal_trigger.trigger();
                    first_error.get_or_insert(RelayError::Config(format!(
                        "worker panicked: {join_error}"
                    )));
                }
            }
        }
        internal_trigger.trigger();
        background.shutdown().await;
        drop(state);
        match first_error {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
}

/// The outbound allowlist: a fixed version, or `GetInfo.version` of the
/// snapchain node (retried until it answers).
async fn resolve_allowlist(
    version: &str,
    snapchain: &EndpointPool,
    retry: RetryPolicy,
    shutdown: &mut Shutdown,
) -> Result<SnapchainAllowlist, RelayError> {
    if version != "auto" {
        let v = SnapchainVersion::parse(version)
            .ok_or_else(|| RelayError::Config(format!("snapchain_version {version:?}")))?;
        return Ok(SnapchainAllowlist::for_version(v));
    }
    let mut backoff = Backoff::new(retry);
    loop {
        match snapchain.get_info().await {
            Ok(info) => match SnapchainVersion::parse(&info.version) {
                Some(v) => return Ok(SnapchainAllowlist::for_version(v)),
                None => warn!(version = %info.version, "cannot parse the snapchain version"),
            },
            Err(status) => {
                warn!(endpoint = %snapchain.current().url, error = %status, "GetInfo for the snapchain version failed");
                snapchain.failover(snapchain.current().index);
            }
        }
        if shutdown.sleep(backoff.next_delay()).await.is_err() {
            return Err(RelayError::Config(
                "stopped before the snapchain version was known".into(),
            ));
        }
    }
}
