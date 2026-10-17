//! One worker per (direction, shard): the loop of FIP A.3 / A.4.
//!
//! For each source block at the cursor:
//!
//! 1. Filter each user message (system messages never reach the worker).
//! 2. Claim its hash in the seen sets. A hash that the other set holds came
//!    from the target network and is skipped (loop prevention, A.5).
//! 3. Submit the claimed messages in batches. Record each batch's outcomes in
//!    the seen set (fsync) or the deferred queue.
//! 4. Persist the cursor (the next height).

use crate::filter::{inbound_decision, outbound_decision, Decision, SnapchainAllowlist};
use crate::metrics::{Counter, Gauge, RelayMetrics};
use crate::retry::{Backoff, RetryPolicy, Shutdown, Stopped};
use crate::source::{BlockSource, RelayBlock};
use crate::store::{Claim, CursorStore, DeferredEntry, DeferredQueue, SeenStatus, SeenStore};
use crate::submit::{Outcome, Submitter};
use crate::types::{now_unix_ms, Direction, MessageHash, Network};
use futures::StreamExt;
use hypersnap_proto::{FarcasterNetwork, Message};
use std::collections::HashSet;
use std::io;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tracing::{debug, info, warn};

/// The outbound allowlist; replaced when the snapchain version changes.
pub struct AllowlistHandle {
    inner: RwLock<SnapchainAllowlist>,
}

impl AllowlistHandle {
    pub fn new(allowlist: SnapchainAllowlist) -> Self {
        Self {
            inner: RwLock::new(allowlist),
        }
    }

    pub fn get(&self) -> SnapchainAllowlist {
        self.inner.read().unwrap().clone()
    }

    pub fn set(&self, allowlist: SnapchainAllowlist) {
        *self.inner.write().unwrap() = allowlist;
    }
}

#[derive(Clone)]
pub enum MessageFilter {
    Inbound {
        network: FarcasterNetwork,
    },
    Outbound {
        network: FarcasterNetwork,
        allowlist: Arc<AllowlistHandle>,
    },
}

impl MessageFilter {
    fn decide(&self, message: &Message, allowlist: Option<&SnapchainAllowlist>) -> Decision {
        match self {
            MessageFilter::Inbound { network } => inbound_decision(message, *network),
            MessageFilter::Outbound { network, .. } => {
                outbound_decision(message, *network, allowlist.expect("outbound allowlist"))
            }
        }
    }

    fn snapshot(&self) -> Option<SnapchainAllowlist> {
        match self {
            MessageFilter::Inbound { .. } => None,
            MessageFilter::Outbound { allowlist, .. } => Some(allowlist.get()),
        }
    }
}

#[derive(Clone, Debug)]
pub struct WorkerConfig {
    /// First height when no cursor is persisted.
    pub start_height: Option<u64>,
    pub batch_size: usize,
    /// Backoff after a source error.
    pub retry: RetryPolicy,
    pub tip_interval: Duration,
    pub deferred_retry: Duration,
    pub deferred_max_attempts: u32,
    pub deferred_check_interval: Duration,
}

#[derive(Debug, thiserror::Error)]
pub enum WorkerError {
    #[error("storage: {0}")]
    Storage(#[from] io::Error),
    #[error("no start height for {network} shard {shard}: set relay.pivot or relay.start_heights")]
    NoStartHeight { network: Network, shard: u32 },
}

enum Exit {
    Stopped,
    Storage(io::Error),
}

impl From<Stopped> for Exit {
    fn from(_: Stopped) -> Self {
        Exit::Stopped
    }
}

impl From<io::Error> for Exit {
    fn from(e: io::Error) -> Self {
        Exit::Storage(e)
    }
}

pub struct ShardWorker {
    direction: Direction,
    shard: u32,
    source: Arc<dyn BlockSource>,
    submitter: Arc<Submitter>,
    filter: MessageFilter,
    seen: Arc<SeenStore>,
    cursors: Arc<CursorStore>,
    deferred: DeferredQueue,
    metrics: Arc<dyn RelayMetrics>,
    cfg: WorkerConfig,
}

impl ShardWorker {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        direction: Direction,
        shard: u32,
        source: Arc<dyn BlockSource>,
        submitter: Arc<Submitter>,
        filter: MessageFilter,
        seen: Arc<SeenStore>,
        cursors: Arc<CursorStore>,
        deferred: DeferredQueue,
        metrics: Arc<dyn RelayMetrics>,
        cfg: WorkerConfig,
    ) -> Self {
        assert_eq!(source.network(), direction.source(), "source network");
        assert_eq!(submitter.direction(), direction, "submitter direction");
        Self {
            direction,
            shard,
            source,
            submitter,
            filter,
            seen,
            cursors,
            deferred,
            metrics,
            cfg,
        }
    }

    pub fn id(&self) -> (Direction, u32) {
        (self.direction, self.shard)
    }

    pub async fn run(mut self, shutdown: Shutdown) -> Result<(), WorkerError> {
        let network = self.direction.source();
        let mut cursor = match self.cursors.load(network, self.shard)? {
            Some(c) => c,
            None => self.cfg.start_height.ok_or(WorkerError::NoStartHeight {
                network,
                shard: self.shard,
            })?,
        };
        info!(
            direction = %self.direction, shard = self.shard, cursor,
            deferred = self.deferred.len(), "worker starting"
        );
        self.metrics
            .gauge(self.direction, self.shard, Gauge::Cursor, cursor);
        self.metrics.gauge(
            self.direction,
            self.shard,
            Gauge::DeferredQueue,
            self.deferred.len() as u64,
        );

        let mut work = shutdown.clone();
        let mut stop = shutdown;
        let mut backoff = Backoff::new(self.cfg.retry);
        let mut deferred_tick = tokio::time::interval(self.cfg.deferred_check_interval);
        deferred_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut tip_tick = tokio::time::interval(self.cfg.tip_interval);
        tip_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        let result: Result<(), Exit> = 'run: loop {
            if work.is_triggered() {
                break Ok(());
            }
            let mut stream = self.source.open(self.shard, cursor);
            loop {
                tokio::select! {
                    biased;
                    _ = stop.wait() => break 'run Ok(()),
                    _ = deferred_tick.tick() => {
                        if let Err(e) = self.retry_deferred(&mut work).await {
                            break 'run Err(e);
                        }
                    }
                    _ = tip_tick.tick() => self.report_gauges(cursor).await,
                    item = stream.next() => match item {
                        None => {
                            warn!(direction = %self.direction, shard = self.shard, "source stream ended; reopening");
                            if work.sleep(backoff.next_delay()).await.is_err() {
                                break 'run Ok(());
                            }
                            continue 'run;
                        }
                        Some(Err(e)) => {
                            self.metrics.count(self.direction, self.shard, Counter::SourceError, 1);
                            warn!(direction = %self.direction, shard = self.shard, cursor, error = %e, "source error; reopening");
                            if work.sleep(backoff.next_delay()).await.is_err() {
                                break 'run Ok(());
                            }
                            continue 'run;
                        }
                        Some(Ok(block)) => {
                            if block.height != cursor || block.shard_id != self.shard {
                                warn!(
                                    direction = %self.direction, shard = self.shard, cursor,
                                    got_shard = block.shard_id, got_height = block.height,
                                    "source returned an unexpected block; reopening"
                                );
                                if work.sleep(backoff.next_delay()).await.is_err() {
                                    break 'run Ok(());
                                }
                                continue 'run;
                            }
                            if let Err(e) = self.process_block(&block, &mut work).await {
                                break 'run Err(e);
                            }
                            cursor = block.height + 1;
                            if let Err(e) = self.cursors.store(network, self.shard, cursor) {
                                break 'run Err(Exit::Storage(e));
                            }
                            self.metrics.count(self.direction, self.shard, Counter::Blocks, 1);
                            self.metrics.gauge(self.direction, self.shard, Gauge::Cursor, cursor);
                            backoff.reset();
                        }
                    },
                }
            }
        };
        match result {
            Ok(()) | Err(Exit::Stopped) => {
                info!(direction = %self.direction, shard = self.shard, cursor, "worker stopped");
                Ok(())
            }
            Err(Exit::Storage(e)) => Err(WorkerError::Storage(e)),
        }
    }

    async fn process_block(
        &mut self,
        block: &RelayBlock,
        shutdown: &mut Shutdown,
    ) -> Result<(), Exit> {
        let (d, s) = (self.direction, self.shard);
        if block.system_messages > 0 {
            self.metrics
                .count(d, s, Counter::SystemSkipped, block.system_messages as u64);
        }
        let allowlist = self.filter.snapshot();
        let mut candidates: Vec<(MessageHash, Message)> = Vec::new();
        let mut in_block = HashSet::new();
        for message in &block.messages {
            match self.filter.decide(message, allowlist.as_ref()) {
                Decision::Drop(reason) => {
                    self.metrics.count(d, s, Counter::Filtered, 1);
                    debug!(direction = %d, shard = s, height = block.height, reason = %reason, "filtered");
                }
                Decision::Relay { hash, message } => {
                    if !in_block.insert(hash) {
                        continue;
                    }
                    if self.deferred.contains(&hash) {
                        self.metrics.count(d, s, Counter::AlreadySeen, 1);
                        continue;
                    }
                    match self.seen.claim(d, hash) {
                        Claim::Claimed => candidates.push((hash, message)),
                        Claim::LoopBlocked { origin } => {
                            self.metrics.count(d, s, Counter::LoopSkipped, 1);
                            debug!(direction = %d, shard = s, hash = %hash, origin = %origin, "loop prevented");
                        }
                        Claim::AlreadyHandled(SeenStatus::Deferred) => {
                            // The seen set says deferred but the queue does not
                            // have it (lost queue file). Submit it again.
                            warn!(direction = %d, shard = s, hash = %hash, "deferred entry missing; resubmitting");
                            candidates.push((hash, message));
                        }
                        Claim::AlreadyHandled(_) => {
                            self.metrics.count(d, s, Counter::AlreadySeen, 1);
                        }
                    }
                }
            }
        }
        for batch in candidates.chunks(self.cfg.batch_size) {
            let outcomes = self.submitter.submit(s, batch.to_vec(), shutdown).await?;
            self.apply_outcomes(outcomes, block.height)?;
        }
        Ok(())
    }

    /// Persists the outcomes of one batch: deferred entries first, then the
    /// seen-set records (both durable before return).
    fn apply_outcomes(
        &mut self,
        outcomes: Vec<(MessageHash, Message, Outcome)>,
        source_height: u64,
    ) -> io::Result<()> {
        let (d, s) = (self.direction, self.shard);
        let now = now_unix_ms();
        let mut records = Vec::with_capacity(outcomes.len());
        let mut deferred_changed = false;
        for (hash, message, outcome) in outcomes {
            let prior = self.deferred.get(&hash).cloned();
            let status = match outcome {
                Outcome::Relayed => {
                    self.metrics.count(d, s, Counter::Relayed, 1);
                    SeenStatus::Relayed
                }
                Outcome::Duplicate => {
                    self.metrics.count(d, s, Counter::Duplicate, 1);
                    SeenStatus::Duplicate
                }
                Outcome::Rejected { error } => {
                    self.metrics.count(d, s, Counter::Rejected, 1);
                    info!(direction = %d, shard = s, hash = %hash, error = %error, "rejected by target");
                    SeenStatus::Rejected
                }
                Outcome::GaveUp { error } => {
                    self.metrics.count(d, s, Counter::GaveUp, 1);
                    warn!(direction = %d, shard = s, hash = %hash, error = %error, "gave up");
                    SeenStatus::GaveUp
                }
                Outcome::Deferred { error } => {
                    let attempts = prior.as_ref().map(|e| e.attempts).unwrap_or(0) + 1;
                    if attempts >= self.cfg.deferred_max_attempts {
                        self.metrics.count(d, s, Counter::Rejected, 1);
                        info!(direction = %d, shard = s, hash = %hash, attempts, error = %error, "still rejected; giving up");
                        SeenStatus::Rejected
                    } else {
                        let delay = self
                            .cfg
                            .deferred_retry
                            .saturating_mul(1 << (attempts - 1).min(16));
                        let entry = DeferredEntry {
                            hash: hash.0.to_vec(),
                            message: Some(message),
                            attempts,
                            next_attempt_unix_ms: now.saturating_add(delay.as_millis() as u64),
                            last_error: error.clone(),
                            source_height: prior
                                .as_ref()
                                .map(|e| e.source_height)
                                .unwrap_or(source_height),
                        };
                        if self.deferred.upsert(hash, entry) {
                            deferred_changed = true;
                            if prior.is_none() {
                                self.metrics.count(d, s, Counter::Deferred, 1);
                                debug!(direction = %d, shard = s, hash = %hash, error = %error, "deferred");
                                records.push((hash, SeenStatus::Deferred));
                            }
                            continue;
                        }
                        self.metrics.count(d, s, Counter::Rejected, 1);
                        warn!(direction = %d, shard = s, hash = %hash, error = %error, "deferred queue full; rejecting");
                        SeenStatus::Rejected
                    }
                }
            };
            if prior.is_some() {
                self.deferred.remove(&hash);
                deferred_changed = true;
            }
            records.push((hash, status));
        }
        if deferred_changed {
            self.deferred.persist()?;
            self.metrics
                .gauge(d, s, Gauge::DeferredQueue, self.deferred.len() as u64);
        }
        self.seen.record(d, &records)
    }

    async fn retry_deferred(&mut self, shutdown: &mut Shutdown) -> Result<(), Exit> {
        let due = self.deferred.due(now_unix_ms(), self.cfg.batch_size);
        if due.is_empty() {
            return Ok(());
        }
        let items: Vec<(MessageHash, Message)> = due
            .into_iter()
            .filter_map(|(hash, entry)| entry.message.map(|m| (hash, m)))
            .collect();
        self.metrics.count(
            self.direction,
            self.shard,
            Counter::DeferredRetry,
            items.len() as u64,
        );
        let outcomes = self.submitter.submit(self.shard, items, shutdown).await?;
        self.apply_outcomes(outcomes, 0)?;
        Ok(())
    }

    async fn report_gauges(&self, cursor: u64) {
        let (d, s) = (self.direction, self.shard);
        match tokio::time::timeout(Duration::from_secs(5), self.source.tip(s)).await {
            Ok(Ok(Some(tip))) => {
                self.metrics.gauge(d, s, Gauge::Tip, tip);
                self.metrics
                    .gauge(d, s, Gauge::Lag, (tip + 1).saturating_sub(cursor));
            }
            Ok(Ok(None)) => {}
            Ok(Err(e)) => debug!(direction = %d, shard = s, error = %e, "tip unavailable"),
            Err(_) => debug!(direction = %d, shard = s, "tip timed out"),
        }
        self.metrics
            .gauge(d, s, Gauge::SeenSet, self.seen.len(d) as u64);
        self.metrics
            .gauge(d, s, Gauge::DeferredQueue, self.deferred.len() as u64);
    }
}
