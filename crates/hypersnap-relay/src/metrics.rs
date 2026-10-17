//! Metrics hooks.
//!
//! The relay reports through the small [`RelayMetrics`] trait so that the
//! node's `StatsdClientWrapper` can be plugged in later without a dependency
//! from this crate on the node crate. A statsd adapter is a few lines:
//!
//! ```ignore
//! impl RelayMetrics for StatsdRelayMetrics {
//!     fn count(&self, d: Direction, shard: u32, c: Counter, v: u64) {
//!         self.0.count_with_shard(shard, &c.metric_name(d), v, vec![]);
//!     }
//!     fn gauge(&self, d: Direction, shard: u32, g: Gauge, v: u64) {
//!         self.0.gauge_with_shard(shard, &g.metric_name(d), v);
//!     }
//!     fn endpoint_failover(&self, n: Network) {
//!         self.0.count(&format!("relay.{}.failover", n), 1, vec![]);
//!     }
//! }
//! ```

use crate::types::{Direction, Network};
use std::collections::BTreeMap;
use std::sync::Mutex;

/// Per-direction, per-shard counters.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Counter {
    /// The target accepted the message.
    Relayed,
    /// The target already had the message.
    Duplicate,
    /// The target rejected the message for a rule. Permanent.
    Rejected,
    /// The target rejected the message for state that it does not have yet.
    /// The message went to the deferred queue.
    Deferred,
    /// A deferred message was submitted again.
    DeferredRetry,
    /// A message or an RPC got a rate-limit error.
    RateLimited,
    /// A message or an RPC got a transient error.
    Transient,
    /// A message used all of its attempts. Permanent.
    GaveUp,
    /// The direction filter dropped the message (type allowlist, scheme, ...).
    Filtered,
    /// The message came from the target network (loop prevention, FIP A.5).
    LoopSkipped,
    /// The direction already has an outcome for the message.
    AlreadySeen,
    /// A system message in a source block (not relayed, FIP A.3 step 5).
    SystemSkipped,
    /// A block was processed and the cursor moved past it.
    Blocks,
    /// Reading blocks from the source failed.
    SourceError,
}

impl Counter {
    pub fn as_str(self) -> &'static str {
        match self {
            Counter::Relayed => "relayed",
            Counter::Duplicate => "duplicate",
            Counter::Rejected => "rejected",
            Counter::Deferred => "deferred",
            Counter::DeferredRetry => "deferred_retry",
            Counter::RateLimited => "rate_limited",
            Counter::Transient => "transient",
            Counter::GaveUp => "gave_up",
            Counter::Filtered => "filtered",
            Counter::LoopSkipped => "loop_skipped",
            Counter::AlreadySeen => "already_seen",
            Counter::SystemSkipped => "system_skipped",
            Counter::Blocks => "blocks",
            Counter::SourceError => "source_error",
        }
    }

    /// For example `relay.inbound.relayed`.
    pub fn metric_name(self, direction: Direction) -> String {
        format!("relay.{}.{}", direction.as_str(), self.as_str())
    }
}

/// Per-direction, per-shard gauges.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Gauge {
    /// Next source height to read.
    Cursor,
    /// Highest finalized (snapchain) or certified (Hypersnap) source height.
    Tip,
    /// Source blocks that the relay has not processed: `tip + 1 - cursor`.
    Lag,
    /// Entries in the deferred queue of the shard worker.
    DeferredQueue,
    /// Entries in the seen set of the direction.
    SeenSet,
}

impl Gauge {
    pub fn as_str(self) -> &'static str {
        match self {
            Gauge::Cursor => "cursor",
            Gauge::Tip => "tip",
            Gauge::Lag => "lag",
            Gauge::DeferredQueue => "deferred_queue",
            Gauge::SeenSet => "seen_set",
        }
    }

    pub fn metric_name(self, direction: Direction) -> String {
        format!("relay.{}.{}", direction.as_str(), self.as_str())
    }
}

pub trait RelayMetrics: Send + Sync + 'static {
    fn count(&self, direction: Direction, shard: u32, counter: Counter, value: u64);
    fn gauge(&self, direction: Direction, shard: u32, gauge: Gauge, value: u64);
    /// The endpoint pool of `network` moved to its next endpoint.
    fn endpoint_failover(&self, _network: Network) {}
}

/// Discards everything.
#[derive(Default)]
pub struct NoopMetrics;

impl RelayMetrics for NoopMetrics {
    fn count(&self, _: Direction, _: u32, _: Counter, _: u64) {}
    fn gauge(&self, _: Direction, _: u32, _: Gauge, _: u64) {}
}

/// Keeps every value in memory. Tests read it, and the binary logs a summary
/// of it at an interval until a statsd sink is plugged in.
#[derive(Default)]
pub struct CountingMetrics {
    counters: Mutex<BTreeMap<(Direction, u32, Counter), u64>>,
    gauges: Mutex<BTreeMap<(Direction, u32, Gauge), u64>>,
    failovers: Mutex<BTreeMap<Network, u64>>,
}

impl CountingMetrics {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self, direction: Direction, shard: u32, counter: Counter) -> u64 {
        *self
            .counters
            .lock()
            .unwrap()
            .get(&(direction, shard, counter))
            .unwrap_or(&0)
    }

    /// Sum of a counter over all shards of a direction.
    pub fn total(&self, direction: Direction, counter: Counter) -> u64 {
        self.counters
            .lock()
            .unwrap()
            .iter()
            .filter(|((d, _, c), _)| *d == direction && *c == counter)
            .map(|(_, v)| *v)
            .sum()
    }

    pub fn gauge_value(&self, direction: Direction, shard: u32, gauge: Gauge) -> Option<u64> {
        self.gauges
            .lock()
            .unwrap()
            .get(&(direction, shard, gauge))
            .copied()
    }

    pub fn failovers(&self, network: Network) -> u64 {
        *self.failovers.lock().unwrap().get(&network).unwrap_or(&0)
    }

    /// One line per direction and shard, for the periodic log summary.
    pub fn summary(&self) -> Vec<String> {
        let counters = self.counters.lock().unwrap().clone();
        let gauges = self.gauges.lock().unwrap().clone();
        let mut keys: Vec<(Direction, u32)> = counters
            .keys()
            .map(|(d, s, _)| (*d, *s))
            .chain(gauges.keys().map(|(d, s, _)| (*d, *s)))
            .collect();
        keys.sort();
        keys.dedup();
        keys.into_iter()
            .map(|(d, s)| {
                let mut parts = vec![format!("{} shard {}:", d, s)];
                for ((cd, cs, c), v) in counters.iter() {
                    if *cd == d && *cs == s {
                        parts.push(format!("{}={}", c.as_str(), v));
                    }
                }
                for ((gd, gs, g), v) in gauges.iter() {
                    if *gd == d && *gs == s {
                        parts.push(format!("{}={}", g.as_str(), v));
                    }
                }
                parts.join(" ")
            })
            .collect()
    }
}

impl RelayMetrics for CountingMetrics {
    fn count(&self, direction: Direction, shard: u32, counter: Counter, value: u64) {
        *self
            .counters
            .lock()
            .unwrap()
            .entry((direction, shard, counter))
            .or_insert(0) += value;
    }

    fn gauge(&self, direction: Direction, shard: u32, gauge: Gauge, value: u64) {
        self.gauges
            .lock()
            .unwrap()
            .insert((direction, shard, gauge), value);
    }

    fn endpoint_failover(&self, network: Network) {
        *self.failovers.lock().unwrap().entry(network).or_insert(0) += 1;
    }
}
