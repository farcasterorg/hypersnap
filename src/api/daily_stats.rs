//! Daily network-wide activity rollups: the node-native replacement for the
//! Dune `dataset_farcaster_{casts,reactions,links}` query.
//!
//! Neynar stopped publishing those datasets, so the series they backed has to be
//! derived from the node's own message stream instead. This indexer folds every
//! committed CastAdd / ReactionAdd / LinkAdd into a per-UTC-day rollup, and
//! [`DailyStatsIndexer::range`] reads those rollups back as a dense daily series
//! for a chart renderer.
//!
//! # What is exact and what is estimated
//!
//! Distinct **fid** counts are exact: the per-day fid sets are stored in full
//! (delta+varint encoded, see [`fidset`]) because retention needs to intersect
//! them, and the fid space is small enough that this is cheap.
//!
//! Distinct **hash** counts (`unique_parent_hashes`, `unique_target_hashes`) are
//! HyperLogLog estimates with ~0.8% standard error (see [`hll`]). Storing those
//! sets exactly would cost gigabytes over a six-month window for numbers that
//! only ever get plotted. The JSON marks them `_estimated`.
//!
//! # Retention semantics
//!
//! Carried over verbatim from the SQL this replaces: `retention.dN` for day D is
//! the number of fids that cast on D **and also cast exactly N days earlier** —
//! not "within the last N days". It is cast activity only; reactions and links
//! do not count. Computed at read time by intersecting stored fid sets, so the
//! windows can change without a reindex.
//!
//! # Storage schema
//!
//! Keys are prefixed with [`keys::DAILY_STATS_PREFIX`] (0xEA):
//! - `[prefix][0x01][day:4]`            -> `DailyCounters` (JSON)
//! - `[prefix][0x02][set_kind:1][day:4]` -> encoded fid set
//! - `[prefix][0x03][hll_kind:1][day:4]` -> HLL registers
//! - `[prefix][0xFF]`                    -> checkpoint:8
//!
//! `day` is days since the Unix epoch, big-endian, so a prefix scan is in date
//! order.

use crate::api::config::DailyStatsConfig;
use crate::api::events::{IndexEvent, MessageEventKind};
use crate::api::indexer::{Indexer, IndexerError, IndexerStats};
use crate::core::util::from_farcaster_time;
use crate::proto::message_data::Body;
use crate::proto::{Message, MessageType};
use crate::storage::db::{RocksDB, RocksDbTransactionBatch};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

const SECONDS_PER_DAY: u64 = 86_400;

/// Upper bound on the span a single query may ask for. Each day in the span
/// costs a handful of RocksDB reads plus set decodes, and the retention lookback
/// pulls in 30 more days, so an unbounded range is a cheap way to stall a
/// worker. A little over a year is well past any dashboard's needs.
pub const MAX_RANGE_DAYS: u32 = 400;

/// Version of the stored rollups' *meaning*, not their encoding.
///
/// Bumping this wipes every key under the daily-stats prefix and clears the
/// backfill cursors, so the next start rebuilds from scratch. Bump it whenever a
/// change makes previously-written numbers wrong rather than merely incomplete —
/// there is no way to repair counters in place, because the stored value carries
/// no record of what went into it.
///
/// - v1: initial.
/// - v2: prune/revoke were being folded as new activity, inflating historical
///   days by an unknowable amount; and messages committed while the store walk
///   ran were dropped entirely, leaving holes at the backfill/live seam. Neither
///   is reconstructable from what was stored, so v1 data is discarded.
pub const DATA_VERSION: u32 = 2;

/// Name the store-walk backfill checkpoints under. Shared with the walker in
/// `api::mod` so a wipe here clears exactly the cursors that walk writes.
pub const BACKFILL_CHECKPOINT_NAME: &str = "daily_stats_hyper_backfill";

mod keys {
    /// Prefix for all daily-stats keys.
    pub const DAILY_STATS_PREFIX: u8 = 0xEA;

    pub const COUNTERS: u8 = 0x01;
    pub const FID_SET: u8 = 0x02;
    pub const HLL: u8 = 0x03;
    /// Version stamp for the *data layout and semantics* under this prefix.
    /// Mismatch against [`super::DATA_VERSION`] wipes everything and re-backfills.
    pub const DATA_VERSION: u8 = 0xFC;
    /// Per-shard backfill cursor: `[prefix][0xFD][shard:4]` -> `fid:8`.
    /// `u64::MAX` means that shard's walk finished.
    pub const BACKFILL_CURSOR: u8 = 0xFD;
    /// First day this node observed *live* traffic, i.e. the boundary below
    /// which rows are store-walk reconstructions rather than observed events.
    pub const LIVE_FROM: u8 = 0xFE;
    pub const CHECKPOINT: u8 = 0xFF;
}

/// Which per-day fid set a key refers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
enum SetKind {
    CastAuthors = 1,
    ReactionActors = 2,
    LinkActors = 3,
    ReactionTargetFids = 4,
    LinkTargetFids = 5,
}

/// Which per-day HLL a key refers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
enum HllKind {
    CastParentHashes = 1,
    ReactionTargetHashes = 2,
}

/// Plain additive counters for one day. Everything here is a straight sum, so
/// unlike the sets it can be folded in without deduplication.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct DailyCounters {
    pub casts: u64,
    pub reactions: u64,
    pub links: u64,
    /// Top-level casts (no parent cast) that carry a parent_url — the FIP-2
    /// numerator.
    pub top_level_with_parent_url: u64,
    /// Top-level casts with neither parent cast nor parent_url.
    pub top_level_without_parent_url: u64,
}

impl DailyCounters {
    fn merge(&mut self, other: &DailyCounters) {
        self.casts += other.casts;
        self.reactions += other.reactions;
        self.links += other.links;
        self.top_level_with_parent_url += other.top_level_with_parent_url;
        self.top_level_without_parent_url += other.top_level_without_parent_url;
    }
}

// ---------------------------------------------------------------------------
// fid set codec
// ---------------------------------------------------------------------------

/// Sorted-u64 set encoded as delta + LEB128 varints.
///
/// Active fids on a given day cluster densely in a ~10^6 space, so successive
/// deltas are almost always one or two bytes. That keeps a 100k-fid day near
/// 200KB instead of the 800KB a raw `u64` array would cost, which matters
/// because retention needs these kept for the whole queryable window rather
/// than just long enough to count.
mod fidset {
    pub fn encode(sorted: &[u64]) -> Vec<u8> {
        let mut out = Vec::with_capacity(sorted.len() * 2);
        let mut prev = 0u64;
        for &v in sorted {
            let mut delta = v - prev;
            prev = v;
            loop {
                let byte = (delta & 0x7f) as u8;
                delta >>= 7;
                if delta == 0 {
                    out.push(byte);
                    break;
                }
                out.push(byte | 0x80);
            }
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> Vec<u64> {
        let mut out = Vec::new();
        let mut acc = 0u64;
        let mut shift = 0u32;
        let mut prev = 0u64;
        for &b in bytes {
            acc |= ((b & 0x7f) as u64) << shift;
            if b & 0x80 == 0 {
                prev += acc;
                out.push(prev);
                acc = 0;
                shift = 0;
            } else {
                shift += 7;
            }
        }
        out
    }

    /// Size of the intersection of two ascending-sorted slices.
    pub fn intersection_len(a: &[u64], b: &[u64]) -> u64 {
        let (mut i, mut j, mut n) = (0usize, 0usize, 0u64);
        while i < a.len() && j < b.len() {
            match a[i].cmp(&b[j]) {
                std::cmp::Ordering::Equal => {
                    n += 1;
                    i += 1;
                    j += 1;
                }
                std::cmp::Ordering::Less => i += 1,
                std::cmp::Ordering::Greater => j += 1,
            }
        }
        n
    }
}

// ---------------------------------------------------------------------------
// HyperLogLog
// ---------------------------------------------------------------------------

/// Minimal HyperLogLog for hash-cardinality estimates.
///
/// p=14 (16384 one-byte registers, 16KB) gives ~0.81% standard error, which is
/// far below the resolution anyone reads off a daily chart. Rolled by hand
/// rather than pulled in as a dependency: the surface used here is one insert
/// and one estimate.
///
/// The element hash is deliberately **not** `DefaultHasher` — SipHash keys are
/// not guaranteed stable across Rust releases, and these registers are
/// persisted, so a toolchain bump would silently corrupt every stored sketch.
/// FNV-1a plus a splitmix64 finalizer is fixed forever.
mod hll {
    pub const P: u32 = 14;
    pub const REGISTERS: usize = 1 << P;

    pub fn hash64(bytes: &[u8]) -> u64 {
        // FNV-1a
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        for &b in bytes {
            h ^= b as u64;
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
        // splitmix64 finalizer — FNV-1a alone has weak avalanche in the high
        // bits, which is exactly where the register index comes from.
        let mut z = h.wrapping_add(0x9e37_79b9_7f4a_7c15);
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    pub fn insert(registers: &mut [u8], bytes: &[u8]) {
        let h = hash64(bytes);
        let idx = (h >> (64 - P)) as usize;
        // Rank = position of the leftmost 1 in the remaining bits, 1-based.
        let w = h << P;
        let rank = if w == 0 {
            (64 - P) as u8 + 1
        } else {
            w.leading_zeros() as u8 + 1
        };
        if rank > registers[idx] {
            registers[idx] = rank;
        }
    }

    pub fn merge_into(dst: &mut [u8], src: &[u8]) {
        for (d, s) in dst.iter_mut().zip(src.iter()) {
            if *s > *d {
                *d = *s;
            }
        }
    }

    pub fn estimate(registers: &[u8]) -> u64 {
        let m = REGISTERS as f64;
        let mut sum = 0.0f64;
        let mut zeros = 0usize;
        for &r in registers {
            sum += 1.0 / ((1u64 << r) as f64);
            if r == 0 {
                zeros += 1;
            }
        }
        // alpha_m for m >= 128
        let alpha = 0.7213 / (1.0 + 1.079 / m);
        let raw = alpha * m * m / sum;
        if raw <= 2.5 * m && zeros > 0 {
            // Small-range: linear counting is materially more accurate here.
            (m * (m / zeros as f64).ln()).round() as u64
        } else {
            raw.round() as u64
        }
    }
}

// ---------------------------------------------------------------------------
// in-memory accumulation
// ---------------------------------------------------------------------------

/// One day's worth of not-yet-flushed activity.
///
/// Events are folded here rather than straight to RocksDB because a set insert
/// per message would mean a read-modify-write of the whole day's set per
/// message — quadratic in the day's message count. Flushing is by day rollover
/// plus an event-count threshold.
struct DayAccumulator {
    counters: DailyCounters,
    sets: HashMap<u8, HashSet<u64>>,
    hlls: HashMap<u8, Vec<u8>>,
}

impl DayAccumulator {
    fn new() -> Self {
        Self {
            counters: DailyCounters::default(),
            sets: HashMap::new(),
            hlls: HashMap::new(),
        }
    }

    /// Returns true if the fid was not already present, so the caller can keep
    /// a running count of resident set entries for the backfill memory budget.
    fn add_fid(&mut self, kind: SetKind, fid: u64) -> bool {
        self.sets.entry(kind as u8).or_default().insert(fid)
    }

    fn add_hash(&mut self, kind: HllKind, hash: &[u8]) {
        let regs = self
            .hlls
            .entry(kind as u8)
            .or_insert_with(|| vec![0u8; hll::REGISTERS]);
        hll::insert(regs, hash);
    }
}

// ---------------------------------------------------------------------------
// public row type
// ---------------------------------------------------------------------------

/// One day of the series, shaped for direct JSON serialization.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct DailyStatsRow {
    /// UTC date, `YYYY-MM-DD`.
    pub date: String,
    pub casts: CastStats,
    pub reactions: ReactionStats,
    pub links: LinkStats,
    pub retention: RetentionStats,
    /// True when this day predates the first live traffic this node observed,
    /// i.e. it was rebuilt by walking the message stores rather than counted as
    /// events arrived.
    ///
    /// Reconstructed days are **survivorship-biased**: a store walk can only
    /// see messages that still exist, so anything deleted since is missing, and
    /// the effect grows the further back you look. Plotted against observed
    /// days without distinction it reads as organic growth toward the present.
    /// Render these differently.
    pub reconstructed: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct CastStats {
    pub total: u64,
    pub unique_authors: u64,
    /// Trailing 7 **calendar** day mean of `unique_authors`, floored.
    ///
    /// The SQL this replaces used `ROWS BETWEEN 6 PRECEDING`, which counts rows
    /// rather than days and so silently widens the window across any date with
    /// no activity. The series here is dense, so the window is always 7 real
    /// days. `null` until 7 days of history are available.
    pub unique_authors_7d_avg: Option<u64>,
    /// HyperLogLog estimate.
    pub unique_parent_hashes_estimated: u64,
    pub top_level_with_parent_url: u64,
    pub top_level_without_parent_url: u64,
    /// `top_level_with_parent_url / top_level_without_parent_url`.
    ///
    /// `null` when the denominator is zero. The SQL returned `1e308` there,
    /// which is not representable in JSON and reads as a real data point on a
    /// chart.
    pub fip2_ratio: Option<f64>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct ReactionStats {
    pub total: u64,
    pub unique_actors: u64,
    pub unique_target_fids: u64,
    /// HyperLogLog estimate.
    pub unique_target_hashes_estimated: u64,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct LinkStats {
    pub total: u64,
    pub unique_actors: u64,
    pub unique_target_fids: u64,
}

/// Backfill state, surfaced by `/v2/farcaster/_status/backfill`.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct BackfillProgress {
    /// Every shard's walk has finished.
    pub complete: bool,
    /// At least one shard has recorded a cursor. False means the walk has not
    /// begun — distinct from `complete: false` with work in flight.
    pub started: bool,
    /// Messages folded since process start. Resets on restart; the durable
    /// progress signal is the per-shard cursors.
    pub messages_folded: u64,
    /// Number of days that have any stored data.
    pub days_with_data: u32,
    pub earliest_day: Option<String>,
    pub latest_day: Option<String>,
    /// Boundary below which rows are marked `reconstructed`.
    pub live_from_day: Option<String>,
    pub shards: Vec<ShardBackfillProgress>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct ShardBackfillProgress {
    pub shard_id: u32,
    /// Last fid walked. `null` once the shard is complete.
    pub cursor_fid: Option<u64>,
    pub complete: bool,
}

/// Fids that cast on this day *and* also cast exactly N days earlier.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct RetentionStats {
    pub d7: u64,
    pub d20: u64,
    pub d30: u64,
}

// ---------------------------------------------------------------------------
// date helpers
// ---------------------------------------------------------------------------

/// Days since the Unix epoch for a Farcaster-epoch second count.
fn day_from_farcaster_seconds(ts: u64) -> u32 {
    (from_farcaster_time(ts) / 1000 / SECONDS_PER_DAY) as u32
}

/// Day bucket a message falls into, from its Farcaster-epoch timestamp.
///
/// Exposed so the backfill walker can window-filter messages without folding
/// them, using exactly the same bucketing the indexer does.
pub fn day_for_message_timestamp(farcaster_seconds: u64) -> u32 {
    day_from_farcaster_seconds(farcaster_seconds)
}

/// `YYYY-MM-DD` for a day number.
pub fn day_to_date_string(day: u32) -> String {
    chrono::DateTime::from_timestamp(day as i64 * SECONDS_PER_DAY as i64, 0)
        .map(|dt| dt.format("%Y-%m-%d").to_string())
        .unwrap_or_else(|| "invalid".to_string())
}

/// Day number for a `YYYY-MM-DD` string.
pub fn date_string_to_day(s: &str) -> Option<u32> {
    let date = chrono::NaiveDate::parse_from_str(s.trim(), "%Y-%m-%d").ok()?;
    let secs = date.and_hms_opt(0, 0, 0)?.and_utc().timestamp();
    if secs < 0 {
        return None;
    }
    Some((secs as u64 / SECONDS_PER_DAY) as u32)
}

/// Today in UTC, as a day number.
pub fn today() -> u32 {
    (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
        / SECONDS_PER_DAY) as u32
}

// ---------------------------------------------------------------------------
// indexer
// ---------------------------------------------------------------------------

pub struct DailyStatsIndexer {
    config: DailyStatsConfig,
    db: Arc<RocksDB>,
    pending: Mutex<BTreeMap<u32, DayAccumulator>>,
    /// Serializes `write_days`.
    ///
    /// Every stored value is folded in with a read-modify-write (counters sum,
    /// fid sets union, HLL registers max), and the drain from `pending` releases
    /// its lock before any of that happens. With the backfill walk running
    /// concurrently with the live path, two flushes can target the same day at
    /// once — both read the same base, and whichever commits last silently
    /// discards the other's delta. Flushes are seconds apart, so serializing
    /// them costs nothing.
    write_lock: Mutex<()>,
    /// Events folded into `pending` since the last flush.
    pending_events: AtomicU64,
    /// Distinct fid entries currently resident across all pending days. Drives
    /// the backfill memory budget.
    pending_fids: AtomicU64,
    /// While set, flushing is budget-driven rather than day-rollover-driven.
    /// See [`DailyStatsIndexer::set_backfill_mode`].
    backfill_mode: std::sync::atomic::AtomicBool,
    /// When the accumulator was last written out. Bounds staleness of the
    /// current day independently of traffic volume.
    last_flush: Mutex<std::time::Instant>,
    /// Messages folded since process start, across live and backfill paths.
    /// This is the number an operator actually wants while a long walk runs —
    /// `days_written` counts merge operations, which goes up and down with the
    /// flush budget and says nothing about progress.
    messages_folded: AtomicU64,
    /// First day live traffic was observed; 0 when unset.
    live_from_day: std::sync::atomic::AtomicU32,
    checkpoint: AtomicU64,
    days_written: AtomicU64,
}

impl DailyStatsIndexer {
    pub fn new(config: DailyStatsConfig, db: Arc<RocksDB>) -> Self {
        // Before reading anything: discard rollups written under older, wrong
        // semantics. Cheap when versions match (one key read).
        Self::wipe_if_stale(&db);

        let checkpoint = Self::load_checkpoint(&db).unwrap_or(0);
        let live_from = Self::load_live_from(&db).unwrap_or(0);
        Self {
            config,
            db,
            pending: Mutex::new(BTreeMap::new()),
            write_lock: Mutex::new(()),
            pending_events: AtomicU64::new(0),
            pending_fids: AtomicU64::new(0),
            backfill_mode: std::sync::atomic::AtomicBool::new(false),
            last_flush: Mutex::new(std::time::Instant::now()),
            messages_folded: AtomicU64::new(0),
            live_from_day: std::sync::atomic::AtomicU32::new(live_from),
            checkpoint: AtomicU64::new(checkpoint),
            days_written: AtomicU64::new(0),
        }
    }

    /// Switch between live and backfill flushing strategies.
    ///
    /// The live path sees messages in roughly timestamp order, so flushing
    /// every day but the newest keeps at most a day or two resident. A
    /// store walk is fid-major instead: a single fid contributes messages
    /// spread across the whole window, so that same rule would flush and
    /// re-merge every day in the range on every batch. In backfill mode we
    /// instead hold all days until a fid-count budget is hit, which turns
    /// hundreds of thousands of day-merges into a handful.
    pub fn set_backfill_mode(&self, on: bool) {
        self.backfill_mode
            .store(on, std::sync::atomic::Ordering::Relaxed);
    }

    /// Declare the boundary between reconstructed and live days.
    ///
    /// Called by the backfill walker with the day it starts, so the walk and the
    /// live path partition the timeline explicitly rather than relying on
    /// whichever message happens to arrive first.
    pub fn set_live_from_day(&self, day: u32) {
        self.note_live_day(day);
    }

    /// Record that live traffic has been seen for `day`, if no earlier live day
    /// is already recorded. Rows before this boundary are reconstructions.
    fn note_live_day(&self, day: u32) {
        use std::sync::atomic::Ordering as O;
        let current = self.live_from_day.load(O::Relaxed);
        if current != 0 && current <= day {
            return;
        }
        self.live_from_day.store(day, O::Relaxed);
        let mut txn = RocksDbTransactionBatch::new();
        txn.put(Self::live_from_key(), day.to_be_bytes().to_vec());
        let _ = self.db.commit(txn);
    }

    // --- keys ---

    fn counters_key(day: u32) -> Vec<u8> {
        let mut k = Vec::with_capacity(6);
        k.push(keys::DAILY_STATS_PREFIX);
        k.push(keys::COUNTERS);
        k.extend_from_slice(&day.to_be_bytes());
        k
    }

    fn set_key(kind: u8, day: u32) -> Vec<u8> {
        let mut k = Vec::with_capacity(7);
        k.push(keys::DAILY_STATS_PREFIX);
        k.push(keys::FID_SET);
        k.push(kind);
        k.extend_from_slice(&day.to_be_bytes());
        k
    }

    fn hll_key(kind: u8, day: u32) -> Vec<u8> {
        let mut k = Vec::with_capacity(7);
        k.push(keys::DAILY_STATS_PREFIX);
        k.push(keys::HLL);
        k.push(kind);
        k.extend_from_slice(&day.to_be_bytes());
        k
    }

    fn checkpoint_key() -> Vec<u8> {
        vec![keys::DAILY_STATS_PREFIX, keys::CHECKPOINT]
    }

    fn data_version_key() -> Vec<u8> {
        vec![keys::DAILY_STATS_PREFIX, keys::DATA_VERSION]
    }

    /// Drop every stored rollup when the on-disk data version is behind the code.
    ///
    /// This is a wipe, not a repair. The counters are sums with no provenance, so
    /// a day inflated by re-counted prunes cannot be corrected — only rebuilt. The
    /// backfill cursors (both this prefix's copy and the shared `0xE3` checkpoints)
    /// are cleared too, otherwise the walk would report itself already complete and
    /// the wiped range would never be refilled.
    fn wipe_if_stale(db: &RocksDB) {
        let stored = db
            .get(&Self::data_version_key())
            .ok()
            .flatten()
            .and_then(|b| b.try_into().ok())
            .map(u32::from_be_bytes)
            .unwrap_or(0);

        if stored == DATA_VERSION {
            return;
        }

        let prefix = vec![keys::DAILY_STATS_PREFIX];
        let mut doomed: Vec<Vec<u8>> = Vec::new();
        let _ = db.for_each_iterator_by_prefix(
            Some(prefix.clone()),
            Some(crate::storage::util::increment_vec_u8(&prefix)),
            &crate::storage::db::PageOptions::default(),
            |key, _| {
                doomed.push(key.to_vec());
                Ok(false)
            },
        );

        // The shared per-shard backfill checkpoints live outside this prefix.
        let ck_prefix = crate::api::backfill::shard_checkpoint_prefix(BACKFILL_CHECKPOINT_NAME);
        let _ = db.for_each_iterator_by_prefix(
            Some(ck_prefix.clone()),
            Some(crate::storage::util::increment_vec_u8(&ck_prefix)),
            &crate::storage::db::PageOptions::default(),
            |key, _| {
                doomed.push(key.to_vec());
                Ok(false)
            },
        );

        if !doomed.is_empty() {
            tracing::warn!(
                keys = doomed.len(),
                from_version = stored,
                to_version = DATA_VERSION,
                "Daily stats data version changed; discarding stored rollups and re-running backfill"
            );
        }
        let mut txn = RocksDbTransactionBatch::new();
        for key in doomed {
            txn.delete(key);
        }
        txn.put(
            Self::data_version_key(),
            DATA_VERSION.to_be_bytes().to_vec(),
        );
        if let Err(e) = db.commit(txn) {
            tracing::error!("Failed to wipe stale daily stats data: {}", e);
        }
    }

    fn live_from_key() -> Vec<u8> {
        vec![keys::DAILY_STATS_PREFIX, keys::LIVE_FROM]
    }

    fn load_checkpoint(db: &RocksDB) -> Option<u64> {
        let bytes = db.get(&Self::checkpoint_key()).ok()??;
        bytes.try_into().ok().map(u64::from_be_bytes)
    }

    fn load_live_from(db: &RocksDB) -> Option<u32> {
        let bytes = db.get(&Self::live_from_key()).ok()??;
        bytes.try_into().ok().map(u32::from_be_bytes)
    }

    // --- reads ---

    fn read_counters(&self, day: u32) -> DailyCounters {
        match self.db.get(&Self::counters_key(day)) {
            Ok(Some(bytes)) => serde_json::from_slice(&bytes).unwrap_or_default(),
            _ => DailyCounters::default(),
        }
    }

    fn read_set(&self, kind: SetKind, day: u32) -> Vec<u64> {
        match self.db.get(&Self::set_key(kind as u8, day)) {
            Ok(Some(bytes)) => fidset::decode(&bytes),
            _ => Vec::new(),
        }
    }

    fn read_hll_estimate(&self, kind: HllKind, day: u32) -> u64 {
        match self.db.get(&Self::hll_key(kind as u8, day)) {
            Ok(Some(bytes)) if bytes.len() == hll::REGISTERS => hll::estimate(&bytes),
            _ => 0,
        }
    }

    // --- folding ---

    /// Fold one message into `pending`, returning how many fid-set entries it
    /// newly created (for the backfill memory budget).
    fn fold_message(&self, message: &Message, pending: &mut BTreeMap<u32, DayAccumulator>) -> u64 {
        let Some(data) = message.data.as_ref() else {
            return 0;
        };
        let day = day_from_farcaster_seconds(data.timestamp as u64);
        let fid = data.fid;
        let acc = pending.entry(day).or_insert_with(DayAccumulator::new);
        let mut new_fids = 0u64;

        match MessageType::try_from(data.r#type).ok() {
            Some(MessageType::CastAdd) => {
                let Some(Body::CastAddBody(body)) = data.body.as_ref() else {
                    return 0;
                };
                acc.counters.casts += 1;
                new_fids += acc.add_fid(SetKind::CastAuthors, fid) as u64;
                match body.parent.as_ref() {
                    Some(crate::proto::cast_add_body::Parent::ParentCastId(cast_id)) => {
                        // A reply. Its parent hash contributes to the distinct
                        // set of casts that were replied to; it is not top-level
                        // so neither parent_url counter moves.
                        acc.add_hash(HllKind::CastParentHashes, &cast_id.hash);
                    }
                    Some(crate::proto::cast_add_body::Parent::ParentUrl(_)) => {
                        acc.counters.top_level_with_parent_url += 1;
                    }
                    None => {
                        acc.counters.top_level_without_parent_url += 1;
                    }
                }
            }
            Some(MessageType::ReactionAdd) => {
                let Some(Body::ReactionBody(body)) = data.body.as_ref() else {
                    return 0;
                };
                acc.counters.reactions += 1;
                new_fids += acc.add_fid(SetKind::ReactionActors, fid) as u64;
                if let Some(crate::proto::reaction_body::Target::TargetCastId(cast_id)) =
                    body.target.as_ref()
                {
                    new_fids += acc.add_fid(SetKind::ReactionTargetFids, cast_id.fid) as u64;
                    acc.add_hash(HllKind::ReactionTargetHashes, &cast_id.hash);
                }
            }
            Some(MessageType::LinkAdd) => {
                let Some(Body::LinkBody(body)) = data.body.as_ref() else {
                    return 0;
                };
                // Deliberately not filtered to `type == "follow"`: the Dune
                // links dataset this replaces counted every link type, and
                // narrowing it here would silently shift the series.
                acc.counters.links += 1;
                new_fids += acc.add_fid(SetKind::LinkActors, fid) as u64;
                if let Some(crate::proto::link_body::Target::TargetFid(target_fid)) =
                    body.target.as_ref()
                {
                    new_fids += acc.add_fid(SetKind::LinkTargetFids, *target_fid) as u64;
                }
            }
            _ => {}
        }
        new_fids
    }

    fn backfill_cursor_key(shard_id: u32) -> Vec<u8> {
        let mut k = Vec::with_capacity(6);
        k.push(keys::DAILY_STATS_PREFIX);
        k.push(keys::BACKFILL_CURSOR);
        k.extend_from_slice(&shard_id.to_be_bytes());
        k
    }

    /// Persist how far the store walk has got on a shard. `u64::MAX` marks the
    /// shard finished.
    pub fn record_backfill_cursor(&self, shard_id: u32, fid: u64) {
        let mut txn = RocksDbTransactionBatch::new();
        txn.put(
            Self::backfill_cursor_key(shard_id),
            fid.to_be_bytes().to_vec(),
        );
        let _ = self.db.commit(txn);
    }

    /// Snapshot of backfill state, for the status endpoint.
    ///
    /// Deliberately derived from persisted cursors and the stored day keys
    /// rather than in-memory counters, so it survives a restart mid-walk —
    /// which, for a walk this long, is the case that actually matters.
    pub fn backfill_progress(&self) -> BackfillProgress {
        let mut shards: Vec<ShardBackfillProgress> = Vec::new();
        let prefix = vec![keys::DAILY_STATS_PREFIX, keys::BACKFILL_CURSOR];
        let _ = self.db.for_each_iterator_by_prefix(
            Some(prefix.clone()),
            Some(crate::storage::util::increment_vec_u8(&prefix)),
            &crate::storage::db::PageOptions::default(),
            |key, value| {
                if key.len() == 6 && value.len() == 8 {
                    let shard_id = u32::from_be_bytes(key[2..6].try_into().unwrap());
                    let fid = u64::from_be_bytes(value[..8].try_into().unwrap());
                    shards.push(ShardBackfillProgress {
                        shard_id,
                        cursor_fid: if fid == u64::MAX { None } else { Some(fid) },
                        complete: fid == u64::MAX,
                    });
                }
                // `true` means STOP in this iterator; keep going.
                Ok(false)
            },
        );
        shards.sort_by_key(|s| s.shard_id);

        // Day coverage: scan the counters keyspace. One small key per day, so
        // even a multi-year history is a few hundred entries.
        let mut days_with_data = 0u32;
        let mut earliest: Option<u32> = None;
        let mut latest: Option<u32> = None;
        let cprefix = vec![keys::DAILY_STATS_PREFIX, keys::COUNTERS];
        let _ = self.db.for_each_iterator_by_prefix(
            Some(cprefix.clone()),
            Some(crate::storage::util::increment_vec_u8(&cprefix)),
            &crate::storage::db::PageOptions::default(),
            |key, _value| {
                if key.len() == 6 {
                    let day = u32::from_be_bytes(key[2..6].try_into().unwrap());
                    days_with_data += 1;
                    earliest = Some(earliest.map_or(day, |e: u32| e.min(day)));
                    latest = Some(latest.map_or(day, |l: u32| l.max(day)));
                }
                Ok(false)
            },
        );

        BackfillProgress {
            // No cursors at all means the walk never started (backfill
            // disabled, or no hyper stores) — that is "not complete", not
            // "vacuously complete".
            complete: !shards.is_empty() && shards.iter().all(|s| s.complete),
            started: !shards.is_empty(),
            messages_folded: self.messages_folded.load(Ordering::Relaxed),
            days_with_data,
            earliest_day: earliest.map(day_to_date_string),
            latest_day: latest.map(day_to_date_string),
            live_from_day: {
                let d = self
                    .live_from_day
                    .load(std::sync::atomic::Ordering::Relaxed);
                if d == 0 {
                    None
                } else {
                    Some(day_to_date_string(d))
                }
            },
            shards,
        }
    }

    /// Record the earliest day represented in a batch of *live* messages.
    ///
    /// Only the live path calls this. Backfill deliberately does not, so the
    /// watermark keeps meaning "the oldest day this node observed as it
    /// happened" — which is exactly the boundary below which rows are
    /// reconstructions.
    fn mark_live(&self, messages: &[Message]) {
        let earliest = messages
            .iter()
            .filter_map(|m| m.data.as_ref())
            .map(|d| day_from_farcaster_seconds(d.timestamp as u64))
            .min();
        if let Some(day) = earliest {
            self.note_live_day(day);
        }
    }

    /// Merge every accumulated day except the newest into storage.
    ///
    /// The newest is held back because more events for it are almost certainly
    /// still arriving; `flush_all` takes it too. Events arrive in roughly
    /// timestamp order on both the live and backfill paths, so this keeps at
    /// most a day or two resident.
    fn flush_completed_days(&self) -> Result<(), IndexerError> {
        let mut pending = self.pending.lock().unwrap();
        if pending.len() <= 1 {
            return Ok(());
        }
        let newest = *pending.keys().next_back().unwrap();
        let to_flush: Vec<u32> = pending.keys().copied().filter(|d| *d != newest).collect();
        let drained: Vec<(u32, DayAccumulator)> = to_flush
            .into_iter()
            .filter_map(|d| pending.remove(&d).map(|a| (d, a)))
            .collect();
        drop(pending);
        self.write_days(drained)
    }

    fn flush_all(&self) -> Result<(), IndexerError> {
        let drained: Vec<(u32, DayAccumulator)> = {
            let mut pending = self.pending.lock().unwrap();
            std::mem::take(&mut *pending).into_iter().collect()
        };
        self.write_days(drained)
    }

    /// Read-merge-write each day. Merging (rather than overwriting) is what
    /// makes the indexer restart-safe and makes a re-run of an overlapping
    /// backfill range converge instead of double-counting the sets — though
    /// note the plain counters *are* additive, so a replayed range does inflate
    /// them. Backfill is checkpointed to avoid that.
    fn write_days(&self, days: Vec<(u32, DayAccumulator)>) -> Result<(), IndexerError> {
        if days.is_empty() {
            return Ok(());
        }
        // Held across the whole read-merge-write cycle, not just the commit:
        // the read is the half that has to be protected.
        let _guard = self.write_lock.lock().unwrap();
        let mut txn = RocksDbTransactionBatch::new();
        let n = days.len() as u64;

        for (day, acc) in days {
            let mut counters = self.read_counters(day);
            counters.merge(&acc.counters);
            let encoded = serde_json::to_vec(&counters)
                .map_err(|e| IndexerError::Serialization(e.to_string()))?;
            txn.put(Self::counters_key(day), encoded);

            for (kind, fids) in acc.sets {
                let mut merged: HashSet<u64> = match self.db.get(&Self::set_key(kind, day)) {
                    Ok(Some(bytes)) => fidset::decode(&bytes).into_iter().collect(),
                    _ => HashSet::new(),
                };
                merged.extend(fids);
                let mut sorted: Vec<u64> = merged.into_iter().collect();
                sorted.sort_unstable();
                txn.put(Self::set_key(kind, day), fidset::encode(&sorted));
            }

            for (kind, mut regs) in acc.hlls {
                if let Ok(Some(existing)) = self.db.get(&Self::hll_key(kind, day)) {
                    if existing.len() == hll::REGISTERS {
                        hll::merge_into(&mut regs, &existing);
                    }
                }
                txn.put(Self::hll_key(kind, day), regs);
            }
        }

        self.db
            .commit(txn)
            .map_err(|e| IndexerError::Storage(e.to_string()))?;
        self.days_written.fetch_add(n, Ordering::Relaxed);
        self.pending_events.store(0, Ordering::Relaxed);
        self.pending_fids.store(0, Ordering::Relaxed);
        *self.last_flush.lock().unwrap() = std::time::Instant::now();
        Ok(())
    }

    /// True when more than `flush_interval_secs` has passed since the last write.
    ///
    /// Checked in both modes. During a backfill the live path shares this
    /// accumulator, so without a time bound today's traffic would be held under
    /// the walk's multi-million-entry memory budget and the series would appear
    /// frozen while the walk ran.
    fn flush_interval_elapsed(&self) -> bool {
        self.last_flush.lock().unwrap().elapsed().as_secs() >= self.config.flush_interval_secs
    }

    fn maybe_flush(&self) -> Result<(), IndexerError> {
        if self
            .backfill_mode
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            // Budget-driven: hold every day until resident fid entries exceed
            // the cap, then write the whole window out at once.
            if self.pending_fids.load(Ordering::Relaxed)
                >= self.config.backfill_max_pending_fids as u64
                || self.flush_interval_elapsed()
            {
                self.flush_all()?;
            }
            return Ok(());
        }
        self.flush_completed_days()?;
        if self.pending_events.load(Ordering::Relaxed) >= self.config.flush_every_events as u64
            || self.flush_interval_elapsed()
        {
            self.flush_all()?;
        }
        Ok(())
    }

    // --- query ---

    /// Dense daily series for `[from_day, to_day]` inclusive.
    ///
    /// Days with no recorded activity come back as explicit zero rows rather
    /// than gaps, so the moving average and the chart's x-axis both stay on real
    /// calendar days.
    pub fn range(&self, from_day: u32, to_day: u32) -> Result<Vec<DailyStatsRow>, IndexerError> {
        if to_day < from_day {
            return Err(IndexerError::InvalidData(
                "`to` must not precede `from`".to_string(),
            ));
        }
        let span = to_day - from_day + 1;
        if span > MAX_RANGE_DAYS {
            return Err(IndexerError::InvalidData(format!(
                "range of {} days exceeds the {} day maximum",
                span, MAX_RANGE_DAYS
            )));
        }

        // Rolling cache of decoded cast-author sets. Retention reaches back 30
        // days and the 7d average reaches back 6, so we start the walk 30 days
        // early and evict anything older than the widest lookback. That bounds
        // resident memory at ~31 days of sets regardless of the span asked for.
        const MAX_LOOKBACK: u32 = 30;
        let walk_from = from_day.saturating_sub(MAX_LOOKBACK);
        let live_from = self
            .live_from_day
            .load(std::sync::atomic::Ordering::Relaxed);
        let mut authors: BTreeMap<u32, Vec<u64>> = BTreeMap::new();
        let mut unique_authors_by_day: BTreeMap<u32, u64> = BTreeMap::new();
        let mut rows = Vec::with_capacity(span as usize);

        for day in walk_from..=to_day {
            let cast_authors = self.read_set(SetKind::CastAuthors, day);
            unique_authors_by_day.insert(day, cast_authors.len() as u64);
            authors.insert(day, cast_authors);
            while let Some((&oldest, _)) = authors.iter().next() {
                if day.saturating_sub(oldest) > MAX_LOOKBACK {
                    authors.remove(&oldest);
                } else {
                    break;
                }
            }

            if day < from_day {
                continue;
            }

            let counters = self.read_counters(day);
            let today_authors = authors.get(&day).cloned().unwrap_or_default();

            let retained = |n: u32| -> u64 {
                if day < n {
                    return 0;
                }
                match authors.get(&(day - n)) {
                    Some(past) => fidset::intersection_len(&today_authors, past),
                    None => 0,
                }
            };

            // 7-day trailing mean, only once a full 7 days of history exists.
            let avg = if day >= walk_from + 6 {
                let sum: u64 = (0..7)
                    .filter_map(|i| unique_authors_by_day.get(&(day - i)))
                    .sum();
                Some(sum / 7)
            } else {
                None
            };

            let fip2 = if counters.top_level_without_parent_url == 0 {
                None
            } else {
                Some(
                    counters.top_level_with_parent_url as f64
                        / counters.top_level_without_parent_url as f64,
                )
            };

            rows.push(DailyStatsRow {
                date: day_to_date_string(day),
                casts: CastStats {
                    total: counters.casts,
                    unique_authors: today_authors.len() as u64,
                    unique_authors_7d_avg: avg,
                    unique_parent_hashes_estimated: self
                        .read_hll_estimate(HllKind::CastParentHashes, day),
                    top_level_with_parent_url: counters.top_level_with_parent_url,
                    top_level_without_parent_url: counters.top_level_without_parent_url,
                    fip2_ratio: fip2,
                },
                reactions: ReactionStats {
                    total: counters.reactions,
                    unique_actors: self.read_set(SetKind::ReactionActors, day).len() as u64,
                    unique_target_fids: self.read_set(SetKind::ReactionTargetFids, day).len()
                        as u64,
                    unique_target_hashes_estimated: self
                        .read_hll_estimate(HllKind::ReactionTargetHashes, day),
                },
                links: LinkStats {
                    total: counters.links,
                    unique_actors: self.read_set(SetKind::LinkActors, day).len() as u64,
                    unique_target_fids: self.read_set(SetKind::LinkTargetFids, day).len() as u64,
                },
                retention: RetentionStats {
                    d7: retained(7),
                    d20: retained(20),
                    d30: retained(30),
                },
                reconstructed: live_from != 0 && day < live_from,
            });
        }

        Ok(rows)
    }
}

#[async_trait]
impl Indexer for DailyStatsIndexer {
    fn name(&self) -> &'static str {
        "daily_stats"
    }

    fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    async fn process_event(&self, event: &IndexEvent) -> Result<(), IndexerError> {
        match event {
            // Merges only. Prune and revoke redeliver a message that was already
            // counted, with its original timestamp, so folding them would inflate
            // a historical day every time storage limits bite.
            IndexEvent::MessageCommitted {
                message,
                kind: MessageEventKind::Merge,
                ..
            } => {
                let new_fids = {
                    let mut pending = self.pending.lock().unwrap();
                    self.fold_message(message, &mut pending)
                };
                self.pending_fids.fetch_add(new_fids, Ordering::Relaxed);
                self.pending_events.fetch_add(1, Ordering::Relaxed);
                self.messages_folded.fetch_add(1, Ordering::Relaxed);
                self.mark_live(std::slice::from_ref(message));
                self.maybe_flush()?;
            }
            IndexEvent::MessagesCommitted {
                messages,
                kind: MessageEventKind::Merge,
                ..
            } => {
                let new_fids = {
                    let mut pending = self.pending.lock().unwrap();
                    let mut n = 0u64;
                    for message in messages {
                        n += self.fold_message(message, &mut pending);
                    }
                    n
                };
                self.pending_fids.fetch_add(new_fids, Ordering::Relaxed);
                self.pending_events
                    .fetch_add(messages.len() as u64, Ordering::Relaxed);
                self.messages_folded
                    .fetch_add(messages.len() as u64, Ordering::Relaxed);
                self.mark_live(messages);
                self.maybe_flush()?;
            }
            IndexEvent::BlockCommitted { .. } => {
                self.flush_completed_days()?;
            }
            _ => {}
        }
        Ok(())
    }

    async fn process_batch(&self, events: &[IndexEvent]) -> Result<(), IndexerError> {
        {
            let mut pending = self.pending.lock().unwrap();
            let mut folded = 0u64;
            let mut new_fids = 0u64;
            for event in events {
                match event {
                    IndexEvent::MessageCommitted {
                        message,
                        kind: MessageEventKind::Merge,
                        ..
                    } => {
                        new_fids += self.fold_message(message, &mut pending);
                        folded += 1;
                    }
                    IndexEvent::MessagesCommitted {
                        messages,
                        kind: MessageEventKind::Merge,
                        ..
                    } => {
                        for message in messages {
                            new_fids += self.fold_message(message, &mut pending);
                        }
                        folded += messages.len() as u64;
                    }
                    _ => {}
                }
            }
            self.pending_events.fetch_add(folded, Ordering::Relaxed);
            self.messages_folded.fetch_add(folded, Ordering::Relaxed);
            self.pending_fids.fetch_add(new_fids, Ordering::Relaxed);
        }
        self.maybe_flush()
    }

    fn last_checkpoint(&self) -> u64 {
        self.checkpoint.load(Ordering::Relaxed)
    }

    async fn save_checkpoint(&self, event_id: u64) -> Result<(), IndexerError> {
        // Flush first: a checkpoint that outruns the data it stands for would
        // make a restart skip events that were only ever in memory.
        self.flush_all()?;
        let mut txn = RocksDbTransactionBatch::new();
        txn.put(Self::checkpoint_key(), event_id.to_be_bytes().to_vec());
        self.db
            .commit(txn)
            .map_err(|e| IndexerError::Storage(e.to_string()))?;
        self.checkpoint.store(event_id, Ordering::Relaxed);
        Ok(())
    }

    fn stats(&self) -> IndexerStats {
        let progress = self.backfill_progress();
        IndexerStats {
            items_indexed: self.messages_folded.load(Ordering::Relaxed),
            last_event_id: self.checkpoint.load(Ordering::Relaxed),
            last_block_height: 0,
            // Derived from the per-shard cursors, not from the event-log
            // checkpoint: this indexer backfills by walking stores, so the
            // checkpoint is never advanced and would report `false` forever.
            backfill_complete: progress.complete,
            size_bytes: 0,
        }
    }

    async fn flush(&self) -> Result<(), IndexerError> {
        self.flush_all()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{CastAddBody, CastId, LinkBody, MessageData, ReactionBody};

    fn make_test_db() -> Arc<RocksDB> {
        let tmp_path = tempfile::tempdir()
            .unwrap()
            .path()
            .as_os_str()
            .to_str()
            .unwrap()
            .to_string();
        let db = RocksDB::new(&tmp_path);
        db.open().unwrap();
        Arc::new(db)
    }

    fn indexer(db: Arc<RocksDB>) -> DailyStatsIndexer {
        DailyStatsIndexer::new(
            DailyStatsConfig {
                enabled: true,
                backfill_on_startup: false,
                backfill_batch_size: 100,
                flush_every_events: 1_000_000,
                ..Default::default()
            },
            db,
        )
    }

    /// Farcaster-epoch seconds for `day` (days since Unix epoch), at noon so
    /// nothing lands on a boundary by accident.
    fn ts_on_day(day: u32) -> u32 {
        let unix_secs = day as u64 * SECONDS_PER_DAY + SECONDS_PER_DAY / 2;
        (unix_secs - crate::core::types::FARCASTER_EPOCH / 1000) as u32
    }

    fn cast(fid: u64, day: u32, parent: Option<crate::proto::cast_add_body::Parent>) -> Message {
        Message {
            data: Some(MessageData {
                fid,
                timestamp: ts_on_day(day),
                r#type: MessageType::CastAdd as i32,
                body: Some(Body::CastAddBody(CastAddBody {
                    parent,
                    ..Default::default()
                })),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    fn reaction(fid: u64, day: u32, target_fid: u64, target_hash: Vec<u8>) -> Message {
        Message {
            data: Some(MessageData {
                fid,
                timestamp: ts_on_day(day),
                r#type: MessageType::ReactionAdd as i32,
                body: Some(Body::ReactionBody(ReactionBody {
                    target: Some(crate::proto::reaction_body::Target::TargetCastId(CastId {
                        fid: target_fid,
                        hash: target_hash,
                    })),
                    ..Default::default()
                })),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    fn link(fid: u64, day: u32, target_fid: u64) -> Message {
        Message {
            data: Some(MessageData {
                fid,
                timestamp: ts_on_day(day),
                r#type: MessageType::LinkAdd as i32,
                body: Some(Body::LinkBody(LinkBody {
                    r#type: "follow".to_string(),
                    target: Some(crate::proto::link_body::Target::TargetFid(target_fid)),
                    ..Default::default()
                })),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    async fn ingest(idx: &DailyStatsIndexer, messages: Vec<Message>) {
        for m in messages {
            idx.process_event(&IndexEvent::message(m, 1, 1))
                .await
                .unwrap();
        }
        idx.flush_all().unwrap();
    }

    #[test]
    fn fidset_roundtrips_and_intersects() {
        let a: Vec<u64> = vec![1, 2, 3, 500, 100_000, 1_500_000];
        let encoded = fidset::encode(&a);
        assert_eq!(fidset::decode(&encoded), a);

        // Delta+varint must actually be compact: 6 fids spanning 1.5M in well
        // under the 48 bytes a raw u64 array would need.
        assert!(encoded.len() < 20, "encoded to {} bytes", encoded.len());

        let b: Vec<u64> = vec![2, 3, 4, 100_000];
        assert_eq!(fidset::intersection_len(&a, &b), 3);
        assert_eq!(fidset::intersection_len(&a, &[]), 0);
        assert_eq!(fidset::decode(&fidset::encode(&[])), Vec::<u64>::new());
    }

    #[test]
    fn hll_estimates_within_error_bound() {
        // p=14 gives ~0.81% standard error; allow 3 sigma before failing so
        // this does not flake, while still catching a broken estimator.
        for &n in &[1000u64, 50_000, 500_000] {
            let mut regs = vec![0u8; hll::REGISTERS];
            for i in 0..n {
                hll::insert(&mut regs, &i.to_be_bytes());
            }
            let est = hll::estimate(&regs) as f64;
            let err = (est - n as f64).abs() / n as f64;
            assert!(err < 0.025, "n={} est={} err={:.4}", n, est, err);
        }
        // Empty sketch must read as zero, not as a linear-counting artifact.
        assert_eq!(hll::estimate(&vec![0u8; hll::REGISTERS]), 0);
    }

    #[test]
    fn hll_merge_is_union_not_sum() {
        let mut a = vec![0u8; hll::REGISTERS];
        let mut b = vec![0u8; hll::REGISTERS];
        for i in 0..10_000u64 {
            hll::insert(&mut a, &i.to_be_bytes());
            // Fully overlapping input: the merged estimate must stay ~10k.
            hll::insert(&mut b, &i.to_be_bytes());
        }
        hll::merge_into(&mut a, &b);
        let est = hll::estimate(&a) as f64;
        assert!((est - 10_000.0).abs() / 10_000.0 < 0.025, "est={}", est);
    }

    #[test]
    fn date_helpers_roundtrip() {
        let day = date_string_to_day("2026-08-09").unwrap();
        assert_eq!(day_to_date_string(day), "2026-08-09");
        assert_eq!(date_string_to_day("not-a-date"), None);
        // Epoch day 0.
        assert_eq!(day_to_date_string(0), "1970-01-01");
    }

    #[tokio::test]
    async fn counts_casts_reactions_links_per_day() {
        let db = make_test_db();
        let idx = indexer(db);
        let d = date_string_to_day("2026-08-01").unwrap();

        ingest(
            &idx,
            vec![
                // Two top-level casts with no parent_url, one with, one reply.
                cast(1, d, None),
                cast(2, d, None),
                cast(
                    3,
                    d,
                    Some(crate::proto::cast_add_body::Parent::ParentUrl(
                        "https://example.com".to_string(),
                    )),
                ),
                cast(
                    1,
                    d,
                    Some(crate::proto::cast_add_body::Parent::ParentCastId(CastId {
                        fid: 9,
                        hash: vec![0xaa; 20],
                    })),
                ),
                reaction(4, d, 1, vec![0xbb; 20]),
                reaction(5, d, 1, vec![0xbb; 20]),
                link(6, d, 7),
            ],
        )
        .await;

        let rows = idx.range(d, d).unwrap();
        assert_eq!(rows.len(), 1);
        let r = &rows[0];
        assert_eq!(r.date, "2026-08-01");
        assert_eq!(r.casts.total, 4);
        // fids 1, 2, 3 authored (1 twice).
        assert_eq!(r.casts.unique_authors, 3);
        assert_eq!(r.casts.top_level_with_parent_url, 1);
        assert_eq!(r.casts.top_level_without_parent_url, 2);
        assert_eq!(r.casts.fip2_ratio, Some(0.5));
        assert_eq!(r.casts.unique_parent_hashes_estimated, 1);

        assert_eq!(r.reactions.total, 2);
        assert_eq!(r.reactions.unique_actors, 2);
        assert_eq!(r.reactions.unique_target_fids, 1);
        assert_eq!(r.reactions.unique_target_hashes_estimated, 1);

        assert_eq!(r.links.total, 1);
        assert_eq!(r.links.unique_actors, 1);
        assert_eq!(r.links.unique_target_fids, 1);
    }

    #[tokio::test]
    async fn fip2_ratio_is_null_not_infinity_when_denominator_zero() {
        let db = make_test_db();
        let idx = indexer(db);
        let d = date_string_to_day("2026-08-01").unwrap();
        ingest(
            &idx,
            vec![cast(
                1,
                d,
                Some(crate::proto::cast_add_body::Parent::ParentUrl(
                    "https://example.com".to_string(),
                )),
            )],
        )
        .await;

        let rows = idx.range(d, d).unwrap();
        assert_eq!(rows[0].casts.top_level_without_parent_url, 0);
        // The SQL returned 1e308 here, which is not valid JSON and plots as a
        // real spike. Must be null.
        assert_eq!(rows[0].casts.fip2_ratio, None);
        let json = serde_json::to_string(&rows[0]).unwrap();
        assert!(json.contains("\"fip2_ratio\":null"), "{}", json);
    }

    #[tokio::test]
    async fn retention_counts_exactly_n_days_earlier() {
        let db = make_test_db();
        let idx = indexer(db);
        let base = date_string_to_day("2026-08-01").unwrap();

        // fid 1 casts on base-7 and base  -> counts toward d7 on `base`.
        // fid 2 casts on base-20 and base -> counts toward d20.
        // fid 3 casts on base-6 and base  -> counts toward NOTHING (the window
        //   is "exactly N days earlier", not "within N days").
        // fid 4 casts only on base        -> counts toward nothing.
        ingest(
            &idx,
            vec![
                cast(1, base - 7, None),
                cast(2, base - 20, None),
                cast(3, base - 6, None),
                cast(1, base, None),
                cast(2, base, None),
                cast(3, base, None),
                cast(4, base, None),
            ],
        )
        .await;

        let rows = idx.range(base, base).unwrap();
        assert_eq!(rows[0].retention.d7, 1, "only fid 1");
        assert_eq!(rows[0].retention.d20, 1, "only fid 2");
        assert_eq!(rows[0].retention.d30, 0);
    }

    #[tokio::test]
    async fn series_is_dense_and_moving_average_uses_calendar_days() {
        let db = make_test_db();
        let idx = indexer(db);
        let start = date_string_to_day("2026-08-01").unwrap();

        // Activity on the first and last day of a 10-day span only. The eight
        // days between must still appear, as explicit zeros.
        ingest(&idx, vec![cast(1, start, None), cast(2, start + 9, None)]).await;

        let rows = idx.range(start, start + 9).unwrap();
        assert_eq!(rows.len(), 10, "series must be dense");
        assert_eq!(rows[3].casts.total, 0);
        assert_eq!(rows[3].casts.unique_authors, 0);
        assert_eq!(rows[3].date, "2026-08-04");

        // Day 9 has 1 unique author; the six preceding calendar days have 0, so
        // the trailing 7-day mean floors to 0 -- NOT 1, which is what a
        // row-counting window would have produced by skipping the empty days.
        assert_eq!(rows[9].casts.unique_authors, 1);
        assert_eq!(rows[9].casts.unique_authors_7d_avg, Some(0));
    }

    #[tokio::test]
    async fn accumulates_across_flushes_without_double_counting_sets() {
        let db = make_test_db();
        let idx = indexer(db);
        let d = date_string_to_day("2026-08-01").unwrap();

        // Same fid casting in two separate flush cycles: counters add, the
        // unique-author set does not.
        ingest(&idx, vec![cast(1, d, None)]).await;
        ingest(&idx, vec![cast(1, d, None)]).await;

        let rows = idx.range(d, d).unwrap();
        assert_eq!(rows[0].casts.total, 2);
        assert_eq!(rows[0].casts.unique_authors, 1);
    }

    #[tokio::test]
    async fn backfilled_days_are_marked_reconstructed_live_days_are_not() {
        let db = make_test_db();
        let idx = indexer(db);
        let old_day = date_string_to_day("2026-03-01").unwrap();
        let live_day = date_string_to_day("2026-08-01").unwrap();

        // Backfill path: process_batch, no live marking.
        idx.set_backfill_mode(true);
        idx.process_batch(&[IndexEvent::messages(vec![cast(1, old_day, None)], 1, 0)])
            .await
            .unwrap();
        idx.set_backfill_mode(false);
        idx.flush_all().unwrap();

        // Live path: sets the watermark.
        ingest(&idx, vec![cast(2, live_day, None)]).await;

        let old_rows = idx.range(old_day, old_day).unwrap();
        assert!(
            old_rows[0].reconstructed,
            "a day before first live traffic is a store-walk reconstruction"
        );
        let live_rows = idx.range(live_day, live_day).unwrap();
        assert!(!live_rows[0].reconstructed);
    }

    #[tokio::test]
    async fn watermark_survives_reload_and_only_moves_earlier() {
        let db = make_test_db();
        let later = date_string_to_day("2026-08-10").unwrap();
        let earlier = date_string_to_day("2026-08-01").unwrap();
        {
            let idx = indexer(db.clone());
            ingest(&idx, vec![cast(1, later, None)]).await;
            // An earlier live day must pull the watermark back...
            ingest(&idx, vec![cast(1, earlier, None)]).await;
            // ...but a later one must not push it forward, or previously
            // observed days would start reporting as reconstructions.
            ingest(&idx, vec![cast(1, later, None)]).await;
        }
        // Reload from disk: the watermark is persisted, not in-memory only.
        let idx = indexer(db);
        let rows = idx.range(earlier, later).unwrap();
        assert!(!rows[0].reconstructed, "earliest live day");
        assert!(!rows.last().unwrap().reconstructed);
    }

    #[tokio::test]
    async fn backfill_mode_holds_all_days_until_budget() {
        let db = make_test_db();
        let idx = DailyStatsIndexer::new(
            DailyStatsConfig {
                enabled: true,
                backfill_max_pending_fids: 1_000_000,
                ..Default::default()
            },
            db,
        );
        let d0 = date_string_to_day("2026-03-01").unwrap();
        idx.set_backfill_mode(true);
        // fid-major order: one fid contributing to many scattered days, which
        // is what the store walk produces and what would thrash the live
        // day-rollover flush rule.
        for day_offset in [0u32, 40, 5, 120, 12] {
            idx.process_batch(&[IndexEvent::messages(
                vec![cast(7, d0 + day_offset, None)],
                1,
                0,
            )])
            .await
            .unwrap();
        }
        // Nothing should have been written yet — budget not reached.
        assert_eq!(idx.range(d0, d0).unwrap()[0].casts.total, 0);
        idx.set_backfill_mode(false);
        idx.flush_all().unwrap();

        for day_offset in [0u32, 40, 5, 120, 12] {
            let rows = idx.range(d0 + day_offset, d0 + day_offset).unwrap();
            assert_eq!(rows[0].casts.total, 1, "day offset {}", day_offset);
            assert_eq!(rows[0].casts.unique_authors, 1);
        }
    }

    #[tokio::test]
    async fn backfill_progress_reports_shards_coverage_and_completion() {
        let db = make_test_db();
        let idx = indexer(db.clone());

        // Nothing has run yet: not started, and crucially NOT reported as
        // complete just because no shard has failed.
        let p = idx.backfill_progress();
        assert!(!p.started);
        assert!(!p.complete, "an unstarted walk must not report complete");
        assert_eq!(p.days_with_data, 0);
        assert_eq!(p.earliest_day, None);

        // Shard 1 mid-walk, shard 2 untouched.
        idx.record_backfill_cursor(1, 4242);
        let p = idx.backfill_progress();
        assert!(p.started);
        assert!(!p.complete);
        assert_eq!(p.shards.len(), 1);
        assert_eq!(p.shards[0].shard_id, 1);
        assert_eq!(p.shards[0].cursor_fid, Some(4242));
        assert!(!p.shards[0].complete);

        // Second shard appears, still incomplete overall.
        idx.record_backfill_cursor(2, 99);
        assert!(!idx.backfill_progress().complete);

        // Both finish.
        idx.record_backfill_cursor(1, u64::MAX);
        idx.record_backfill_cursor(2, u64::MAX);
        let p = idx.backfill_progress();
        assert!(p.complete);
        assert_eq!(p.shards.len(), 2);
        assert_eq!(p.shards[0].cursor_fid, None);

        // Coverage is derived from stored days, and survives a reload.
        ingest(
            &idx,
            vec![
                cast(1, date_string_to_day("2026-03-01").unwrap(), None),
                cast(1, date_string_to_day("2026-08-01").unwrap(), None),
            ],
        )
        .await;
        let reloaded = indexer(db);
        let p = reloaded.backfill_progress();
        assert_eq!(p.days_with_data, 2);
        assert_eq!(p.earliest_day.as_deref(), Some("2026-03-01"));
        assert_eq!(p.latest_day.as_deref(), Some("2026-08-01"));
        assert!(p.complete, "cursors persist across restart");
    }

    #[tokio::test]
    async fn stats_reports_folded_messages_and_derived_completion() {
        let db = make_test_db();
        let idx = indexer(db);
        let d = date_string_to_day("2026-08-01").unwrap();

        ingest(&idx, vec![cast(1, d, None), cast(2, d, None)]).await;
        let st = idx.stats();
        assert_eq!(st.items_indexed, 2, "folded messages, not day-merge writes");
        // The store walk never advances the event-log checkpoint, so completion
        // must come from the cursors instead.
        assert!(!st.backfill_complete);

        idx.record_backfill_cursor(1, u64::MAX);
        assert!(idx.stats().backfill_complete);
    }

    #[tokio::test]
    async fn prune_and_revoke_are_not_counted_as_activity() {
        let db = make_test_db();
        let idx = indexer(db);
        let d = date_string_to_day("2026-08-01").unwrap();
        let msg = cast(1, d, None);

        // The merge is real activity.
        idx.process_event(&IndexEvent::message(msg.clone(), 1, 1))
            .await
            .unwrap();

        // Prune and revoke redeliver the *same* message with its original
        // timestamp. Folding them would inflate this day every time storage
        // limits bite — silently, and forever upward.
        idx.process_event(&IndexEvent::message_of_kind(
            msg.clone(),
            1,
            2,
            MessageEventKind::Prune,
        ))
        .await
        .unwrap();
        idx.process_event(&IndexEvent::message_of_kind(
            msg.clone(),
            1,
            3,
            MessageEventKind::Revoke,
        ))
        .await
        .unwrap();
        idx.flush_all().unwrap();

        let rows = idx.range(d, d).unwrap();
        assert_eq!(rows[0].casts.total, 1, "only the merge counts");
        assert_eq!(rows[0].casts.unique_authors, 1);
    }

    #[tokio::test]
    async fn batched_prune_is_also_ignored() {
        let db = make_test_db();
        let idx = indexer(db);
        let d = date_string_to_day("2026-08-01").unwrap();
        let msgs = vec![cast(1, d, None), cast(2, d, None)];

        idx.process_batch(&[IndexEvent::messages(msgs.clone(), 1, 1)])
            .await
            .unwrap();
        idx.process_batch(&[IndexEvent::MessagesCommitted {
            messages: msgs,
            shard_id: 1,
            block_height: 2,
            kind: MessageEventKind::Prune,
        }])
        .await
        .unwrap();
        idx.flush_all().unwrap();

        assert_eq!(idx.range(d, d).unwrap()[0].casts.total, 2);
    }

    #[tokio::test]
    async fn stale_data_version_wipes_rollups_and_backfill_cursors() {
        let db = make_test_db();
        let d = date_string_to_day("2026-08-01").unwrap();
        {
            let idx = indexer(db.clone());
            ingest(&idx, vec![cast(1, d, None)]).await;
            idx.record_backfill_cursor(1, u64::MAX);
            assert_eq!(idx.range(d, d).unwrap()[0].casts.total, 1);
            assert!(idx.backfill_progress().complete);
        }

        // Simulate an older data version on disk.
        let mut txn = RocksDbTransactionBatch::new();
        txn.put(
            vec![keys::DAILY_STATS_PREFIX, keys::DATA_VERSION],
            1u32.to_be_bytes().to_vec(),
        );
        db.commit(txn).unwrap();

        let reopened = indexer(db.clone());
        assert_eq!(
            reopened.range(d, d).unwrap()[0].casts.total,
            0,
            "rollups written under the old semantics must be discarded"
        );
        let progress = reopened.backfill_progress();
        assert!(
            !progress.started && !progress.complete,
            "cursors must clear too, or the walk reports itself done and never refills"
        );

        // Matching version is a no-op: reopening must not wipe good data.
        ingest(&reopened, vec![cast(1, d, None)]).await;
        drop(reopened);
        let again = indexer(db);
        assert_eq!(again.range(d, d).unwrap()[0].casts.total, 1);
    }

    #[tokio::test]
    async fn current_day_is_flushed_on_the_interval_without_hitting_the_event_threshold() {
        let db = make_test_db();
        // Event/memory thresholds effectively disabled; only the clock can flush.
        let idx = DailyStatsIndexer::new(
            DailyStatsConfig {
                enabled: true,
                flush_every_events: usize::MAX,
                backfill_max_pending_fids: usize::MAX,
                flush_interval_secs: 0,
                ..Default::default()
            },
            db,
        );
        let d = date_string_to_day("2026-08-01").unwrap();

        // A single message, well under any count threshold. With interval 0 the
        // very next maybe_flush must write it — this is what keeps "today" from
        // reading as empty on a quiet node.
        idx.process_event(&IndexEvent::message(cast(1, d, None), 1, 1))
            .await
            .unwrap();

        let rows = idx.range(d, d).unwrap();
        assert_eq!(
            rows[0].casts.total, 1,
            "time-based flush must land the current day without an event-count trip"
        );
    }

    /// Regression guard for the lost-update race between the concurrent backfill
    /// walk and the live path. Both fold into the same accumulator and both
    /// flush; `write_days` reads the stored value, merges, and writes it back, so
    /// without serialization the later commit discards the earlier delta and the
    /// day silently undercounts.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_flushes_do_not_lose_counts() {
        let db = make_test_db();
        // Flush on every single message, from every task, to maximise overlap.
        let idx = Arc::new(DailyStatsIndexer::new(
            DailyStatsConfig {
                enabled: true,
                flush_every_events: 1,
                flush_interval_secs: 0,
                ..Default::default()
            },
            db,
        ));
        let d = date_string_to_day("2026-08-18").unwrap();

        const TASKS: u64 = 4;
        const PER_TASK: u64 = 50;
        let mut handles = Vec::new();
        for t in 0..TASKS {
            let idx = idx.clone();
            handles.push(tokio::spawn(async move {
                for i in 0..PER_TASK {
                    // Distinct fid per task so unique_authors is checkable too.
                    let fid = t + 1;
                    idx.process_event(&IndexEvent::message(cast(fid, d, None), 1, i))
                        .await
                        .unwrap();
                }
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
        idx.flush_all().unwrap();

        let rows = idx.range(d, d).unwrap();
        assert_eq!(
            rows[0].casts.total,
            TASKS * PER_TASK,
            "every folded message must survive concurrent flushes"
        );
        assert_eq!(
            rows[0].casts.unique_authors, TASKS,
            "set members must survive too — the union is read-modify-write as well"
        );
    }

    #[tokio::test]
    async fn rejects_inverted_and_oversized_ranges() {
        let db = make_test_db();
        let idx = indexer(db);
        let d = date_string_to_day("2026-08-01").unwrap();
        assert!(idx.range(d, d - 1).is_err());
        assert!(idx.range(d, d + MAX_RANGE_DAYS).is_err());
        assert!(idx.range(d, d + MAX_RANGE_DAYS - 1).is_ok());
    }
}
