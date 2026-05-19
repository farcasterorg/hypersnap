//! Retro Rewards Finalizer — multi-mutuality allocation
//!
//! End-to-end reproducible retro allocation from hub endpoints. The growth
//! signal is **sustained mutual engagement**, not onboarding-window activity:
//!
//!   growth_score(f) = Σ over u with reciprocal all-time, post-transfer
//!                     engagement:
//!                         mutuality( count(f→u), count(u→f) )
//!                         · credibility(u)
//!   composite(f)    = credibility(f)^k
//!                   · trust(f)^j
//!                   · (engager_entropy(f) · interaction_entropy(f))^p
//!                   · (new_user_engagement_share(f) + ε)^q
//!                   · growth_score(f)^g
//!
//! - `k` (`--credibility-exponent`, default 4.0) compounds the trust
//!   differential. With `k = 1` the trust signal is overwhelmed by raw
//!   volume; raising `k` lets a high-trust account pull ahead of a
//!   high-volume-low-trust account whose mutual partners include lots of
//!   low-trust crediters.
//! - `j` (`--trust-exponent`, default 0.5) restores enough EigenTrust
//!   dynamic range to crush low-trust farms (~30× ratio between
//!   bottom-decile and seed) without over-concentrating the pool in the
//!   top-trust group. Catches the "wide farm" pattern — accounts whose
//!   crediters are many low-trust accounts spread broadly (so entropy
//!   stays high but trust collapses). `j = 0` disables.
//! - `p` (`--ring-symmetry-exponent`, default 3.0) penalizes accounts
//!   whose engagement is concentrated on BOTH sides — the canonical
//!   symmetric-mutual-engagement-ring shape. Real humans with tight
//!   communities have low engager_entropy but healthy
//!   interaction_entropy, so the product stays high; rings have low on
//!   both sides and the product collapses. `p = 0` disables this term.
//! - `q` (`--new-user-share-exponent`, default 0.5) catches the
//!   *zero-share* farm direction that filter 5 misses. New-user share
//!   differs by ~300× between real accounts (~0.5–3%) and "wide farms"
//!   (~0%); also separates legit accounts from established-celebrity
//!   accounts that sit at near-zero new-user engagement.
//! - `g` (`--growth-exponent`, default 0.5) compresses raw growth so a
//!   single hyper-active account can't dominate the pool from volume
//!   alone. Other signals (credibility, trust, entropy, new-user
//!   share) are unaffected; this knob only flattens within-trust-tier
//!   differences. With `g = 1.0` (no compression), growth differences
//!   translate linearly into pool share.
//!
//! `mutuality(a, b)` takes one of five forms (selectable via `--mutuality-modes`),
//! each wrapped in `ln(1 + x)` so per-pair contribution saturates with volume.
//! A ring pair with 1000 interactions contributes `ln(1001) ≈ 6.9`, not 1000,
//! preventing volume-spam rings from dominating score sums.
//!
//! - `min` → `ln(1 + min(a, b))` — strictest; capped at the weaker side.
//! - `geom` → `ln(1 + sqrt(a · b))` — requires both > 0; scales sublinearly.
//! - `harmonic` → `ln(1 + 2ab/(a+b))` — harsh on asymmetry.
//! - `avg` → `ln(1 + (a + b)/2)` (gated on both > 0).
//! - `sum` → `ln(1 + a + b)` (gated on both > 0).
//!
//! Per mode, the pool is renormalized over eligibility-filter survivors; a
//! `final.<mode>.csv` is emitted. A `mutuality_comparison.md` shows the
//! top-20 of each mode side-by-side plus a Spearman rank-correlation matrix
//! so you can see which modes produce materially different rankings.
//!
//! ## Transfer semantics
//!
//! Every engagement metric in this binary excludes events from before
//! **either** party's most recent custody change. Concretely, `count(u→f)`
//! only includes an event at `ts` when `ts > max(u.effective_ts,
//! f.effective_ts)`. This matches the "transfer resets score" rule: a
//! newly-transferred FID neither carries forward nor counts engagement
//! attributable to the previous custodian. The same filter applies to the
//! metrics consumed by filters 2–6 (engager_counts, replies_received,
//! total_casts counted toward the current custodian's activity, etc.).
//!
//! Filter 5 (new-user onboarding share) uses the *engager's* custody-reset
//! "first 30 days" — i.e., the 30 days following each engager's
//! effective_ts — not their original registration.
//!
//! ## Trust score (EigenTrust)
//!
//! `credibility(f)` uses an EigenTrust-derived `trust_score` in place of the
//! earlier flat `0.5` placeholder. EigenTrust propagates trust mass from a
//! **seed cohort** through the post-transfer follow graph:
//!
//! - Seed criterion: `fid ≤ --seed-max-fid` (default 50,000). Targets the
//!   first hand-onboarded users as trust anchors. No timestamp criteria —
//!   the OP Mainnet contract migration reset effective-age signals for
//!   older accounts, so FID number is the reliable anchor.
//! - `trust_score(f) = clamp( eigentrust(f) / p99(eigentrust) × age_factor(f),
//!                            0, 1 )`
//!
//! Sockpuppets cannot self-bootstrap high trust because they have no inbound
//! follow edges from the seed cohort (transitively). Real users do.
//!
//! ## Threshold calibration (separate, broader cohort)
//!
//! Filter thresholds are calibrated against a **calibration cohort** —
//! broader than the seed cohort — representing typical active accounts:
//!
//! - Calibration criterion: `total_casts ≥ --calibration-min-casts` (10)
//!   AND `active_days ≥ --calibration-min-active-days` (5). Activity-based
//!   only; no timestamp component (see migration note above).
//!
//! Using the seed cohort alone for threshold calibration is too strict
//! (seeds are the top of the graph; typical users sit well below). This
//! cohort catches any account with nontrivial sustained activity.
//!
//! ## Eligibility filters (applied identically across all mutuality modes)
//!
//! 0. App detection — `signer_authorizations ≥ --app-threshold`.
//! 1. Minimum activity — `total_casts > 0`.
//! 2. Received engagement — `unique_engagers ≥ --min-engagers`.
//! 3. Engager diversity — Shannon entropy ≥ seed-cohort percentile threshold.
//! 4. Engagement per cast (optional via `--strict`).
//! 5. New-user engagement share — `< seed-cohort upper-tail threshold`.
//! 6. Replies received per cast — `≥ seed-cohort percentile threshold`.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use alloy_primitives::{address, U256};
use alloy_provider::{Provider, ProviderBuilder};
use alloy_rpc_types::{BlockNumberOrTag, BlockTransactionsKind, Filter};
use alloy_sol_types::{sol, SolEvent, SolType};
use clap::Parser;
use indicatif::{ProgressBar, ProgressStyle};
use serde::{Deserialize, Serialize};

sol! {
    /// Subset of the Farcaster IdRegistry contract — just the Recover
    /// event we need to detect forced recoveries during the bug window.
    #[allow(missing_docs)]
    event Recover(address indexed from, address indexed to, uint256 indexed id);
}

const ID_REGISTRY_ADDRESS_OP: alloy_primitives::Address =
    address!("00000000Fc6c5F01Fc30151999387Bb99A9f489b");
/// Per-batch block range for `eth_getLogs`. Alchemy and most major RPCs
/// support 10K block ranges; we use 8K to leave headroom.
const RECOVERY_BLOCK_BATCH: u64 = 8_000;

// ---- Constants ----

const NUM_SHARDS: u32 = 2;
const BATCH_SIZE: usize = 100;
const RETROACTIVE_POOL: f64 = 200_000_000.0;

const THIRTY_DAYS_SECS: u64 = 30 * 24 * 3600;
const SIX_MONTHS_SECS: f64 = 15_552_000.0;
const FARCASTER_EPOCH: u64 = 1_609_459_200;
const AUTOFOLLOW_WINDOW_SECS: u64 = 60;

const W_AGE: f64 = 0.25;
const W_TRUST: f64 = 0.35;
const W_ENTROPY: f64 = 0.20;
const W_STAKE: f64 = 0.10;
const W_DIVERSITY: f64 = 0.10;

// EigenTrust parameters (PoQ Section 2 Step 2).
const POQ_DAMPING_FACTOR: f64 = 0.85;
const POQ_MAX_ITERATIONS: usize = 50;
const POQ_CONVERGENCE_TOLERANCE: f64 = 1e-6;

// ---- Mutuality modes ----

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum MutualityMode {
    Min,
    Geom,
    Harmonic,
    Avg,
    Sum,
}

impl MutualityMode {
    fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "min" => Some(Self::Min),
            "geom" | "geomean" | "geometric" => Some(Self::Geom),
            "harmonic" | "harm" => Some(Self::Harmonic),
            "avg" | "mean" | "average" => Some(Self::Avg),
            "sum" => Some(Self::Sum),
            _ => None,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Min => "min",
            Self::Geom => "geom",
            Self::Harmonic => "harmonic",
            Self::Avg => "avg",
            Self::Sum => "sum",
        }
    }

    /// `mutuality(a, b)`. Returns 0 iff either side is 0. The raw per-mode
    /// aggregate is wrapped in `ln(1 + x)` so per-pair contribution saturates
    /// with volume — a ring pair with 1000 interactions contributes ~ln(1001)
    /// ≈ 6.9, not 1000, preventing volume-spam rings from trivially
    /// out-scoring real relationships.
    fn apply(self, a: f64, b: f64) -> f64 {
        if a <= 0.0 || b <= 0.0 {
            return 0.0;
        }
        let raw = match self {
            Self::Min => a.min(b),
            Self::Geom => (a * b).sqrt(),
            Self::Harmonic => 2.0 * a * b / (a + b),
            Self::Avg => (a + b) / 2.0,
            Self::Sum => a + b,
        };
        (1.0 + raw).ln()
    }
}

// ---- CLI ----

#[derive(Parser)]
#[command(
    name = "retro_rewards_finalize",
    about = "Reproducible retro allocation from hub data, with selectable mutuality aggregation"
)]
struct Cli {
    #[arg(long, default_value = "https://haatz.quilibrium.com")]
    hub_url: String,

    #[arg(long, default_value = "retro_rewards_final")]
    output_dir: String,

    /// Comma-separated list of mutuality modes to evaluate. Each emits its
    /// own `final.<mode>.csv`. Options: min, geom, harmonic, avg, sum.
    /// Default is `harmonic` — penalizes asymmetric volume so a high-volume
    /// account that talks AT a partner who barely reciprocates does not
    /// receive the high-volume credit. Pass multiple modes (e.g.
    /// `min,geom,sum`) to produce side-by-side comparison outputs.
    #[arg(long, default_value = "harmonic")]
    mutuality_modes: String,

    /// Exponent `k` applied to `credibility_weight` in the composite:
    /// `composite(f) = credibility(f)^k · ring_symmetry(f)^p · growth(f)`.
    /// With `k = 1` the trust signal is overwhelmed by raw volume — a
    /// 30× volume gap can only be partly offset by a 0.5 → 0.6
    /// credibility differential. Raising `k` compounds the trust
    /// differential so high-trust accounts pull ahead of high-volume-
    /// low-trust accounts. Default `4.0` was calibrated against the
    /// 429539 vs 2420 case where `k = 1` ranks the high-volume spammy
    /// account 3× above the higher-trust seed account; combined with
    /// the ring-symmetry penalty (`p = 2.0` by default), this flips
    /// the ranking.
    #[arg(long, default_value_t = 4.0)]
    credibility_exponent: f64,

    /// Exponent `p` applied to the ring-symmetry term `engager_entropy
    /// · interaction_entropy` in the composite:
    /// `composite(f) = credibility(f)^k · (engager_entropy ·
    /// interaction_entropy)^p · growth(f)`. Symmetric rings show low
    /// entropy on BOTH sides (concentrated inbound + outbound, because
    /// the same small set of accounts cycles engagement); real humans
    /// with tight communities show concentration on inbound only and
    /// healthy diversity on outbound. Multiplying by the entropy
    /// product penalizes the ring shape harder than `k` alone (which
    /// only discounts the credibility differential, not the
    /// concentration). `p = 0` disables the penalty for back-compat.
    #[arg(long, default_value_t = 3.0)]
    ring_symmetry_exponent: f64,

    /// Exponent `j` applied to `trust_score` in the composite:
    /// `composite(f) = ... · trust(f)^j · ...`. The credibility blend
    /// only weights trust at 0.35× before saturating with age + entropy
    /// + diversity, so a 33× trust gap (e.g. 2420 at 0.245 vs 429539
    /// at 0.0073) collapses to a 16% credibility gap. Multiplying the
    /// composite by `trust^j` restores the natural dynamic range of
    /// EigenTrust and catches the "wide farm" pattern — accounts whose
    /// engagement is broadly distributed across many low-trust
    /// crediters (high entropy, low trust). Ring-symmetry penalty
    /// can't see these because they spread engagement; only the trust
    /// differential exposes them. Default `0.5` (sqrt) preserves enough
    /// EigenTrust dynamic range to crush low-trust farms (~30× ratio
    /// between bottom-decile and seed) without over-concentrating the
    /// pool in the top-trust group. `1.0` is the strict version; `0`
    /// disables.
    #[arg(long, default_value_t = 0.5)]
    trust_exponent: f64,

    /// Exponent `q` applied to `(new_user_engagement_share + ε)` in the
    /// composite. New-user share differs by ~300× between real accounts
    /// (~0.5–3%) and "wide farm" accounts (~0%). The signal is
    /// orthogonal to trust — some high-trust, high-mutual-engagement
    /// accounts still get near-zero new-user engagement (the
    /// established-celebrity pattern, e.g. FID 7251 at trust=0.68 with
    /// 0.065% new-user share). Filter 5 only catches the *high-share*
    /// farm direction (new-account-flooding); this term catches the
    /// *zero-share* direction. `q = 0` disables.
    #[arg(long, default_value_t = 0.5)]
    new_user_share_exponent: f64,

    /// Smoothing constant `ε` added to `new_user_engagement_share`
    /// before exponentiation. Without it, any literal-zero share zeros
    /// out the composite. Default `0.001` means a 0%-share account
    /// gets `0.001^q` (~`0.0316` at `q=0.5`) vs `~0.13` for a 1%-share
    /// account — about 4× ratio. Lower ε deepens the penalty.
    #[arg(long, default_value_t = 0.001)]
    new_user_share_smoothing: f64,

    /// Exponent `g` applied to raw `growth_score` before composing.
    /// `growth^g` compresses the long tail at the top so a single
    /// hyper-active account can't dominate the pool from raw volume
    /// alone. With `g = 1.0` (no compression), growth differences
    /// translate linearly into pool share — a 10× growth gap becomes
    /// a 10× pool gap. With `g = 0.5` (sqrt) the same 10× gap
    /// compresses to ~3.2×. All other signals (credibility, trust,
    /// entropy, new-user share) are unaffected; this knob only
    /// flattens within-trust-tier differences. Default `0.5`.
    #[arg(long, default_value_t = 0.5)]
    growth_exponent: f64,

    #[arg(long, default_value_t = 250)]
    app_threshold: u32,

    #[arg(long, default_value_t = 3)]
    min_engagers: u32,

    /// EigenTrust seed: all FIDs with `fid ≤ --seed-max-fid` qualify as
    /// trust anchors. Default 50,000 — targets the first hand-onboarded
    /// users. No timestamp dependency (OP Mainnet migration reset the
    /// effective-age signal; FID number is unaffected).
    #[arg(long, default_value_t = 50_000)]
    seed_max_fid: u64,

    /// Filter threshold calibration cohort: minimum post-transfer cast count.
    #[arg(long, default_value_t = 10)]
    calibration_min_casts: u32,

    /// Filter threshold calibration cohort: minimum distinct active days.
    #[arg(long, default_value_t = 5)]
    calibration_min_active_days: u32,

    #[arg(long, default_value_t = 0.10)]
    threshold_percentile: f64,

    /// Absolute floor for filter 5 (`new_user_engagement_share`).
    /// FIDs whose share is below this floor pass filter 5 regardless of
    /// where they sit in the cohort percentile distribution. Without
    /// this, the percentile gate catches legitimately popular accounts
    /// whose absolute share is small (e.g. 3%) but happens to fall in
    /// the cohort top 10%.
    #[arg(long, default_value_t = 0.10)]
    new_user_share_absolute_floor: f64,

    /// Absolute floor for filter 3, applied to BOTH `engager_entropy`
    /// and `interaction_entropy`. FIDs that clear the floor on both
    /// metrics pass filter 3 even if their `engager_entropy` is below
    /// the cohort percentile cutoff. Real humans with tight communities
    /// have naturally low `engager_entropy` but healthy
    /// `interaction_entropy`; one-sided rings show low entropy on both
    /// sides and still fail. Combined with the `is_seed` bypass, this
    /// catches the false-positive pattern (e.g. FID 15466) without
    /// admitting clear ring patterns (e.g. FID 460451).
    #[arg(long, default_value_t = 0.60)]
    engager_entropy_absolute_floor: f64,

    #[arg(long)]
    strict: bool,

    /// Optimism RPC URL for fetching `Recover` events from the
    /// Farcaster IdRegistry contract. When set, the retro tool
    /// detects forced-recovery transfers (the user kept the same FID
    /// via the recovery method, not a real ownership change) and
    /// preserves the original `effective_ts` for affected FIDs.
    /// Empty = skip the correction (default).
    ///
    /// Retro-only: making this a forward rule would create a
    /// gameable "set recovery to my other wallet, recover, reset
    /// crediting age" exploit. The bug window is bounded; the
    /// correction is a one-shot historical reconciliation.
    #[arg(long, default_value = "")]
    id_registry_rpc_url: String,

    /// Block range bounds for the recovery fetch. Default
    /// `recovery_start_block = 0` triggers auto-detection of the
    /// IdRegistry deployment block via binary search on eth_getCode
    /// (~30 RPC calls). Override only if you want to *narrow* the
    /// scan to the bug window — pass the snapchain timestamp converted
    /// to an OP block number.
    #[arg(long, default_value_t = 0)]
    recovery_start_block: u64,
    #[arg(long, default_value_t = u64::MAX)]
    recovery_end_block: u64,

    /// Run the recovery fetch and print a summary, then exit. Useful
    /// for verifying the RPC + recovery detection are wired correctly
    /// before kicking off the full (expensive) retro evaluation.
    #[arg(long, default_value_t = false)]
    verify_recoveries_only: bool,

    /// Optional path to a RocksDB-backed cache for batch hub responses
    /// (id-registrations, signers, following, reactions, cast-bodies).
    /// Each FID's per-endpoint response is stored under
    /// `<endpoint_byte><fid_BE>` so subsequent runs can replay from disk
    /// instead of re-fetching from the hub. Empty = disabled.
    /// Re-running the same eval with different scoring exponents but
    /// the same hub URL becomes near-instant (no network) once the
    /// cache is populated. Wipe the directory to force a fresh fetch.
    #[arg(long, default_value = "")]
    hub_cache_dir: String,
}

// ---- Batch response types ----

#[derive(Debug, Deserialize)]
struct FidsResponse {
    fids: Vec<u64>,
    #[serde(rename = "nextPageToken")]
    next_page_token: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
struct BatchSignerEntry {
    metadata: String,
    metadata_type: u32,
}

#[derive(Debug, Deserialize, Serialize)]
struct BatchIdRegEntry {
    block_timestamp: u64,
    event_type: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct BatchFollowEntry {
    fid: u64,
    followed_at: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
struct BatchReactionEntry {
    target_fid: u64,
    timestamp: u32,
}

#[derive(Debug, Deserialize, Serialize)]
struct BatchCastBody {
    #[allow(dead_code)]
    hash: Option<String>,
    #[allow(dead_code)]
    text: Option<String>,
    parent_fid: Option<u64>,
    #[allow(dead_code)]
    parent_hash: Option<String>,
    #[serde(default)]
    mentions: Vec<u64>,
    #[allow(dead_code)]
    #[serde(default)]
    embeds: Vec<serde_json::Value>,
    timestamp: u32,
}

alloy_sol_types::sol! {
    struct SignedKeyRequestMetadata {
        uint256 requestFid;
        address requestSigner;
        bytes signature;
        uint256 deadline;
    }
}

// ---- FidMetrics ----

#[derive(Default)]
struct FidMetrics {
    reg_ts: Option<u64>,
    effective_ts: Option<u64>,
    age_factor: f64,

    // Credibility inputs (post-transfer)
    interaction_entropy: f64,
    client_diversity: f64,
    /// EigenTrust-derived per-FID trust score ∈ [0, 1]. Replaces the flat
    /// `TRUST_PLACEHOLDER` from earlier versions. Seeded on PoQ-qualifying
    /// accounts (effective age + posting history criteria).
    trust_score: f64,
    /// Raw EigenTrust value pre-normalization, retained for diagnostics.
    eigentrust_raw: f64,
    credibility_weight: f64,

    /// True if this FID meets the PoQ seed criterion (effective age
    /// ≥ seed_min_age_days AND ≥ seed_min_casts AND ≥ seed_min_active_days).
    /// Used both as EigenTrust seed mass and as the active cohort for
    /// filter-threshold calibration.
    is_seed: bool,

    // Filter 0 — reverse-indexed from others' signer metadata
    signer_authorizations: u32,

    // Filter 1 — post-transfer cast count
    total_casts: u32,

    /// Count of distinct days with at least one post-transfer cast.
    active_days: u32,
    /// Transient set used during Phase 2b to count distinct days.
    active_day_set: HashSet<u64>,

    // Filters 2–4 — inbound engagement (post-transfer)
    engager_counts: HashMap<u64, u32>,
    unique_engagers: u32,
    engager_entropy: f64,
    engagement_per_cast: f64,

    // Filter 5 — engagement received from others' effective-30-day onboarding
    new_user_engagement_count: u32,
    total_engagement_count: u32,
    new_user_engagement_share: f64,

    // Filter 6 — direct replies to this FID's casts (post-transfer)
    replies_received: u32,
    replies_per_cast: f64,

    // Growth input — all-time post-transfer engagement by this FID to others
    all_time_engagement: HashMap<u64, u32>,

    // Helper for Filter 5 — this FID's outbound during THEIR own
    // first 30 days post-transfer
    outbound_first_30d: HashMap<u64, u32>,

    // Per-mode outputs
    growth_by_mode: HashMap<MutualityMode, f64>,
    composite_by_mode: HashMap<MutualityMode, f64>,
    final_tokens_by_mode: HashMap<MutualityMode, f64>,

    // Filter results (shared across modes)
    filter_0_pass: bool,
    filter_1_pass: bool,
    filter_2_pass: bool,
    filter_3_pass: bool,
    filter_4_pass: bool,
    filter_5_pass: bool,
    filter_6_pass: bool,
    eligible: bool,
    fail_reason: String,
}

// ---- HubClient ----

struct HubClient {
    client: reqwest::Client,
    base_url: String,
    /// Per-endpoint counters of FIDs whose data we permanently failed to
    /// fetch (after retries + chunk-splitting). Reported at end-of-run so
    /// the operator can decide whether to trust the outputs.
    failed_id_registrations: AtomicU64,
    failed_signers: AtomicU64,
    failed_following: AtomicU64,
    failed_reactions: AtomicU64,
    failed_cast_bodies: AtomicU64,
    /// Optional disk cache for batch responses keyed per-FID per-endpoint.
    /// `None` if `--hub-cache-dir` was empty. When set, every batch call
    /// checks the cache first and only fetches the FIDs not already on
    /// disk; new fetches are written back so subsequent re-runs become
    /// near-instant. Wipe the directory to force a refresh.
    cache: Option<rocksdb::DB>,
    cache_hits: AtomicU64,
    cache_misses: AtomicU64,
}

/// Single-byte tag identifying the endpoint within the shared cache DB.
/// Picked from a tiny enumeration so each endpoint's keyspace is disjoint
/// even though all five share the same database.
fn endpoint_cache_tag(endpoint: &str) -> Option<u8> {
    match endpoint {
        "id-registrations" => Some(0x01),
        "signers" => Some(0x02),
        "following" => Some(0x03),
        "reactions" => Some(0x04),
        "cast-bodies" => Some(0x05),
        _ => None,
    }
}

fn cache_key(tag: u8, fid: u64) -> [u8; 9] {
    let mut k = [0u8; 9];
    k[0] = tag;
    k[1..].copy_from_slice(&fid.to_be_bytes());
    k
}

impl HubClient {
    fn new_with_cache(base_url: &str, cache_dir: Option<&Path>) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(120))
            .build()
            .expect("failed to build HTTP client");
        let cache = cache_dir.map(|p| {
            let mut opts = rocksdb::Options::default();
            opts.create_if_missing(true);
            // Heavy sequential write workload during initial population
            // and heavy point-read workload during hits — defaults are
            // fine, but wider write_buffer helps the populate path.
            opts.set_write_buffer_size(64 * 1024 * 1024);
            rocksdb::DB::open(&opts, p).expect("failed to open hub cache DB")
        });
        if cache.is_some() {
            eprintln!("Hub cache enabled at {}", cache_dir.unwrap().display());
        }
        Self {
            client,
            base_url: base_url.trim_end_matches('/').to_string(),
            failed_id_registrations: AtomicU64::new(0),
            failed_signers: AtomicU64::new(0),
            failed_following: AtomicU64::new(0),
            failed_reactions: AtomicU64::new(0),
            failed_cast_bodies: AtomicU64::new(0),
            cache,
            cache_hits: AtomicU64::new(0),
            cache_misses: AtomicU64::new(0),
        }
    }

    /// Print per-endpoint summary of FIDs whose data could not be fetched
    /// after retries + chunk-splitting. Non-zero values mean the run's
    /// downstream metrics are silently incomplete for those FIDs.
    fn report_fetch_failures(&self) {
        if self.cache.is_some() {
            let hits = self.cache_hits.load(Ordering::Relaxed);
            let misses = self.cache_misses.load(Ordering::Relaxed);
            let total = hits + misses;
            let pct = if total > 0 {
                (hits as f64 / total as f64) * 100.0
            } else {
                0.0
            };
            eprintln!(
                "\nHub cache: {} hits, {} misses ({:.1}% hit rate)",
                hits, misses, pct
            );
        }
        let any = [
            ("id-registrations", &self.failed_id_registrations),
            ("signers", &self.failed_signers),
            ("following", &self.failed_following),
            ("reactions", &self.failed_reactions),
            ("cast-bodies", &self.failed_cast_bodies),
        ];
        let mut total = 0u64;
        for (_, c) in &any {
            total += c.load(Ordering::Relaxed);
        }
        if total == 0 {
            eprintln!("Fetch reliability: 0 permanently-failed FIDs across all endpoints.");
            return;
        }
        eprintln!("Fetch reliability: permanently-failed FIDs (after retries + chunk split):");
        for (name, c) in &any {
            let n = c.load(Ordering::Relaxed);
            if n > 0 {
                eprintln!("  {}: {}", name, n);
            }
        }
    }

    async fn get_fids(
        &self,
        shard_id: u32,
        page_token: Option<&str>,
    ) -> Result<FidsResponse, reqwest::Error> {
        let mut url = format!(
            "{}/v1/fids?shard_id={}&page_size=1000",
            self.base_url, shard_id
        );
        if let Some(t) = page_token {
            url.push_str(&format!("&page_token={}", urlencoding::encode(t)));
        }
        self.client.get(&url).send().await?.json().await
    }

    async fn batch_post<T: for<'de> Deserialize<'de>>(
        &self,
        endpoint: &str,
        fids: &[u64],
    ) -> Result<HashMap<String, Vec<T>>, String> {
        let url = format!("{}/v2/farcaster/batch/{}", self.base_url, endpoint);
        let body = serde_json::json!({ "fids": fids });
        let resp = self
            .client
            .post(&url)
            .json(&body)
            .send()
            .await
            .map_err(|e| format!("HTTP error: {}", e))?;
        resp.json()
            .await
            .map_err(|e| format!("JSON parse error: {}", e))
    }

    /// Resilient wrapper around `batch_post`. Cache-aware: when
    /// `--hub-cache-dir` is set, FIDs already on disk are returned from
    /// the cache and only the misses go to the network. Retries with
    /// exponential backoff, then on persistent failure splits the chunk
    /// in half and recurses, so a single poisoned FID can't take down a
    /// 1000-FID batch. Single-FID chunks that still fail get counted in
    /// `counter` and skipped — the caller sees an empty entry for that
    /// FID, but the count is reported at end of run so the operator
    /// knows the dataset has holes. Successful fetches are written back
    /// to the cache for the next run.
    async fn batch_post_resilient<T: for<'de> Deserialize<'de> + Serialize + Send>(
        &self,
        endpoint: &str,
        counter: &AtomicU64,
        fids: &[u64],
    ) -> HashMap<u64, Vec<T>> {
        let cache_tag = endpoint_cache_tag(endpoint);
        let mut result: HashMap<u64, Vec<T>> = HashMap::new();

        // Cache fast-path: pull what's already on disk, only fetch the
        // misses. Corrupt cache entries (deserialization failure) are
        // treated as misses and overwritten on the next successful
        // fetch.
        let fids_to_fetch: Vec<u64> =
            if let (Some(cache), Some(tag)) = (self.cache.as_ref(), cache_tag) {
                let mut to_fetch = Vec::new();
                for &fid in fids {
                    let key = cache_key(tag, fid);
                    match cache.get(key) {
                        Ok(Some(bytes)) => match serde_json::from_slice::<Vec<T>>(&bytes) {
                            Ok(v) => {
                                result.insert(fid, v);
                                self.cache_hits.fetch_add(1, Ordering::Relaxed);
                            }
                            Err(_) => {
                                to_fetch.push(fid);
                                self.cache_misses.fetch_add(1, Ordering::Relaxed);
                            }
                        },
                        _ => {
                            to_fetch.push(fid);
                            self.cache_misses.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
                to_fetch
            } else {
                fids.to_vec()
            };

        if fids_to_fetch.is_empty() {
            return result;
        }

        let fetched = self
            .batch_post_inner::<T>(endpoint, counter, &fids_to_fetch)
            .await;

        // Cache writeback: only for FIDs that appeared in the
        // response. FIDs missing from `fetched` are either no-data
        // (hub returned nothing for them) or in a permanently-failed
        // chunk; either way we leave them uncached so a subsequent run
        // can re-attempt.
        if let (Some(cache), Some(tag)) = (self.cache.as_ref(), cache_tag) {
            for (&fid, entries) in &fetched {
                if let Ok(bytes) = serde_json::to_vec(entries) {
                    let _ = cache.put(cache_key(tag, fid), bytes);
                }
            }
        }

        result.extend(fetched);
        result
    }

    /// Inner: pure retry + chunk-split, no cache. The cache layer wraps
    /// this in `batch_post_resilient`. Async recursion needs `Box::pin`
    /// because rustc can't size a self-referential future.
    fn batch_post_inner<'a, T: for<'de> Deserialize<'de> + Send + 'a>(
        &'a self,
        endpoint: &'a str,
        counter: &'a AtomicU64,
        fids: &'a [u64],
    ) -> Pin<Box<dyn Future<Output = HashMap<u64, Vec<T>>> + Send + 'a>> {
        Box::pin(async move {
            const MAX_ATTEMPTS: u32 = 5;
            let mut delay_ms: u64 = 250;
            let mut last_err = String::new();
            for attempt in 1..=MAX_ATTEMPTS {
                match self.batch_post::<T>(endpoint, fids).await {
                    Ok(m) => return parse_batch_map(m),
                    Err(e) => {
                        last_err = e;
                        if attempt < MAX_ATTEMPTS {
                            tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                            delay_ms = delay_ms.saturating_mul(2).min(8_000);
                        }
                    }
                }
            }
            if fids.len() > 1 {
                let mid = fids.len() / 2;
                eprintln!(
                    "  batch {} failed after {} retries on chunk size {} ({}); splitting {}+{}",
                    endpoint,
                    MAX_ATTEMPTS,
                    fids.len(),
                    last_err,
                    mid,
                    fids.len() - mid,
                );
                let (left, right) = fids.split_at(mid);
                let mut combined = self.batch_post_inner::<T>(endpoint, counter, left).await;
                let r = self.batch_post_inner::<T>(endpoint, counter, right).await;
                combined.extend(r);
                return combined;
            }
            counter.fetch_add(1, Ordering::Relaxed);
            eprintln!(
                "  batch {} permanently failed for FID {}: {}",
                endpoint, fids[0], last_err
            );
            HashMap::new()
        })
    }

    async fn batch_id_registrations(&self, fids: &[u64]) -> HashMap<u64, Vec<BatchIdRegEntry>> {
        self.batch_post_resilient::<BatchIdRegEntry>(
            "id-registrations",
            &self.failed_id_registrations,
            fids,
        )
        .await
    }

    async fn batch_signers(&self, fids: &[u64]) -> HashMap<u64, Vec<BatchSignerEntry>> {
        self.batch_post_resilient::<BatchSignerEntry>("signers", &self.failed_signers, fids)
            .await
    }

    async fn batch_following(&self, fids: &[u64]) -> HashMap<u64, Vec<BatchFollowEntry>> {
        self.batch_post_resilient::<BatchFollowEntry>("following", &self.failed_following, fids)
            .await
    }

    async fn batch_reactions(&self, fids: &[u64]) -> HashMap<u64, Vec<BatchReactionEntry>> {
        self.batch_post_resilient::<BatchReactionEntry>("reactions", &self.failed_reactions, fids)
            .await
    }

    async fn batch_cast_bodies(&self, fids: &[u64]) -> HashMap<u64, Vec<BatchCastBody>> {
        self.batch_post_resilient::<BatchCastBody>("cast-bodies", &self.failed_cast_bodies, fids)
            .await
    }
}

fn parse_batch_map<T>(m: HashMap<String, Vec<T>>) -> HashMap<u64, Vec<T>> {
    m.into_iter()
        .filter_map(|(k, v)| k.parse::<u64>().ok().map(|fid| (fid, v)))
        .collect()
}

fn extract_request_fid(s: &BatchSignerEntry) -> Option<u64> {
    if s.metadata_type != 1 {
        return None;
    }
    let bytes =
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &s.metadata).ok()?;
    if bytes.is_empty() {
        return None;
    }
    let decoded = SignedKeyRequestMetadata::abi_decode(&bytes, true).ok()?;
    decoded.requestFid.try_into().ok()
}

// ---- Main ----

#[tokio::main]
async fn main() {
    let args = Cli::parse();
    let modes: Vec<MutualityMode> = args
        .mutuality_modes
        .split(',')
        .filter_map(MutualityMode::parse)
        .collect();
    if modes.is_empty() {
        eprintln!(
            "Error: no valid mutuality modes in '{}'. Valid: min, geom, harmonic, avg, sum.",
            args.mutuality_modes
        );
        std::process::exit(1);
    }

    let cache_dir = if args.hub_cache_dir.is_empty() {
        None
    } else {
        let p = PathBuf::from(&args.hub_cache_dir);
        if let Some(parent) = p.parent() {
            if !parent.as_os_str().is_empty() {
                let _ = fs::create_dir_all(parent);
            }
        }
        Some(p)
    };
    let hub = HubClient::new_with_cache(&args.hub_url, cache_dir.as_deref());
    let output = PathBuf::from(&args.output_dir);
    fs::create_dir_all(&output).expect("create output dir");

    eprintln!("=== Retro Rewards Finalize (multi-mutuality) ===");
    eprintln!("Hub:    {}", args.hub_url);
    eprintln!("Output: {}", output.display());
    eprintln!(
        "Modes:  {}",
        modes
            .iter()
            .map(|m| m.name())
            .collect::<Vec<_>>()
            .join(", ")
    );
    eprintln!();

    // Phase 1
    eprintln!("Phase 1: Enumerating all FIDs…");
    let all_fids = collect_all_fids(&hub).await;
    eprintln!("  {} FIDs", all_fids.len());
    if all_fids.is_empty() {
        eprintln!("No FIDs found. Exiting.");
        return;
    }

    let mut metrics: HashMap<u64, FidMetrics> = HashMap::with_capacity(all_fids.len());
    for fid in &all_fids {
        metrics.insert(*fid, FidMetrics::default());
    }

    // Phase 1c: optional Recover-event ingestion. Builds a set of
    // (fid, block_timestamp) pairs that compute_age_facts uses to
    // distinguish forced recoveries from real ownership changes.
    let recoveries = match fetch_recoveries(
        &args.id_registry_rpc_url,
        args.recovery_start_block,
        args.recovery_end_block,
    )
    .await
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("  WARNING: failed to fetch Recover events");
            let mut current: Option<&dyn std::error::Error> = Some(e.as_ref());
            let mut depth = 0;
            while let Some(err) = current {
                eprintln!("    caused by [{}]: {}", depth, err);
                current = err.source();
                depth += 1;
            }
            if args.verify_recoveries_only {
                std::process::exit(1);
            }
            eprintln!("  Continuing without correction.");
            HashSet::new()
        }
    };

    if args.verify_recoveries_only {
        eprintln!("\n=== --verify-recoveries-only ===");
        eprintln!(
            "Total (fid, timestamp) recovery pairs: {}",
            recoveries.len()
        );
        if recoveries.is_empty() && !args.id_registry_rpc_url.is_empty() {
            eprintln!("No recoveries found — either the block range is wrong or the RPC URL points to the wrong chain.");
            eprintln!(
                "Sanity check: is `eth_chainId` returning 0xa (Optimism mainnet) for this URL?"
            );
            std::process::exit(2);
        }
        let mut sample: Vec<&(u64, u64)> = recoveries.iter().take(10).collect();
        sample.sort_by_key(|(fid, _)| *fid);
        eprintln!("First {} (sample):", sample.len());
        for (fid, ts) in sample {
            let dt = chrono::DateTime::from_timestamp(*ts as i64, 0)
                .map(|d| d.to_rfc3339())
                .unwrap_or_else(|| "?".into());
            eprintln!("  fid {:>10}  ts {} ({})", fid, ts, dt);
        }
        eprintln!("\n--verify-recoveries-only: exiting successfully without running the eval.");
        std::process::exit(0);
    }

    // Phase 2a: id-registrations → effective_ts for every FID (needed before
    // we can apply the transfer filter to any interaction.)
    eprintln!("\nPhase 2a: Fetching id-registrations…");
    fetch_id_registrations(&hub, &all_fids, &mut metrics, &recoveries).await;

    // Phase 2b: signers + following + reactions + cast-bodies, with per-event
    // transfer filtering.
    eprintln!("\nPhase 2b: Fetching interactions and building post-transfer index…");
    let mut follow_graph: HashMap<u64, Vec<u64>> = HashMap::new();
    fetch_and_index(&hub, &all_fids, &mut metrics, &mut follow_graph).await;

    // Phase 2c: transient active-day sets → final counts
    for m in metrics.values_mut() {
        m.active_days = m.active_day_set.len() as u32;
        m.active_day_set.clear();
    }

    // Phase 3a: non-trust engager statistics
    eprintln!("\nPhase 3a: Computing engager statistics…");
    for m in metrics.values_mut() {
        m.unique_engagers = m.engager_counts.len() as u32;
        m.engager_entropy = normalized_entropy(&m.engager_counts);
        m.engagement_per_cast = if m.total_casts == 0 {
            0.0
        } else {
            m.unique_engagers as f64 / ((m.total_casts as f64 + 1.0).ln())
        };
        m.total_engagement_count = m.engager_counts.values().sum::<u32>();
        m.replies_per_cast = if m.total_casts == 0 {
            0.0
        } else {
            m.replies_received as f64 / m.total_casts as f64
        };
    }

    // Phase 3b: seed set — first N FIDs (pure FID-number cutoff, no
    // timestamp criteria because OP Mainnet migration corrupted effective_ts).
    eprintln!(
        "\nPhase 3b: Building seed set (FID ≤ {})…",
        args.seed_max_fid
    );
    let seed_set: HashSet<u64> = all_fids
        .iter()
        .copied()
        .filter(|&fid| fid <= args.seed_max_fid)
        .collect();
    for (&fid, m) in metrics.iter_mut() {
        m.is_seed = seed_set.contains(&fid);
    }
    eprintln!("  seed set size: {} FIDs", seed_set.len());

    // Phase 3c: EigenTrust on the post-transfer follow graph, seeded on
    // seed_set. Gives per-FID trust_score that can't be self-bootstrapped
    // within a sybil ring — sockpuppets have no inbound edges from the seed
    // set (transitively) and stay near zero.
    eprintln!("\nPhase 3c: Running EigenTrust propagation…");
    let eigentrust = compute_eigentrust(&follow_graph, &seed_set);
    let eigentrust_norm = top_n_avg_norm(&eigentrust, 100);
    for (&fid, m) in metrics.iter_mut() {
        let raw = eigentrust.get(&fid).copied().unwrap_or(0.0);
        m.eigentrust_raw = raw;
        let normalized = (raw / eigentrust_norm).min(1.0);
        m.trust_score = (normalized * m.age_factor).clamp(0.0, 1.0);
    }

    // Phase 3d: credibility weights now using per-FID trust_score
    eprintln!("\nPhase 3d: Computing credibility weights with real trust scores…");
    for m in metrics.values_mut() {
        m.credibility_weight = compute_credibility_weight(
            m.age_factor,
            m.trust_score,
            m.interaction_entropy,
            m.client_diversity,
        );
    }

    // Phase 4a: crediter trust threshold — needed early because filter 5
    // derivation gates new-user engagement by the *crediter's* eventual
    // trust. A crediter who later accrued reputation isn't a sockpuppet
    // even if they were <30 days old at the time, so their engagement
    // shouldn't count against the target's new-user-share.
    eprintln!("\nPhase 4a: Computing crediter trust threshold…");
    let in_cal = |m: &FidMetrics| {
        meets_calibration_criteria(
            m,
            args.calibration_min_casts,
            args.calibration_min_active_days,
        )
    };
    let calibration_size = metrics.values().filter(|m| in_cal(m)).count();
    // Hard trust floor for growth-credit contributions and filter-5 gating.
    // Crediters whose trust_score sits below this floor contribute zero to
    // anyone's growth and have their first-30d engagement counted as
    // new-user-share. Calibrated as the threshold-percentile of trust over
    // the calibration cohort: genuine mid-tier users sit above; ring
    // sockpuppets (whose EigenTrust sits near the noise floor) sit below.
    let crediter_trust_threshold =
        cohort_percentile_threshold(&metrics, in_cal, args.threshold_percentile, |m| {
            m.trust_score
        });
    eprintln!(
        "  calibration cohort: {} FIDs (casts ≥ {}, active_days ≥ {})",
        calibration_size, args.calibration_min_casts, args.calibration_min_active_days
    );
    eprintln!("  crediter_trust ≥ {:.4}", crediter_trust_threshold);

    // Filter 5 derivation: sum over u of u's outbound_first_30d[target] into
    // target's new_user_engagement_count, but ONLY for crediters whose
    // eventual trust_score sits below crediter_trust_threshold. This
    // separates farm targets (whose new-user crediters stay near the
    // EigenTrust noise floor) from genuine onboarding magnets (whose
    // new-user crediters eventually accrue real trust).
    let mut new_user_received: HashMap<u64, u32> = HashMap::new();
    let mut gated_crediters = 0u64;
    for m in metrics.values() {
        if m.trust_score >= crediter_trust_threshold {
            gated_crediters += 1;
            continue;
        }
        for (&f, &count) in &m.outbound_first_30d {
            *new_user_received.entry(f).or_default() += count;
        }
    }
    eprintln!(
        "  filter 5 gating: {} crediters above trust threshold (their first-30d engagement excluded from new-user-share)",
        gated_crediters
    );
    for (fid, m) in metrics.iter_mut() {
        m.new_user_engagement_count = new_user_received.get(fid).copied().unwrap_or(0);
        m.new_user_engagement_share = if m.total_engagement_count > 0 {
            m.new_user_engagement_count as f64 / m.total_engagement_count as f64
        } else {
            0.0
        };
    }

    // Phase 4b: remaining filter thresholds (shared across all modes).
    // Thresholds are calibrated against the **calibration cohort** — broader
    // than the EigenTrust seed cohort, representing typical real users.
    // Activity-based only (no timestamp criteria): the OP Mainnet migration
    // corrupted effective_ts for older accounts, so age-based filtering
    // would silently exclude legitimate long-term users.
    eprintln!("\nPhase 4b: Computing remaining filter thresholds…");
    let entropy_threshold =
        cohort_percentile_threshold(&metrics, in_cal, args.threshold_percentile, |m| {
            m.engager_entropy
        });
    let ratio_threshold =
        cohort_percentile_threshold(&metrics, in_cal, args.threshold_percentile, |m| {
            m.engagement_per_cast
        });
    let new_user_share_threshold =
        cohort_percentile_threshold(&metrics, in_cal, 1.0 - args.threshold_percentile, |m| {
            m.new_user_engagement_share
        });
    let replies_per_cast_threshold =
        cohort_percentile_threshold(&metrics, in_cal, args.threshold_percentile, |m| {
            m.replies_per_cast
        });
    eprintln!(
        "  entropy ≥ {:.4}, engagement/cast ≥ {:.4}, new-user-share < {:.4}, replies/cast ≥ {:.4}",
        entropy_threshold, ratio_threshold, new_user_share_threshold, replies_per_cast_threshold
    );
    if calibration_size == 0 {
        eprintln!("  WARNING: calibration cohort is empty. Thresholds are 0 → filter 5 will fail everyone.");
        eprintln!("           Check that id-registration timestamps are being parsed correctly.");
    }

    eprintln!("\nPhase 5: Applying eligibility filters…");
    let mut counts = FilterCounts::default();
    let mut filter_3_saved_by_seed = 0u64;
    let mut filter_3_saved_by_floor = 0u64;
    let mut filter_5_saved_by_floor = 0u64;
    let mut filter_5_saved_by_trust = 0u64;
    for m in metrics.values_mut() {
        m.filter_0_pass = m.signer_authorizations < args.app_threshold;
        m.filter_1_pass = m.total_casts > 0;
        m.filter_2_pass = m.unique_engagers >= args.min_engagers;
        // Filter 3: engager_entropy must be at or above the cohort
        // percentile. Two escape hatches catch real humans whose tight
        // friend communities give them naturally low engager entropy:
        //  - is_seed: hand-onboarded trust anchors pass unconditionally.
        //  - dual-entropy floor: pass if BOTH engager_entropy and
        //    interaction_entropy are at or above the absolute floor.
        //    Rings show low entropy on both sides; real humans with
        //    concentrated inbound engagement still have diverse outbound
        //    engagement, so they clear the floor on the outbound side.
        let entropy_percentile_pass = m.engager_entropy >= entropy_threshold;
        let entropy_seed_pass = m.is_seed;
        let entropy_floor_pass = m.engager_entropy >= args.engager_entropy_absolute_floor
            && m.interaction_entropy >= args.engager_entropy_absolute_floor;
        m.filter_3_pass = entropy_percentile_pass || entropy_seed_pass || entropy_floor_pass;
        if !entropy_percentile_pass && m.filter_3_pass {
            if entropy_seed_pass {
                filter_3_saved_by_seed += 1;
            } else if entropy_floor_pass {
                filter_3_saved_by_floor += 1;
            }
        }
        m.filter_4_pass = !args.strict || m.engagement_per_cast >= ratio_threshold;
        // Filter 5: new_user_engagement_share must be below the cohort
        // percentile, with two escape hatches:
        //  - absolute floor: shares below the floor pass regardless of
        //    where they sit in the cohort distribution. Catches the
        //    case where the cohort is heavy with mid-tier users whose
        //    near-zero share pushes the 90th percentile down to ~3%,
        //    which would otherwise fail legitimate popular accounts.
        //  - trust escape: FIDs whose trust_score is at or above the
        //    crediter_trust_threshold get a free pass. Sybil
        //    accumulation can't pump trust_score (the gating logic
        //    above already prevents low-trust crediters from feeding
        //    each other), so a high trust score is a strong
        //    "organically credible" signal.
        let percentile_pass = m.new_user_engagement_share < new_user_share_threshold;
        let floor_pass = m.new_user_engagement_share < args.new_user_share_absolute_floor;
        let trust_pass = m.trust_score >= crediter_trust_threshold;
        m.filter_5_pass = percentile_pass || floor_pass || trust_pass;
        if !percentile_pass && m.filter_5_pass {
            if floor_pass {
                filter_5_saved_by_floor += 1;
            } else if trust_pass {
                filter_5_saved_by_trust += 1;
            }
        }
        m.filter_6_pass = m.replies_per_cast >= replies_per_cast_threshold;

        if !m.filter_0_pass {
            m.fail_reason = "app".to_string();
            counts.fail_0 += 1;
        } else if !m.filter_1_pass {
            m.fail_reason = "no_casts".to_string();
            counts.fail_1 += 1;
        } else if !m.filter_2_pass {
            m.fail_reason = format!("engagers<{}", args.min_engagers);
            counts.fail_2 += 1;
        } else if !m.filter_3_pass {
            m.fail_reason = "low_entropy".to_string();
            counts.fail_3 += 1;
        } else if !m.filter_4_pass {
            m.fail_reason = "low_eng_per_cast".to_string();
            counts.fail_4 += 1;
        } else if !m.filter_5_pass {
            m.fail_reason = "high_new_user_share".to_string();
            counts.fail_5 += 1;
        } else if !m.filter_6_pass {
            m.fail_reason = "low_replies_per_cast".to_string();
            counts.fail_6 += 1;
        }
        m.eligible = m.fail_reason.is_empty();
        if m.eligible {
            counts.pass += 1;
        }
    }
    eprintln!(
        "  pass: {}  |  fail 0: {}  |  fail 1: {}  |  fail 2: {}  |  fail 3: {}  |  fail 4: {}  |  fail 5: {}  |  fail 6: {}",
        counts.pass, counts.fail_0, counts.fail_1, counts.fail_2, counts.fail_3, counts.fail_4, counts.fail_5, counts.fail_6
    );
    eprintln!(
        "  filter 3 escape hatches: {} saved by is_seed, {} saved by dual-entropy floor (≥{:.4})",
        filter_3_saved_by_seed, filter_3_saved_by_floor, args.engager_entropy_absolute_floor,
    );
    eprintln!(
        "  filter 5 escape hatches: {} saved by absolute floor (<{:.4}), {} saved by trust (≥{:.4})",
        filter_5_saved_by_floor,
        args.new_user_share_absolute_floor,
        filter_5_saved_by_trust,
        crediter_trust_threshold,
    );

    // Phase 6: per-mode growth scoring, composite, renormalization
    eprintln!("\nPhase 6: Per-mode growth scoring and pool renormalization…");
    compute_growth_scores(
        &all_fids,
        &mut metrics,
        &modes,
        crediter_trust_threshold,
        args.credibility_exponent,
        args.ring_symmetry_exponent,
        args.trust_exponent,
        args.new_user_share_exponent,
        args.new_user_share_smoothing,
        args.growth_exponent,
    );

    for mode in &modes {
        let eligible_total: f64 = metrics
            .values()
            .filter(|m| m.eligible)
            .filter_map(|m| m.composite_by_mode.get(mode).copied())
            .filter(|v| *v > 0.0)
            .sum();
        if eligible_total > 0.0 {
            for m in metrics.values_mut() {
                if !m.eligible {
                    continue;
                }
                let comp = m.composite_by_mode.get(mode).copied().unwrap_or(0.0);
                m.final_tokens_by_mode
                    .insert(*mode, comp / eligible_total * RETROACTIVE_POOL);
            }
        }
        let allocated = metrics
            .values()
            .filter(|m| m.final_tokens_by_mode.get(mode).copied().unwrap_or(0.0) > 0.0)
            .count();
        eprintln!("  [{}] {} FIDs allocated", mode.name(), allocated);
    }

    // Phase 7: outputs
    eprintln!("\nPhase 7: Writing outputs…");
    for mode in &modes {
        let path = output.join(format!("final.{}.csv", mode.name()));
        write_final_csv(&path, &all_fids, &metrics, *mode).expect("write final csv");
    }
    write_eligibility_csv(&output.join("eligibility.csv"), &all_fids, &metrics, &modes)
        .expect("write eligibility.csv");
    write_mutuality_comparison_md(
        &output.join("mutuality_comparison.md"),
        &all_fids,
        &metrics,
        &modes,
    )
    .expect("write mutuality_comparison.md");
    write_report_md(
        &output.join("eligibility_report.md"),
        &args,
        entropy_threshold,
        ratio_threshold,
        new_user_share_threshold,
        replies_per_cast_threshold,
        &counts,
        &metrics,
        &modes,
    )
    .expect("write eligibility_report.md");

    hub.report_fetch_failures();

    eprintln!("\nDone.");
    for mode in &modes {
        eprintln!("  final.{}.csv", mode.name());
    }
    eprintln!("  eligibility.csv");
    eprintln!("  mutuality_comparison.md");
    eprintln!("  eligibility_report.md");
}

// ---- Phase 1 ----

async fn collect_all_fids(hub: &HubClient) -> Vec<u64> {
    let mut set: HashSet<u64> = HashSet::new();
    for shard_id in 1..=NUM_SHARDS {
        let mut token: Option<String> = None;
        loop {
            match hub.get_fids(shard_id, token.as_deref()).await {
                Ok(r) => {
                    if r.fids.is_empty() {
                        break;
                    }
                    set.extend(r.fids);
                    match r.next_page_token {
                        Some(t) if !t.is_empty() => token = Some(t),
                        _ => break,
                    }
                }
                Err(e) => {
                    eprintln!("  warning: shard {} fetch failed: {:?}", shard_id, e);
                    break;
                }
            }
        }
    }
    let mut v: Vec<u64> = set.into_iter().collect();
    v.sort();
    v
}

// ---- Phase 2a ----

async fn fetch_id_registrations(
    hub: &HubClient,
    all_fids: &[u64],
    metrics: &mut HashMap<u64, FidMetrics>,
    recoveries: &HashSet<(u64, u64)>,
) {
    let pb = progress_bar(all_fids.len() as u64, "id-reg");
    for chunk in all_fids.chunks(BATCH_SIZE) {
        let id_regs = hub.batch_id_registrations(chunk).await;
        for &fid in chunk {
            let events = id_regs.get(&fid).map(|v| v.as_slice()).unwrap_or(&[]);
            let (age, reg, eff) = compute_age_facts(events, fid, recoveries);
            if let Some(m) = metrics.get_mut(&fid) {
                m.age_factor = age;
                m.reg_ts = reg;
                m.effective_ts = eff;
            }
            pb.inc(1);
        }
    }
    pb.finish_with_message("done");
}

/// Binary-search the lowest block at which `addr` has non-empty bytecode.
/// That block is at most one off from the actual deployment block (the
/// contract is created in this block; the previous block had nothing).
/// ~log2(latest) RPC calls — about 30 for current OP heights.
async fn find_deployment_block<P>(
    provider: &P,
    addr: alloy_primitives::Address,
    latest: u64,
) -> Result<u64, Box<dyn std::error::Error>>
where
    P: Provider<alloy_transport_http::Http<reqwest::Client>>,
{
    let mut lo: u64 = 1;
    let mut hi: u64 = latest;
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        let code = provider
            .get_code_at(addr)
            .block_id(BlockNumberOrTag::Number(mid).into())
            .await?;
        if code.is_empty() {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    Ok(lo)
}

/// Fetch `Recover` events from the Farcaster IdRegistry contract within
/// `[start_block, end_block]`. Returns a set of (fid, block_timestamp)
/// pairs — `compute_age_facts` skips Transfer events whose
/// (fid, block_timestamp) matches, so the original `effective_ts` is
/// preserved for forced-recovery cases.
///
/// Returns an empty set if `rpc_url` is empty (the correction is
/// opt-in). Errors are surfaced — operator has to fix the RPC config
/// rather than silently skipping.
async fn fetch_recoveries(
    rpc_url: &str,
    start_block: u64,
    end_block: u64,
) -> Result<HashSet<(u64, u64)>, Box<dyn std::error::Error>> {
    if rpc_url.is_empty() {
        return Ok(HashSet::new());
    }
    let provider = ProviderBuilder::new().on_http(rpc_url.parse()?);

    // Resolve "u64::MAX" sentinel to the latest block.
    let resolved_end = if end_block == u64::MAX {
        provider.get_block_number().await?
    } else {
        end_block
    };

    // Auto-detect the IdRegistry contract deployment block via binary
    // search on eth_getCode. Bumps `start_block` up to the deployment
    // block if the user passed something earlier — fewer empty-block
    // log queries. ~30 RPC calls (log2 of current block height).
    let detected = find_deployment_block(&provider, ID_REGISTRY_ADDRESS_OP, resolved_end).await?;
    let effective_start = start_block.max(detected);
    eprintln!(
        "  IdRegistry deployment detected at block {} (using start_block = {})",
        detected, effective_start
    );

    eprintln!(
        "\nFetching IdRegistry Recover events from {} (blocks {}..={})…",
        rpc_url, effective_start, resolved_end
    );

    // Walk the block range in batches and collect Recover events.
    let mut events_by_block_fid: Vec<(u64, u64)> = Vec::new(); // (block_number, fid)
    let mut cur = effective_start;
    let pb = progress_bar(
        (resolved_end.saturating_sub(effective_start) / RECOVERY_BLOCK_BATCH).max(1) + 1,
        "recover-logs",
    );
    while cur <= resolved_end {
        let stop = (cur + RECOVERY_BLOCK_BATCH - 1).min(resolved_end);
        let filter = Filter::new()
            .address(ID_REGISTRY_ADDRESS_OP)
            .from_block(BlockNumberOrTag::Number(cur))
            .to_block(BlockNumberOrTag::Number(stop))
            .event_signature(Recover::SIGNATURE_HASH);
        let logs = provider.get_logs(&filter).await?;
        for log in logs {
            // Recover has 3 indexed topics: from (1), to (2), id (3).
            // The id is the FID.
            if let Some(id_topic) = log.topics().get(3) {
                let fid = U256::from_be_slice(id_topic.as_slice()).to::<u64>();
                if let Some(bn) = log.block_number {
                    events_by_block_fid.push((bn, fid));
                }
            }
        }
        cur = stop.saturating_add(1);
        pb.inc(1);
    }
    pb.finish_with_message("done");

    if events_by_block_fid.is_empty() {
        eprintln!("  no Recover events found in range");
        return Ok(HashSet::new());
    }
    eprintln!(
        "  found {} Recover events; resolving block timestamps…",
        events_by_block_fid.len()
    );

    // Resolve block timestamps for unique block numbers.
    let mut unique_blocks: Vec<u64> = events_by_block_fid.iter().map(|(bn, _)| *bn).collect();
    unique_blocks.sort_unstable();
    unique_blocks.dedup();

    let mut block_ts: HashMap<u64, u64> = HashMap::new();
    let pb = progress_bar(unique_blocks.len() as u64, "block-ts");
    for bn in &unique_blocks {
        let block = provider
            .get_block_by_number(BlockNumberOrTag::Number(*bn), BlockTransactionsKind::Hashes)
            .await?;
        if let Some(b) = block {
            block_ts.insert(*bn, b.header.timestamp);
        }
        pb.inc(1);
    }
    pb.finish_with_message("done");

    let recoveries: HashSet<(u64, u64)> = events_by_block_fid
        .into_iter()
        .filter_map(|(bn, fid)| block_ts.get(&bn).map(|ts| (fid, *ts)))
        .collect();
    eprintln!(
        "  built recovery set with {} (fid, timestamp) pairs",
        recoveries.len()
    );
    Ok(recoveries)
}

fn compute_age_facts(
    events: &[BatchIdRegEntry],
    fid: u64,
    recoveries: &HashSet<(u64, u64)>,
) -> (f64, Option<u64>, Option<u64>) {
    if events.is_empty() {
        return (0.0, None, None);
    }
    let mut latest_transfer = 0u64;
    let mut earliest_reg = u64::MAX;
    for e in events {
        if e.event_type == "Transfer" {
            // Skip recovery-flow transfers: they share (fid,
            // block_timestamp) with a contemporaneous on-chain
            // Recover event, meaning the same custodian regained
            // access rather than a new owner taking over.
            if recoveries.contains(&(fid, e.block_timestamp)) {
                continue;
            }
            latest_transfer = latest_transfer.max(e.block_timestamp);
        }
        if e.event_type == "Register" {
            earliest_reg = earliest_reg.min(e.block_timestamp);
        }
    }
    let reg_ts = if earliest_reg < u64::MAX {
        Some(earliest_reg)
    } else {
        None
    };
    let effective = if latest_transfer > 0 {
        latest_transfer
    } else if earliest_reg < u64::MAX {
        earliest_reg
    } else {
        return (0.0, None, None);
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let age_secs = now.saturating_sub(effective);
    (
        (age_secs as f64 / SIX_MONTHS_SECS).min(1.0),
        reg_ts,
        Some(effective),
    )
}

// ---- Phase 2b ----

async fn fetch_and_index(
    hub: &HubClient,
    all_fids: &[u64],
    metrics: &mut HashMap<u64, FidMetrics>,
    follow_graph: &mut HashMap<u64, Vec<u64>>,
) {
    let pb = progress_bar(all_fids.len() as u64, "data");
    for chunk in all_fids.chunks(BATCH_SIZE) {
        let (signers, following, reactions, casts) = tokio::join!(
            hub.batch_signers(chunk),
            hub.batch_following(chunk),
            hub.batch_reactions(chunk),
            hub.batch_cast_bodies(chunk),
        );

        for &src in chunk {
            let src_eff = metrics.get(&src).and_then(|m| m.effective_ts);
            // 30-day window starts from the current custodian's effective_ts,
            // so a transferred FID's "first 30 days" is reset to the transfer.
            let src_first_30d_end = src_eff.map(|t| t + THIRTY_DAYS_SECS);

            // 1) Signers → diversity + Filter 0 reverse counter
            let mut app_fids: HashSet<u64> = HashSet::new();
            if let Some(list) = signers.get(&src) {
                for s in list {
                    if let Some(rf) = extract_request_fid(s) {
                        app_fids.insert(rf);
                        if rf != src {
                            if let Some(t) = metrics.get_mut(&rf) {
                                t.signer_authorizations = t.signer_authorizations.saturating_add(1);
                            }
                        }
                    }
                }
            }
            let client_diversity = if app_fids.len() <= 1 {
                0.0
            } else {
                (app_fids.len() as f64).log2().min(1.0)
            };

            // 2) Cast bodies: loop each cast, apply transfer filter per-edge
            let mut partner_counts: HashMap<u64, u64> = HashMap::new();
            let mut src_total_casts: u32 = 0;

            if let Some(list) = casts.get(&src) {
                for cast in list {
                    let ts = cast.timestamp as u64 + FARCASTER_EPOCH;
                    let src_post_transfer = src_eff.map(|e| ts > e).unwrap_or(false);
                    // Count as src's own cast only if post-transfer.
                    if src_post_transfer {
                        src_total_casts = src_total_casts.saturating_add(1);
                        let day_bucket = ts / 86_400;
                        if let Some(m) = metrics.get_mut(&src) {
                            m.active_day_set.insert(day_bucket);
                        }
                    }

                    // Collect targets of this cast (parent + mentions)
                    let mut targets: Vec<u64> = Vec::new();
                    if let Some(p) = cast.parent_fid {
                        if p != 0 && p != src {
                            targets.push(p);
                        }
                    }
                    for &m in &cast.mentions {
                        if m != 0 && m != src {
                            targets.push(m);
                        }
                    }

                    for tgt in targets {
                        let tgt_eff = metrics.get(&tgt).and_then(|m| m.effective_ts);
                        let tgt_post_transfer = tgt_eff.map(|e| ts > e).unwrap_or(false);
                        let both_post_transfer = src_post_transfer && tgt_post_transfer;

                        // Entropy (src's partner count): only post-transfer on src side
                        if src_post_transfer {
                            *partner_counts.entry(tgt).or_default() += 1;
                        }

                        // Filter 5 feed: src's outbound during src's own
                        // effective-30-day window (post-transfer)
                        if src_post_transfer {
                            if let Some(end) = src_first_30d_end {
                                if ts <= end {
                                    if let Some(m) = metrics.get_mut(&src) {
                                        *m.outbound_first_30d.entry(tgt).or_default() += 1;
                                    }
                                }
                            }
                        }

                        // All-time post-transfer engagement (growth input):
                        // requires both sides in current custody.
                        if both_post_transfer {
                            if let Some(m) = metrics.get_mut(&src) {
                                *m.all_time_engagement.entry(tgt).or_default() += 1;
                            }
                        }

                        // Inbound engager index (tgt-side): tgt counts src as
                        // engager only if the interaction was post-transfer on
                        // tgt's side — otherwise it's for a previous custodian.
                        if tgt_post_transfer {
                            if let Some(t) = metrics.get_mut(&tgt) {
                                *t.engager_counts.entry(src).or_default() += 1;
                            }
                        }

                        // Filter 6: direct reply bumps parent's replies_received
                        // (only when parent was current custodian then).
                        if cast.parent_fid == Some(tgt) && tgt_post_transfer {
                            if let Some(t) = metrics.get_mut(&tgt) {
                                t.replies_received = t.replies_received.saturating_add(1);
                            }
                        }
                    }
                }
            }

            // 3) Reactions
            if let Some(list) = reactions.get(&src) {
                for r in list {
                    if r.target_fid == 0 || r.target_fid == src {
                        continue;
                    }
                    let ts = r.timestamp as u64 + FARCASTER_EPOCH;
                    let src_post_transfer = src_eff.map(|e| ts > e).unwrap_or(false);
                    let tgt_eff = metrics.get(&r.target_fid).and_then(|m| m.effective_ts);
                    let tgt_post_transfer = tgt_eff.map(|e| ts > e).unwrap_or(false);
                    let both_post_transfer = src_post_transfer && tgt_post_transfer;

                    if src_post_transfer {
                        *partner_counts.entry(r.target_fid).or_default() += 1;
                        if let Some(end) = src_first_30d_end {
                            if ts <= end {
                                if let Some(m) = metrics.get_mut(&src) {
                                    *m.outbound_first_30d.entry(r.target_fid).or_default() += 1;
                                }
                            }
                        }
                    }
                    if both_post_transfer {
                        if let Some(m) = metrics.get_mut(&src) {
                            *m.all_time_engagement.entry(r.target_fid).or_default() += 1;
                        }
                    }
                    if tgt_post_transfer {
                        if let Some(t) = metrics.get_mut(&r.target_fid) {
                            *t.engager_counts.entry(src).or_default() += 1;
                        }
                    }
                }
            }

            // 4) Following
            if let Some(list) = following.get(&src) {
                for f in list {
                    if f.fid == 0 || f.fid == src {
                        continue;
                    }
                    let ts = match f
                        .followed_at
                        .as_ref()
                        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                    {
                        Some(dt) => dt.timestamp() as u64,
                        None => continue,
                    };
                    let src_post_transfer = src_eff.map(|e| ts > e).unwrap_or(false);
                    let tgt_eff = metrics.get(&f.fid).and_then(|m| m.effective_ts);
                    let tgt_post_transfer = tgt_eff.map(|e| ts > e).unwrap_or(false);
                    let both_post_transfer = src_post_transfer && tgt_post_transfer;

                    // Post-transfer follow graph (for EigenTrust): require
                    // both sides in current custody.
                    if both_post_transfer {
                        follow_graph.entry(src).or_default().push(f.fid);
                    }

                    // Entropy: count follow only after autofollow window past src's effective_ts.
                    let outside_autofollow = match src_eff {
                        Some(e) => ts > e + AUTOFOLLOW_WINDOW_SECS,
                        None => false,
                    };
                    if src_post_transfer && outside_autofollow {
                        *partner_counts.entry(f.fid).or_default() += 1;

                        if let Some(end) = src_first_30d_end {
                            if ts <= end {
                                if let Some(m) = metrics.get_mut(&src) {
                                    *m.outbound_first_30d.entry(f.fid).or_default() += 1;
                                }
                            }
                        }
                    }
                    if both_post_transfer && outside_autofollow {
                        if let Some(m) = metrics.get_mut(&src) {
                            *m.all_time_engagement.entry(f.fid).or_default() += 1;
                        }
                    }
                    if tgt_post_transfer && outside_autofollow {
                        if let Some(t) = metrics.get_mut(&f.fid) {
                            *t.engager_counts.entry(src).or_default() += 1;
                        }
                    }
                }
            }

            // Finalize src's own-side values
            let entropy = shannon_entropy_normalized(&partner_counts);
            if let Some(m) = metrics.get_mut(&src) {
                m.interaction_entropy = entropy;
                m.client_diversity = client_diversity;
                m.total_casts = src_total_casts;
            }

            pb.inc(1);
        }
    }
    pb.finish_with_message("done");
}

// ---- Phase 6: per-mode growth scoring ----

fn compute_growth_scores(
    all_fids: &[u64],
    metrics: &mut HashMap<u64, FidMetrics>,
    modes: &[MutualityMode],
    crediter_trust_threshold: f64,
    credibility_exponent: f64,
    ring_symmetry_exponent: f64,
    trust_exponent: f64,
    new_user_share_exponent: f64,
    new_user_share_smoothing: f64,
    growth_exponent: f64,
) {
    // Per-mode credit accumulator
    let mut credits: HashMap<MutualityMode, HashMap<u64, f64>> = HashMap::new();
    for mode in modes {
        credits.insert(*mode, HashMap::new());
    }

    // Build a lightweight snapshot to avoid borrowing issues: (fid →
    // all_time_engagement keys + credibility_weight).
    let pb = progress_bar(all_fids.len() as u64, "growth");
    for &f in all_fids {
        let (cred_f, engagement) = match metrics.get(&f) {
            Some(m) if !m.all_time_engagement.is_empty() => (
                m.credibility_weight,
                m.all_time_engagement
                    .iter()
                    .map(|(&u, &c)| (u, c))
                    .collect::<Vec<_>>(),
            ),
            _ => {
                pb.inc(1);
                continue;
            }
        };
        if cred_f <= 0.0 {
            pb.inc(1);
            continue;
        }

        for (u, count_fu) in engagement {
            let count_uf = metrics
                .get(&u)
                .and_then(|mu| mu.all_time_engagement.get(&f).copied())
                .unwrap_or(0);
            if count_uf == 0 {
                continue;
            }
            // Hard floor: skip crediters whose trust sits below the
            // calibration-cohort threshold. Ring sockpuppets land here.
            let trust_u = metrics.get(&u).map(|m| m.trust_score).unwrap_or(0.0);
            if trust_u < crediter_trust_threshold {
                continue;
            }
            let cred_u = metrics.get(&u).map(|m| m.credibility_weight).unwrap_or(0.0);
            if cred_u <= 0.0 {
                continue;
            }

            for mode in modes {
                let mutuality = mode.apply(count_fu as f64, count_uf as f64);
                if mutuality <= 0.0 {
                    continue;
                }
                let contribution = mutuality * cred_u;
                *credits.get_mut(mode).unwrap().entry(f).or_default() += contribution;
            }
        }
        pb.inc(1);
    }
    pb.finish_with_message("done");

    // Flush credits into metrics.
    //
    //   composite(f) = credibility(f)^k
    //                · trust(f)^j
    //                · (engager_entropy(f) · interaction_entropy(f))^p
    //                · (new_user_share(f) + ε)^q
    //                · growth(f)^g
    //
    // - `credibility^k` compounds the trust differential so a high-trust
    //   account can pull ahead of a high-volume-low-trust account whose
    //   credibility advantage in the underlying score is narrow (typical
    //   range 0.5–0.7). `k = 1` lets raw volume dominate.
    // - `trust^j` restores EigenTrust's full dynamic range (which the
    //   credibility linear-blend at W_TRUST = 0.35 saturates against
    //   age + entropy + diversity). Catches the "wide farm" pattern —
    //   accounts whose engagement is broadly distributed across many
    //   low-trust crediters; the ring-symmetry term can't see these
    //   because their entropies are high.
    // - The ring-symmetry term penalizes accounts whose engagement is
    //   concentrated on BOTH sides — symmetric mutual-engagement rings
    //   show low entropy on both inbound and outbound, while real humans
    //   with tight communities show low inbound + high outbound. `p = 0`
    //   disables.
    // - `(new_user_share + ε)^q` catches the *zero-share* farm direction
    //   that filter 5 misses. Filter 5 fires only on the *high-share*
    //   direction (account being flooded by new accounts). Some farms —
    //   and some celebrity-tier real accounts — sit at literal-zero
    //   new-user share, indicating an established crediter pool with no
    //   organic onboarding magnetism. The smoothing constant ε prevents
    //   zero-share accounts from being completely zeroed out.
    for mode in modes {
        let mode_credits = credits.remove(mode).unwrap_or_default();
        for (fid, growth) in mode_credits {
            if let Some(m) = metrics.get_mut(&fid) {
                let entropy_product = m.engager_entropy * m.interaction_entropy;
                let symmetry_factor = if ring_symmetry_exponent > 0.0 {
                    entropy_product.max(0.0).powf(ring_symmetry_exponent)
                } else {
                    1.0
                };
                let trust_factor = if trust_exponent > 0.0 {
                    m.trust_score.max(0.0).powf(trust_exponent)
                } else {
                    1.0
                };
                let new_user_factor = if new_user_share_exponent > 0.0 {
                    (m.new_user_engagement_share.max(0.0) + new_user_share_smoothing)
                        .powf(new_user_share_exponent)
                } else {
                    1.0
                };
                let compressed_growth = if growth_exponent != 1.0 && growth_exponent > 0.0 {
                    growth.max(0.0).powf(growth_exponent)
                } else {
                    growth
                };
                let composite = m.credibility_weight.powf(credibility_exponent)
                    * trust_factor
                    * symmetry_factor
                    * new_user_factor
                    * compressed_growth;
                m.growth_by_mode.insert(*mode, growth);
                m.composite_by_mode.insert(*mode, composite);
            }
        }
    }
}

// ---- Helpers ----

/// Percentile of `extract(m)` over FIDs passing `in_cohort`.
fn cohort_percentile_threshold<C, F>(
    metrics: &HashMap<u64, FidMetrics>,
    in_cohort: C,
    percentile: f64,
    extract: F,
) -> f64
where
    C: Fn(&FidMetrics) -> bool,
    F: Fn(&FidMetrics) -> f64,
{
    let mut vals: Vec<f64> = metrics
        .values()
        .filter(|m| in_cohort(m))
        .map(&extract)
        .collect();
    if vals.is_empty() {
        return 0.0;
    }
    vals.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let idx = (vals.len() as f64 * percentile) as usize;
    vals[idx.min(vals.len() - 1)]
}

/// Predicate: does this FID meet the threshold-calibration criteria?
/// Activity-based only — no timestamp criteria because OP Mainnet migration
/// corrupted effective_ts for old accounts.
fn meets_calibration_criteria(m: &FidMetrics, min_casts: u32, min_active_days: u32) -> bool {
    m.total_casts >= min_casts && m.active_days >= min_active_days
}

/// EigenTrust propagation (PoQ Section 2 Step 2).
fn compute_eigentrust(
    follow_graph: &HashMap<u64, Vec<u64>>,
    seed_set: &HashSet<u64>,
) -> HashMap<u64, f64> {
    let mut universe: HashSet<u64> = HashSet::new();
    for (&j, followees) in follow_graph {
        universe.insert(j);
        for &i in followees {
            universe.insert(i);
        }
    }
    for &s in seed_set {
        universe.insert(s);
    }
    if universe.is_empty() || seed_set.is_empty() {
        return HashMap::new();
    }

    let seed_weight = 1.0 / seed_set.len() as f64;
    let mut t: HashMap<u64, f64> = HashMap::with_capacity(universe.len());
    for &fid in &universe {
        t.insert(
            fid,
            if seed_set.contains(&fid) {
                seed_weight
            } else {
                0.0
            },
        );
    }

    let d = POQ_DAMPING_FACTOR;

    for iter in 0..POQ_MAX_ITERATIONS {
        let mut next: HashMap<u64, f64> = HashMap::with_capacity(universe.len());
        for &fid in &universe {
            let seed_val = if seed_set.contains(&fid) {
                seed_weight
            } else {
                0.0
            };
            next.insert(fid, (1.0 - d) * seed_val);
        }
        for (&j, followees) in follow_graph {
            let t_j = *t.get(&j).unwrap_or(&0.0);
            if t_j == 0.0 || followees.is_empty() {
                continue;
            }
            let share = d * t_j / followees.len() as f64;
            for &i in followees {
                *next.entry(i).or_default() += share;
            }
        }
        let mut delta = 0.0f64;
        for (&fid, &v) in &next {
            delta += (v - *t.get(&fid).unwrap_or(&0.0)).abs();
        }
        t = next;
        if delta < POQ_CONVERGENCE_TOLERANCE {
            eprintln!(
                "  EigenTrust converged after {} iters (Δ={:.2e})",
                iter + 1,
                delta
            );
            break;
        }
        if iter + 1 == POQ_MAX_ITERATIONS {
            eprintln!(
                "  EigenTrust reached max iterations ({}) with Δ={:.2e}",
                POQ_MAX_ITERATIONS, delta
            );
        }
    }
    t
}

/// 99th-percentile non-zero EigenTrust value, used to normalize raw scores.
/// Normalization reference for raw EigenTrust scores: the average of the top
/// `n` values in the distribution. Power-law-friendly: it lands at the actual
/// "high-trust" level rather than the long tail (which `percentile_99` did,
/// causing most non-zero accounts to saturate to `trust_score = 1.0`).
fn top_n_avg_norm(eigentrust: &HashMap<u64, f64>, n: usize) -> f64 {
    let mut vals: Vec<f64> = eigentrust.values().copied().filter(|v| *v > 0.0).collect();
    if vals.is_empty() {
        return 1.0;
    }
    vals.sort_by(|a, b| b.partial_cmp(a).unwrap_or(std::cmp::Ordering::Equal));
    let take = n.min(vals.len());
    let sum: f64 = vals.iter().take(take).sum();
    (sum / take as f64).max(1.0e-12)
}

fn compute_credibility_weight(age: f64, trust: f64, entropy: f64, diversity: f64) -> f64 {
    W_AGE * age + W_TRUST * trust + W_ENTROPY * entropy + W_STAKE * 0.0 + W_DIVERSITY * diversity
}

fn shannon_entropy_normalized(counts: &HashMap<u64, u64>) -> f64 {
    let total: u64 = counts.values().sum();
    if total == 0 {
        return 0.0;
    }
    let t = total as f64;
    let mut h = 0.0f64;
    for &c in counts.values() {
        if c > 0 {
            let p = c as f64 / t;
            h -= p * p.log2();
        }
    }
    let n = counts.len() as f64;
    if n > 1.0 {
        h / n.log2()
    } else {
        0.0
    }
}

fn normalized_entropy(counts: &HashMap<u64, u32>) -> f64 {
    let total: u64 = counts.values().map(|&c| c as u64).sum();
    if total == 0 {
        return 0.0;
    }
    let t = total as f64;
    let mut h = 0.0f64;
    for &c in counts.values() {
        if c > 0 {
            let p = c as f64 / t;
            h -= p * p.log2();
        }
    }
    let n = counts.len() as f64;
    if n > 1.0 {
        h / n.log2()
    } else {
        0.0
    }
}

// ---- Output writers ----

#[derive(Default)]
struct FilterCounts {
    pass: usize,
    fail_0: usize,
    fail_1: usize,
    fail_2: usize,
    fail_3: usize,
    fail_4: usize,
    fail_5: usize,
    fail_6: usize,
}

fn write_final_csv(
    path: &Path,
    fids: &[u64],
    metrics: &HashMap<u64, FidMetrics>,
    mode: MutualityMode,
) -> std::io::Result<()> {
    let mut wtr = csv::Writer::from_path(path)?;
    wtr.write_record(["fid", "tokens"])?;

    let mut ranked: Vec<u64> = fids
        .iter()
        .copied()
        .filter(|fid| {
            metrics
                .get(fid)
                .is_some_and(|m| m.final_tokens_by_mode.get(&mode).copied().unwrap_or(0.0) > 0.0)
        })
        .collect();
    ranked.sort_by(|a, b| {
        let ta = metrics[b]
            .final_tokens_by_mode
            .get(&mode)
            .copied()
            .unwrap_or(0.0);
        let tb = metrics[a]
            .final_tokens_by_mode
            .get(&mode)
            .copied()
            .unwrap_or(0.0);
        ta.partial_cmp(&tb).unwrap_or(std::cmp::Ordering::Equal)
    });
    for fid in &ranked {
        let t = metrics[fid]
            .final_tokens_by_mode
            .get(&mode)
            .copied()
            .unwrap_or(0.0);
        wtr.write_record([fid.to_string(), format!("{:.6}", t)])?;
    }
    wtr.flush()?;
    Ok(())
}

fn write_eligibility_csv(
    path: &Path,
    fids: &[u64],
    metrics: &HashMap<u64, FidMetrics>,
    modes: &[MutualityMode],
) -> std::io::Result<()> {
    let mut wtr = csv::Writer::from_path(path)?;

    let mut headers: Vec<String> = vec![
        "fid".into(),
        "age_factor".into(),
        "is_seed".into(),
        "eigentrust_raw".into(),
        "trust_score".into(),
        "interaction_entropy".into(),
        "client_diversity".into(),
        "credibility_weight".into(),
        "total_casts".into(),
        "active_days".into(),
        "unique_engagers".into(),
        "engager_entropy".into(),
        "engagement_per_cast".into(),
        "new_user_engagement_count".into(),
        "total_engagement_count".into(),
        "new_user_engagement_share".into(),
        "replies_received".into(),
        "replies_per_cast".into(),
        "signer_authorizations".into(),
        "mutual_partner_count".into(),
        "filter_0_pass".into(),
        "filter_1_pass".into(),
        "filter_2_pass".into(),
        "filter_3_pass".into(),
        "filter_4_pass".into(),
        "filter_5_pass".into(),
        "filter_6_pass".into(),
        "eligible".into(),
        "fail_reason".into(),
    ];
    for mode in modes {
        headers.push(format!("growth_{}", mode.name()));
        headers.push(format!("composite_{}", mode.name()));
        headers.push(format!("tokens_{}", mode.name()));
    }
    wtr.write_record(&headers)?;

    let mut sorted: Vec<u64> = fids.to_vec();
    // Sort by the first mode's composite (stable fallback if modes is empty).
    let first_mode = modes.first().copied();
    sorted.sort_by(|a, b| {
        let va = first_mode
            .and_then(|m| {
                metrics
                    .get(a)
                    .and_then(|x| x.composite_by_mode.get(&m).copied())
            })
            .unwrap_or(0.0);
        let vb = first_mode
            .and_then(|m| {
                metrics
                    .get(b)
                    .and_then(|x| x.composite_by_mode.get(&m).copied())
            })
            .unwrap_or(0.0);
        vb.partial_cmp(&va).unwrap_or(std::cmp::Ordering::Equal)
    });

    for fid in sorted {
        let m = match metrics.get(&fid) {
            Some(m) => m,
            None => continue,
        };
        let mut row: Vec<String> = vec![
            fid.to_string(),
            format!("{:.6}", m.age_factor),
            m.is_seed.to_string(),
            format!("{:.10}", m.eigentrust_raw),
            format!("{:.6}", m.trust_score),
            format!("{:.6}", m.interaction_entropy),
            format!("{:.6}", m.client_diversity),
            format!("{:.6}", m.credibility_weight),
            m.total_casts.to_string(),
            m.active_days.to_string(),
            m.unique_engagers.to_string(),
            format!("{:.6}", m.engager_entropy),
            format!("{:.6}", m.engagement_per_cast),
            m.new_user_engagement_count.to_string(),
            m.total_engagement_count.to_string(),
            format!("{:.6}", m.new_user_engagement_share),
            m.replies_received.to_string(),
            format!("{:.6}", m.replies_per_cast),
            m.signer_authorizations.to_string(),
            m.all_time_engagement.len().to_string(),
            m.filter_0_pass.to_string(),
            m.filter_1_pass.to_string(),
            m.filter_2_pass.to_string(),
            m.filter_3_pass.to_string(),
            m.filter_4_pass.to_string(),
            m.filter_5_pass.to_string(),
            m.filter_6_pass.to_string(),
            m.eligible.to_string(),
            m.fail_reason.clone(),
        ];
        for mode in modes {
            row.push(format!(
                "{:.6}",
                m.growth_by_mode.get(mode).copied().unwrap_or(0.0)
            ));
            row.push(format!(
                "{:.6}",
                m.composite_by_mode.get(mode).copied().unwrap_or(0.0)
            ));
            row.push(format!(
                "{:.6}",
                m.final_tokens_by_mode.get(mode).copied().unwrap_or(0.0)
            ));
        }
        wtr.write_record(&row)?;
    }
    wtr.flush()?;
    Ok(())
}

fn write_mutuality_comparison_md(
    path: &Path,
    fids: &[u64],
    metrics: &HashMap<u64, FidMetrics>,
    modes: &[MutualityMode],
) -> std::io::Result<()> {
    let mut md = String::new();
    md.push_str("# Retro Rewards — Mutuality Mode Comparison\n\n");
    md.push_str("Each mutuality function produces its own allocation. This document lists the top 20 FIDs per mode and the Spearman rank correlation between modes, so you can see where they agree or disagree.\n\n");

    // Top 20 per mode
    md.push_str("## Top 20 FIDs per mode\n\n");
    for mode in modes {
        md.push_str(&format!("### `{}`\n\n", mode.name()));
        md.push_str(
            "| Rank | FID | Tokens | Composite | Growth | Mutual partners | Credibility |\n",
        );
        md.push_str("|---|---|---|---|---|---|---|\n");
        let mut ranked: Vec<(u64, &FidMetrics)> = metrics
            .iter()
            .filter(|(_, m)| m.final_tokens_by_mode.get(mode).copied().unwrap_or(0.0) > 0.0)
            .map(|(&f, m)| (f, m))
            .collect();
        ranked.sort_by(|a, b| {
            let ta = a.1.final_tokens_by_mode.get(mode).copied().unwrap_or(0.0);
            let tb = b.1.final_tokens_by_mode.get(mode).copied().unwrap_or(0.0);
            tb.partial_cmp(&ta).unwrap_or(std::cmp::Ordering::Equal)
        });
        for (i, (fid, m)) in ranked.iter().take(20).enumerate() {
            md.push_str(&format!(
                "| {} | {} | {:.2} | {:.4} | {:.4} | {} | {:.4} |\n",
                i + 1,
                fid,
                m.final_tokens_by_mode.get(mode).copied().unwrap_or(0.0),
                m.composite_by_mode.get(mode).copied().unwrap_or(0.0),
                m.growth_by_mode.get(mode).copied().unwrap_or(0.0),
                m.all_time_engagement.len(),
                m.credibility_weight,
            ));
        }
        md.push('\n');
    }

    // Spearman matrix over top-5000 of each mode
    md.push_str("## Spearman rank correlation (top-5000 per mode)\n\n");
    md.push_str("Rank correlation on the intersection of each pair of modes' top-5000 FIDs. 1.00 = identical ordering; 0.00 = uncorrelated; negative = inverted.\n\n");

    let mode_ranks: HashMap<MutualityMode, HashMap<u64, u32>> = modes
        .iter()
        .map(|mode| {
            let mut ranked: Vec<(u64, f64)> = fids
                .iter()
                .filter_map(|&fid| {
                    metrics
                        .get(&fid)
                        .and_then(|m| m.final_tokens_by_mode.get(mode).copied())
                        .filter(|v| *v > 0.0)
                        .map(|v| (fid, v))
                })
                .collect();
            ranked.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
            let map: HashMap<u64, u32> = ranked
                .into_iter()
                .take(5000)
                .enumerate()
                .map(|(i, (fid, _))| (fid, (i + 1) as u32))
                .collect();
            (*mode, map)
        })
        .collect();

    md.push_str("| |");
    for mode in modes {
        md.push_str(&format!(" `{}` |", mode.name()));
    }
    md.push('\n');
    md.push_str("|---|");
    for _ in modes {
        md.push_str("---|");
    }
    md.push('\n');
    for mode_a in modes {
        md.push_str(&format!("| `{}` |", mode_a.name()));
        for mode_b in modes {
            let rho = spearman(&mode_ranks[mode_a], &mode_ranks[mode_b]);
            md.push_str(&format!(" {:.3} |", rho));
        }
        md.push('\n');
    }
    md.push('\n');

    md.push_str("## Interpretation\n\n");
    md.push_str("- Modes with ρ ≥ 0.99 against each other produce essentially the same ranking — pick the simpler one and drop the rest.\n");
    md.push_str("- Modes with ρ < 0.9 produce materially different rankings — worth looking at side-by-side before committing.\n");
    md.push_str("- If the bot-survivor FIDs you know (e.g. 535436) show up in some modes but not others, the modes where they're absent are doing the work you want.\n");

    fs::write(path, md)?;
    Ok(())
}

fn spearman(a: &HashMap<u64, u32>, b: &HashMap<u64, u32>) -> f64 {
    let (small, large) = if a.len() <= b.len() { (a, b) } else { (b, a) };
    let mut pairs: Vec<(u32, u32)> = Vec::with_capacity(small.len());
    for (fid, ra) in small {
        if let Some(rb) = large.get(fid) {
            pairs.push((*ra, *rb));
        }
    }
    let n = pairs.len();
    if n < 10 {
        return 0.0;
    }

    let mut a_sorted: Vec<(usize, u32)> = pairs
        .iter()
        .enumerate()
        .map(|(i, (r, _))| (i, *r))
        .collect();
    a_sorted.sort_by_key(|(_, r)| *r);
    let mut ra = vec![0u32; n];
    for (new_rank, (orig, _)) in a_sorted.iter().enumerate() {
        ra[*orig] = (new_rank + 1) as u32;
    }

    let mut b_sorted: Vec<(usize, u32)> = pairs
        .iter()
        .enumerate()
        .map(|(i, (_, r))| (i, *r))
        .collect();
    b_sorted.sort_by_key(|(_, r)| *r);
    let mut rb = vec![0u32; n];
    for (new_rank, (orig, _)) in b_sorted.iter().enumerate() {
        rb[*orig] = (new_rank + 1) as u32;
    }

    let mut sum_d_sq: f64 = 0.0;
    for i in 0..n {
        let d = ra[i] as f64 - rb[i] as f64;
        sum_d_sq += d * d;
    }
    let n_f = n as f64;
    1.0 - (6.0 * sum_d_sq) / (n_f * n_f * n_f - n_f)
}

#[allow(clippy::too_many_arguments)]
fn write_report_md(
    path: &Path,
    args: &Cli,
    entropy_threshold: f64,
    ratio_threshold: f64,
    new_user_share_threshold: f64,
    replies_per_cast_threshold: f64,
    counts: &FilterCounts,
    metrics: &HashMap<u64, FidMetrics>,
    modes: &[MutualityMode],
) -> std::io::Result<()> {
    let total = metrics.len();
    let mut md = String::new();
    md.push_str("# Retro Rewards — Final Allocation Report\n\n");
    md.push_str(&format!(
        "Reproducible end-to-end run. Hub: `{}`. Pool: {:.0} tokens per mode.\n\n",
        args.hub_url, RETROACTIVE_POOL
    ));

    md.push_str("## Scoring model\n\n");
    md.push_str("Growth is sustained mutual engagement, filtered by custody-transfer events:\n\n");
    md.push_str("```\n");
    md.push_str("growth(f) = Σ over u with mutual post-transfer engagement:\n");
    md.push_str("              mutuality(count(f→u), count(u→f)) · credibility(u)\n");
    md.push('\n');
    md.push_str("count(a→b) includes only events with\n");
    md.push_str("  ts > max(a.effective_ts, b.effective_ts)\n");
    md.push_str("```\n\n");
    md.push_str("composite(f) = credibility(f) · growth(f); pool split proportional to composite among eligible FIDs.\n\n");

    md.push_str("## Mutuality modes evaluated\n\n");
    md.push_str("| Mode | `mutuality(a, b)` |\n|---|---|\n");
    md.push_str("| `min` | `min(a, b)` |\n");
    md.push_str("| `geom` | `sqrt(a · b)` |\n");
    md.push_str("| `harmonic` | `2ab / (a + b)` |\n");
    md.push_str("| `avg` | `(a + b) / 2` (gated on both > 0) |\n");
    md.push_str("| `sum` | `a + b` (gated on both > 0) |\n\n");
    md.push_str("See `mutuality_comparison.md` for top-20 per mode and Spearman correlation between modes.\n\n");

    md.push_str("## Eligibility filter summary\n\n");
    md.push_str(&format!("Total FIDs evaluated: **{}**\n\n", total));
    md.push_str("| Filter | Description | Threshold | Eliminated |\n");
    md.push_str("|---|---|---|---|\n");
    md.push_str(&format!(
        "| 0 | App detection (signer authorizations) | ≥ {} → app | {} |\n",
        args.app_threshold, counts.fail_0
    ));
    md.push_str(&format!(
        "| 1 | Minimum post-transfer activity | total_casts > 0 | {} |\n",
        counts.fail_1
    ));
    md.push_str(&format!(
        "| 2 | Received engagement (post-transfer) | unique_engagers ≥ {} | {} |\n",
        args.min_engagers, counts.fail_2
    ));
    md.push_str(&format!(
        "| 3 | Engager diversity | Shannon entropy ≥ {:.4} | {} |\n",
        entropy_threshold, counts.fail_3
    ));
    md.push_str(&format!(
        "| 4 | Engagement per cast {} | ≥ {:.4} | {} |\n",
        if args.strict {
            "(strict)"
        } else {
            "(disabled)"
        },
        ratio_threshold,
        counts.fail_4
    ));
    md.push_str(&format!(
        "| 5 | New-user engagement share (upper tail) | < {:.4} | {} |\n",
        new_user_share_threshold, counts.fail_5
    ));
    md.push_str(&format!(
        "| 6 | Replies received per cast | ≥ {:.4} | {} |\n",
        replies_per_cast_threshold, counts.fail_6
    ));
    md.push_str(&format!(
        "\n**Eligible after all filters: {}**\n\n",
        counts.pass
    ));

    md.push_str("## Per-mode allocation counts\n\n");
    md.push_str("| Mode | FIDs with non-zero allocation |\n|---|---|\n");
    for mode in modes {
        let allocated = metrics
            .values()
            .filter(|m| m.final_tokens_by_mode.get(mode).copied().unwrap_or(0.0) > 0.0)
            .count();
        md.push_str(&format!("| `{}` | {} |\n", mode.name(), allocated));
    }
    md.push('\n');

    md.push_str("## Reproducibility\n\n");
    md.push_str("```\n");
    md.push_str(&format!(
        "retro_rewards_finalize --hub-url {} --output-dir {} --mutuality-modes {}{}\n",
        args.hub_url,
        args.output_dir,
        args.mutuality_modes,
        if args.strict { " --strict" } else { "" }
    ));
    md.push_str("```\n\n");
    md.push_str("No intermediate CSVs. No labels. No patterns. Every exclusion and every score is derived from protocol endpoints at run time, with custody-transfer events as the only temporal boundary.\n");

    fs::write(path, md)?;
    Ok(())
}

fn progress_bar(len: u64, prefix: &str) -> ProgressBar {
    let pb = ProgressBar::new(len);
    pb.set_style(
        ProgressStyle::with_template("{prefix} [{bar:40.cyan/blue}] {pos}/{len} ({eta})")
            .unwrap()
            .progress_chars("=> "),
    );
    pb.set_prefix(prefix.to_string());
    pb
}
