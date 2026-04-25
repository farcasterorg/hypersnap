//! Retro Rewards Finalizer — multi-mutuality allocation
//!
//! End-to-end reproducible retro allocation from hub endpoints. The growth
//! signal is **sustained mutual engagement**, not onboarding-window activity:
//!
//!   growth_score(f) = Σ over u with reciprocal all-time, post-transfer
//!                     engagement:
//!                         mutuality( count(f→u), count(u→f) )
//!                         · credibility(u)
//!   composite(f)    = credibility(f) · growth_score(f)
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
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use alloy_sol_types::SolType;
use clap::Parser;
use indicatif::{ProgressBar, ProgressStyle};
use serde::Deserialize;

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
    /// Default is `sum` — the protocol-canonical choice per FIP-proof-of-work-
    /// tokenization Section 6. Pass multiple modes (e.g. `min,geom,sum`) to
    /// produce side-by-side comparison outputs.
    #[arg(long, default_value = "sum")]
    mutuality_modes: String,

    #[arg(long, default_value_t = 100)]
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

    #[arg(long)]
    strict: bool,
}

// ---- Batch response types ----

#[derive(Debug, Deserialize)]
struct FidsResponse {
    fids: Vec<u64>,
    #[serde(rename = "nextPageToken")]
    next_page_token: Option<String>,
}

#[derive(Debug, Deserialize)]
struct BatchSignerEntry {
    metadata: String,
    metadata_type: u32,
}

#[derive(Debug, Deserialize)]
struct BatchIdRegEntry {
    block_timestamp: u64,
    event_type: String,
}

#[derive(Debug, Deserialize)]
struct BatchFollowEntry {
    fid: u64,
    followed_at: Option<String>,
}

#[derive(Debug, Deserialize)]
struct BatchReactionEntry {
    target_fid: u64,
    timestamp: u32,
}

#[derive(Debug, Deserialize)]
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
}

impl HubClient {
    fn new(base_url: &str) -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(120))
            .build()
            .expect("failed to build HTTP client");
        Self {
            client,
            base_url: base_url.trim_end_matches('/').to_string(),
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

    async fn batch_id_registrations(&self, fids: &[u64]) -> HashMap<u64, Vec<BatchIdRegEntry>> {
        match self
            .batch_post::<BatchIdRegEntry>("id-registrations", fids)
            .await
        {
            Ok(m) => parse_batch_map(m),
            Err(e) => {
                eprintln!("Warning: batch id-registrations failed: {}", e);
                HashMap::new()
            }
        }
    }

    async fn batch_signers(&self, fids: &[u64]) -> HashMap<u64, Vec<BatchSignerEntry>> {
        match self.batch_post::<BatchSignerEntry>("signers", fids).await {
            Ok(m) => parse_batch_map(m),
            Err(e) => {
                eprintln!("Warning: batch signers failed: {}", e);
                HashMap::new()
            }
        }
    }

    async fn batch_following(&self, fids: &[u64]) -> HashMap<u64, Vec<BatchFollowEntry>> {
        match self.batch_post::<BatchFollowEntry>("following", fids).await {
            Ok(m) => parse_batch_map(m),
            Err(e) => {
                eprintln!("Warning: batch following failed: {}", e);
                HashMap::new()
            }
        }
    }

    async fn batch_reactions(&self, fids: &[u64]) -> HashMap<u64, Vec<BatchReactionEntry>> {
        match self
            .batch_post::<BatchReactionEntry>("reactions", fids)
            .await
        {
            Ok(m) => parse_batch_map(m),
            Err(e) => {
                eprintln!("Warning: batch reactions failed: {}", e);
                HashMap::new()
            }
        }
    }

    async fn batch_cast_bodies(&self, fids: &[u64]) -> HashMap<u64, Vec<BatchCastBody>> {
        match self.batch_post::<BatchCastBody>("cast-bodies", fids).await {
            Ok(m) => parse_batch_map(m),
            Err(e) => {
                eprintln!("Warning: batch cast-bodies failed: {}", e);
                HashMap::new()
            }
        }
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

    let hub = HubClient::new(&args.hub_url);
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

    // Phase 2a: id-registrations → effective_ts for every FID (needed before
    // we can apply the transfer filter to any interaction.)
    eprintln!("\nPhase 2a: Fetching id-registrations…");
    fetch_id_registrations(&hub, &all_fids, &mut metrics).await;

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

    // Filter 5 derivation: sum over u of u's outbound_first_30d[target] into
    // target's new_user_engagement_count.
    let mut new_user_received: HashMap<u64, u32> = HashMap::new();
    for m in metrics.values() {
        for (&f, &count) in &m.outbound_first_30d {
            *new_user_received.entry(f).or_default() += count;
        }
    }
    for (fid, m) in metrics.iter_mut() {
        m.new_user_engagement_count = new_user_received.get(fid).copied().unwrap_or(0);
        m.new_user_engagement_share = if m.total_engagement_count > 0 {
            m.new_user_engagement_count as f64 / m.total_engagement_count as f64
        } else {
            0.0
        };
    }

    // Phase 4: thresholds + eligibility filters (shared across all modes).
    // Thresholds are calibrated against the **calibration cohort** — broader
    // than the EigenTrust seed cohort, representing typical real users.
    // Activity-based only (no timestamp criteria): the OP Mainnet migration
    // corrupted effective_ts for older accounts, so age-based filtering
    // would silently exclude legitimate long-term users.
    eprintln!("\nPhase 4: Computing filter thresholds (calibrated against calibration cohort)…");
    let in_cal = |m: &FidMetrics| {
        meets_calibration_criteria(
            m,
            args.calibration_min_casts,
            args.calibration_min_active_days,
        )
    };
    let calibration_size = metrics.values().filter(|m| in_cal(m)).count();
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
    // Hard trust floor for growth-credit contributions. Crediters whose
    // trust_score sits below this floor contribute zero to anyone's growth.
    // Calibrated as the 10th-percentile trust over the calibration cohort:
    // genuine mid-tier users sit above; ring sockpuppets (whose EigenTrust
    // sits near the noise floor) sit below.
    let crediter_trust_threshold =
        cohort_percentile_threshold(&metrics, in_cal, args.threshold_percentile, |m| {
            m.trust_score
        });
    eprintln!(
        "  calibration cohort: {} FIDs (casts ≥ {}, active_days ≥ {})",
        calibration_size, args.calibration_min_casts, args.calibration_min_active_days
    );
    eprintln!(
        "  entropy ≥ {:.4}, engagement/cast ≥ {:.4}, new-user-share < {:.4}, replies/cast ≥ {:.4}, crediter_trust ≥ {:.4}",
        entropy_threshold, ratio_threshold, new_user_share_threshold, replies_per_cast_threshold, crediter_trust_threshold
    );
    if calibration_size == 0 {
        eprintln!("  WARNING: calibration cohort is empty. Thresholds are 0 → filter 5 will fail everyone.");
        eprintln!("           Check that id-registration timestamps are being parsed correctly.");
    }

    eprintln!("\nPhase 5: Applying eligibility filters…");
    let mut counts = FilterCounts::default();
    for m in metrics.values_mut() {
        m.filter_0_pass = m.signer_authorizations < args.app_threshold;
        m.filter_1_pass = m.total_casts > 0;
        m.filter_2_pass = m.unique_engagers >= args.min_engagers;
        m.filter_3_pass = m.engager_entropy >= entropy_threshold;
        m.filter_4_pass = !args.strict || m.engagement_per_cast >= ratio_threshold;
        m.filter_5_pass = m.new_user_engagement_share < new_user_share_threshold;
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

    // Phase 6: per-mode growth scoring, composite, renormalization
    eprintln!("\nPhase 6: Per-mode growth scoring and pool renormalization…");
    compute_growth_scores(&all_fids, &mut metrics, &modes, crediter_trust_threshold);

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
) {
    let pb = progress_bar(all_fids.len() as u64, "id-reg");
    for chunk in all_fids.chunks(BATCH_SIZE) {
        let id_regs = hub.batch_id_registrations(chunk).await;
        for &fid in chunk {
            let events = id_regs.get(&fid).map(|v| v.as_slice()).unwrap_or(&[]);
            let (age, reg, eff) = compute_age_facts(events);
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

fn compute_age_facts(events: &[BatchIdRegEntry]) -> (f64, Option<u64>, Option<u64>) {
    if events.is_empty() {
        return (0.0, None, None);
    }
    let mut latest_transfer = 0u64;
    let mut earliest_reg = u64::MAX;
    for e in events {
        if e.event_type == "Transfer" {
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

    // Flush credits into metrics
    for mode in modes {
        let mode_credits = credits.remove(mode).unwrap_or_default();
        for (fid, growth) in mode_credits {
            if let Some(m) = metrics.get_mut(&fid) {
                let composite = m.credibility_weight * growth;
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
