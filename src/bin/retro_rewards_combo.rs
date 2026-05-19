//! Retroactive Rewards Combination Analyzer
//!
//! Runs the Growth-PoW retroactive scoring pipeline for every non-empty
//! subset of a 7-feature configuration space — 127 combinations total.
//!
//! The **baseline** (no features enabled) reproduces the ORIGINAL
//! `retro_rewards.rs` output exactly. Each of the seven feature flags is a
//! targeted departure from that baseline, corresponding to the seven
//! differences I identified between the original and the multi-mode
//! `retro_rewards_new.rs`:
//!
//!   1. **flipped_multiplier** — weight each credit by the inviter's trust
//!      (with a floor) instead of the recipient's credibility weight.
//!   2. **reciprocity_gate** — require `out_f→u > 0`, multiply credit by
//!      `min(out_u→f, out_f→u) / max(...)`.
//!   3. **eigentrust** — replace the flat `trust = 0.5` with EigenTrust
//!      propagated from a seed set (effective age ≥ 180d AND ≥100 casts
//!      across ≥30 active days), normalized by 99th-percentile, multiplied
//!      by age_factor. No cluster penalty.
//!   4. **cohort_concentration** — dampen credit when the recipient appears
//!      as a top-N interactor for many members of the new user's registration
//!      cohort.
//!   5. **top_n_restriction** — only credit the top-10 counterparties per
//!      new user (baseline credits every counterparty).
//!   6. **no_hardcoded_exclusion** — do NOT zero out the hardcoded FID list
//!      `[1, 9152, 16823, 18548, 193137, 309857, 460608, 1446240]` (baseline
//!      does zero these out).
//!   7. **gini_dispersion** — activity_score = `ln(total+1) × (1 − gini(daily))`
//!      instead of the plain `ln(total).max(0)`.
//!
//! All 2⁷ − 1 = 127 non-empty subsets are evaluated. Output: one CSV per
//! combination under `<output_dir>/combo_NNN.csv` (NNN = 3-digit bitmask),
//! plus a top-level `index.csv` mapping each bitmask to its feature list,
//! seed-set size, and number of FIDs with non-zero allocation.
//!
//! Section 10.2.a structural-follow exclusion is NOT among the seven features
//! and is not applied (per user direction to drop the auto-follow penalty).
//!
//! Uses the same batch endpoints as the original (`/batch/following`,
//! `/batch/reactions`, `/batch/cast-interactions`, `/batch/signers`,
//! `/batch/id-registrations`) — no SimHash, no cast-body pull.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use alloy_sol_types::SolType;
use clap::Parser;
use indicatif::{ProgressBar, ProgressStyle};
use serde::Deserialize;

// ---- Constants ----

const NUM_SHARDS: u32 = 2;
const BATCH_SIZE: usize = 100;

const THIRTY_DAYS_SECS: u64 = 30 * 24 * 3600;
const SIX_MONTHS_SECS: f64 = 15_552_000.0;
const FARCASTER_EPOCH: u64 = 1_609_459_200;
const AUTOFOLLOW_WINDOW_SECS: u64 = 60;
const COHORT_LENGTH_SECS: u64 = 7 * 24 * 3600;

/// Flat trust placeholder (baseline; feature 3 replaces with EigenTrust).
const TRUST_SCORE_PLACEHOLDER: f64 = 0.5;

// Credibility weights (Section 8 of FIP-proof-of-work-tokenization)
const W_AGE: f64 = 0.25;
const W_TRUST: f64 = 0.35;
const W_ENTROPY: f64 = 0.20;
const W_STAKE: f64 = 0.10;
const W_DIVERSITY: f64 = 0.10;

const GROWTH_WEIGHT: f64 = 1.0;
const RETROACTIVE_POOL: f64 = 200_000_000.0;

/// Baseline behavior zeroes these FIDs out. Feature 6 disables that.
const RETROACTIVE_EXCLUDED_FIDS_APP: &[u64] =
    &[1, 9152, 16823, 18548, 193137, 309857, 460608, 1446240];

// Feature-4 parameters
const CONCENTRATION_BASELINE: f64 = 0.01;
const CONCENTRATION_SLOPE: f64 = 50.0;
const TOP_N_INTERACTORS: usize = 10;

// Feature-1 parameter: inviter trust floor
const COUNTERPARTY_FLOOR: f64 = 0.05;

// Feature-3 parameters
const POQ_DAMPING_FACTOR: f64 = 0.85;
const POQ_MAX_ITERATIONS: usize = 50;
const POQ_CONVERGENCE_TOLERANCE: f64 = 1e-6;
const POQ_SEED_MIN_AGE_SECS: u64 = 180 * 24 * 3600;
const POQ_SEED_MIN_CASTS: u32 = 100;
const POQ_SEED_MIN_ACTIVE_DAYS: u32 = 30;

// ---- CLI ----

#[derive(Parser)]
#[command(
    name = "retro_rewards_combo",
    about = "Runs retro scoring for all 127 combinations of 7 feature toggles"
)]
struct Cli {
    #[arg(long, default_value = "http://localhost:2281")]
    hub_url: String,

    /// Output directory for all combination CSVs and index.csv
    #[arg(long, default_value = "retro_rewards_combo")]
    output_dir: String,

    /// Bitmask of combinations to skip (useful for resuming partial runs).
    /// Comma-separated list of decimal bitmasks, e.g. `--skip 1,3,127`.
    #[arg(long, default_value = "")]
    skip: String,
}

// ---- FeatureSet ----

#[derive(Debug, Clone, Copy, Default)]
struct FeatureSet {
    flipped_multiplier: bool,     // 1
    reciprocity_gate: bool,       // 2
    eigentrust: bool,             // 3
    cohort_concentration: bool,   // 4
    top_n_restriction: bool,      // 5
    no_hardcoded_exclusion: bool, // 6
    gini_dispersion: bool,        // 7
}

impl FeatureSet {
    fn from_bitmask(mask: u8) -> Self {
        Self {
            flipped_multiplier: mask & 0b0000001 != 0,
            reciprocity_gate: mask & 0b0000010 != 0,
            eigentrust: mask & 0b0000100 != 0,
            cohort_concentration: mask & 0b0001000 != 0,
            top_n_restriction: mask & 0b0010000 != 0,
            no_hardcoded_exclusion: mask & 0b0100000 != 0,
            gini_dispersion: mask & 0b1000000 != 0,
        }
    }

    /// Human-readable label: sorted feature ids joined by "-". e.g., "1-3-7".
    fn label(&self) -> String {
        let mut parts: Vec<&str> = Vec::new();
        if self.flipped_multiplier {
            parts.push("1");
        }
        if self.reciprocity_gate {
            parts.push("2");
        }
        if self.eigentrust {
            parts.push("3");
        }
        if self.cohort_concentration {
            parts.push("4");
        }
        if self.top_n_restriction {
            parts.push("5");
        }
        if self.no_hardcoded_exclusion {
            parts.push("6");
        }
        if self.gini_dispersion {
            parts.push("7");
        }
        if parts.is_empty() {
            "baseline".to_string()
        } else {
            parts.join("-")
        }
    }

    /// Verbose label: feature names joined by "+".
    fn verbose_label(&self) -> String {
        let mut parts: Vec<&str> = Vec::new();
        if self.flipped_multiplier {
            parts.push("flipped_multiplier");
        }
        if self.reciprocity_gate {
            parts.push("reciprocity_gate");
        }
        if self.eigentrust {
            parts.push("eigentrust");
        }
        if self.cohort_concentration {
            parts.push("cohort_concentration");
        }
        if self.top_n_restriction {
            parts.push("top_n_restriction");
        }
        if self.no_hardcoded_exclusion {
            parts.push("no_hardcoded_exclusion");
        }
        if self.gini_dispersion {
            parts.push("gini_dispersion");
        }
        if parts.is_empty() {
            "baseline".to_string()
        } else {
            parts.join("+")
        }
    }
}

// ---- Batch response types ----

#[derive(Debug, Deserialize)]
struct FidsResponse {
    fids: Vec<u64>,
    #[serde(rename = "nextPageToken")]
    next_page_token: Option<String>,
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
struct BatchCastInteraction {
    parent_fid: Option<u64>,
    #[serde(default)]
    mentions: Vec<u64>,
    timestamp: u32,
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

alloy_sol_types::sol! {
    struct SignedKeyRequestMetadata {
        uint256 requestFid;
        address requestSigner;
        bytes signature;
        uint256 deadline;
    }
}

// ---- Core types ----

#[derive(Default, Clone)]
struct FidStats {
    reg_ts: Option<u64>,
    age_factor: f64,
    interaction_entropy: f64,
    client_diversity: f64,
    /// Credibility WITH flat trust = 0.5 (baseline value); each combination
    /// recomputes this using its effective trust.
    credibility_baseline: f64,
    /// EigenTrust-derived trust score, ∈ [0, 1]. Computed once.
    trust_eigentrust: f64,
    is_seed: bool,
    total_casts: u32,
    active_days: u32,
}

/// A per-combination FID output row.
#[derive(Default, Clone)]
struct ComboRow {
    trust_score: f64,
    credibility_weight: f64,
    growth_score: f64,
    composite_score: f64,
    allocation_share: f64,
    tokens: f64,
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
        if let Some(token) = page_token {
            url.push_str(&format!("&page_token={}", urlencoding::encode(token)));
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
            Ok(map) => parse_batch_map(map),
            Err(e) => {
                eprintln!("Warning: batch id-registrations failed: {}", e);
                HashMap::new()
            }
        }
    }

    async fn batch_signers(&self, fids: &[u64]) -> HashMap<u64, Vec<BatchSignerEntry>> {
        match self.batch_post::<BatchSignerEntry>("signers", fids).await {
            Ok(map) => parse_batch_map(map),
            Err(e) => {
                eprintln!("Warning: batch signers failed: {}", e);
                HashMap::new()
            }
        }
    }

    async fn batch_following(&self, fids: &[u64]) -> HashMap<u64, Vec<BatchFollowEntry>> {
        match self.batch_post::<BatchFollowEntry>("following", fids).await {
            Ok(map) => parse_batch_map(map),
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
            Ok(map) => parse_batch_map(map),
            Err(e) => {
                eprintln!("Warning: batch reactions failed: {}", e);
                HashMap::new()
            }
        }
    }

    async fn batch_cast_interactions(
        &self,
        fids: &[u64],
    ) -> HashMap<u64, Vec<BatchCastInteraction>> {
        match self
            .batch_post::<BatchCastInteraction>("cast-interactions", fids)
            .await
        {
            Ok(map) => parse_batch_map(map),
            Err(e) => {
                eprintln!("Warning: batch cast-interactions failed: {}", e);
                HashMap::new()
            }
        }
    }
}

fn parse_batch_map<T>(map: HashMap<String, Vec<T>>) -> HashMap<u64, Vec<T>> {
    map.into_iter()
        .filter_map(|(k, v)| k.parse::<u64>().ok().map(|fid| (fid, v)))
        .collect()
}

fn extract_app_fid_from_signer(signer: &BatchSignerEntry) -> Option<u64> {
    if signer.metadata_type != 1 {
        return None;
    }
    let metadata_bytes =
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &signer.metadata)
            .ok()?;
    if metadata_bytes.is_empty() {
        return None;
    }
    let decoded = SignedKeyRequestMetadata::abi_decode(&metadata_bytes, true).ok()?;
    decoded.requestFid.try_into().ok()
}

// ---- Main ----

#[tokio::main]
async fn main() {
    let args = Cli::parse();
    let hub = HubClient::new(&args.hub_url);

    let output_dir = PathBuf::from(&args.output_dir);
    std::fs::create_dir_all(&output_dir).expect("failed to create output directory");

    let skip_set: HashSet<u8> = args
        .skip
        .split(',')
        .filter_map(|s| s.trim().parse::<u8>().ok())
        .collect();

    eprintln!("Connecting to hub at '{}'...", args.hub_url);
    eprintln!("Output directory: {}", output_dir.display());
    if !skip_set.is_empty() {
        eprintln!("Skipping {} combinations per --skip flag", skip_set.len());
    }

    // Phase 1: enumerate FIDs
    eprintln!("\nPhase 1: Enumerating all FIDs...");
    let all_fids = collect_all_fids(&hub).await;
    eprintln!("  Found {} FIDs", all_fids.len());
    if all_fids.is_empty() {
        eprintln!("No FIDs found. Exiting.");
        return;
    }

    // Phase 2: fetch + build precomputed indexes
    eprintln!("\nPhase 2: Fetching batch data and building shared indexes...");
    let shared = fetch_and_index(&hub, &all_fids).await;
    eprintln!(
        "  stats: {} | u→f pairs: {} | f→u pairs: {} | follow graph: {} nodes",
        shared.stats.len(),
        shared
            .u_to_f_counts
            .values()
            .map(|m| m.len())
            .sum::<usize>(),
        shared
            .f_to_u_counts
            .values()
            .map(|m| m.len())
            .sum::<usize>(),
        shared.follow_graph.len(),
    );

    // Phase 3: seed set + EigenTrust (only needed for feature 3, but cheap to compute once)
    eprintln!("\nPhase 3: Computing PoQ seed set + EigenTrust (for feature 3)...");
    let seed_set = build_poq_seed_set(&shared.stats);
    eprintln!("  Seed set size: {}", seed_set.len());
    let eigentrust_raw = compute_eigentrust(&shared.follow_graph, &seed_set);
    let eigentrust_norm = percentile_99_norm(&eigentrust_raw);
    // Final trust_eigentrust per FID = normalized × age_factor, clamped.
    let mut stats = shared.stats;
    for (&fid, s) in stats.iter_mut() {
        let raw = eigentrust_raw.get(&fid).copied().unwrap_or(0.0);
        let normalized = (raw / eigentrust_norm).min(1.0);
        s.trust_eigentrust = (normalized * s.age_factor).clamp(0.0, 1.0);
        s.is_seed = seed_set.contains(&fid);
    }

    // Phase 4: top-N per u + cohort concentration
    eprintln!("\nPhase 4: Precomputing top-N and cohort concentration (for features 4, 5)...");
    let top_n_by_user = compute_top_n(&all_fids, &stats, &shared.u_to_f_counts);
    let concentration = compute_concentration_dampening(&stats, &top_n_by_user);
    eprintln!(
        "  top-N entries: {} | concentration entries: {}",
        top_n_by_user.values().map(|v| v.len()).sum::<usize>(),
        concentration.len()
    );

    // Phase 5: enumerate all 127 non-empty combinations, run scoring per combination.
    eprintln!("\nPhase 5: Running {} combinations...", 127);
    let mut index_rows: Vec<IndexRow> = Vec::with_capacity(127);
    let pb = make_progress_bar(127, "combos");
    for mask in 1u8..=127 {
        if skip_set.contains(&mask) {
            pb.inc(1);
            continue;
        }
        let features = FeatureSet::from_bitmask(mask);
        let combo = run_combination(
            mask,
            features,
            &all_fids,
            &stats,
            &shared.u_to_f_counts,
            &shared.f_to_u_counts,
            &top_n_by_user,
            &concentration,
            &shared.daily_activity,
        );
        let filename = format!("combo_{:03}.csv", mask);
        let path = output_dir.join(&filename);
        write_csv(&path, &all_fids, &combo);

        let nonzero = combo.values().filter(|r| r.tokens > 0.0).count();
        let top_fid = top_fid_by_tokens(&combo);
        index_rows.push(IndexRow {
            bitmask: mask,
            filename,
            label: features.label(),
            verbose_label: features.verbose_label(),
            nonzero_count: nonzero,
            top_fid,
        });
        pb.inc(1);
    }
    pb.finish_with_message("done");

    // Phase 6: write index.csv
    let index_path = output_dir.join("index.csv");
    write_index(&index_path, &index_rows, seed_set.len(), &stats);
    eprintln!(
        "\nDone. Wrote 127 combinations + index to {}",
        output_dir.display()
    );
}

// ---- Phase 1: enumerate FIDs ----

async fn collect_all_fids(hub: &HubClient) -> Vec<u64> {
    let mut fid_set: HashSet<u64> = HashSet::new();
    for shard_id in 1..=NUM_SHARDS {
        let mut page_token: Option<String> = None;
        loop {
            match hub.get_fids(shard_id, page_token.as_deref()).await {
                Ok(resp) => {
                    if resp.fids.is_empty() {
                        break;
                    }
                    fid_set.extend(resp.fids);
                    match resp.next_page_token {
                        Some(t) if !t.is_empty() => page_token = Some(t),
                        _ => break,
                    }
                }
                Err(e) => {
                    eprintln!(
                        "Warning: error fetching FIDs for shard {}: {:?}",
                        shard_id, e
                    );
                    break;
                }
            }
        }
    }
    let mut fids: Vec<u64> = fid_set.into_iter().collect();
    fids.sort();
    fids
}

// ---- Phase 2: shared indexes ----

struct SharedData {
    stats: HashMap<u64, FidStats>,
    /// u_to_f_counts[u][f] = count of u's outbound interactions (casts+reactions+follows)
    /// to f within u's OWN first-30-days window. Matches baseline scoring semantics.
    u_to_f_counts: HashMap<u64, HashMap<u64, u32>>,
    /// f_to_u_counts[u][f] = count of f's outbound interactions to u within
    /// u's first-30-days window. Used by feature 2 (reciprocity).
    f_to_u_counts: HashMap<u64, HashMap<u64, u32>>,
    follow_graph: HashMap<u64, Vec<u64>>,
    daily_activity: HashMap<u64, Vec<u32>>,
}

async fn fetch_and_index(hub: &HubClient, all_fids: &[u64]) -> SharedData {
    // Step 2a: fetch id-registrations → reg_ts + age_factor (needed to window-filter)
    eprintln!("  Step 2a: Fetching id-registrations...");
    let mut reg_ts_map: HashMap<u64, u64> = HashMap::new();
    let mut stats: HashMap<u64, FidStats> = HashMap::with_capacity(all_fids.len());
    let pb = make_progress_bar(all_fids.len() as u64, "  id-reg");
    for chunk in all_fids.chunks(BATCH_SIZE) {
        let id_regs = hub.batch_id_registrations(chunk).await;
        for &fid in chunk {
            let events = id_regs.get(&fid).map(|v| v.as_slice()).unwrap_or(&[]);
            let (age, reg_ts) = compute_age_factor(events);
            if let Some(ts) = reg_ts {
                reg_ts_map.insert(fid, ts);
            }
            stats.insert(
                fid,
                FidStats {
                    reg_ts,
                    age_factor: age,
                    ..Default::default()
                },
            );
            pb.inc(1);
        }
    }
    pb.finish_with_message("done");

    // Step 2b: fetch signers/following/reactions/casts; build edges, posting history, follow graph.
    eprintln!("  Step 2b: Fetching interactions and building edge indexes...");
    let pb = make_progress_bar(all_fids.len() as u64, "  edges");

    let mut u_to_f_counts: HashMap<u64, HashMap<u64, u32>> = HashMap::with_capacity(all_fids.len());
    let mut f_to_u_counts: HashMap<u64, HashMap<u64, u32>> = HashMap::with_capacity(all_fids.len());
    let mut follow_graph: HashMap<u64, Vec<u64>> = HashMap::with_capacity(all_fids.len());
    let mut daily_activity: HashMap<u64, Vec<u32>> = HashMap::with_capacity(all_fids.len());

    for chunk in all_fids.chunks(BATCH_SIZE) {
        let (signers, following, reactions, casts) = tokio::join!(
            hub.batch_signers(chunk),
            hub.batch_following(chunk),
            hub.batch_reactions(chunk),
            hub.batch_cast_interactions(chunk),
        );

        for &src in chunk {
            let src_reg = reg_ts_map.get(&src).copied();
            let empty_casts: Vec<BatchCastInteraction> = Vec::new();
            let empty_reactions: Vec<BatchReactionEntry> = Vec::new();
            let empty_following: Vec<BatchFollowEntry> = Vec::new();
            let cast_list = casts.get(&src).unwrap_or(&empty_casts);
            let reaction_list = reactions.get(&src).unwrap_or(&empty_reactions);
            let follow_list = following.get(&src).unwrap_or(&empty_following);

            // Entropy + diversity
            let entropy =
                compute_interaction_entropy(src, src_reg, cast_list, reaction_list, follow_list);
            let diversity =
                compute_client_diversity(signers.get(&src).map(|v| v.as_slice()).unwrap_or(&[]));

            // Posting history (for seed set)
            let total_casts = cast_list.len() as u32;
            let mut distinct_days: HashSet<u64> = HashSet::new();
            for cast in cast_list {
                distinct_days.insert((cast.timestamp as u64 + FARCASTER_EPOCH) / 86_400);
            }
            let active_days = distinct_days.len() as u32;

            let age = stats.get(&src).map(|s| s.age_factor).unwrap_or(0.0);
            let credibility_baseline =
                compute_credibility_weight(age, TRUST_SCORE_PLACEHOLDER, entropy, diversity);

            let stats_entry = stats.entry(src).or_default();
            stats_entry.interaction_entropy = entropy;
            stats_entry.client_diversity = diversity;
            stats_entry.credibility_baseline = credibility_baseline;
            stats_entry.total_casts = total_casts;
            stats_entry.active_days = active_days;

            // Per-src daily activity histogram (src's first-30-days window)
            if let Some(r) = src_reg {
                let window_end = r + THIRTY_DAYS_SECS;
                let mut days = vec![0u32; 31];
                for cast in cast_list {
                    let ts = cast.timestamp as u64 + FARCASTER_EPOCH;
                    if ts >= r && ts <= window_end {
                        let d = ((ts - r) / 86_400).min(30) as usize;
                        days[d] = days[d].saturating_add(1);
                    }
                }
                for rx in reaction_list {
                    let ts = rx.timestamp as u64 + FARCASTER_EPOCH;
                    if ts >= r && ts <= window_end {
                        let d = ((ts - r) / 86_400).min(30) as usize;
                        days[d] = days[d].saturating_add(1);
                    }
                }
                daily_activity.insert(src, days);
            }

            // Follow graph (for EigenTrust)
            let mut followee_list: Vec<u64> = Vec::with_capacity(follow_list.len());
            for f in follow_list {
                if f.fid == 0 || f.fid == src {
                    continue;
                }
                followee_list.push(f.fid);
            }
            if !followee_list.is_empty() {
                follow_graph.insert(src, followee_list);
            }

            // Edge accumulation: walk each of src's outbound events; increment BOTH
            //   u_to_f_counts[src][tgt]  — if ts ∈ src's 30-day window
            //   f_to_u_counts[tgt][src]  — if ts ∈ tgt's 30-day window

            // Casts
            for cast in cast_list {
                let ts = cast.timestamp as u64 + FARCASTER_EPOCH;
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
                    // u_to_f: source's window
                    if let Some(r) = src_reg {
                        if ts >= r && ts <= r + THIRTY_DAYS_SECS {
                            *u_to_f_counts
                                .entry(src)
                                .or_default()
                                .entry(tgt)
                                .or_default() += 1;
                        }
                    }
                    // f_to_u: target's window (reversed pivoting)
                    if let Some(tgt_reg) = reg_ts_map.get(&tgt) {
                        let tgt_reg = *tgt_reg;
                        if ts >= tgt_reg && ts <= tgt_reg + THIRTY_DAYS_SECS {
                            *f_to_u_counts
                                .entry(tgt)
                                .or_default()
                                .entry(src)
                                .or_default() += 1;
                        }
                    }
                }
            }

            // Reactions
            for rx in reaction_list {
                if rx.target_fid == 0 || rx.target_fid == src {
                    continue;
                }
                let ts = rx.timestamp as u64 + FARCASTER_EPOCH;
                if let Some(r) = src_reg {
                    if ts >= r && ts <= r + THIRTY_DAYS_SECS {
                        *u_to_f_counts
                            .entry(src)
                            .or_default()
                            .entry(rx.target_fid)
                            .or_default() += 1;
                    }
                }
                if let Some(tgt_reg) = reg_ts_map.get(&rx.target_fid) {
                    let tgt_reg = *tgt_reg;
                    if ts >= tgt_reg && ts <= tgt_reg + THIRTY_DAYS_SECS {
                        *f_to_u_counts
                            .entry(rx.target_fid)
                            .or_default()
                            .entry(src)
                            .or_default() += 1;
                    }
                }
            }

            // Follows (retain baseline's 60-second autofollow filter for u_to_f consistency)
            for f in follow_list {
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
                // u_to_f side: baseline filters 60s-after-src-reg
                if let Some(r) = src_reg {
                    if ts > r + AUTOFOLLOW_WINDOW_SECS && ts <= r + THIRTY_DAYS_SECS {
                        *u_to_f_counts
                            .entry(src)
                            .or_default()
                            .entry(f.fid)
                            .or_default() += 1;
                    }
                }
                // f_to_u side: target window, same 60s filter for symmetry
                if let Some(tgt_reg) = reg_ts_map.get(&f.fid) {
                    let tgt_reg = *tgt_reg;
                    if ts > tgt_reg + AUTOFOLLOW_WINDOW_SECS && ts <= tgt_reg + THIRTY_DAYS_SECS {
                        *f_to_u_counts
                            .entry(f.fid)
                            .or_default()
                            .entry(src)
                            .or_default() += 1;
                    }
                }
            }

            pb.inc(1);
        }
    }
    pb.finish_with_message("done");

    SharedData {
        stats,
        u_to_f_counts,
        f_to_u_counts,
        follow_graph,
        daily_activity,
    }
}

// ---- PoQ seed set + EigenTrust (feature 3) ----

fn build_poq_seed_set(stats: &HashMap<u64, FidStats>) -> HashSet<u64> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    stats
        .iter()
        .filter_map(|(&fid, s)| {
            let reg = s.reg_ts?;
            let age = now.saturating_sub(reg);
            if age < POQ_SEED_MIN_AGE_SECS {
                return None;
            }
            if s.total_casts < POQ_SEED_MIN_CASTS {
                return None;
            }
            if s.active_days < POQ_SEED_MIN_ACTIVE_DAYS {
                return None;
            }
            Some(fid)
        })
        .collect()
}

fn compute_eigentrust(
    follow_graph: &HashMap<u64, Vec<u64>>,
    seed_set: &HashSet<u64>,
) -> HashMap<u64, f64> {
    let mut universe: HashSet<u64> = HashSet::new();
    for (&j, targets) in follow_graph {
        universe.insert(j);
        for &i in targets {
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
    }
    t
}

fn percentile_99_norm(eigentrust: &HashMap<u64, f64>) -> f64 {
    let mut vals: Vec<f64> = eigentrust.values().copied().filter(|v| *v > 0.0).collect();
    if vals.is_empty() {
        return 1.0;
    }
    vals.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let idx = ((vals.len() as f64) * 0.99) as usize;
    vals[idx.min(vals.len() - 1)].max(1.0e-12)
}

// ---- Phase 4: top-N + cohort concentration ----

fn compute_top_n(
    all_fids: &[u64],
    stats: &HashMap<u64, FidStats>,
    u_to_f: &HashMap<u64, HashMap<u64, u32>>,
) -> HashMap<u64, Vec<(u64, u32)>> {
    let mut result: HashMap<u64, Vec<(u64, u32)>> = HashMap::with_capacity(all_fids.len());
    for &u in all_fids {
        if stats.get(&u).and_then(|s| s.reg_ts).is_none() {
            continue;
        }
        let Some(map) = u_to_f.get(&u) else { continue };
        let mut pairs: Vec<(u64, u32)> = map.iter().map(|(&f, &c)| (f, c)).collect();
        if pairs.is_empty() {
            continue;
        }
        pairs.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        pairs.truncate(TOP_N_INTERACTORS);
        result.insert(u, pairs);
    }
    result
}

fn compute_concentration_dampening(
    stats: &HashMap<u64, FidStats>,
    top_n: &HashMap<u64, Vec<(u64, u32)>>,
) -> HashMap<(u64, u64), f64> {
    let mut cohort_size: HashMap<u64, u32> = HashMap::new();
    let mut pair_count: HashMap<(u64, u64), u32> = HashMap::new();

    for (&u, pairs) in top_n {
        let c = match stats.get(&u).and_then(|s| s.reg_ts) {
            Some(r) => cohort_id(r),
            None => continue,
        };
        *cohort_size.entry(c).or_default() += 1;
        for (f, _) in pairs {
            *pair_count.entry((c, *f)).or_default() += 1;
        }
    }

    let mut result: HashMap<(u64, u64), f64> = HashMap::with_capacity(pair_count.len());
    for ((c, f), count) in pair_count {
        let size = *cohort_size.get(&c).unwrap_or(&1) as f64;
        if size == 0.0 {
            continue;
        }
        let concentration = count as f64 / size;
        let excess = (concentration - CONCENTRATION_BASELINE).max(0.0);
        let dampen = 1.0 / (1.0 + excess * CONCENTRATION_SLOPE);
        result.insert((c, f), dampen);
    }
    result
}

fn cohort_id(reg_ts: u64) -> u64 {
    reg_ts / COHORT_LENGTH_SECS
}

// ---- Phase 5: feature-toggled scoring loop ----

#[allow(clippy::too_many_arguments)]
fn run_combination(
    _mask: u8,
    features: FeatureSet,
    all_fids: &[u64],
    stats: &HashMap<u64, FidStats>,
    u_to_f: &HashMap<u64, HashMap<u64, u32>>,
    f_to_u: &HashMap<u64, HashMap<u64, u32>>,
    top_n: &HashMap<u64, Vec<(u64, u32)>>,
    concentration: &HashMap<(u64, u64), f64>,
    daily_activity: &HashMap<u64, Vec<u32>>,
) -> HashMap<u64, ComboRow> {
    // Per-combination effective trust and credibility.
    let mut eff_trust: HashMap<u64, f64> = HashMap::with_capacity(stats.len());
    let mut eff_credibility: HashMap<u64, f64> = HashMap::with_capacity(stats.len());
    for (&fid, s) in stats {
        let t = if features.eigentrust {
            s.trust_eigentrust
        } else {
            TRUST_SCORE_PLACEHOLDER
        };
        eff_trust.insert(fid, t);
        eff_credibility.insert(
            fid,
            compute_credibility_weight(s.age_factor, t, s.interaction_entropy, s.client_diversity),
        );
    }

    let mut growth: HashMap<u64, f64> = HashMap::new();

    for &u in all_fids {
        let u_reg = match stats.get(&u).and_then(|s| s.reg_ts) {
            Some(r) => r,
            None => continue,
        };
        let u_cohort = cohort_id(u_reg);

        // Pick counterparty iterator per feature 5.
        // We'll iterate a Vec<(f, count)> in both cases for uniformity.
        let counterparties: Vec<(u64, u32)> = if features.top_n_restriction {
            top_n.get(&u).cloned().unwrap_or_default()
        } else {
            match u_to_f.get(&u) {
                Some(m) => m.iter().map(|(&f, &c)| (f, c)).collect(),
                None => continue,
            }
        };
        if counterparties.is_empty() {
            continue;
        }

        let total: u32 = counterparties.iter().map(|(_, c)| *c).sum();
        if total == 0 {
            continue;
        }
        let total_f = total as f64;

        // Activity score per feature 7.
        let activity_score = if features.gini_dispersion {
            let disp = daily_activity.get(&u).map(|d| 1.0 - gini(d)).unwrap_or(0.0);
            (total_f + 1.0).ln() * disp
        } else {
            total_f.ln().max(0.0)
        };
        if activity_score <= 0.0 {
            continue;
        }

        // Precompute inviter weight per feature 1. (Constant across counterparties for this u.)
        let inviter_weight = if features.flipped_multiplier {
            eff_trust
                .get(&u)
                .copied()
                .unwrap_or(0.0)
                .max(COUNTERPARTY_FLOOR)
        } else {
            0.0 // unused
        };

        for (f, count) in counterparties {
            let share = count as f64 / total_f;

            // Feature 1: pick multiplier
            let multiplier = if features.flipped_multiplier {
                inviter_weight
            } else {
                eff_credibility.get(&f).copied().unwrap_or(0.0)
            };

            // Feature 2: reciprocity gate + scaling
            let reciprocity = if features.reciprocity_gate {
                let out_f_to_u = f_to_u.get(&u).and_then(|m| m.get(&f)).copied().unwrap_or(0);
                if out_f_to_u == 0 {
                    continue;
                }
                let hi = count.max(out_f_to_u);
                let lo = count.min(out_f_to_u);
                lo as f64 / hi.max(1) as f64
            } else {
                1.0
            };

            // Feature 4: cohort-concentration dampening
            let dampen = if features.cohort_concentration {
                concentration.get(&(u_cohort, f)).copied().unwrap_or(1.0)
            } else {
                1.0
            };

            let contribution = activity_score * share * multiplier * reciprocity * dampen;
            if contribution > 0.0 {
                *growth.entry(f).or_default() += contribution;
            }
        }
    }

    // Aggregate composite = credibility × growth; apply hardcoded exclusion per feature 6.
    let mut result: HashMap<u64, ComboRow> = HashMap::with_capacity(all_fids.len());
    for &fid in all_fids {
        let growth_score = growth.get(&fid).copied().unwrap_or(0.0);
        let credibility = eff_credibility.get(&fid).copied().unwrap_or(0.0);
        let mut composite = credibility * GROWTH_WEIGHT * growth_score;
        if !features.no_hardcoded_exclusion && RETROACTIVE_EXCLUDED_FIDS_APP.contains(&fid) {
            composite = 0.0;
        }
        result.insert(
            fid,
            ComboRow {
                trust_score: eff_trust.get(&fid).copied().unwrap_or(0.0),
                credibility_weight: credibility,
                growth_score,
                composite_score: composite,
                allocation_share: 0.0,
                tokens: 0.0,
            },
        );
    }

    let total: f64 = result.values().map(|r| r.composite_score).sum();
    if total > 0.0 {
        for r in result.values_mut() {
            r.allocation_share = r.composite_score / total;
            r.tokens = r.allocation_share * RETROACTIVE_POOL;
        }
    }

    result
}

fn top_fid_by_tokens(combo: &HashMap<u64, ComboRow>) -> u64 {
    combo
        .iter()
        .filter(|(_, r)| r.tokens > 0.0)
        .max_by(|a, b| {
            a.1.tokens
                .partial_cmp(&b.1.tokens)
                .unwrap_or(std::cmp::Ordering::Equal)
        })
        .map(|(fid, _)| *fid)
        .unwrap_or(0)
}

// ---- Helpers ----

fn compute_age_factor(events: &[BatchIdRegEntry]) -> (f64, Option<u64>) {
    if events.is_empty() {
        return (0.0, None);
    }
    let mut latest_transfer = 0u64;
    let mut earliest_reg = u64::MAX;
    for event in events {
        if event.event_type == "Transfer" {
            latest_transfer = latest_transfer.max(event.block_timestamp);
        }
        if event.event_type == "Register" {
            earliest_reg = earliest_reg.min(event.block_timestamp);
        }
    }
    let effective = if latest_transfer > 0 {
        latest_transfer
    } else if earliest_reg < u64::MAX {
        earliest_reg
    } else {
        return (0.0, None);
    };
    let reg_ts = if earliest_reg < u64::MAX {
        Some(earliest_reg)
    } else {
        None
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let age_secs = now.saturating_sub(effective);
    ((age_secs as f64 / SIX_MONTHS_SECS).min(1.0), reg_ts)
}

fn compute_interaction_entropy(
    src: u64,
    src_reg: Option<u64>,
    casts: &[BatchCastInteraction],
    reactions: &[BatchReactionEntry],
    following: &[BatchFollowEntry],
) -> f64 {
    let mut partner_counts: HashMap<u64, u64> = HashMap::new();
    for cast in casts {
        if let Some(p) = cast.parent_fid {
            if p != 0 && p != src {
                *partner_counts.entry(p).or_default() += 1;
            }
        }
        for &m in &cast.mentions {
            if m != 0 && m != src {
                *partner_counts.entry(m).or_default() += 1;
            }
        }
    }
    for rx in reactions {
        if rx.target_fid != 0 && rx.target_fid != src {
            *partner_counts.entry(rx.target_fid).or_default() += 1;
        }
    }
    for f in following {
        if f.fid == 0 || f.fid == src {
            continue;
        }
        if let (Some(r), Some(followed_at)) = (src_reg, f.followed_at.as_ref()) {
            if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(followed_at) {
                let ts = dt.timestamp() as u64;
                if ts <= r + AUTOFOLLOW_WINDOW_SECS {
                    continue;
                }
            }
        }
        *partner_counts.entry(f.fid).or_default() += 1;
    }
    shannon_entropy_normalized(&partner_counts)
}

fn compute_client_diversity(signers: &[BatchSignerEntry]) -> f64 {
    let mut app_fids: HashSet<u64> = HashSet::new();
    for signer in signers {
        if let Some(app_fid) = extract_app_fid_from_signer(signer) {
            app_fids.insert(app_fid);
        }
    }
    let n = app_fids.len();
    if n <= 1 {
        0.0
    } else {
        (n as f64).log2().min(1.0)
    }
}

fn compute_credibility_weight(
    age_factor: f64,
    trust_score: f64,
    interaction_entropy: f64,
    client_diversity: f64,
) -> f64 {
    W_AGE * age_factor
        + W_TRUST * trust_score
        + W_ENTROPY * interaction_entropy
        + W_STAKE * 0.0
        + W_DIVERSITY * client_diversity
}

fn shannon_entropy_normalized(counts: &HashMap<u64, u64>) -> f64 {
    let total: u64 = counts.values().sum();
    if total == 0 {
        return 0.0;
    }
    let total_f = total as f64;
    let mut entropy = 0.0f64;
    for &count in counts.values() {
        if count > 0 {
            let p = count as f64 / total_f;
            entropy -= p * p.log2();
        }
    }
    let n = counts.len() as f64;
    if n > 1.0 {
        entropy / n.log2()
    } else {
        0.0
    }
}

fn gini(xs: &[u32]) -> f64 {
    if xs.is_empty() {
        return 0.0;
    }
    let total: u64 = xs.iter().map(|&x| x as u64).sum();
    if total == 0 {
        return 1.0;
    }
    let mut sorted: Vec<u64> = xs.iter().map(|&x| x as u64).collect();
    sorted.sort();
    let n = sorted.len() as f64;
    let mut cumulative = 0.0f64;
    for (i, &v) in sorted.iter().enumerate() {
        cumulative += (2.0 * (i as f64 + 1.0) - n - 1.0) * v as f64;
    }
    cumulative / (n * total as f64)
}

// ---- Output ----

fn write_csv(path: &Path, fids: &[u64], combo: &HashMap<u64, ComboRow>) {
    let mut wtr = csv::Writer::from_path(path).expect("failed to create CSV writer");
    wtr.write_record([
        "fid",
        "trust_score",
        "credibility_weight",
        "growth_score",
        "composite_score",
        "allocation_share",
        "tokens",
    ])
    .unwrap();

    let mut ranked: Vec<u64> = fids
        .iter()
        .copied()
        .filter(|fid| combo.get(fid).is_some_and(|r| r.tokens > 0.0))
        .collect();
    ranked.sort_by(|a, b| {
        combo[b]
            .tokens
            .partial_cmp(&combo[a].tokens)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    for fid in &ranked {
        let r = &combo[fid];
        wtr.write_record([
            fid.to_string(),
            format!("{:.6}", r.trust_score),
            format!("{:.6}", r.credibility_weight),
            format!("{:.6}", r.growth_score),
            format!("{:.6}", r.composite_score),
            format!("{:.10}", r.allocation_share),
            format!("{:.6}", r.tokens),
        ])
        .unwrap();
    }

    wtr.flush().unwrap();
}

struct IndexRow {
    bitmask: u8,
    filename: String,
    label: String,
    verbose_label: String,
    nonzero_count: usize,
    top_fid: u64,
}

fn write_index(
    path: &Path,
    rows: &[IndexRow],
    seed_set_size: usize,
    _stats: &HashMap<u64, FidStats>,
) {
    let mut wtr = csv::Writer::from_path(path).expect("failed to create index CSV");
    wtr.write_record([
        "bitmask",
        "filename",
        "features",
        "feature_names",
        "nonzero_fids",
        "top_fid",
        "seed_set_size",
    ])
    .unwrap();
    for r in rows {
        wtr.write_record([
            r.bitmask.to_string(),
            r.filename.clone(),
            r.label.clone(),
            r.verbose_label.clone(),
            r.nonzero_count.to_string(),
            r.top_fid.to_string(),
            seed_set_size.to_string(),
        ])
        .unwrap();
    }
    wtr.flush().unwrap();
}

fn make_progress_bar(len: u64, prefix: &str) -> ProgressBar {
    let pb = ProgressBar::new(len);
    pb.set_style(
        ProgressStyle::with_template("{prefix} [{bar:40.cyan/blue}] {pos}/{len} ({eta})")
            .unwrap()
            .progress_chars("=> "),
    );
    pb.set_prefix(prefix.to_string());
    pb
}
