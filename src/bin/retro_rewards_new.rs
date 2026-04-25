//! Retroactive Rewards Calculator (Preview Tool)
//!
//! Queries a running Hypersnap node's batch HTTP API and computes a preview of
//! per-FID retroactive reward scores, applying the Growth PoW rules from
//! FIP-proof-of-work-tokenization with the Section 10.2 adjustments that
//! correct for known historical distortions.
//!
//! ## This is a PREVIEW tool
//!
//! The authoritative retroactive distribution runs deterministically under
//! consensus at `EPOCH_GENESIS_HEIGHT` against PoQ-committed trust scores
//! (FIP-proof-of-quality, `[RootPrefix::TrustScore] ++ [fid]`). This binary
//! exists so we can see the distribution shape, calibrate Section 10.2
//! parameters, and catch bugs before genesis. It uses f64 arithmetic; the
//! real run will use deterministic integer math under consensus.
//!
//! ## Section 10.2 adjustments, as implemented
//!
//!   10.2.a Structural-follow exclusion — DISABLED (see note below)
//!   10.2.b Reciprocity-weighted maintenance credit
//!   10.2.c Cohort-concentration dampening
//!   10.2.d Low-trust counterparty dampening
//!   10.2.e Content authenticity: real SimHash over cast text + temporal dispersion
//!   10.2.f New-user diversity gate
//!   10.2.g Credit-recipient trust floor
//!
//! **10.2.a disabled.** Structural-follow detection was removed at the user's
//! request: penalizing FIDs who appear in cohort-wide default follow lists
//! also penalizes legitimate FIDs who happened to be on those lists, and
//! seemed to be making the ranking worse rather than better. The detection
//! function (`detect_structural_edges`) remains in this file for reference
//! but is no longer called; `structural_edges` is always an empty set.
//!
//! ## Trust scores — three modes, one run
//!
//! The binary runs the scoring pipeline **three times** with three different
//! trust-score definitions, writing a CSV per mode. This lets you compare
//! outputs directly and see which ranking holds up.
//!
//! 1. **Placeholder**: `trust = 0.5` for every FID. Baseline — isolates the
//!    effect of Section 10.2 adjustments without any trust discrimination.
//!
//! 2. **Louvain**: PoQ Section 2 with cluster_penalty derived from Louvain
//!    modularity-maximizing community detection on the mutual-follow graph.
//!    Seed set → EigenTrust → (1 − cluster_penalty) × age_factor, clamped.
//!    Louvain substitutes for the PoQ-specified spectral step; the purpose is
//!    identical (detect densely-connected subgraphs with low external
//!    connectivity and penalize them) and Louvain is arguably better at it.
//!
//! 3. **Spectral**: PoQ Section 2 as specified. Same pipeline as Louvain but
//!    clusters come from simultaneous iteration on the normalized adjacency
//!    matrix (equivalent to smallest-k eigenvectors of the normalized
//!    Laplacian) followed by k-means in the embedding space.
//!
//! All three modes share the same Phase 2 data pull, seed set, EigenTrust,
//! mutual-follow graph, structural-follow detection, and Section 10.2
//! scoring pipeline. They differ only in how `trust_score` is computed, and
//! that difference propagates through credibility, the diversity gate, the
//! counterparty floor, and the recipient trust floor.
//!
//! Output: `<prefix>.placeholder.csv`, `<prefix>.louvain.csv`, `<prefix>.spectral.csv`.
//!
//! The authoritative PoQ computation will eventually run under consensus and
//! commit scores to `[RootPrefix::TrustScore]`. Until then, this preview
//! tool computes trust locally from the same protocol-native inputs (follow
//! graph, effective age from id-registrations, cast history). PoQ is the
//! sole definition of trust; this is not a proxy.
//!
//! ## Content fingerprinting
//!
//! Uses SimHash (Charikar 2002) per PoQ Section 3:
//!   - Char 3-grams → xxHash64 (two seeds → 128-bit)
//!   - Sign-sum per bit → 128-bit fingerprint
//!   - Near-duplicate = Hamming distance ≤ 12 bits (~90% similarity)

use std::collections::{BTreeSet, HashMap, HashSet};
use std::hash::Hasher;
use std::time::{SystemTime, UNIX_EPOCH};

use alloy_sol_types::SolType;
use clap::Parser;
use indicatif::{ProgressBar, ProgressStyle};
use serde::Deserialize;
use twox_hash::XxHash64;

// ---- Constants ----

const NUM_SHARDS: u32 = 2;
const BATCH_SIZE: usize = 100;

const THIRTY_DAYS_SECS: u64 = 30 * 24 * 3600;
const SIX_MONTHS_SECS: f64 = 15_552_000.0;
const FARCASTER_EPOCH: u64 = 1_609_459_200;
const COHORT_LENGTH_SECS: u64 = 7 * 24 * 3600;
const DUPLICATE_WINDOW_SECS: u64 = 7 * 24 * 3600;

// Credibility weights (FIP Section 8)
const W_AGE: f64 = 0.25;
const W_TRUST: f64 = 0.35;
const W_ENTROPY: f64 = 0.20;
const W_STAKE: f64 = 0.10;
const W_DIVERSITY: f64 = 0.10;

// Section 10.2 parameters (FIP-proof-of-work-tokenization Section 15)
const STRUCTURAL_FOLLOW_THRESHOLD: f64 = 0.10;
const STRUCTURAL_FOLLOW_K: usize = 50;
const MIN_COHORT_SIZE: usize = 50;
const CONCENTRATION_BASELINE: f64 = 0.01;
const CONCENTRATION_SLOPE: f64 = 50.0;
const COUNTERPARTY_FLOOR: f64 = 0.05;
const MIN_NEW_USER_DIVERSITY: usize = 3;
const RETRO_CREDIT_FLOOR: f64 = 0.10;
const TOP_N_INTERACTORS: usize = 10;

// PoQ parameters (FIP-proof-of-quality Section 2 & 15)
const POQ_DAMPING_FACTOR: f64 = 0.85;
const POQ_MAX_ITERATIONS: usize = 50;
const POQ_CONVERGENCE_TOLERANCE: f64 = 1e-6;
const POQ_SEED_MIN_AGE_SECS: u64 = 180 * 24 * 3600;
const POQ_SEED_MIN_CASTS: u32 = 100;
const POQ_SEED_MIN_ACTIVE_DAYS: u32 = 30;
const POQ_SIMHASH_NGRAM: usize = 3;
const POQ_SIMHASH_HAMMING_THRESHOLD: u32 = 12;

// Cluster detection (PoQ Section 2 Step 3)
const LOUVAIN_MAX_PASSES: usize = 10;
const LOUVAIN_MAX_LOCAL_ITERATIONS: usize = 20;
const SPECTRAL_K: usize = 32;
const SPECTRAL_ITERATIONS: usize = 40;
const KMEANS_MAX_ITERATIONS: usize = 30;

// Retroactive pool (FIP Section 15): TOTAL_SUPPLY × RETROACTIVE_SHARE = 2B × 0.10
const RETROACTIVE_POOL: f64 = 200_000_000.0;

#[derive(Parser)]
#[command(
    name = "retro_rewards",
    about = "Preview of Growth-PoW retroactive distribution with Section 10.2 adjustments + PoQ trust (three-mode compare)"
)]
struct Cli {
    #[arg(long, default_value = "http://localhost:2281")]
    hub_url: String,

    /// Output file prefix. Each mode writes `<prefix>.<mode>.csv`.
    #[arg(long, default_value = "retro_rewards")]
    output_prefix: String,
}

#[derive(Debug, Clone, Copy)]
enum TrustMode {
    Placeholder,
    Louvain,
    Spectral,
}

impl TrustMode {
    fn name(self) -> &'static str {
        match self {
            TrustMode::Placeholder => "placeholder",
            TrustMode::Louvain => "louvain",
            TrustMode::Spectral => "spectral",
        }
    }

    fn label(self) -> &'static str {
        match self {
            TrustMode::Placeholder => "Placeholder (trust = 0.5 for all FIDs)",
            TrustMode::Louvain => "Louvain cluster penalty + EigenTrust",
            TrustMode::Spectral => "Spectral cluster penalty + EigenTrust",
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
struct BatchCastBody {
    #[allow(dead_code)]
    hash: Option<String>,
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

// ---- Core data structures ----

#[derive(Default, Clone)]
struct FidStats {
    reg_ts: Option<u64>,
    effective_ts: Option<u64>,
    age_factor: f64,
    /// Raw EigenTrust vector value (unnormalized, sums to 1 across all FIDs).
    eigentrust_raw: f64,
    /// Normalized and age-weighted PoQ trust score, ∈ [0, 1].
    trust_score: f64,
    interaction_entropy: f64,
    client_diversity: f64,
    credibility_weight: f64,
    /// Total CastAdd count (pre-dedup). Used for seed-set posting history.
    total_casts: u32,
    /// Distinct days with any cast activity. Used for seed-set criterion.
    active_days: u32,
    is_seed: bool,
    growth_score: f64,
    composite_score: f64,
    allocation_share: f64,
    tokens: f64,
    // Diagnostics
    diversity_count: u32,
    top_counterparties: u32,
    structural_edges_dropped: u32,
}

#[derive(Default, Clone, Debug)]
struct EdgeCounts {
    /// Cast/reply/mention interactions after SimHash near-duplicate collapse
    casts: u32,
    reactions: u32,
    follow_in_window: bool,
    follow_structural: bool,
}

impl EdgeCounts {
    fn credited_count(&self) -> u32 {
        let follow_contrib = if self.follow_in_window && !self.follow_structural {
            1
        } else {
            0
        };
        self.casts + self.reactions + follow_contrib
    }

    fn has_any_credited(&self) -> bool {
        self.credited_count() > 0
    }
}

#[derive(Clone, Debug)]
struct EarlyFollow {
    target: u64,
    followed_at: u64,
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

    async fn batch_cast_bodies(&self, fids: &[u64]) -> HashMap<u64, Vec<BatchCastBody>> {
        match self.batch_post::<BatchCastBody>("cast-bodies", fids).await {
            Ok(map) => parse_batch_map(map),
            Err(e) => {
                eprintln!("Warning: batch cast-bodies failed: {}", e);
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

    eprintln!("Connecting to hub at '{}'...", args.hub_url);

    // Phase 1: enumerate FIDs
    eprintln!("\nPhase 1: Enumerating all FIDs...");
    let all_fids = collect_all_fids(&hub).await;
    eprintln!("  Found {} FIDs", all_fids.len());
    if all_fids.is_empty() {
        eprintln!("No FIDs found. Exiting.");
        return;
    }

    // Phase 2: fetch all batch data, build edge index, follow graph, cast history.
    eprintln!("\nPhase 2: Fetching batch data and building indexes...");
    let Phase2 {
        stats: base_stats,
        outbound,
        early_follows,
        daily_activity,
        follow_graph,
    } = fetch_and_index(&hub, &all_fids).await;

    // Phase 3: PoQ seed set (shared across modes).
    eprintln!("\nPhase 3: Building PoQ seed set...");
    let seed_set = build_poq_seed_set(&base_stats);
    eprintln!("  Seed set size: {}", seed_set.len());

    // Phase 4: EigenTrust propagation (shared — used by Louvain and Spectral modes).
    eprintln!("\nPhase 4: Running EigenTrust propagation...");
    let eigentrust = compute_eigentrust(&follow_graph, &seed_set);
    let eigentrust_norm = percentile_99_norm(&eigentrust);

    // Phase 5: symmetric mutual-follow graph (shared cluster-detection input).
    eprintln!("\nPhase 5: Building symmetric mutual-follow graph...");
    let mutual = build_symmetric_mutual_follows(&follow_graph);
    let mutual_edge_count: usize = mutual.values().map(|v| v.len()).sum::<usize>() / 2;
    eprintln!(
        "  Mutual-follow graph: {} nodes, {} edges",
        mutual.len(),
        mutual_edge_count
    );

    // Phase 6: cluster detection for each non-placeholder mode.
    eprintln!("\nPhase 6a: Louvain community detection...");
    let louvain_clusters = louvain_cluster(&mutual);
    let louvain_n_clusters = louvain_clusters.values().collect::<HashSet<_>>().len();
    eprintln!("  Louvain: {} clusters", louvain_n_clusters);

    eprintln!(
        "\nPhase 6b: Spectral clustering ({} eigenvectors → k-means)...",
        SPECTRAL_K
    );
    let spectral_clusters = spectral_cluster(&mutual, SPECTRAL_K);
    let spectral_n_clusters = spectral_clusters.values().collect::<HashSet<_>>().len();
    eprintln!("  Spectral: {} clusters", spectral_n_clusters);

    // Phase 7: per-mode scoring pipeline.
    for mode in [
        TrustMode::Placeholder,
        TrustMode::Louvain,
        TrustMode::Spectral,
    ] {
        eprintln!("\n=== Mode: {} ===", mode.label());
        let clusters_for_mode = match mode {
            TrustMode::Placeholder => None,
            TrustMode::Louvain => Some(&louvain_clusters),
            TrustMode::Spectral => Some(&spectral_clusters),
        };
        run_scoring_mode(
            mode,
            &all_fids,
            &base_stats,
            &outbound,
            &early_follows,
            &daily_activity,
            &eigentrust,
            eigentrust_norm,
            &seed_set,
            clusters_for_mode,
            &mutual,
            &args.output_prefix,
        );
    }

    eprintln!(
        "\nDone. Three CSVs written with prefix '{}'.",
        args.output_prefix
    );
}

// ---- Phase 1 ----

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

// ---- Phase 2: fetch batch data + build indexes ----

struct Phase2 {
    stats: HashMap<u64, FidStats>,
    outbound: HashMap<u64, HashMap<u64, EdgeCounts>>,
    early_follows: HashMap<u64, Vec<EarlyFollow>>,
    daily_activity: HashMap<u64, Vec<u32>>,
    /// follower → Vec<followee>. Used by EigenTrust.
    follow_graph: HashMap<u64, Vec<u64>>,
}

async fn fetch_and_index(hub: &HubClient, all_fids: &[u64]) -> Phase2 {
    // Step 2a: registrations → effective_ts + reg_ts + age_factor
    eprintln!("  Step 2a: Fetching id-registrations (effective-age windowing prerequisite)...");
    let mut reg_ts: HashMap<u64, u64> = HashMap::new();
    let mut effective_ts: HashMap<u64, u64> = HashMap::new();
    let mut ages: HashMap<u64, f64> = HashMap::new();
    let pb = make_progress_bar(all_fids.len() as u64, "  id-reg");
    for chunk in all_fids.chunks(BATCH_SIZE) {
        let id_regs = hub.batch_id_registrations(chunk).await;
        for &fid in chunk {
            let events = id_regs.get(&fid).map(|v| v.as_slice()).unwrap_or(&[]);
            let (age, reg, eff) = compute_age_facts(events);
            ages.insert(fid, age);
            if let Some(ts) = reg {
                reg_ts.insert(fid, ts);
            }
            if let Some(ts) = eff {
                effective_ts.insert(fid, ts);
            }
            pb.inc(1);
        }
    }
    pb.finish_with_message("done");

    // Step 2b: signers/following/reactions/cast-bodies → edges + follow graph + cast history
    eprintln!("  Step 2b: Fetching interactions, casts, and building indexes...");
    let pb = make_progress_bar(all_fids.len() as u64, "  edges");

    let mut stats: HashMap<u64, FidStats> = HashMap::with_capacity(all_fids.len());
    let mut outbound: HashMap<u64, HashMap<u64, EdgeCounts>> =
        HashMap::with_capacity(all_fids.len());
    let mut early_follows: HashMap<u64, Vec<EarlyFollow>> = HashMap::with_capacity(all_fids.len());
    let mut daily_activity: HashMap<u64, Vec<u32>> = HashMap::with_capacity(all_fids.len());
    let mut follow_graph: HashMap<u64, Vec<u64>> = HashMap::with_capacity(all_fids.len());

    for chunk in all_fids.chunks(BATCH_SIZE) {
        let (signers, following, reactions, casts) = tokio::join!(
            hub.batch_signers(chunk),
            hub.batch_following(chunk),
            hub.batch_reactions(chunk),
            hub.batch_cast_bodies(chunk),
        );

        for &src in chunk {
            let src_reg = reg_ts.get(&src).copied();
            let src_eff = effective_ts.get(&src).copied();
            let age = ages.get(&src).copied().unwrap_or(0.0);

            // Entropy from all interactions
            let entropy = compute_interaction_entropy(
                src,
                src_reg,
                casts.get(&src).map(|v| v.as_slice()).unwrap_or(&[]),
                reactions.get(&src).map(|v| v.as_slice()).unwrap_or(&[]),
                following.get(&src).map(|v| v.as_slice()).unwrap_or(&[]),
            );
            let diversity =
                compute_client_diversity(signers.get(&src).map(|v| v.as_slice()).unwrap_or(&[]));

            // Posting history for PoQ seed set: count all casts and distinct active days.
            let (total_casts, active_days) =
                compute_posting_history(casts.get(&src).map(|v| v.as_slice()).unwrap_or(&[]));

            // Initial credibility (trust recomputed in Phase 4)
            let credibility = compute_credibility_weight(age, 0.0, entropy, diversity);

            stats.insert(
                src,
                FidStats {
                    reg_ts: src_reg,
                    effective_ts: src_eff,
                    age_factor: age,
                    trust_score: 0.0,
                    interaction_entropy: entropy,
                    client_diversity: diversity,
                    credibility_weight: credibility,
                    total_casts,
                    active_days,
                    ..Default::default()
                },
            );

            // Per-source daily activity histogram within src's own first-30-days window
            // (used for 10.2.e temporal dispersion)
            if let Some(r) = src_reg {
                let window_end = r + THIRTY_DAYS_SECS;
                let mut days: Vec<u32> = vec![0; 31];
                if let Some(cs) = casts.get(&src) {
                    for cast in cs {
                        let ts = cast.timestamp as u64 + FARCASTER_EPOCH;
                        if ts >= r && ts <= window_end {
                            let d = ((ts - r) / 86_400).min(30) as usize;
                            days[d] = days[d].saturating_add(1);
                        }
                    }
                }
                if let Some(rs) = reactions.get(&src) {
                    for rx in rs {
                        let ts = rx.timestamp as u64 + FARCASTER_EPOCH;
                        if ts >= r && ts <= window_end {
                            let d = ((ts - r) / 86_400).min(30) as usize;
                            days[d] = days[d].saturating_add(1);
                        }
                    }
                }
                daily_activity.insert(src, days);
            }

            // Follow graph + early follows (first K by followed_at)
            if let Some(fs) = following.get(&src) {
                let mut followee_list: Vec<u64> = Vec::with_capacity(fs.len());
                let mut parsed: Vec<EarlyFollow> = Vec::new();
                for f in fs {
                    if f.fid == 0 || f.fid == src {
                        continue;
                    }
                    followee_list.push(f.fid);
                    if let Some(followed_at) = &f.followed_at {
                        if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(followed_at) {
                            parsed.push(EarlyFollow {
                                target: f.fid,
                                followed_at: dt.timestamp() as u64,
                            });
                        }
                    }
                }
                if !followee_list.is_empty() {
                    follow_graph.insert(src, followee_list);
                }
                parsed.sort_by_key(|e| e.followed_at);
                parsed.truncate(STRUCTURAL_FOLLOW_K);
                early_follows.insert(src, parsed);
            }

            // Real SimHash fingerprints for cast near-dup collapse (10.2.e + PoQ Section 3).
            // Applied per-source; within DUPLICATE_WINDOW_SECS, near-duplicate casts
            // collapse to a single credit unit.
            let empty_vec: Vec<BatchCastBody> = Vec::new();
            let cast_list = casts.get(&src).unwrap_or(&empty_vec);
            let mut prior_fps: Vec<(u64, u128)> = Vec::new();

            for cast in cast_list {
                let ts = cast.timestamp as u64 + FARCASTER_EPOCH;
                let text = cast.text.as_deref().unwrap_or("");
                let fp = simhash_128(text, POQ_SIMHASH_NGRAM);

                // Hamming-distance dedup within a 7-day window, per source.
                let is_near_dup = prior_fps.iter().any(|(prev_ts, prev_fp)| {
                    ts.saturating_sub(*prev_ts) < DUPLICATE_WINDOW_SECS
                        && hamming_distance_128(*prev_fp, fp) <= POQ_SIMHASH_HAMMING_THRESHOLD
                });
                prior_fps.push((ts, fp));
                if is_near_dup {
                    continue;
                }

                // Emit edges to distinct targets (parent + mentions)
                let mut tgts: BTreeSet<u64> = BTreeSet::new();
                if let Some(p) = cast.parent_fid {
                    if p != 0 && p != src {
                        tgts.insert(p);
                    }
                }
                for m in &cast.mentions {
                    if *m != 0 && *m != src {
                        tgts.insert(*m);
                    }
                }
                for tgt in tgts {
                    if !within_target_window(ts, reg_ts.get(&tgt).copied()) {
                        continue;
                    }
                    let entry = outbound.entry(src).or_default().entry(tgt).or_default();
                    entry.casts = entry.casts.saturating_add(1);
                }
            }

            // Reactions
            for rx in reactions.get(&src).unwrap_or(&Vec::new()) {
                if rx.target_fid == 0 || rx.target_fid == src {
                    continue;
                }
                let ts = rx.timestamp as u64 + FARCASTER_EPOCH;
                if !within_target_window(ts, reg_ts.get(&rx.target_fid).copied()) {
                    continue;
                }
                let entry = outbound
                    .entry(src)
                    .or_default()
                    .entry(rx.target_fid)
                    .or_default();
                entry.reactions = entry.reactions.saturating_add(1);
            }

            // Follows (only within-target-window; structural flag applied in Phase 5)
            for f in following.get(&src).unwrap_or(&Vec::new()) {
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
                if !within_target_window(ts, reg_ts.get(&f.fid).copied()) {
                    continue;
                }
                let entry = outbound.entry(src).or_default().entry(f.fid).or_default();
                entry.follow_in_window = true;
            }

            pb.inc(1);
        }
    }
    pb.finish_with_message("done");

    Phase2 {
        stats,
        outbound,
        early_follows,
        daily_activity,
        follow_graph,
    }
}

fn within_target_window(ts: u64, target_reg_ts: Option<u64>) -> bool {
    match target_reg_ts {
        Some(r) => ts >= r && ts <= r + THIRTY_DAYS_SECS,
        None => false,
    }
}

// ---- Phase 3: PoQ seed set + EigenTrust ----

/// Seed criterion (PoQ Section 2 Step 1): effective age ≥ 180 days AND
/// ≥ 100 casts across ≥ 30 distinct active days. Protocol-native inputs only.
fn build_poq_seed_set(stats: &HashMap<u64, FidStats>) -> HashSet<u64> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    stats
        .iter()
        .filter_map(|(&fid, s)| {
            let eff = s.effective_ts?;
            let eff_age = now.saturating_sub(eff);
            if eff_age < POQ_SEED_MIN_AGE_SECS {
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

/// EigenTrust (PoQ Section 2 Step 2): damped power iteration seeded on the
/// seed set, converging across the follow graph.
///
/// Follows = follower → followee. For EigenTrust the trust flow is
/// follower → followee, so out_degree(j) is len(follow_graph[j]) and
/// the contribution from j to i is t(j) / out_degree(j) whenever j follows i.
fn compute_eigentrust(
    follow_graph: &HashMap<u64, Vec<u64>>,
    seed_set: &HashSet<u64>,
) -> HashMap<u64, f64> {
    // Universe: all FIDs that appear as a follower or followee.
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
        // (1 - d) * seed contribution
        for &fid in &universe {
            let seed_val = if seed_set.contains(&fid) {
                seed_weight
            } else {
                0.0
            };
            next.insert(fid, (1.0 - d) * seed_val);
        }
        // d * sum(t(j) / out_degree(j) * 1) for each follower j → followee i
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
        // Check convergence
        let mut delta = 0.0f64;
        for (&fid, &v) in &next {
            let prev = *t.get(&fid).unwrap_or(&0.0);
            delta += (v - prev).abs();
        }
        t = next;
        if delta < POQ_CONVERGENCE_TOLERANCE {
            eprintln!(
                "  EigenTrust converged after {} iterations (Δ={:.2e})",
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

/// Normalization constant for raw EigenTrust → [0, 1] range. Uses the 99th
/// percentile so ~1% of FIDs saturate to 1.0, matching PoQ's intent that a
/// meaningful cohort has high trust.
fn percentile_99_norm(eigentrust: &HashMap<u64, f64>) -> f64 {
    let mut vals: Vec<f64> = eigentrust.values().copied().filter(|v| *v > 0.0).collect();
    if vals.is_empty() {
        return 1.0;
    }
    vals.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let idx = ((vals.len() as f64) * 0.99) as usize;
    let p99 = vals[idx.min(vals.len() - 1)];
    if p99 > 0.0 {
        p99
    } else {
        1.0
    }
}

// ---- Phase 5: structural-follow detection (10.2.a) ----
//
// NOTE: This function is retained for reference but is no longer called.
// The auto-follow-list penalty was disabled at the user's request; see
// the module-level doc for context. If re-enabled, invoke this from
// `run_scoring_mode` and pass its result in place of the empty HashSet.

#[allow(dead_code)]
fn detect_structural_edges(
    stats: &HashMap<u64, FidStats>,
    early_follows: &HashMap<u64, Vec<EarlyFollow>>,
) -> HashSet<(u64, u64)> {
    let mut cohorts: HashMap<u64, Vec<u64>> = HashMap::new();
    for (&fid, s) in stats {
        if let Some(r) = s.reg_ts {
            cohorts.entry(cohort_id(r)).or_default().push(fid);
        }
    }

    let mut structural: HashSet<(u64, u64)> = HashSet::new();

    for (_cid, members) in cohorts {
        if members.len() < MIN_COHORT_SIZE {
            continue;
        }

        let mut inbound_counts: HashMap<u64, u32> = HashMap::new();
        for &u in &members {
            if let Some(ef) = early_follows.get(&u) {
                let seen: BTreeSet<u64> = ef.iter().map(|e| e.target).collect();
                for t in seen {
                    *inbound_counts.entry(t).or_default() += 1;
                }
            }
        }

        if inbound_counts.is_empty() {
            continue;
        }

        let cohort_size = members.len() as f64;
        let shares: Vec<f64> = inbound_counts
            .values()
            .map(|&c| c as f64 / cohort_size)
            .collect();
        let baseline = median(&shares);
        let threshold_share = baseline + STRUCTURAL_FOLLOW_THRESHOLD;

        let flagged: HashSet<u64> = inbound_counts
            .iter()
            .filter_map(|(&t, &c)| {
                if (c as f64) / cohort_size > threshold_share {
                    Some(t)
                } else {
                    None
                }
            })
            .collect();

        for &u in &members {
            if let Some(ef) = early_follows.get(&u) {
                for edge in ef {
                    if flagged.contains(&edge.target) {
                        structural.insert((u, edge.target));
                    }
                }
            }
        }
    }

    structural
}

fn cohort_id(reg_ts: u64) -> u64 {
    reg_ts / COHORT_LENGTH_SECS
}

fn median(xs: &[f64]) -> f64 {
    if xs.is_empty() {
        return 0.0;
    }
    let mut v = xs.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let mid = v.len() / 2;
    if v.len().is_multiple_of(2) {
        (v[mid - 1] + v[mid]) / 2.0
    } else {
        v[mid]
    }
}

// ---- Phase 6: top-N counterparties per user ----

fn compute_top_n(
    all_fids: &[u64],
    stats: &HashMap<u64, FidStats>,
    outbound: &HashMap<u64, HashMap<u64, EdgeCounts>>,
    structural_edges: &HashSet<(u64, u64)>,
) -> HashMap<u64, Vec<(u64, u32)>> {
    let pb = make_progress_bar(all_fids.len() as u64, "  top-N");
    let mut result: HashMap<u64, Vec<(u64, u32)>> = HashMap::with_capacity(all_fids.len());

    for &u in all_fids {
        pb.inc(1);
        if stats.get(&u).and_then(|s| s.reg_ts).is_none() {
            continue;
        }
        let u_out = match outbound.get(&u) {
            Some(m) => m,
            None => continue,
        };

        let mut pairs: Vec<(u64, u32)> = u_out
            .iter()
            .filter_map(|(&f, ec)| {
                let is_struct = structural_edges.contains(&(u, f));
                let mut counts = ec.clone();
                if is_struct {
                    counts.follow_structural = true;
                }
                let cnt = counts.credited_count();
                if cnt == 0 {
                    None
                } else {
                    Some((f, cnt))
                }
            })
            .collect();

        if pairs.is_empty() {
            continue;
        }

        pairs.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        pairs.truncate(TOP_N_INTERACTORS);
        result.insert(u, pairs);
    }

    pb.finish_with_message("done");
    result
}

// ---- Phase 7: cohort-concentration dampening (10.2.c) ----

fn compute_concentration_dampening(
    stats: &HashMap<u64, FidStats>,
    top_n_by_user: &HashMap<u64, Vec<(u64, u32)>>,
) -> HashMap<(u64, u64), f64> {
    let mut cohort_size: HashMap<u64, u32> = HashMap::new();
    let mut pair_count: HashMap<(u64, u64), u32> = HashMap::new();

    for (&u, pairs) in top_n_by_user {
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

// ---- Phase 8: growth scoring with 10.2 adjustments ----

#[allow(clippy::too_many_arguments)]
fn compute_growth_scores(
    all_fids: &[u64],
    stats: &mut HashMap<u64, FidStats>,
    outbound: &HashMap<u64, HashMap<u64, EdgeCounts>>,
    top_n_by_user: &HashMap<u64, Vec<(u64, u32)>>,
    concentration_dampen: &HashMap<(u64, u64), f64>,
    structural_edges: &HashSet<(u64, u64)>,
    daily_activity: &HashMap<u64, Vec<u32>>,
) -> HashMap<u64, f64> {
    let pb = make_progress_bar(all_fids.len() as u64, "  growth");
    let mut growth: HashMap<u64, f64> = HashMap::new();

    for &u in all_fids {
        pb.inc(1);
        let u_reg = match stats.get(&u).and_then(|s| s.reg_ts) {
            Some(r) => r,
            None => continue,
        };
        let u_cohort = cohort_id(u_reg);

        // 10.2.d: u's trust as counterparty weight (floored).
        let u_trust = stats.get(&u).map(|s| s.trust_score).unwrap_or(0.0);
        let counterparty_weight = u_trust.max(COUNTERPARTY_FLOOR);

        let top = match top_n_by_user.get(&u) {
            Some(t) => t,
            None => continue,
        };

        // 10.2.f: diversity gate — distinct bidirectional counterparties above trust floor.
        let mut diversity_partners: HashSet<u64> = HashSet::new();
        if let Some(u_out_map) = outbound.get(&u) {
            for (&f, ec) in u_out_map {
                if !ec.has_any_credited() {
                    continue;
                }
                let f_trust = stats.get(&f).map(|s| s.trust_score).unwrap_or(0.0);
                if f_trust < COUNTERPARTY_FLOOR {
                    continue;
                }
                let out_f_to_u = outbound
                    .get(&f)
                    .and_then(|m| m.get(&u))
                    .map(|e| e.credited_count())
                    .unwrap_or(0);
                if out_f_to_u > 0 {
                    diversity_partners.insert(f);
                }
            }
        }
        let bidi_count = diversity_partners.len() as u32;
        let s = stats.get_mut(&u).unwrap();
        s.diversity_count = bidi_count;

        if (bidi_count as usize) < MIN_NEW_USER_DIVERSITY {
            continue;
        }

        // 10.2.e temporal dispersion
        let dispersion = daily_activity.get(&u).map(|d| 1.0 - gini(d)).unwrap_or(0.0);

        let top_total: u32 = top.iter().map(|(_, c)| c).sum();
        if top_total == 0 {
            continue;
        }
        let activity_score = ((top_total as f64 + 1.0).ln()) * dispersion;
        if activity_score <= 0.0 {
            continue;
        }

        let mut structural_dropped: u32 = 0;
        let mut credited_count: u32 = 0;

        for &(f, u_to_f_count) in top {
            if structural_edges.contains(&(u, f)) {
                structural_dropped += 1;
            }

            // 10.2.g: recipient trust floor
            let f_trust = stats.get(&f).map(|s| s.trust_score).unwrap_or(0.0);
            if f_trust < RETRO_CREDIT_FLOOR {
                continue;
            }

            // 10.2.b: reciprocity
            let out_f_to_u = outbound
                .get(&f)
                .and_then(|m| m.get(&u))
                .map(|e| e.credited_count())
                .unwrap_or(0);
            if out_f_to_u == 0 {
                continue;
            }
            let (hi, lo) = if u_to_f_count > out_f_to_u {
                (u_to_f_count, out_f_to_u)
            } else {
                (out_f_to_u, u_to_f_count)
            };
            let reciprocity = lo as f64 / hi.max(1) as f64;

            // 10.2.c: cohort-concentration dampening
            let dampen = concentration_dampen
                .get(&(u_cohort, f))
                .copied()
                .unwrap_or(1.0);

            let share = u_to_f_count as f64 / top_total as f64;
            let contribution = activity_score * share * reciprocity * counterparty_weight * dampen;

            if contribution > 0.0 {
                *growth.entry(f).or_default() += contribution;
                credited_count += 1;
            }
        }

        let s = stats.get_mut(&u).unwrap();
        s.structural_edges_dropped = structural_dropped;
        s.top_counterparties = credited_count;
    }

    pb.finish_with_message("done");
    growth
}

// ---- Helpers ----

/// Returns (age_factor, reg_ts, effective_ts).
///
/// - `reg_ts`: earliest Register event timestamp (used for windowing)
/// - `effective_ts`: last Transfer timestamp, fallback to reg_ts (used for age_factor)
///
/// Per FIP-proof-of-work-tokenization Section 2, transfers reset effective age.
fn compute_age_facts(events: &[BatchIdRegEntry]) -> (f64, Option<u64>, Option<u64>) {
    if events.is_empty() {
        return (0.0, None, None);
    }

    let mut latest_transfer: u64 = 0;
    let mut earliest_reg: u64 = u64::MAX;
    for event in events {
        if event.event_type == "Transfer" {
            latest_transfer = latest_transfer.max(event.block_timestamp);
        }
        if event.event_type == "Register" {
            earliest_reg = earliest_reg.min(event.block_timestamp);
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
    let age_factor = (age_secs as f64 / SIX_MONTHS_SECS).min(1.0);

    (age_factor, reg_ts, Some(effective))
}

fn compute_posting_history(casts: &[BatchCastBody]) -> (u32, u32) {
    let total = casts.len() as u32;
    let mut days: HashSet<u64> = HashSet::new();
    for cast in casts {
        let ts = cast.timestamp as u64 + FARCASTER_EPOCH;
        days.insert(ts / 86_400);
    }
    (total, days.len() as u32)
}

fn compute_interaction_entropy(
    src: u64,
    src_reg: Option<u64>,
    casts: &[BatchCastBody],
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
                if (dt.timestamp() as u64) < r {
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
    let mut cumulative: f64 = 0.0;
    for (i, &v) in sorted.iter().enumerate() {
        cumulative += (2.0 * (i as f64 + 1.0) - n - 1.0) * v as f64;
    }
    cumulative / (n * total as f64)
}

// ---- SimHash (PoQ Section 3 fingerprinting) ----

/// 128-bit SimHash over char n-grams (Charikar 2002).
/// - Tokenize into overlapping char n-grams (n=3 by default)
/// - Per token: two xxHash64 values concatenated into u128
/// - Sign-sum per bit → final 128-bit fingerprint
fn simhash_128(text: &str, n: usize) -> u128 {
    if text.is_empty() {
        return 0;
    }
    let chars: Vec<char> = text.chars().collect();
    if chars.len() < n {
        return xxhash_128(text.as_bytes());
    }
    let mut bits = [0i64; 128];
    for i in 0..=(chars.len() - n) {
        let ngram: String = chars[i..i + n].iter().collect();
        let h = xxhash_128(ngram.as_bytes());
        for (b, bit) in bits.iter_mut().enumerate() {
            if (h >> b) & 1 == 1 {
                *bit += 1;
            } else {
                *bit -= 1;
            }
        }
    }
    let mut out: u128 = 0;
    for (b, &s) in bits.iter().enumerate() {
        if s > 0 {
            out |= 1u128 << b;
        }
    }
    out
}

fn xxhash_128(bytes: &[u8]) -> u128 {
    let mut h_lo = XxHash64::with_seed(0);
    h_lo.write(bytes);
    let mut h_hi = XxHash64::with_seed(0x9E37_79B9_7F4A_7C15);
    h_hi.write(bytes);
    ((h_hi.finish() as u128) << 64) | (h_lo.finish() as u128)
}

fn hamming_distance_128(a: u128, b: u128) -> u32 {
    (a ^ b).count_ones()
}

// ---- Output ----

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

fn write_csv(path: &str, fids: &[u64], stats: &HashMap<u64, FidStats>) {
    let mut wtr = csv::Writer::from_path(path).expect("failed to create CSV writer");
    wtr.write_record([
        "fid",
        "age_factor",
        "trust_score",
        "is_seed",
        "interaction_entropy",
        "client_diversity",
        "credibility_weight",
        "growth_score",
        "composite_score",
        "allocation_share",
        "tokens",
        "total_casts",
        "active_days",
        "diversity_count",
        "top_counterparties",
        "structural_edges_dropped",
    ])
    .unwrap();

    let mut ranked: Vec<u64> = fids
        .iter()
        .copied()
        .filter(|fid| stats.get(fid).is_some_and(|s| s.tokens > 0.0))
        .collect();
    ranked.sort_by(|a, b| {
        stats[b]
            .tokens
            .partial_cmp(&stats[a].tokens)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    for fid in &ranked {
        let s = &stats[fid];
        wtr.write_record([
            fid.to_string(),
            format!("{:.6}", s.age_factor),
            format!("{:.6}", s.trust_score),
            if s.is_seed { "1" } else { "0" }.to_string(),
            format!("{:.6}", s.interaction_entropy),
            format!("{:.6}", s.client_diversity),
            format!("{:.6}", s.credibility_weight),
            format!("{:.6}", s.growth_score),
            format!("{:.6}", s.composite_score),
            format!("{:.10}", s.allocation_share),
            format!("{:.6}", s.tokens),
            s.total_casts.to_string(),
            s.active_days.to_string(),
            s.diversity_count.to_string(),
            s.top_counterparties.to_string(),
            s.structural_edges_dropped.to_string(),
        ])
        .unwrap();
    }

    wtr.flush().unwrap();
    eprintln!(
        "Wrote {} FIDs with non-zero allocation (of {} total)",
        ranked.len(),
        fids.len()
    );
}

fn print_summary(
    mode_label: &str,
    fids: &[u64],
    stats: &HashMap<u64, FidStats>,
    structural_edges: usize,
    seed_set_size: usize,
) {
    let total = fids.len();
    let allocated = stats.values().filter(|s| s.tokens > 0.0).count();

    eprintln!("\n--- Summary [{}] ---", mode_label);
    eprintln!("Total FIDs: {}", total);
    eprintln!("PoQ seed set: {}", seed_set_size);
    eprintln!("FIDs with non-zero allocation: {}", allocated);
    eprintln!("Structural follow edges flagged: {}", structural_edges);
    eprintln!("Token pool (preview): {:.0}", RETROACTIVE_POOL);

    let mut ranked: Vec<(u64, &FidStats)> = stats
        .iter()
        .filter(|(_, s)| s.tokens > 0.0)
        .map(|(&fid, s)| (fid, s))
        .collect();
    ranked.sort_by(|a, b| {
        b.1.tokens
            .partial_cmp(&a.1.tokens)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    eprintln!("\nTop 50 FIDs by token allocation [{}]:", mode_label);
    eprintln!(
        "{:<10} {:>12} {:>8} {:>6} {:>6} {:>6}",
        "FID", "Tokens", "Share%", "Trust", "Seed", "Divers"
    );
    eprintln!("{}", "-".repeat(54));
    for (fid, s) in ranked.iter().take(50) {
        eprintln!(
            "{:<10} {:>12.2} {:>7.3}% {:>6.3} {:>6} {:>6}",
            fid,
            s.tokens,
            s.allocation_share * 100.0,
            s.trust_score,
            if s.is_seed { "Y" } else { "N" },
            s.diversity_count,
        );
    }
}

// ---- Per-mode scoring wrapper ----

#[allow(clippy::too_many_arguments)]
fn run_scoring_mode(
    mode: TrustMode,
    all_fids: &[u64],
    base_stats: &HashMap<u64, FidStats>,
    outbound: &HashMap<u64, HashMap<u64, EdgeCounts>>,
    early_follows: &HashMap<u64, Vec<EarlyFollow>>,
    daily_activity: &HashMap<u64, Vec<u32>>,
    eigentrust: &HashMap<u64, f64>,
    eigentrust_norm: f64,
    seed_set: &HashSet<u64>,
    clusters: Option<&HashMap<u64, u32>>,
    mutual: &HashMap<u64, Vec<u64>>,
    output_prefix: &str,
) {
    let mut stats = base_stats.clone();

    // Cluster penalty per mode.
    let cluster_penalty: HashMap<u64, f64> = match (mode, clusters) {
        (TrustMode::Placeholder, _) | (_, None) => HashMap::new(),
        (_, Some(c)) => compute_cluster_penalties(c, mutual),
    };

    // Trust score per mode.
    for (&fid, s) in stats.iter_mut() {
        s.trust_score = match mode {
            TrustMode::Placeholder => 0.5,
            _ => {
                let raw = eigentrust.get(&fid).copied().unwrap_or(0.0);
                s.eigentrust_raw = raw;
                let cp = cluster_penalty.get(&fid).copied().unwrap_or(0.0);
                let normalized = (raw / eigentrust_norm).min(1.0);
                (normalized * (1.0 - cp) * s.age_factor).clamp(0.0, 1.0)
            }
        };
        s.is_seed = seed_set.contains(&fid);
    }

    // Recompute credibility with this mode's trust.
    for s in stats.values_mut() {
        s.credibility_weight = compute_credibility_weight(
            s.age_factor,
            s.trust_score,
            s.interaction_entropy,
            s.client_diversity,
        );
    }

    // Section 10.2 pipeline.
    // 10.2.a structural-follow exclusion is disabled: auto-follow-list
    // penalty is not applied. `early_follows` is retained in the Phase 2
    // output for future reuse but we pass an empty set here.
    let _ = early_follows;
    let structural_edges: HashSet<(u64, u64)> = HashSet::new();
    let top_n_by_user = compute_top_n(all_fids, &stats, outbound, &structural_edges);
    let concentration_dampen = compute_concentration_dampening(&stats, &top_n_by_user);
    let growth_scores = compute_growth_scores(
        all_fids,
        &mut stats,
        outbound,
        &top_n_by_user,
        &concentration_dampen,
        &structural_edges,
        daily_activity,
    );

    // Aggregate + allocate.
    for fid in all_fids {
        let s = stats.entry(*fid).or_default();
        s.growth_score = *growth_scores.get(fid).unwrap_or(&0.0);
        s.composite_score = s.credibility_weight * s.growth_score;
    }
    let total_score: f64 = stats.values().map(|s| s.composite_score).sum();
    if total_score > 0.0 {
        for s in stats.values_mut() {
            s.allocation_share = s.composite_score / total_score;
            s.tokens = s.allocation_share * RETROACTIVE_POOL;
        }
    }

    let path = format!("{}.{}.csv", output_prefix, mode.name());
    eprintln!("  Writing {} ...", path);
    write_csv(&path, all_fids, &stats);
    print_summary(
        mode.label(),
        all_fids,
        &stats,
        structural_edges.len(),
        seed_set.len(),
    );
}

// ---- Cluster detection ----

/// Build an undirected mutual-follow graph: edge (a, b) iff both a→b and b→a
/// exist in the directed follow graph. Edge lists are symmetric.
fn build_symmetric_mutual_follows(follow_graph: &HashMap<u64, Vec<u64>>) -> HashMap<u64, Vec<u64>> {
    // For fast mutual check, materialize an "i follows" set per FID.
    let follows_set: HashMap<u64, HashSet<u64>> = follow_graph
        .iter()
        .map(|(&src, targets)| (src, targets.iter().copied().collect()))
        .collect();

    let mut mutual: HashMap<u64, Vec<u64>> = HashMap::with_capacity(follow_graph.len());
    for (&src, targets) in follow_graph {
        for &tgt in targets {
            if let Some(tgt_follows) = follows_set.get(&tgt) {
                if tgt_follows.contains(&src) {
                    mutual.entry(src).or_default().push(tgt);
                }
            }
        }
    }
    mutual
}

/// Louvain community detection on a symmetric unit-weight graph. Multi-level:
/// phase-1 local optimization + phase-2 aggregation, repeated until no merge.
/// Returns per-FID cluster id (u32).
fn louvain_cluster(mutual: &HashMap<u64, Vec<u64>>) -> HashMap<u64, u32> {
    let fids: Vec<u64> = mutual.keys().copied().collect();
    let n0 = fids.len();
    if n0 == 0 {
        return HashMap::new();
    }
    let fid_to_idx: HashMap<u64, usize> = fids.iter().enumerate().map(|(i, &f)| (f, i)).collect();

    // Initial adjacency (index space), weight 1 per mutual edge.
    let mut adj: Vec<Vec<(usize, f64)>> = vec![Vec::new(); n0];
    for (i, &f) in fids.iter().enumerate() {
        if let Some(nbrs) = mutual.get(&f) {
            for &nb in nbrs {
                if let Some(&j) = fid_to_idx.get(&nb) {
                    adj[i].push((j, 1.0));
                }
            }
        }
    }

    // Track: for each original FID index, which super-node at current level.
    let mut fid_to_super: Vec<usize> = (0..n0).collect();
    let mut current_n = n0;
    let mut current_adj = adj;

    for _pass in 0..LOUVAIN_MAX_PASSES {
        let community = louvain_one_level(&current_adj, current_n);

        // Relabel communities contiguously.
        let mut relabel: HashMap<usize, usize> = HashMap::new();
        for &c in &community {
            let next = relabel.len();
            relabel.entry(c).or_insert(next);
        }
        let new_n = relabel.len();
        if new_n == current_n {
            break;
        }

        // Update fid_to_super: each original fid's current super-node → its new community
        for super_idx in fid_to_super.iter_mut() {
            let c = community[*super_idx];
            *super_idx = *relabel.get(&c).unwrap();
        }

        // Build aggregated super-graph.
        let mut new_adj_map: Vec<HashMap<usize, f64>> = vec![HashMap::new(); new_n];
        for i in 0..current_n {
            let ci = *relabel.get(&community[i]).unwrap();
            for &(j, w) in &current_adj[i] {
                let cj = *relabel.get(&community[j]).unwrap();
                *new_adj_map[ci].entry(cj).or_default() += w;
            }
        }
        current_adj = new_adj_map
            .into_iter()
            .map(|m| m.into_iter().collect())
            .collect();
        current_n = new_n;
    }

    fids.iter()
        .enumerate()
        .map(|(i, &fid)| (fid, fid_to_super[i] as u32))
        .collect()
}

/// One level of Louvain: repeatedly move each node to its best-gain community.
fn louvain_one_level(adj: &[Vec<(usize, f64)>], n: usize) -> Vec<usize> {
    let degree: Vec<f64> = adj
        .iter()
        .map(|nbrs| nbrs.iter().map(|(_, w)| *w).sum::<f64>())
        .collect();
    let total_w: f64 = degree.iter().sum::<f64>() / 2.0;
    let m2 = 2.0 * total_w;

    let mut community: Vec<usize> = (0..n).collect();
    let mut sum_tot: Vec<f64> = degree.clone();

    if m2 == 0.0 {
        return community;
    }

    for _ in 0..LOUVAIN_MAX_LOCAL_ITERATIONS {
        let mut moved = false;
        for i in 0..n {
            let current_c = community[i];
            let k_i = degree[i];

            let mut w_to_c: HashMap<usize, f64> = HashMap::new();
            for &(j, w) in &adj[i] {
                if j == i {
                    continue;
                }
                let c = community[j];
                *w_to_c.entry(c).or_default() += w;
            }

            // Remove i from its current community for the decision.
            sum_tot[current_c] -= k_i;

            let mut best_c = current_c;
            let mut best_gain = 0.0;
            // Consider staying (after removal).
            let w_curr = *w_to_c.get(&current_c).unwrap_or(&0.0);
            let stay_gain = w_curr - k_i * sum_tot[current_c] / m2;
            if stay_gain > best_gain + 1e-12 {
                best_gain = stay_gain;
            }
            for (&c, &w) in &w_to_c {
                if c == current_c {
                    continue;
                }
                let gain = w - k_i * sum_tot[c] / m2;
                if gain > best_gain + 1e-12 {
                    best_gain = gain;
                    best_c = c;
                }
            }

            community[i] = best_c;
            sum_tot[best_c] += k_i;
            if best_c != current_c {
                moved = true;
            }
        }
        if !moved {
            break;
        }
    }

    community
}

/// Spectral clustering (PoQ Section 2 Step 3 as specified):
///   - Symmetric normalized adjacency P = D^(-1/2) A D^(-1/2)
///   - Top-k eigenvectors of P ≡ smallest-k eigenvectors of normalized Laplacian.
///   - Simultaneous iteration (subspace iteration) for top-k, then k-means.
fn spectral_cluster(mutual: &HashMap<u64, Vec<u64>>, k: usize) -> HashMap<u64, u32> {
    let fids: Vec<u64> = mutual.keys().copied().collect();
    let n = fids.len();
    if n < 2 * k {
        return fids
            .iter()
            .enumerate()
            .map(|(i, &f)| (f, (i % k.max(1)) as u32))
            .collect();
    }
    let fid_to_idx: HashMap<u64, usize> = fids.iter().enumerate().map(|(i, &f)| (f, i)).collect();

    // Edge list (i < j) and degrees.
    let mut degree: Vec<f64> = vec![0.0; n];
    let mut edges: Vec<(usize, usize)> = Vec::new();
    for (i, &f) in fids.iter().enumerate() {
        if let Some(nbrs) = mutual.get(&f) {
            degree[i] = nbrs.len() as f64;
            for &nb in nbrs {
                if let Some(&j) = fid_to_idx.get(&nb) {
                    if i < j {
                        edges.push((i, j));
                    }
                }
            }
        }
    }
    let d_inv_sqrt: Vec<f64> = degree
        .iter()
        .map(|&d| if d > 0.0 { 1.0 / d.sqrt() } else { 0.0 })
        .collect();

    // Initialize Q with seeded pseudo-random values (LCG).
    let mut rng: u64 = 0xDEAD_BEEF_CAFE_BABE;
    let mut q: Vec<Vec<f64>> = vec![vec![0.0; k]; n];
    for row in q.iter_mut() {
        for cell in row.iter_mut() {
            rng = rng
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            *cell = ((rng >> 33) as f64 / (1u64 << 31) as f64) - 1.0;
        }
    }
    gram_schmidt_cols(&mut q, k);

    let pb = make_progress_bar(SPECTRAL_ITERATIONS as u64, "  spectral");
    for _iter in 0..SPECTRAL_ITERATIONS {
        let mut y: Vec<Vec<f64>> = vec![vec![0.0; k]; n];
        // y = P · q, where P[i,j] = d_inv_sqrt[i] * d_inv_sqrt[j] if (i,j) ∈ edges, else 0.
        for &(i, j) in &edges {
            let s = d_inv_sqrt[i] * d_inv_sqrt[j];
            for c in 0..k {
                y[i][c] += s * q[j][c];
                y[j][c] += s * q[i][c];
            }
        }
        gram_schmidt_cols(&mut y, k);
        q = y;
        pb.inc(1);
    }
    pb.finish_with_message("done");

    // k-means on rows of Q.
    let labels = kmeans(&q, k);
    fids.iter()
        .enumerate()
        .map(|(i, &fid)| (fid, labels[i]))
        .collect()
}

/// Modified Gram-Schmidt on columns of an n×k dense matrix (rows × cols).
fn gram_schmidt_cols(mat: &mut [Vec<f64>], k: usize) {
    let n = mat.len();
    if n == 0 {
        return;
    }
    for c in 0..k {
        let mut norm_sq = 0.0;
        for row in mat.iter() {
            norm_sq += row[c] * row[c];
        }
        let norm = norm_sq.sqrt();
        if norm < 1e-12 {
            // Re-seed deterministically (rare in practice with random init).
            for (i, row) in mat.iter_mut().enumerate() {
                row[c] = ((c * n + i) as f64 * 0.17).sin();
            }
            let ns: f64 = mat.iter().map(|r| r[c] * r[c]).sum();
            let nm = ns.sqrt().max(1e-12);
            for row in mat.iter_mut() {
                row[c] /= nm;
            }
        } else {
            for row in mat.iter_mut() {
                row[c] /= norm;
            }
        }
        for cc in (c + 1)..k {
            let mut dot = 0.0;
            for row in mat.iter() {
                dot += row[c] * row[cc];
            }
            for row in mat.iter_mut() {
                row[cc] -= dot * row[c];
            }
        }
    }
}

/// k-means on row vectors with deterministic initialization (evenly-spaced
/// indices). Returns cluster labels.
fn kmeans(points: &[Vec<f64>], k: usize) -> Vec<u32> {
    let n = points.len();
    if n == 0 || k == 0 {
        return vec![0; n];
    }
    let d = points[0].len();

    let mut centroids: Vec<Vec<f64>> = Vec::with_capacity(k);
    for i in 0..k {
        let idx = (i * n / k).min(n - 1);
        centroids.push(points[idx].clone());
    }
    let mut labels: Vec<u32> = vec![0; n];

    for _iter in 0..KMEANS_MAX_ITERATIONS {
        let mut changed = false;
        for (i, p) in points.iter().enumerate() {
            let mut best_c: u32 = 0;
            let mut best_d = f64::INFINITY;
            for (c, cent) in centroids.iter().enumerate() {
                let mut dist = 0.0;
                for dim in 0..d {
                    let diff = p[dim] - cent[dim];
                    dist += diff * diff;
                }
                if dist < best_d {
                    best_d = dist;
                    best_c = c as u32;
                }
            }
            if labels[i] != best_c {
                labels[i] = best_c;
                changed = true;
            }
        }
        if !changed {
            break;
        }

        let mut sums: Vec<Vec<f64>> = vec![vec![0.0; d]; k];
        let mut counts: Vec<u32> = vec![0; k];
        for (i, p) in points.iter().enumerate() {
            let c = labels[i] as usize;
            counts[c] += 1;
            for dim in 0..d {
                sums[c][dim] += p[dim];
            }
        }
        for c in 0..k {
            if counts[c] > 0 {
                for dim in 0..d {
                    centroids[c][dim] = sums[c][dim] / counts[c] as f64;
                }
            }
        }
    }

    labels
}

/// Per-FID cluster penalty per PoQ Section 2 Step 3:
///   cluster_penalty(i) = max(0, 1 − actual_external / expected_external)
///
/// Expected external for a cluster of size k in graph of N nodes, E mutual
/// edges: avg_degree · k · (N − k) / N.
fn compute_cluster_penalties(
    cluster_of: &HashMap<u64, u32>,
    mutual: &HashMap<u64, Vec<u64>>,
) -> HashMap<u64, f64> {
    if cluster_of.is_empty() || mutual.is_empty() {
        return HashMap::new();
    }

    let mut cluster_size: HashMap<u32, u64> = HashMap::new();
    for &c in cluster_of.values() {
        *cluster_size.entry(c).or_default() += 1;
    }
    let n: u64 = cluster_of.len() as u64;

    let mut external: HashMap<u32, u64> = HashMap::new();
    let mut total_edges: u64 = 0;
    for (&src, nbrs) in mutual {
        let sc = match cluster_of.get(&src) {
            Some(c) => *c,
            None => continue,
        };
        for &tgt in nbrs {
            if src >= tgt {
                continue;
            }
            let tc = match cluster_of.get(&tgt) {
                Some(c) => *c,
                None => continue,
            };
            total_edges += 1;
            if sc != tc {
                *external.entry(sc).or_default() += 1;
                *external.entry(tc).or_default() += 1;
            }
        }
    }

    if n == 0 || total_edges == 0 {
        return HashMap::new();
    }

    let e_total = total_edges as f64;
    let n_f = n as f64;
    let avg_degree = 2.0 * e_total / n_f;

    let mut penalty_by_cluster: HashMap<u32, f64> = HashMap::new();
    for (&c, &size) in &cluster_size {
        let k = size as f64;
        let expected = avg_degree * k * (n_f - k) / n_f;
        let actual = *external.get(&c).unwrap_or(&0) as f64;
        let penalty = if expected > 0.0 {
            (1.0 - actual / expected).clamp(0.0, 1.0)
        } else {
            0.0
        };
        penalty_by_cluster.insert(c, penalty);
    }

    cluster_of
        .iter()
        .map(|(&fid, &c)| (fid, *penalty_by_cluster.get(&c).unwrap_or(&0.0)))
        .collect()
}
