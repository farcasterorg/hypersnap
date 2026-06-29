/// Retroactive Rewards Calculator
///
/// Standalone binary that queries a running Hypersnap node's batch HTTP API to compute
/// per-FID retroactive reward scores based on the FIP's Growth PoW rules.
///
/// Uses v2 batch endpoints for efficient bulk data retrieval (following, reactions,
/// cast interactions, signers, id registrations) with backfilled/pruned data.
///
/// Usage: cargo run --bin retro_rewards -- --hub-url http://localhost:2281 --output retro_rewards.csv
use std::collections::{HashMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};

use alloy_sol_types::SolType;
use clap::Parser;
use indicatif::{ProgressBar, ProgressStyle};
use serde::Deserialize;

const NUM_SHARDS: u32 = 2;
const THIRTY_DAYS_SECS: u64 = 30 * 24 * 3600;
const AUTOFOLLOW_WINDOW_SECS: u64 = 60;
const SIX_MONTHS_SECS: f64 = 15_552_000.0;
const FARCASTER_EPOCH: u64 = 1609459200;
const TRUST_SCORE_PLACEHOLDER: f64 = 0.5;
const RETROACTIVE_EXCLUDED_FIDS_APP: &[u64] =
    &[1, 9152, 16823, 18548, 193137, 309857, 460608, 1446240];

const W_AGE: f64 = 0.25;
const W_TRUST: f64 = 0.35;
const W_ENTROPY: f64 = 0.20;
const W_STAKE: f64 = 0.10;
const W_DIVERSITY: f64 = 0.10;

const GROWTH_WEIGHT: f64 = 1.0;
const RETROACTIVE_POOL: f64 = 200_000_000.0;

/// Number of FIDs per batch request
const BATCH_SIZE: usize = 100;

#[derive(Parser)]
#[command(
    name = "retro_rewards",
    about = "Compute retroactive reward scores from a Hypersnap node's HTTP API"
)]
struct Cli {
    #[arg(long, default_value = "http://localhost:2281")]
    hub_url: String,

    #[arg(long, default_value = "retro_rewards.csv")]
    output: String,
}

// --- v1 response types ---

#[derive(Debug, Deserialize)]
struct FidsResponse {
    fids: Vec<u64>,
    #[serde(rename = "nextPageToken")]
    next_page_token: Option<String>,
}

// --- Batch response element types ---

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

// --- Scoring ---

#[derive(Default, Clone)]
struct FidScores {
    age_factor: f64,
    trust_score: f64,
    interaction_entropy: f64,
    client_diversity: f64,
    credibility_weight: f64,
    growth_score: f64,
    composite_score: f64,
    allocation_share: f64,
    tokens: f64,
    excluded: bool,
}

struct HubClient {
    client: reqwest::Client,
    base_url: String,
}

alloy_sol_types::sol! {
    struct SignedKeyRequestMetadata {
        uint256 requestFid;
        address requestSigner;
        bytes signature;
        uint256 deadline;
    }
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

#[tokio::main]
async fn main() {
    let args = Cli::parse();
    let hub = HubClient::new(&args.hub_url);

    eprintln!("Connecting to hub at '{}'...", args.hub_url);

    // Phase 1: Enumerate all FIDs
    eprintln!("Phase 1: Enumerating all FIDs...");
    let all_fids = collect_all_fids(&hub).await;
    eprintln!("Found {} FIDs", all_fids.len());

    if all_fids.is_empty() {
        eprintln!("No FIDs found. Exiting.");
        return;
    }

    // Phase 2: Compute per-FID credibility weights using batch endpoints
    eprintln!("Phase 2: Computing per-FID credibility weights...");
    let pb = make_progress_bar(all_fids.len() as u64, "Credibility");
    let mut scores: HashMap<u64, FidScores> = HashMap::new();
    let mut registration_ts: HashMap<u64, u64> = HashMap::new();

    for chunk in all_fids.chunks(BATCH_SIZE) {
        // Fetch all data for this batch in parallel
        let (id_regs, signers, following, reactions, casts) = tokio::join!(
            hub.batch_id_registrations(chunk),
            hub.batch_signers(chunk),
            hub.batch_following(chunk),
            hub.batch_reactions(chunk),
            hub.batch_cast_interactions(chunk),
        );

        for &fid in chunk {
            // Age factor from id registration events
            let (age, reg_ts) = compute_age_factor_from_batch(
                fid,
                id_regs.get(&fid).map(|v| v.as_slice()).unwrap_or(&[]),
            );
            if let Some(ts) = reg_ts {
                registration_ts.insert(fid, ts);
            }

            // Interaction entropy from casts + reactions + following
            let entropy = compute_interaction_entropy_from_batch(
                fid,
                reg_ts,
                casts.get(&fid).map(|v| v.as_slice()).unwrap_or(&[]),
                reactions.get(&fid).map(|v| v.as_slice()).unwrap_or(&[]),
                following.get(&fid).map(|v| v.as_slice()).unwrap_or(&[]),
            );

            // Client diversity from signers
            let diversity = compute_client_diversity_from_batch(
                signers.get(&fid).map(|v| v.as_slice()).unwrap_or(&[]),
            );

            let cred = compute_credibility_weight(age, TRUST_SCORE_PLACEHOLDER, entropy, diversity);
            scores.insert(
                fid,
                FidScores {
                    age_factor: age,
                    trust_score: TRUST_SCORE_PLACEHOLDER,
                    interaction_entropy: entropy,
                    client_diversity: diversity,
                    credibility_weight: cred,
                    ..Default::default()
                },
            );
            pb.inc(1);
        }
    }
    pb.finish_with_message("done");

    // Phase 3: Growth PoW scoring using batch endpoints
    eprintln!("Phase 3: Computing growth scores...");
    let growth_scores =
        compute_growth_scores_batched(&all_fids, &hub, &registration_ts, &scores).await;

    // Phase 4: Aggregate and compute tokens
    eprintln!("Phase 4: Aggregating scores...");
    let mut excluded_count = 0usize;
    for &fid in &all_fids {
        let s = scores.get_mut(&fid).unwrap();
        s.growth_score = *growth_scores.get(&fid).unwrap_or(&0.0);
        s.composite_score = s.credibility_weight * GROWTH_WEIGHT * s.growth_score;

        if RETROACTIVE_EXCLUDED_FIDS_APP.contains(&fid) {
            s.excluded = true;
            s.composite_score = 0.0;
            excluded_count += 1;
        }
    }
    eprintln!("Excluded {} FIDs from rewards", excluded_count);

    let total_score: f64 = scores.values().map(|s| s.composite_score).sum();
    if total_score > 0.0 {
        for s in scores.values_mut() {
            s.allocation_share = s.composite_score / total_score;
            s.tokens = s.allocation_share * RETROACTIVE_POOL;
        }
    }

    eprintln!("Writing output to '{}'...", args.output);
    write_csv(&args.output, &all_fids, &scores);
    print_summary(&all_fids, &scores);
    eprintln!("Done.");
}

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

// --- Batch computation functions ---

fn compute_age_factor_from_batch(_fid: u64, events: &[BatchIdRegEntry]) -> (f64, Option<u64>) {
    if events.is_empty() {
        return (0.0, None);
    }

    let mut latest_transfer_ts = 0u64;
    let mut earliest_reg_ts = u64::MAX;

    for event in events {
        if event.event_type == "Transfer" {
            latest_transfer_ts = latest_transfer_ts.max(event.block_timestamp);
        }
        if event.event_type == "Register" {
            earliest_reg_ts = earliest_reg_ts.min(event.block_timestamp);
        }
    }

    let effective_ts = if latest_transfer_ts > 0 {
        latest_transfer_ts
    } else if earliest_reg_ts < u64::MAX {
        earliest_reg_ts
    } else {
        return (0.0, None);
    };

    let reg_ts = if earliest_reg_ts < u64::MAX {
        Some(earliest_reg_ts)
    } else {
        None
    };

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let age_secs = now.saturating_sub(effective_ts);
    ((age_secs as f64 / SIX_MONTHS_SECS).min(1.0), reg_ts)
}

fn compute_interaction_entropy_from_batch(
    fid: u64,
    reg_ts: Option<u64>,
    casts: &[BatchCastInteraction],
    reactions: &[BatchReactionEntry],
    following: &[BatchFollowEntry],
) -> f64 {
    let mut partner_counts: HashMap<u64, u64> = HashMap::new();

    // Cast interactions (replies + mentions)
    for cast in casts {
        if let Some(parent_fid) = cast.parent_fid {
            if parent_fid != 0 && parent_fid != fid {
                *partner_counts.entry(parent_fid).or_default() += 1;
            }
        }
        for &mention_fid in &cast.mentions {
            if mention_fid != 0 && mention_fid != fid {
                *partner_counts.entry(mention_fid).or_default() += 1;
            }
        }
    }

    // Reactions
    for reaction in reactions {
        if reaction.target_fid != 0 && reaction.target_fid != fid {
            *partner_counts.entry(reaction.target_fid).or_default() += 1;
        }
    }

    // Following (with autofollow filtering)
    for follow in following {
        if follow.fid == 0 || follow.fid == fid {
            continue;
        }
        if let Some(reg) = reg_ts {
            if let Some(ref followed_at) = follow.followed_at {
                if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(followed_at) {
                    let follow_ts = dt.timestamp() as u64;
                    if follow_ts <= reg + AUTOFOLLOW_WINDOW_SECS {
                        continue;
                    }
                }
            }
        }
        *partner_counts.entry(follow.fid).or_default() += 1;
    }

    shannon_entropy(&partner_counts)
}

fn compute_client_diversity_from_batch(signers: &[BatchSignerEntry]) -> f64 {
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

async fn compute_growth_scores_batched(
    all_fids: &[u64],
    hub: &HubClient,
    registration_ts: &HashMap<u64, u64>,
    cred_scores: &HashMap<u64, FidScores>,
) -> HashMap<u64, f64> {
    let mut growth: HashMap<u64, f64> = HashMap::new();
    let pb = make_progress_bar(all_fids.len() as u64, "Growth PoW");

    for chunk in all_fids.chunks(BATCH_SIZE) {
        // Fetch batch data
        let (following, reactions, casts) = tokio::join!(
            hub.batch_following(chunk),
            hub.batch_reactions(chunk),
            hub.batch_cast_interactions(chunk),
        );

        for &fid in chunk {
            let reg_ts = match registration_ts.get(&fid) {
                Some(&ts) => ts,
                None => {
                    pb.inc(1);
                    continue;
                }
            };
            let window_end = reg_ts + THIRTY_DAYS_SECS;
            let mut counterparty_counts: HashMap<u64, u64> = HashMap::new();

            // Casts in first 30 days
            if let Some(cast_list) = casts.get(&fid) {
                for cast in cast_list {
                    let absolute_ts = cast.timestamp as u64 + FARCASTER_EPOCH;
                    if absolute_ts > window_end {
                        continue;
                    }
                    if let Some(parent_fid) = cast.parent_fid {
                        if parent_fid != 0 && parent_fid != fid {
                            *counterparty_counts.entry(parent_fid).or_default() += 1;
                        }
                    }
                    for &mention_fid in &cast.mentions {
                        if mention_fid != 0 && mention_fid != fid {
                            *counterparty_counts.entry(mention_fid).or_default() += 1;
                        }
                    }
                }
            }

            // Reactions in first 30 days
            if let Some(reaction_list) = reactions.get(&fid) {
                for reaction in reaction_list {
                    let absolute_ts = reaction.timestamp as u64 + FARCASTER_EPOCH;
                    if absolute_ts > window_end {
                        continue;
                    }
                    if reaction.target_fid != 0 && reaction.target_fid != fid {
                        *counterparty_counts.entry(reaction.target_fid).or_default() += 1;
                    }
                }
            }

            // Following (with autofollow filtering + 30-day window)
            if let Some(follow_list) = following.get(&fid) {
                for follow in follow_list {
                    if follow.fid == 0 || follow.fid == fid {
                        continue;
                    }
                    if let Some(ref followed_at) = follow.followed_at {
                        if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(followed_at) {
                            let follow_ts = dt.timestamp() as u64;
                            if follow_ts <= reg_ts + AUTOFOLLOW_WINDOW_SECS {
                                continue;
                            }
                            if follow_ts > window_end {
                                continue;
                            }
                        }
                    }
                    *counterparty_counts.entry(follow.fid).or_default() += 1;
                }
            }

            if !counterparty_counts.is_empty() {
                let total_interactions: u64 = counterparty_counts.values().sum();
                let activity_score = (total_interactions as f64).ln().max(0.0);

                for (&counterparty_fid, &count) in &counterparty_counts {
                    let share = count as f64 / total_interactions as f64;
                    let counterparty_cred = cred_scores
                        .get(&counterparty_fid)
                        .map_or(0.0, |s| s.credibility_weight);
                    let contribution = activity_score * share * counterparty_cred;
                    *growth.entry(counterparty_fid).or_default() += contribution;
                }
            }

            pb.inc(1);
        }
    }

    pb.finish_with_message("done");
    growth
}

// --- Helpers ---

fn shannon_entropy(counts: &HashMap<u64, u64>) -> f64 {
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

fn write_csv(path: &str, fids: &[u64], scores: &HashMap<u64, FidScores>) {
    let mut wtr = csv::Writer::from_path(path).expect("failed to create CSV writer");
    wtr.write_record([
        "fid",
        "age_factor",
        "trust_score",
        "interaction_entropy",
        "client_diversity",
        "credibility_weight",
        "growth_score",
        "composite_score",
        "allocation_share",
        "tokens",
    ])
    .unwrap();

    let mut included: Vec<u64> = fids
        .iter()
        .copied()
        .filter(|fid| !scores[fid].excluded)
        .collect();
    included.sort_by(|a, b| scores[b].tokens.partial_cmp(&scores[a].tokens).unwrap());

    for fid in &included {
        let s = &scores[fid];
        wtr.write_record(&[
            fid.to_string(),
            format!("{:.6}", s.age_factor),
            format!("{:.6}", s.trust_score),
            format!("{:.6}", s.interaction_entropy),
            format!("{:.6}", s.client_diversity),
            format!("{:.6}", s.credibility_weight),
            format!("{:.6}", s.growth_score),
            format!("{:.6}", s.composite_score),
            format!("{:.10}", s.allocation_share),
            format!("{:.6}", s.tokens),
        ])
        .unwrap();
    }

    wtr.flush().unwrap();
    eprintln!(
        "Wrote {} FIDs (excluded {} from output)",
        included.len(),
        fids.len() - included.len()
    );
}

fn print_summary(fids: &[u64], scores: &HashMap<u64, FidScores>) {
    let total = fids.len();
    let included = scores.values().filter(|s| !s.excluded).count();
    let nonzero = scores
        .values()
        .filter(|s| !s.excluded && s.composite_score > 0.0)
        .count();

    eprintln!("\n=== Summary ===");
    eprintln!("Total FIDs: {}", total);
    eprintln!("Included FIDs: {}", included);
    eprintln!("FIDs with non-zero score: {}", nonzero);
    eprintln!("Token pool: {:.0}", RETROACTIVE_POOL);

    let mut ranked: Vec<(u64, &FidScores)> = scores
        .iter()
        .filter(|(_, s)| !s.excluded)
        .map(|(&fid, s)| (fid, s))
        .collect();
    ranked.sort_by(|a, b| b.1.tokens.partial_cmp(&a.1.tokens).unwrap());

    eprintln!("\nTop 50 FIDs by token allocation:");
    eprintln!("{:<10} {:>15} {:>10}", "FID", "Tokens", "Share%");
    eprintln!("{}", "-".repeat(37));
    for (fid, s) in ranked.iter().take(50) {
        eprintln!(
            "{:<10} {:>15.2} {:>9.4}%",
            fid,
            s.tokens,
            s.allocation_share * 100.0
        );
    }
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
