//! Retro Rewards Report Generator
//!
//! Consumes the outputs of `retro_rewards`, `retro_rewards_new`, and
//! `retro_rewards_combo` and generates a static single-page-app report
//! letting you compare all 131 rankings side by side.
//!
//! Input layout:
//!   - Baseline:   <baseline_csv>                                  (from retro_rewards)
//!   - New modes:  <new_prefix>.{placeholder,louvain,spectral}.csv (from retro_rewards_new)
//!   - Combos:     <combo_dir>/combo_NNN.csv + index.csv           (from retro_rewards_combo)
//!
//! Output layout (static SPA, served by any HTTP server):
//!   <output>/
//!     index.html
//!     app.js
//!     styles.css
//!     data/
//!       rankings_index.json          — metadata for all 131 rankings
//!       rankings/<id>.json           — one file per ranking (sparse, non-zero entries only)
//!       fid_trajectories/shard_NNNN.json × 1024
//!                                    — per-FID rank+tokens across all 131 rankings,
//!                                      sharded by (fid % 1024) so lookups only load
//!                                      a single ~1-2 MB shard instead of the full map.
//!       feature_impact.json          — precomputed ablation of the 7 combo features
//!       similarity.json              — Spearman correlation matrix (131 × 131)
//!
//! Run the report:
//!   cd <output> && python3 -m http.server 8765
//!   # then open http://localhost:8765

use std::collections::{BTreeSet, HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use clap::Parser;
use indicatif::{ProgressBar, ProgressStyle};
use serde::Serialize;

// Embedded frontend assets: one copy in the binary, written to the output
// directory at runtime. Update the files and rebuild to ship changes.
const INDEX_HTML: &str = include_str!("retro_rewards_report_assets/index.html");
const STYLES_CSS: &str = include_str!("retro_rewards_report_assets/styles.css");
const APP_JS: &str = include_str!("retro_rewards_report_assets/app.js");

const FEATURE_NAMES: [(&str, &str); 7] = [
    ("1", "flipped_multiplier"),
    ("2", "reciprocity_gate"),
    ("3", "eigentrust"),
    ("4", "cohort_concentration"),
    ("5", "top_n_restriction"),
    ("6", "no_hardcoded_exclusion"),
    ("7", "gini_dispersion"),
];

/// Number of FIDs from the top of each ranking used for Spearman similarity.
const SIMILARITY_TOP_N: usize = 5000;

/// Cap for per-feature impact tables (helps/hurts lists).
const IMPACT_TOP_N: usize = 50;

/// Number of shards for FID trajectories. Must match `TRAJECTORY_SHARDS` in app.js.
/// Power of two so the client can compute `fid & (N - 1)` cheaply; 1024 gives
/// ~1-2 MB per shard on the current dataset.
const TRAJECTORY_SHARDS: u64 = 1024;

#[derive(Parser)]
#[command(
    name = "retro_rewards_report",
    about = "Generate static SPA report comparing all retro_rewards outputs"
)]
struct Cli {
    #[arg(long, default_value = "retro_rewards.csv")]
    baseline: String,

    /// Prefix for the three `retro_rewards_new` outputs.
    /// Expects <prefix>.placeholder.csv, <prefix>.louvain.csv, <prefix>.spectral.csv.
    #[arg(long, default_value = "retro_rewards")]
    new_prefix: String,

    #[arg(long, default_value = "retro_rewards_combo")]
    combo_dir: String,

    #[arg(long, default_value = "retro_rewards_report")]
    output: String,
}

// ---- Core types ----

#[derive(Clone)]
struct Ranking {
    id: String,
    source: String,
    label: String,
    features: Vec<u8>,
    bitmask: Option<u32>,
    /// Sorted by tokens descending. Only entries with tokens > 0.
    entries: Vec<(u64, f64)>,
    /// fid → (rank, tokens). Rank is 1-based, matching display.
    rank_lookup: HashMap<u64, (u32, f64)>,
}

fn main() {
    let args = Cli::parse();
    let output = PathBuf::from(&args.output);
    fs::create_dir_all(output.join("data/rankings")).expect("create output dir");

    eprintln!("=== Retro Rewards Report ===");

    // ---- Load rankings in a fixed order ----
    let mut rankings: Vec<Ranking> = Vec::with_capacity(131);

    eprintln!("Loading baseline: {}", args.baseline);
    rankings.push(load_ranking(
        &args.baseline,
        "baseline".to_string(),
        "retro_rewards.rs".to_string(),
        "Original baseline".to_string(),
        Vec::new(),
        None,
    ));

    for mode in ["placeholder", "louvain", "spectral"] {
        let path = format!("{}.{}.csv", args.new_prefix, mode);
        eprintln!("Loading new-mode: {}", path);
        rankings.push(load_ranking(
            &path,
            format!("new_{}", mode),
            "retro_rewards_new.rs".to_string(),
            format!("New: {} trust mode", mode),
            Vec::new(),
            None,
        ));
    }

    let combo_dir = PathBuf::from(&args.combo_dir);
    eprintln!("Loading combo directory: {}", combo_dir.display());
    let pb = progress_bar(127, "combos");
    for mask in 1u8..=127 {
        let filename = format!("combo_{:03}.csv", mask);
        let path = combo_dir.join(&filename);
        if !path.exists() {
            eprintln!("  missing {} (skipping)", path.display());
            pb.inc(1);
            continue;
        }
        let features = bitmask_to_features(mask);
        let label = features
            .iter()
            .map(|f| f.to_string())
            .collect::<Vec<_>>()
            .join("-");
        rankings.push(load_ranking(
            path.to_str().unwrap(),
            format!("combo_{:03}", mask),
            "retro_rewards_combo.rs".to_string(),
            label,
            features,
            Some(mask as u32),
        ));
        pb.inc(1);
    }
    pb.finish_with_message("done");

    eprintln!("Loaded {} rankings", rankings.len());

    // ---- Write per-ranking JSONs + rankings_index.json ----
    eprintln!("Writing per-ranking data…");
    let pb = progress_bar(rankings.len() as u64, "ranking-json");
    let mut index_entries: Vec<RankingMeta> = Vec::with_capacity(rankings.len());
    for r in &rankings {
        write_ranking_json(&output, r).expect("write ranking json");
        index_entries.push(RankingMeta {
            id: r.id.clone(),
            source: r.source.clone(),
            label: r.label.clone(),
            features: r.features.clone(),
            bitmask: r.bitmask,
            non_zero_count: r.entries.len(),
            top_fid: r.entries.first().map(|e| e.0),
            pool_total: r.entries.iter().map(|e| e.1).sum(),
        });
        pb.inc(1);
    }
    pb.finish_with_message("done");

    let feature_names_map: HashMap<String, String> = FEATURE_NAMES
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    write_json(
        &output.join("data/rankings_index.json"),
        &RankingsIndex {
            rankings: index_entries,
            feature_names: feature_names_map,
        },
    )
    .expect("write rankings_index.json");

    // ---- FID trajectories, sharded by fid % TRAJECTORY_SHARDS ----
    eprintln!(
        "Building FID trajectories (sharded into {} files)…",
        TRAJECTORY_SHARDS
    );
    build_and_write_trajectory_shards(&rankings, &output);

    // ---- Feature impact (ablation over combo rankings only) ----
    eprintln!("Computing feature impact…");
    let impact = compute_feature_impact(&rankings);
    write_json(&output.join("data/feature_impact.json"), &impact)
        .expect("write feature_impact.json");

    // ---- Similarity (Spearman over top-5000 of each ranking) ----
    eprintln!(
        "Computing {}×{} Spearman similarity matrix (top-{} intersection)…",
        rankings.len(),
        rankings.len(),
        SIMILARITY_TOP_N
    );
    let similarity = compute_similarity(&rankings);
    write_json(&output.join("data/similarity.json"), &similarity).expect("write similarity.json");

    // ---- Frontend assets ----
    fs::write(output.join("index.html"), INDEX_HTML).expect("write index.html");
    fs::write(output.join("styles.css"), STYLES_CSS).expect("write styles.css");
    fs::write(output.join("app.js"), APP_JS).expect("write app.js");

    eprintln!("\nReport written to {}", output.display());
    eprintln!("\nTo view:");
    eprintln!("  cd {} && python3 -m http.server 8765", output.display());
    eprintln!("  open http://localhost:8765");
}

// ---- CSV loading ----

fn load_ranking(
    path: &str,
    id: String,
    source: String,
    label: String,
    features: Vec<u8>,
    bitmask: Option<u32>,
) -> Ranking {
    let entries = match read_tokens_csv(Path::new(path)) {
        Ok(e) => e,
        Err(err) => {
            eprintln!(
                "  warning: failed to load {} ({}), using empty ranking",
                path, err
            );
            Vec::new()
        }
    };
    let mut rank_lookup: HashMap<u64, (u32, f64)> = HashMap::with_capacity(entries.len());
    for (i, (fid, tokens)) in entries.iter().enumerate() {
        rank_lookup.insert(*fid, ((i + 1) as u32, *tokens));
    }
    Ranking {
        id,
        source,
        label,
        features,
        bitmask,
        entries,
        rank_lookup,
    }
}

fn read_tokens_csv(path: &Path) -> Result<Vec<(u64, f64)>, String> {
    let mut rdr = csv::Reader::from_path(path).map_err(|e| e.to_string())?;
    let headers = rdr.headers().map_err(|e| e.to_string())?.clone();
    let fid_idx = headers
        .iter()
        .position(|h| h == "fid")
        .ok_or_else(|| format!("{}: missing 'fid' column", path.display()))?;
    let tokens_idx = headers
        .iter()
        .position(|h| h == "tokens")
        .ok_or_else(|| format!("{}: missing 'tokens' column", path.display()))?;

    let mut out: Vec<(u64, f64)> = Vec::new();
    for result in rdr.records() {
        let record = result.map_err(|e| e.to_string())?;
        let fid: u64 = match record.get(fid_idx).and_then(|s| s.parse().ok()) {
            Some(v) => v,
            None => continue,
        };
        let tokens: f64 = record
            .get(tokens_idx)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0.0);
        if tokens > 0.0 {
            out.push((fid, tokens));
        }
    }
    out.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    Ok(out)
}

fn bitmask_to_features(mask: u8) -> Vec<u8> {
    let mut out = Vec::new();
    for bit in 0..7 {
        if mask & (1 << bit) != 0 {
            out.push(bit + 1);
        }
    }
    out
}

// ---- JSON output types ----

#[derive(Serialize)]
struct RankingsIndex {
    rankings: Vec<RankingMeta>,
    #[serde(rename = "featureNames")]
    feature_names: HashMap<String, String>,
}

#[derive(Serialize)]
struct RankingMeta {
    id: String,
    source: String,
    label: String,
    features: Vec<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bitmask: Option<u32>,
    non_zero_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    top_fid: Option<u64>,
    pool_total: f64,
}

#[derive(Serialize)]
struct RankingFile<'a> {
    id: &'a str,
    label: &'a str,
    entries: &'a Vec<(u64, f64)>,
}

/// One shard of the FID trajectories map. The `rankings` list is intentionally
/// omitted: the client reads it from `rankings_index.json` (loaded at startup)
/// so we don't duplicate ~2 KB × 1024 shards of ranking ids.
type FidTrajectoryShard = HashMap<String, Vec<(u32, u32, f64)>>;

#[derive(Serialize)]
struct FeatureImpact {
    features: Vec<FeatureImpactRow>,
}

#[derive(Serialize)]
struct FeatureImpactRow {
    id: u8,
    name: String,
    helps: Vec<FidDelta>,
    hurts: Vec<FidDelta>,
}

#[derive(Serialize)]
struct FidDelta {
    fid: u64,
    delta: f64,
}

#[derive(Serialize)]
struct SimilarityMatrix {
    rankings: Vec<String>,
    matrix: Vec<Vec<f64>>,
}

fn write_json<T: Serialize>(path: &Path, data: &T) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_vec(data).expect("serialize");
    fs::write(path, json)
}

fn write_ranking_json(output_root: &Path, r: &Ranking) -> std::io::Result<()> {
    let path = output_root.join(format!("data/rankings/{}.json", r.id));
    let file = RankingFile {
        id: &r.id,
        label: &r.label,
        entries: &r.entries,
    };
    write_json(&path, &file)
}

// ---- Trajectories (sharded) ----

fn build_and_write_trajectory_shards(rankings: &[Ranking], output: &Path) {
    let shard_dir = output.join("data/fid_trajectories");
    fs::create_dir_all(&shard_dir).expect("create trajectory shard dir");

    // Gather the universe of FIDs that have a non-zero allocation anywhere.
    let mut all_fids: BTreeSet<u64> = BTreeSet::new();
    for r in rankings {
        for (fid, _) in &r.entries {
            all_fids.insert(*fid);
        }
    }
    eprintln!(
        "  {} unique FIDs with at least one non-zero allocation",
        all_fids.len()
    );

    // Allocate empty shards up-front so every shard file exists on disk (even
    // if sparse or empty) — the client can assume the shard path resolves for
    // any FID < u64::MAX.
    let mut shards: Vec<FidTrajectoryShard> =
        (0..TRAJECTORY_SHARDS).map(|_| HashMap::new()).collect();

    let pb = progress_bar(all_fids.len() as u64, "trajectories");
    for fid in all_fids {
        let mut traj: Vec<(u32, u32, f64)> = Vec::new();
        for (i, r) in rankings.iter().enumerate() {
            if let Some(&(rank, tokens)) = r.rank_lookup.get(&fid) {
                traj.push((i as u32, rank, tokens));
            }
        }
        if !traj.is_empty() {
            let shard_id = (fid % TRAJECTORY_SHARDS) as usize;
            shards[shard_id].insert(fid.to_string(), traj);
        }
        pb.inc(1);
    }
    pb.finish_with_message("done");

    let pb = progress_bar(TRAJECTORY_SHARDS, "shard-write");
    for (i, shard) in shards.iter().enumerate() {
        let path = shard_dir.join(format!("shard_{:04}.json", i));
        write_json(&path, shard).expect("write trajectory shard");
        pb.inc(1);
    }
    pb.finish_with_message("done");
}

// ---- Feature impact ----

/// For each of 7 features, compute per-FID mean token delta between combos
/// that include the feature and combos that exclude it. Baseline (no features)
/// and the 3 new-mode rankings are excluded from this analysis — only
/// retro_rewards_combo rankings are used, since they form the 7-feature
/// ablation grid.
fn compute_feature_impact(rankings: &[Ranking]) -> FeatureImpact {
    let combos: Vec<&Ranking> = rankings.iter().filter(|r| r.bitmask.is_some()).collect();

    // FID universe: any FID that has a non-zero allocation in at least one combo.
    let mut all_fids: HashSet<u64> = HashSet::new();
    for r in &combos {
        for (fid, _) in &r.entries {
            all_fids.insert(*fid);
        }
    }

    let mut features_out: Vec<FeatureImpactRow> = Vec::with_capacity(7);
    for bit in 0..7u8 {
        let feat_id = bit + 1;
        let mut on_sum: HashMap<u64, f64> = HashMap::new();
        let mut off_sum: HashMap<u64, f64> = HashMap::new();
        let mut on_count: u32 = 0;
        let mut off_count: u32 = 0;
        for r in &combos {
            let mask = r.bitmask.unwrap() as u8;
            let has_feature = mask & (1 << bit) != 0;
            if has_feature {
                on_count += 1;
                for (fid, tokens) in &r.entries {
                    *on_sum.entry(*fid).or_default() += tokens;
                }
            } else {
                off_count += 1;
                for (fid, tokens) in &r.entries {
                    *off_sum.entry(*fid).or_default() += tokens;
                }
            }
        }

        let on_denom = on_count.max(1) as f64;
        let off_denom = off_count.max(1) as f64;

        let mut deltas: Vec<(u64, f64)> = all_fids
            .iter()
            .map(|&fid| {
                let on_mean = on_sum.get(&fid).copied().unwrap_or(0.0) / on_denom;
                let off_mean = off_sum.get(&fid).copied().unwrap_or(0.0) / off_denom;
                (fid, on_mean - off_mean)
            })
            .collect();
        deltas.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

        let helps: Vec<FidDelta> = deltas
            .iter()
            .take(IMPACT_TOP_N)
            .filter(|(_, d)| *d > 0.0)
            .map(|(fid, d)| FidDelta {
                fid: *fid,
                delta: *d,
            })
            .collect();
        let hurts: Vec<FidDelta> = deltas
            .iter()
            .rev()
            .take(IMPACT_TOP_N)
            .filter(|(_, d)| *d < 0.0)
            .map(|(fid, d)| FidDelta {
                fid: *fid,
                delta: *d,
            })
            .collect();

        let name = FEATURE_NAMES
            .iter()
            .find(|(id, _)| id.parse::<u8>().unwrap() == feat_id)
            .map(|(_, n)| n.to_string())
            .unwrap_or_default();
        features_out.push(FeatureImpactRow {
            id: feat_id,
            name,
            helps,
            hurts,
        });
    }

    FeatureImpact {
        features: features_out,
    }
}

// ---- Spearman similarity ----

fn compute_similarity(rankings: &[Ranking]) -> SimilarityMatrix {
    let n = rankings.len();

    // Per ranking: top-SIMILARITY_TOP_N as a map fid → rank (1-based).
    let top_sets: Vec<HashMap<u64, u32>> = rankings
        .iter()
        .map(|r| {
            r.entries
                .iter()
                .take(SIMILARITY_TOP_N)
                .enumerate()
                .map(|(i, (fid, _))| (*fid, (i + 1) as u32))
                .collect()
        })
        .collect();

    let pb = progress_bar((n as u64 * (n as u64 + 1)) / 2, "similarity");
    let mut matrix = vec![vec![0.0_f64; n]; n];
    for i in 0..n {
        matrix[i][i] = 1.0;
        for j in (i + 1)..n {
            let rho = spearman(&top_sets[i], &top_sets[j]);
            matrix[i][j] = rho;
            matrix[j][i] = rho;
            pb.inc(1);
        }
        pb.inc(1);
    }
    pb.finish_with_message("done");

    SimilarityMatrix {
        rankings: rankings.iter().map(|r| r.id.clone()).collect(),
        matrix,
    }
}

/// Spearman rank correlation on the intersection of two {fid: rank} maps.
/// With at least 10 common fids; otherwise 0.
fn spearman(a: &HashMap<u64, u32>, b: &HashMap<u64, u32>) -> f64 {
    let (small, large) = if a.len() <= b.len() { (a, b) } else { (b, a) };
    let mut pairs: Vec<(u32, u32)> = Vec::with_capacity(small.len());
    for (fid, rank_a) in small {
        if let Some(rank_b) = large.get(fid) {
            pairs.push((*rank_a, *rank_b));
        }
    }
    let n = pairs.len();
    if n < 10 {
        return 0.0;
    }

    // Re-rank within the intersection: assign 1..n based on original rank order.
    // (Ranks in `pairs` are the original 1..SIMILARITY_TOP_N ranks; for Spearman
    //  we want ranks within the intersection set, not the full top-N.)
    let mut a_ranks: Vec<(usize, u32)> = pairs
        .iter()
        .enumerate()
        .map(|(i, (r, _))| (i, *r))
        .collect();
    a_ranks.sort_by_key(|(_, r)| *r);
    let mut re_a = vec![0u32; n];
    for (new_rank, (orig_idx, _)) in a_ranks.iter().enumerate() {
        re_a[*orig_idx] = (new_rank + 1) as u32;
    }

    let mut b_ranks: Vec<(usize, u32)> = pairs
        .iter()
        .enumerate()
        .map(|(i, (_, r))| (i, *r))
        .collect();
    b_ranks.sort_by_key(|(_, r)| *r);
    let mut re_b = vec![0u32; n];
    for (new_rank, (orig_idx, _)) in b_ranks.iter().enumerate() {
        re_b[*orig_idx] = (new_rank + 1) as u32;
    }

    // Standard Spearman with no-ties shortcut:  ρ = 1 − 6 Σ d² / (n³ − n)
    let mut sum_d_sq: f64 = 0.0;
    for i in 0..n {
        let d = re_a[i] as f64 - re_b[i] as f64;
        sum_d_sq += d * d;
    }
    let n_f = n as f64;
    1.0 - (6.0 * sum_d_sq) / (n_f * n_f * n_f - n_f)
}

// ---- Progress bar helper ----

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
