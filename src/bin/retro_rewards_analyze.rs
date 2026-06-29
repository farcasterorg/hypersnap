//! Retro Rewards Analyzer
//!
//! Consumes the output of `retro_rewards_report` and either:
//!
//!   A) emits a labeling template of the most-contested FIDs
//!      (those whose rank varies most across the 131 rankings), or
//!
//!   B) scores every ranking against a user-provided labels CSV to
//!      recommend which of the 131 rankings best separates the labeled
//!      good and bad FIDs, with feature attribution and bootstrapped CIs.
//!
//! ## Subcommands
//!
//! ```text
//! retro_rewards_analyze candidates \
//!     --report-dir retro_rewards_report \
//!     --output     labels_template.csv \
//!     --n          1000
//!
//! retro_rewards_analyze score \
//!     --report-dir retro_rewards_report \
//!     --labels     labels.csv \
//!     --output-dir analysis
//! ```
//!
//! The labels CSV must have at least `fid` and `label` columns. `label`
//! values are `good` (intended to rank high) or `bad` (intended to rank low);
//! other values are ignored. Extra columns are permitted.
//!
//! ## What the score report gives you
//!
//! The scoring path is a single honest metric wrapped in interpretation:
//!
//!   - **AUC** (via Mann-Whitney U): probability that a randomly-chosen good
//!     FID ranks above a randomly-chosen bad FID in each ranking. 0.5 = no
//!     signal, 1.0 = perfect separation.
//!   - **Bootstrap 95% confidence interval** on AUC from 200 resamples.
//!   - **Per-group mean rank**, **non-zero coverage**, **matched counts**.
//!   - **Feature attribution**: for combo rankings (127 of 131), which of
//!     the 7 toggleable features are over/under-represented in the top-quintile
//!     vs bottom-quintile of rankings by AUC. Signed probability difference.
//!   - **Top-5 recommended rankings** with rationale.
//!
//! ## Caveats the tool prints explicitly
//!
//!   - AUC depends on the labels; labeling bias propagates.
//!   - Feature attribution is correlational, not causal.
//!   - With ~500-1000 labels, AUC differences under ~0.03 are likely noise.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};
use serde::Deserialize;

#[derive(Parser)]
#[command(
    name = "retro_rewards_analyze",
    about = "Score and recommend retro-reward rankings using a labeled FID set"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Emit a labeling template of the most-contested FIDs.
    Candidates {
        #[arg(long, default_value = "retro_rewards_report")]
        report_dir: String,
        #[arg(long, default_value = "labels_template.csv")]
        output: String,
        #[arg(long, default_value_t = 1000)]
        n: usize,
        /// Require each candidate to have non-zero allocation in at least this
        /// many rankings. Filters out FIDs with too little signal to label
        /// meaningfully.
        #[arg(long, default_value_t = 5)]
        min_nonzero: u32,
    },
    /// Score every ranking against one or more labels CSVs and emit a
    /// recommendation.
    Score {
        #[arg(long, default_value = "retro_rewards_report")]
        report_dir: String,
        /// One or more labels CSVs. Each must have at least `fid` and `label`
        /// columns. Label sets are merged; conflicts (same fid labeled good
        /// in one file and bad in another) are dropped from both sets with
        /// a warning.
        #[arg(long, num_args = 1.., required = true)]
        labels: Vec<String>,
        #[arg(long, default_value = "analysis")]
        output_dir: String,
        /// Number of bootstrap samples for AUC confidence interval.
        #[arg(long, default_value_t = 200)]
        bootstrap: usize,
        /// Seed for the bootstrap resampler.
        #[arg(long, default_value_t = 0xDEAD_BEEF_u64)]
        seed: u64,
    },
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Command::Candidates {
            report_dir,
            output,
            n,
            min_nonzero,
        } => {
            run_candidates(&report_dir, &output, n, min_nonzero);
        }
        Command::Score {
            report_dir,
            labels,
            output_dir,
            bootstrap,
            seed,
        } => {
            run_score(&report_dir, &labels, &output_dir, bootstrap, seed);
        }
    }
}

// ---- Report-dir reader ----

#[derive(Deserialize, Clone)]
struct RankingsIndex {
    rankings: Vec<RankingMeta>,
    #[serde(rename = "featureNames", default)]
    _feature_names: HashMap<String, String>,
}

#[derive(Deserialize, Clone)]
struct RankingMeta {
    id: String,
    source: String,
    label: String,
    #[serde(default)]
    features: Vec<u8>,
    #[serde(default)]
    bitmask: Option<u32>,
    non_zero_count: usize,
    #[serde(default)]
    #[allow(dead_code)]
    top_fid: Option<u64>,
    #[serde(default)]
    pool_total: f64,
}

#[derive(Deserialize)]
struct RankingFile {
    #[allow(dead_code)]
    id: String,
    #[allow(dead_code)]
    label: String,
    /// (fid, tokens) sorted by tokens descending.
    entries: Vec<(u64, f64)>,
}

struct Ranking {
    meta: RankingMeta,
    entries: Vec<(u64, f64)>,
    /// fid → 1-based rank in this ranking. Absent iff tokens == 0.
    rank_lookup: HashMap<u64, u32>,
}

fn load_report(report_dir: &str) -> Vec<Ranking> {
    let root = Path::new(report_dir);
    let index_path = root.join("data/rankings_index.json");
    let bytes = fs::read(&index_path).unwrap_or_else(|e| {
        panic!("failed to read {}: {}", index_path.display(), e);
    });
    let index: RankingsIndex = serde_json::from_slice(&bytes).expect("parse rankings_index.json");

    let mut out = Vec::with_capacity(index.rankings.len());
    for meta in index.rankings {
        let ranking_path = root.join(format!("data/rankings/{}.json", meta.id));
        let bytes = match fs::read(&ranking_path) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("  skipping {}: {}", ranking_path.display(), e);
                continue;
            }
        };
        let file: RankingFile = match serde_json::from_slice(&bytes) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("  skipping {} (parse error: {})", ranking_path.display(), e);
                continue;
            }
        };
        let mut rank_lookup: HashMap<u64, u32> = HashMap::with_capacity(file.entries.len());
        for (i, (fid, _)) in file.entries.iter().enumerate() {
            rank_lookup.insert(*fid, (i + 1) as u32);
        }
        out.push(Ranking {
            meta,
            entries: file.entries,
            rank_lookup,
        });
    }
    out
}

// ---- Candidates subcommand ----

fn run_candidates(report_dir: &str, output: &str, n: usize, min_nonzero: u32) {
    eprintln!("Loading rankings from {}", report_dir);
    let rankings = load_report(report_dir);
    eprintln!("  {} rankings loaded", rankings.len());

    // Build the per-FID across-ranking rank vector.
    // Ranks for rankings where the FID has zero allocation are set to
    // (entries_len_of_that_ranking + 1) — a "one past the last ranked" value.
    let mut all_fids: HashSet<u64> = HashSet::new();
    for r in &rankings {
        for (fid, _) in &r.entries {
            all_fids.insert(*fid);
        }
    }
    eprintln!(
        "  {} unique FIDs with at least one non-zero allocation",
        all_fids.len()
    );

    // For each ranking, the "unranked" pseudo-rank (one past the end).
    let unranked_rank: Vec<u32> = rankings
        .iter()
        .map(|r| (r.entries.len() as u32) + 1)
        .collect();

    struct Row {
        fid: u64,
        std_rank: f64,
        mean_rank: f64,
        best_rank: u32,
        worst_rank: u32,
        n_nonzero: u32,
    }

    let mut rows: Vec<Row> = Vec::with_capacity(all_fids.len());
    for fid in all_fids {
        let mut ranks: Vec<u32> = Vec::with_capacity(rankings.len());
        let mut nonzero: u32 = 0;
        for (i, r) in rankings.iter().enumerate() {
            if let Some(&rk) = r.rank_lookup.get(&fid) {
                ranks.push(rk);
                nonzero += 1;
            } else {
                ranks.push(unranked_rank[i]);
            }
        }
        if nonzero < min_nonzero {
            continue;
        }
        let (mean, std) = mean_and_std(&ranks);
        let best = *ranks.iter().min().unwrap();
        let worst = *ranks.iter().max().unwrap();
        rows.push(Row {
            fid,
            std_rank: std,
            mean_rank: mean,
            best_rank: best,
            worst_rank: worst,
            n_nonzero: nonzero,
        });
    }

    // Descending std; ties broken by lower mean rank (FID is overall more
    // prominent → its label is more directly useful for separating top-
    // contested FIDs from the rest).
    rows.sort_by(|a, b| {
        b.std_rank
            .partial_cmp(&a.std_rank)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(
                a.mean_rank
                    .partial_cmp(&b.mean_rank)
                    .unwrap_or(std::cmp::Ordering::Equal),
            )
    });
    rows.truncate(n);

    eprintln!("Writing {} candidates to {}", rows.len(), output);
    let mut wtr = csv::Writer::from_path(output).expect("create csv");
    wtr.write_record([
        "fid",
        "std_rank",
        "mean_rank",
        "best_rank",
        "worst_rank",
        "n_nonzero",
        "label",
    ])
    .unwrap();
    for row in &rows {
        wtr.write_record([
            row.fid.to_string(),
            format!("{:.2}", row.std_rank),
            format!("{:.2}", row.mean_rank),
            row.best_rank.to_string(),
            row.worst_rank.to_string(),
            row.n_nonzero.to_string(),
            String::new(),
        ])
        .unwrap();
    }
    wtr.flush().unwrap();

    eprintln!(
        "\nDone. Fill the `label` column with 'good' or 'bad' (others ignored),\nthen run `retro_rewards_analyze score --labels {}` to analyze.",
        output
    );
}

fn mean_and_std(xs: &[u32]) -> (f64, f64) {
    if xs.is_empty() {
        return (0.0, 0.0);
    }
    let n = xs.len() as f64;
    let mean = xs.iter().map(|&x| x as f64).sum::<f64>() / n;
    let var = xs.iter().map(|&x| (x as f64 - mean).powi(2)).sum::<f64>() / n;
    (mean, var.sqrt())
}

// ---- Score subcommand ----

#[derive(Debug, Deserialize)]
struct LabelRow {
    fid: u64,
    label: String,
}

fn run_score(
    report_dir: &str,
    labels_paths: &[String],
    output_dir: &str,
    bootstrap_samples: usize,
    seed: u64,
) {
    eprintln!("Loading rankings from {}", report_dir);
    let rankings = load_report(report_dir);

    eprintln!("Loading labels from {} file(s)", labels_paths.len());
    let (good, bad) = load_labels_multi(labels_paths);
    eprintln!(
        "  {} good / {} bad (total {})",
        good.len(),
        bad.len(),
        good.len() + bad.len()
    );
    if good.len() < 10 || bad.len() < 10 {
        eprintln!(
            "Error: need at least 10 'good' and 10 'bad' labeled FIDs. Got good={}, bad={}.",
            good.len(),
            bad.len()
        );
        std::process::exit(1);
    }

    fs::create_dir_all(output_dir).expect("create output dir");

    // Score every ranking.
    let mut scored: Vec<RankingScore> = Vec::with_capacity(rankings.len());
    eprintln!(
        "Scoring {} rankings (bootstrap = {} samples)…",
        rankings.len(),
        bootstrap_samples
    );
    for r in &rankings {
        scored.push(score_ranking(r, &good, &bad, bootstrap_samples, seed));
    }

    // Write per-ranking CSV.
    let per_ranking_path = PathBuf::from(output_dir).join("per_ranking.csv");
    write_per_ranking_csv(&per_ranking_path, &scored).expect("write per_ranking csv");
    eprintln!("  wrote {}", per_ranking_path.display());

    // Feature attribution (combos only).
    let attribution = compute_feature_attribution(&scored);
    let attribution_path = PathBuf::from(output_dir).join("feature_attribution.csv");
    write_attribution_csv(&attribution_path, &attribution).expect("write attribution");
    eprintln!("  wrote {}", attribution_path.display());

    // Markdown report.
    let md_path = PathBuf::from(output_dir).join("analysis.md");
    write_markdown_report(
        &md_path,
        &scored,
        &attribution,
        good.len(),
        bad.len(),
        bootstrap_samples,
    )
    .expect("write markdown");
    eprintln!("  wrote {}", md_path.display());

    eprintln!(
        "\nDone. Open {} for the headline recommendation.",
        md_path.display()
    );
}

fn load_labels_multi(paths: &[String]) -> (HashSet<u64>, HashSet<u64>) {
    // Merge labels across files; if the same FID is labeled good in one file
    // and bad in another, drop it from both sets and warn.
    let mut good_raw: HashSet<u64> = HashSet::new();
    let mut bad_raw: HashSet<u64> = HashSet::new();

    for path in paths {
        eprintln!("  loading {}", path);
        let mut rdr = match csv::Reader::from_path(path) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("  warning: failed to open {}: {}", path, e);
                continue;
            }
        };
        let mut file_good = 0usize;
        let mut file_bad = 0usize;
        for result in rdr.deserialize::<LabelRow>() {
            let row = match result {
                Ok(r) => r,
                Err(_) => continue,
            };
            match row.label.trim().to_ascii_lowercase().as_str() {
                "good" | "1" | "pos" | "positive" => {
                    good_raw.insert(row.fid);
                    file_good += 1;
                }
                "bad" | "-1" | "neg" | "negative" => {
                    bad_raw.insert(row.fid);
                    file_bad += 1;
                }
                _ => {}
            }
        }
        eprintln!("    → {} good, {} bad", file_good, file_bad);
    }

    let conflicts: Vec<u64> = good_raw.intersection(&bad_raw).copied().collect();
    if !conflicts.is_empty() {
        eprintln!(
            "  warning: {} fid(s) labeled both good and bad across files — dropping from both sets: {:?}",
            conflicts.len(),
            conflicts.iter().take(10).collect::<Vec<_>>()
        );
        for fid in &conflicts {
            good_raw.remove(fid);
            bad_raw.remove(fid);
        }
    }
    (good_raw, bad_raw)
}

struct RankingScore {
    meta: RankingMeta,
    auc: f64,
    auc_ci_lo: f64,
    auc_ci_hi: f64,
    mean_rank_good: f64,
    mean_rank_bad: f64,
    coverage_good: f64, // fraction of labeled good FIDs with non-zero allocation
    coverage_bad: f64,
    n_good_matched: usize,
    n_bad_matched: usize,
}

fn score_ranking(
    r: &Ranking,
    good: &HashSet<u64>,
    bad: &HashSet<u64>,
    bootstrap_samples: usize,
    seed: u64,
) -> RankingScore {
    // Assign each labeled FID a "penalty rank": 1-based rank in the
    // ranking, or (n_entries + 1) if not ranked.
    let unranked = (r.entries.len() as u32) + 1;
    let good_ranks: Vec<u32> = good
        .iter()
        .map(|fid| r.rank_lookup.get(fid).copied().unwrap_or(unranked))
        .collect();
    let bad_ranks: Vec<u32> = bad
        .iter()
        .map(|fid| r.rank_lookup.get(fid).copied().unwrap_or(unranked))
        .collect();

    let auc = mann_whitney_auc(&good_ranks, &bad_ranks);

    // Bootstrap CI.
    let (ci_lo, ci_hi) = bootstrap_auc_ci(
        &good_ranks,
        &bad_ranks,
        bootstrap_samples,
        seed.wrapping_add(r.meta.id.len() as u64 * 0x9E37_79B9_7F4A_7C15),
    );

    let mean_rank_good = mean_f(&good_ranks);
    let mean_rank_bad = mean_f(&bad_ranks);

    let n_good_nonzero = good
        .iter()
        .filter(|fid| r.rank_lookup.contains_key(fid))
        .count();
    let n_bad_nonzero = bad
        .iter()
        .filter(|fid| r.rank_lookup.contains_key(fid))
        .count();

    RankingScore {
        meta: r.meta.clone(),
        auc,
        auc_ci_lo: ci_lo,
        auc_ci_hi: ci_hi,
        mean_rank_good,
        mean_rank_bad,
        coverage_good: n_good_nonzero as f64 / good.len().max(1) as f64,
        coverage_bad: n_bad_nonzero as f64 / bad.len().max(1) as f64,
        n_good_matched: n_good_nonzero,
        n_bad_matched: n_bad_nonzero,
    }
}

fn mean_f(xs: &[u32]) -> f64 {
    if xs.is_empty() {
        return 0.0;
    }
    xs.iter().map(|&x| x as f64).sum::<f64>() / xs.len() as f64
}

/// AUC via Mann-Whitney U, where "above" = lower rank number (higher
/// allocation). Ties contribute 0.5 per pair.
///
/// AUC = P(rank_of_good < rank_of_bad) + 0.5 · P(rank_of_good == rank_of_bad)
fn mann_whitney_auc(good_ranks: &[u32], bad_ranks: &[u32]) -> f64 {
    let n_good = good_ranks.len();
    let n_bad = bad_ranks.len();
    if n_good == 0 || n_bad == 0 {
        return 0.5;
    }
    let mut u: f64 = 0.0;
    for &g in good_ranks {
        for &b in bad_ranks {
            if g < b {
                u += 1.0;
            } else if g == b {
                u += 0.5;
            }
        }
    }
    u / (n_good as f64 * n_bad as f64)
}

fn bootstrap_auc_ci(
    good_ranks: &[u32],
    bad_ranks: &[u32],
    samples: usize,
    seed: u64,
) -> (f64, f64) {
    if samples == 0 || good_ranks.is_empty() || bad_ranks.is_empty() {
        return (0.5, 0.5);
    }
    let mut rng = Lcg::new(seed);
    let mut aucs: Vec<f64> = Vec::with_capacity(samples);
    let mut g_buf: Vec<u32> = vec![0; good_ranks.len()];
    let mut b_buf: Vec<u32> = vec![0; bad_ranks.len()];
    for _ in 0..samples {
        for slot in g_buf.iter_mut() {
            *slot = good_ranks[rng.next() as usize % good_ranks.len()];
        }
        for slot in b_buf.iter_mut() {
            *slot = bad_ranks[rng.next() as usize % bad_ranks.len()];
        }
        aucs.push(mann_whitney_auc(&g_buf, &b_buf));
    }
    aucs.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let lo_idx = ((samples as f64) * 0.025) as usize;
    let hi_idx = ((samples as f64) * 0.975) as usize;
    (aucs[lo_idx.min(samples - 1)], aucs[hi_idx.min(samples - 1)])
}

/// Simple deterministic LCG, adequate for bootstrap resampling.
struct Lcg(u64);
impl Lcg {
    fn new(seed: u64) -> Self {
        Self(seed.wrapping_add(1))
    }
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0
    }
}

// ---- Feature attribution ----

struct FeatureAttribution {
    id: u8,
    name: String,
    p_top: f64,
    p_bottom: f64,
    signal: f64,
    n_top: usize,
    n_bottom: usize,
}

const FEATURE_NAMES: [(u8, &str); 7] = [
    (1, "flipped_multiplier"),
    (2, "reciprocity_gate"),
    (3, "eigentrust"),
    (4, "cohort_concentration"),
    (5, "top_n_restriction"),
    (6, "no_hardcoded_exclusion"),
    (7, "gini_dispersion"),
];

fn compute_feature_attribution(scored: &[RankingScore]) -> Vec<FeatureAttribution> {
    // Filter to combos (they have Some(bitmask)) — the 7-feature grid is only
    // defined over combo rankings.
    let combos: Vec<&RankingScore> = scored.iter().filter(|s| s.meta.bitmask.is_some()).collect();
    if combos.is_empty() {
        return Vec::new();
    }

    let mut sorted = combos.clone();
    sorted.sort_by(|a, b| {
        b.auc
            .partial_cmp(&a.auc)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    let quintile = sorted.len().div_ceil(5);
    let top = &sorted[..quintile];
    let bottom_start = sorted.len().saturating_sub(quintile);
    let bottom = &sorted[bottom_start..];

    let mut out: Vec<FeatureAttribution> = Vec::with_capacity(7);
    for (fid_id, fname) in FEATURE_NAMES {
        let bit = 1u32 << (fid_id - 1);
        let n_top_with = top
            .iter()
            .filter(|s| s.meta.bitmask.map(|b| b & bit != 0).unwrap_or(false))
            .count();
        let n_bot_with = bottom
            .iter()
            .filter(|s| s.meta.bitmask.map(|b| b & bit != 0).unwrap_or(false))
            .count();
        let p_top = n_top_with as f64 / top.len().max(1) as f64;
        let p_bot = n_bot_with as f64 / bottom.len().max(1) as f64;
        out.push(FeatureAttribution {
            id: fid_id,
            name: fname.to_string(),
            p_top,
            p_bottom: p_bot,
            signal: p_top - p_bot,
            n_top: top.len(),
            n_bottom: bottom.len(),
        });
    }

    // Sort by |signal| descending so the headline-moving features appear first.
    out.sort_by(|a, b| {
        b.signal
            .abs()
            .partial_cmp(&a.signal.abs())
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    out
}

// ---- Output writers ----

fn write_per_ranking_csv(path: &Path, scored: &[RankingScore]) -> std::io::Result<()> {
    let mut wtr = csv::Writer::from_path(path)?;
    wtr.write_record([
        "id",
        "source",
        "label",
        "features",
        "bitmask",
        "auc",
        "auc_ci_lo",
        "auc_ci_hi",
        "mean_rank_good",
        "mean_rank_bad",
        "coverage_good",
        "coverage_bad",
        "n_good_matched",
        "n_bad_matched",
        "non_zero_count",
        "pool_total",
    ])?;
    let mut sorted: Vec<&RankingScore> = scored.iter().collect();
    sorted.sort_by(|a, b| {
        b.auc
            .partial_cmp(&a.auc)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    for s in sorted {
        let features = s
            .meta
            .features
            .iter()
            .map(|f| f.to_string())
            .collect::<Vec<_>>()
            .join("-");
        wtr.write_record([
            s.meta.id.clone(),
            s.meta.source.clone(),
            s.meta.label.clone(),
            features,
            s.meta.bitmask.map(|b| b.to_string()).unwrap_or_default(),
            format!("{:.4}", s.auc),
            format!("{:.4}", s.auc_ci_lo),
            format!("{:.4}", s.auc_ci_hi),
            format!("{:.2}", s.mean_rank_good),
            format!("{:.2}", s.mean_rank_bad),
            format!("{:.4}", s.coverage_good),
            format!("{:.4}", s.coverage_bad),
            s.n_good_matched.to_string(),
            s.n_bad_matched.to_string(),
            s.meta.non_zero_count.to_string(),
            format!("{:.2}", s.meta.pool_total),
        ])?;
    }
    wtr.flush()?;
    Ok(())
}

fn write_attribution_csv(path: &Path, attribution: &[FeatureAttribution]) -> std::io::Result<()> {
    let mut wtr = csv::Writer::from_path(path)?;
    wtr.write_record([
        "feature_id",
        "feature_name",
        "p_top_quintile",
        "p_bottom_quintile",
        "signal",
        "n_top",
        "n_bottom",
    ])?;
    for a in attribution {
        wtr.write_record([
            a.id.to_string(),
            a.name.clone(),
            format!("{:.4}", a.p_top),
            format!("{:.4}", a.p_bottom),
            format!("{:+.4}", a.signal),
            a.n_top.to_string(),
            a.n_bottom.to_string(),
        ])?;
    }
    wtr.flush()?;
    Ok(())
}

fn write_markdown_report(
    path: &Path,
    scored: &[RankingScore],
    attribution: &[FeatureAttribution],
    n_good: usize,
    n_bad: usize,
    bootstrap_samples: usize,
) -> std::io::Result<()> {
    let mut sorted: Vec<&RankingScore> = scored.iter().collect();
    sorted.sort_by(|a, b| {
        b.auc
            .partial_cmp(&a.auc)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    let baseline = scored.iter().find(|s| s.meta.id == "baseline");

    let mut md = String::new();
    md.push_str("# Retro Rewards — Ranking Analysis\n\n");
    md.push_str(&format!(
        "Labels: **{} good / {} bad** (total {}). Bootstrap: {} samples for 95% CI on AUC.\n\n",
        n_good,
        n_bad,
        n_good + n_bad,
        bootstrap_samples
    ));

    md.push_str("## Top 10 rankings by AUC\n\n");
    md.push_str(
        "AUC = probability a randomly-chosen **good** FID ranks above a randomly-chosen **bad** FID. 0.5 = no signal; 1.0 = perfect.\n\n",
    );
    md.push_str(
        "| Rank | ID | Source | Features | AUC | 95% CI | ΔAUC vs baseline | Mean rank good | Mean rank bad | Coverage good |\n",
    );
    md.push_str("|---|---|---|---|---|---|---|---|---|---|\n");
    let baseline_auc = baseline.map(|b| b.auc).unwrap_or(0.5);
    for (i, s) in sorted.iter().take(10).enumerate() {
        let features = s
            .meta
            .features
            .iter()
            .map(|f| f.to_string())
            .collect::<Vec<_>>()
            .join("-");
        md.push_str(&format!(
            "| {} | `{}` | {} | {} | {:.4} | [{:.4}, {:.4}] | {:+.4} | {:.1} | {:.1} | {:.1}% |\n",
            i + 1,
            s.meta.id,
            s.meta.source,
            if features.is_empty() {
                "—".to_string()
            } else {
                features
            },
            s.auc,
            s.auc_ci_lo,
            s.auc_ci_hi,
            s.auc - baseline_auc,
            s.mean_rank_good,
            s.mean_rank_bad,
            s.coverage_good * 100.0,
        ));
    }
    md.push('\n');

    md.push_str("## Bottom 5 rankings by AUC\n\n");
    md.push_str("| Rank | ID | Source | Features | AUC | 95% CI |\n");
    md.push_str("|---|---|---|---|---|---|\n");
    let total = sorted.len();
    for (offset, s) in sorted.iter().rev().take(5).enumerate() {
        let features = s
            .meta
            .features
            .iter()
            .map(|f| f.to_string())
            .collect::<Vec<_>>()
            .join("-");
        md.push_str(&format!(
            "| {} | `{}` | {} | {} | {:.4} | [{:.4}, {:.4}] |\n",
            total - offset,
            s.meta.id,
            s.meta.source,
            if features.is_empty() {
                "—".to_string()
            } else {
                features
            },
            s.auc,
            s.auc_ci_lo,
            s.auc_ci_hi,
        ));
    }
    md.push('\n');

    if let Some(b) = baseline {
        md.push_str("## Baseline comparison\n\n");
        md.push_str(&format!(
            "- **Original baseline** (`retro_rewards.csv`): AUC = {:.4} (95% CI [{:.4}, {:.4}])\n",
            b.auc, b.auc_ci_lo, b.auc_ci_hi
        ));
        let best = sorted[0];
        md.push_str(&format!(
            "- **Best ranking** (`{}`): AUC = {:.4} (95% CI [{:.4}, {:.4}])\n",
            best.meta.id, best.auc, best.auc_ci_lo, best.auc_ci_hi
        ));
        md.push_str(&format!("- Δ AUC = **{:+.4}**. ", best.auc - b.auc));
        if best.auc_ci_lo > b.auc_ci_hi {
            md.push_str(
                "CIs do not overlap — the best ranking outperforms baseline at the 95% level.\n\n",
            );
        } else if best.auc_ci_hi < b.auc_ci_lo {
            md.push_str("CIs do not overlap — the best ranking **underperforms** baseline at the 95% level.\n\n");
        } else {
            md.push_str("CIs overlap — the difference is not statistically significant at this label count.\n\n");
        }
    }

    md.push_str("## Feature attribution (combos only)\n\n");
    md.push_str("For each of the 7 `retro_rewards_combo` feature toggles: how often it is ON in the **top quintile** of rankings by AUC vs the **bottom quintile**. Positive signal = feature correlates with better rankings; negative = correlates with worse.\n\n");
    md.push_str("| Feature | p(ON | top) | p(ON | bottom) | Signal | Interpretation |\n");
    md.push_str("|---|---|---|---|---|\n");
    for a in attribution {
        let interp = if a.signal.abs() < 0.1 {
            "—"
        } else if a.signal > 0.3 {
            "strongly helps"
        } else if a.signal > 0.1 {
            "mildly helps"
        } else if a.signal < -0.3 {
            "strongly hurts"
        } else {
            "mildly hurts"
        };
        md.push_str(&format!(
            "| {}. `{}` | {:.1}% | {:.1}% | {:+.3} | {} |\n",
            a.id,
            a.name,
            a.p_top * 100.0,
            a.p_bottom * 100.0,
            a.signal,
            interp
        ));
    }
    md.push('\n');

    md.push_str("## Recommendation\n\n");
    let best = sorted[0];
    let best_features = best
        .meta
        .features
        .iter()
        .map(|f| format!("feature {}", f))
        .collect::<Vec<_>>()
        .join(", ");
    md.push_str(&format!(
        "**Top pick: `{}`** ({}) with AUC **{:.4}** (95% CI [{:.4}, {:.4}]).\n\n",
        best.meta.id, best.meta.source, best.auc, best.auc_ci_lo, best.auc_ci_hi
    ));
    if best.meta.features.is_empty() {
        md.push_str("No features toggled (baseline-like).\n\n");
    } else {
        md.push_str(&format!("Active: {}.\n\n", best_features));
    }

    md.push_str("Runners-up (within 0.01 AUC of the top pick):\n\n");
    for s in sorted.iter().skip(1).take(5) {
        if best.auc - s.auc > 0.01 {
            break;
        }
        let features = s
            .meta
            .features
            .iter()
            .map(|f| f.to_string())
            .collect::<Vec<_>>()
            .join("-");
        md.push_str(&format!(
            "- `{}` — AUC {:.4} [{:.4}, {:.4}] — features: {}\n",
            s.meta.id,
            s.auc,
            s.auc_ci_lo,
            s.auc_ci_hi,
            if features.is_empty() {
                "—".to_string()
            } else {
                features
            }
        ));
    }
    md.push('\n');

    md.push_str("## Caveats\n\n");
    md.push_str("- **Labels are your input.** Every conclusion below rests on how you labeled the 'good' and 'bad' FIDs. Labeling bias propagates directly to the recommendation.\n");
    md.push_str("- **Correlation, not causation.** Feature attribution says which features are more common in high-AUC rankings — not that those features *caused* the improvement. Features interact.\n");
    md.push_str("- **Statistical power.** With this label count, AUC differences smaller than the width of the CI (~0.02-0.04 typically) should be treated as noise. If two rankings are within a CI of each other, prefer the simpler one.\n");
    md.push_str("- **Coverage matters.** A ranking that achieves high AUC but allocates zero tokens to most of your good FIDs (low `coverage_good`) is not actually rewarding the people you want rewarded — it's just ordering a few of them correctly. Prefer rankings with both high AUC *and* high coverage.\n");
    md.push_str("- **No ground truth.** AUC measures separation under your labels; it does not measure whether the allocation magnitudes are reasonable. Still eyeball the top-50 of the recommended ranking before shipping it.\n");

    fs::write(path, md)?;
    Ok(())
}
