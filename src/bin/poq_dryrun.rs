//! Parameter-sweep dry-run for the in-protocol PoQ scoring pipeline.
//!
//! Loads `PoqReader` over a chain's RocksDB, runs `evaluate_epoch` with
//! configurable `ScoringParams` overrides, and emits the resulting
//! `EpochScoringOutput` as JSON on stdout. Operators run it multiple
//! times with different flag values and diff the output (via `jq`,
//! `dyff`, etc.) to predict the effect of a parameter change before
//! coordinating a network-wide rollout.
//!
//! This binary does NOT mutate the DB. Read-only access; safe to point
//! at a live node's data directory (though grabbing a snapshot via
//! `rocksdb checkpoint` is preferable to avoid log-tail surprises).
//!
//! Usage:
//!   poq_dryrun \
//!     --db-path /var/lib/hypersnap/snapchain \
//!     --epoch 42 \
//!     [--seed-max-fid 50000] \
//!     [--vouch-boost-min-vouchee-trust 0.05] \
//!     [--crediter-trust-threshold 0.05] \
//!     [--app-pow-max-per-epoch-atoms 250000000] \
//!     [--app-pow-receipt-weight 0.5] \
//!     [--app-pow-add-weight 5.0] \
//!     [--threshold-percentile 0.10] \
//!     [--app-threshold 100] \
//!     [--min-engagers 3] \
//!     [--enable-f4] \
//!     [--budget-da 5000000] \
//!     [--budget-growth 2000000] \
//!     [--budget-app 3000000]

use clap::Parser;
use hypersnap::hyper::poq_reader::PoqReader;
use hypersnap::storage::db::RocksDB;
use proof_of_quality::reader::SnapchainStateReader;
use proof_of_quality::scoring::evaluate_epoch;
use proof_of_quality::{ScoringParams, WorkMarket};
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Parser, Debug)]
#[command(
    name = "poq_dryrun",
    about = "Dry-run the PoQ scoring pipeline with configurable parameter overrides"
)]
struct Args {
    /// Path to the chain's snapchain RocksDB. Read-only access; the
    /// DB is opened in standard mode (not strictly read-only — be
    /// sure the live node is not actively writing if you point at
    /// its directory).
    #[arg(long)]
    db_path: PathBuf,

    /// Epoch to evaluate. Picks the trie state at the time the
    /// binary runs (no time-travel).
    #[arg(long)]
    epoch: u64,

    /// Unix timestamp passed as `now_unix` to `evaluate_epoch`.
    /// Used for the §8.1 age_factor calculation. Defaults to the
    /// machine clock.
    #[arg(long)]
    now_unix: Option<u64>,

    /// Seed-set upper bound. FIDs ≤ this value are EigenTrust
    /// seeds. Default 50_000 (FIP-proof-of-quality §calibration).
    #[arg(long, default_value = "50000")]
    seed_max_fid: u64,

    // --- Scoring tunables ---
    #[arg(long)]
    credibility_exponent: Option<f64>,
    #[arg(long)]
    trust_exponent: Option<f64>,
    #[arg(long)]
    ring_symmetry_exponent: Option<f64>,
    #[arg(long)]
    new_user_share_exponent: Option<f64>,
    #[arg(long)]
    new_user_share_smoothing: Option<f64>,
    #[arg(long)]
    growth_exponent: Option<f64>,
    #[arg(long)]
    crediter_trust_threshold: Option<f64>,
    #[arg(long)]
    vouch_boost_min_vouchee_trust: Option<f64>,

    // --- App-PoW tunables ---
    #[arg(long)]
    app_pow_receipt_weight: Option<f64>,
    #[arg(long)]
    app_pow_add_weight: Option<f64>,
    #[arg(long)]
    app_pow_max_per_epoch_atoms: Option<u128>,

    // --- Eligibility tunables ---
    #[arg(long)]
    app_threshold: Option<u32>,
    #[arg(long)]
    min_engagers: Option<u32>,
    #[arg(long)]
    calibration_min_casts: Option<u32>,
    #[arg(long)]
    calibration_min_active_days: Option<u32>,
    #[arg(long)]
    threshold_percentile: Option<f64>,
    /// Enable F4 (engagement-per-cast) — off by default per FIP §8.3.
    #[arg(long)]
    enable_f4: bool,

    // --- Market budgets (atoms) ---
    #[arg(long)]
    budget_da: Option<u128>,
    #[arg(long)]
    budget_growth: Option<u128>,
    #[arg(long)]
    budget_app: Option<u128>,

    // --- DA-PoW tunables ---
    #[arg(long)]
    da_pow_challenges_per_epoch: Option<u32>,
}

fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn build_params(args: &Args) -> ScoringParams {
    let mut p = ScoringParams::default();
    if let Some(v) = args.credibility_exponent {
        p.credibility_exponent = v;
    }
    if let Some(v) = args.trust_exponent {
        p.trust_exponent = v;
    }
    if let Some(v) = args.ring_symmetry_exponent {
        p.ring_symmetry_exponent = v;
    }
    if let Some(v) = args.new_user_share_exponent {
        p.new_user_share_exponent = v;
    }
    if let Some(v) = args.new_user_share_smoothing {
        p.new_user_share_smoothing = v;
    }
    if let Some(v) = args.growth_exponent {
        p.growth_exponent = v;
    }
    if let Some(v) = args.crediter_trust_threshold {
        p.crediter_trust_threshold = v;
    }
    if let Some(v) = args.vouch_boost_min_vouchee_trust {
        p.vouch_boost_min_vouchee_trust = v;
    }
    if let Some(v) = args.app_pow_receipt_weight {
        p.app_pow_receipt_weight = v;
    }
    if let Some(v) = args.app_pow_add_weight {
        p.app_pow_add_weight = v;
    }
    if let Some(v) = args.app_pow_max_per_epoch_atoms {
        p.app_pow_max_per_epoch_atoms = v;
    }
    if let Some(v) = args.app_threshold {
        p.eligibility.app_threshold = v;
    }
    if let Some(v) = args.min_engagers {
        p.eligibility.min_engagers = v;
    }
    if let Some(v) = args.calibration_min_casts {
        p.eligibility.calibration_min_casts = v;
    }
    if let Some(v) = args.calibration_min_active_days {
        p.eligibility.calibration_min_active_days = v;
    }
    if let Some(v) = args.threshold_percentile {
        p.eligibility.threshold_percentile = v;
    }
    if args.enable_f4 {
        p.eligibility.enable_f4 = true;
    }
    if let Some(v) = args.da_pow_challenges_per_epoch {
        p.da_pow_challenges_per_epoch = v;
    }
    // Market budgets. Default 0 (no allocation) unless overridden.
    if let Some(v) = args.budget_da {
        p.market_budgets.insert(WorkMarket::DataAvailability, v);
    }
    if let Some(v) = args.budget_growth {
        p.market_budgets.insert(WorkMarket::Growth, v);
    }
    if let Some(v) = args.budget_app {
        p.market_budgets.insert(WorkMarket::AppUsage, v);
    }
    p
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let db_path = args.db_path.to_str().ok_or("db_path must be valid UTF-8")?;
    let db = RocksDB::new(db_path);
    db.open()?;
    let db = Arc::new(db);

    // Build a PoqReader. The reader walks `HyperFidActive` (or
    // similar) to determine the universe; we pass an empty initial
    // set and let the reader populate from on-chain state.
    let reader = PoqReader::new(db.clone(), BTreeSet::new());

    // Seed set: FIDs ≤ seed_max_fid that ALSO appear in the active
    // universe. The reader's `all_active_fids` gives us the
    // universe.
    let universe = reader.all_active_fids()?;
    let seeds: BTreeSet<u64> = universe
        .iter()
        .copied()
        .filter(|f| *f > 0 && *f <= args.seed_max_fid)
        .collect();

    let params = build_params(&args);
    let now_unix = args.now_unix.unwrap_or_else(now_unix_secs);

    eprintln!(
        "evaluating epoch {} (universe size: {}, seed size: {}, now_unix: {})",
        args.epoch,
        universe.len(),
        seeds.len(),
        now_unix
    );

    let out = evaluate_epoch(&reader, args.epoch, now_unix, &seeds, &params)?;

    // Emit JSON to stdout. The output shape matches
    // `EpochScoringOutput` (epoch + per-market reward lists + trust
    // snapshot) so downstream tooling can diff against another run.
    let json = serde_json::to_string_pretty(&out)?;
    println!("{}", json);
    Ok(())
}
