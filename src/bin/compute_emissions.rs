//! Compute per-epoch emissions from a follow graph + engagement CSV.
//!
//! Usage:
//!   compute_emissions \
//!     --follows follows.csv \
//!     --engagement engagement.csv \
//!     --epoch 5 \
//!     --tranche-atoms 100000000 \
//!     --output emissions.csv
//!
//! Input file formats:
//!
//! follows.csv:    src_fid,target_fid           (one edge per line; src follows target)
//! engagement.csv: a_fid,b_fid,a_to_b,b_to_a    (per-pair counts, both directions)
//!
//! Output:
//!   emissions.csv: fid,atoms                   (one row per recipient)
//!
//! Seeds default to FID ≤ SEED_MAX_FID = 50_000 per the FIP. Use --seed-max-fid
//! to override for testing.

use clap::Parser;
use hypersnap::emission::mutuality::PairEngagement;
use hypersnap::emission::params::SEED_MAX_FID;
use hypersnap::emission::{
    compute_epoch_emissions, EmissionComputeInputs, EmissionParams, MutualityMode,
};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    version,
    about = "Compute Hypersnap epoch emissions per FIP-proof-of-work-tokenization"
)]
struct Args {
    #[arg(long)]
    follows: PathBuf,
    #[arg(long)]
    engagement: PathBuf,
    #[arg(long)]
    epoch: u64,
    /// Total atoms to distribute this epoch (1 HYPER = 1_000_000 atoms).
    #[arg(long)]
    tranche_atoms: u64,
    #[arg(long, default_value_t = SEED_MAX_FID)]
    seed_max_fid: u64,
    #[arg(long, default_value_t = 0.05)]
    crediter_trust_floor: f64,
    #[arg(long, default_value_t = 1)]
    min_per_recipient_atoms: u64,
    #[arg(long, value_enum, default_value_t = MutualityModeArg::Sum)]
    mutuality: MutualityModeArg,
    #[arg(long)]
    output: PathBuf,
}

#[derive(clap::ValueEnum, Clone, Debug)]
enum MutualityModeArg {
    Min,
    Geom,
    Harmonic,
    Avg,
    Sum,
}

impl From<MutualityModeArg> for MutualityMode {
    fn from(a: MutualityModeArg) -> Self {
        match a {
            MutualityModeArg::Min => MutualityMode::Min,
            MutualityModeArg::Geom => MutualityMode::Geom,
            MutualityModeArg::Harmonic => MutualityMode::Harmonic,
            MutualityModeArg::Avg => MutualityMode::Avg,
            MutualityModeArg::Sum => MutualityMode::Sum,
        }
    }
}

fn read_follows(path: &PathBuf) -> std::io::Result<HashMap<u64, Vec<u64>>> {
    let mut follows: HashMap<u64, Vec<u64>> = HashMap::new();
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    for (i, line) in reader.lines().enumerate() {
        let line = line?;
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = trimmed.split(',').collect();
        if parts.len() != 2 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("follows.csv line {}: expected 2 fields", i + 1),
            ));
        }
        let src: u64 = parts[0].trim().parse().map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("follows.csv line {}: invalid src_fid", i + 1),
            )
        })?;
        let tgt: u64 = parts[1].trim().parse().map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("follows.csv line {}: invalid target_fid", i + 1),
            )
        })?;
        follows.entry(src).or_default().push(tgt);
    }
    Ok(follows)
}

fn read_engagement(path: &PathBuf) -> std::io::Result<Vec<(u64, u64, PairEngagement)>> {
    let mut out: Vec<(u64, u64, PairEngagement)> = Vec::new();
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    for (i, line) in reader.lines().enumerate() {
        let line = line?;
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = trimmed.split(',').collect();
        if parts.len() != 4 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("engagement.csv line {}: expected 4 fields", i + 1),
            ));
        }
        let a: u64 = parts[0].trim().parse().map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("engagement.csv line {}: invalid a_fid", i + 1),
            )
        })?;
        let b: u64 = parts[1].trim().parse().map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("engagement.csv line {}: invalid b_fid", i + 1),
            )
        })?;
        let a_to_b: u64 = parts[2].trim().parse().map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("engagement.csv line {}: invalid a_to_b", i + 1),
            )
        })?;
        let b_to_a: u64 = parts[3].trim().parse().map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("engagement.csv line {}: invalid b_to_a", i + 1),
            )
        })?;
        out.push((a, b, PairEngagement::new(a_to_b, b_to_a)));
    }
    Ok(out)
}

fn main() -> std::io::Result<()> {
    let args = Args::parse();

    eprintln!("[compute_emissions] reading {}", args.follows.display());
    let follows = read_follows(&args.follows)?;
    eprintln!(
        "[compute_emissions] {} sources with outgoing follows",
        follows.len()
    );

    eprintln!("[compute_emissions] reading {}", args.engagement.display());
    let engagement = read_engagement(&args.engagement)?;
    eprintln!("[compute_emissions] {} engagement pairs", engagement.len());

    // Seeds: FID ≤ seed_max_fid that appear anywhere in the graph.
    let mut seed_set: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();
    for src in follows.keys() {
        if *src <= args.seed_max_fid {
            seed_set.insert(*src);
        }
    }
    for ts in follows.values() {
        for t in ts {
            if *t <= args.seed_max_fid {
                seed_set.insert(*t);
            }
        }
    }
    let seeds: Vec<u64> = seed_set.into_iter().collect();
    eprintln!("[compute_emissions] {} seed FIDs", seeds.len());

    let params = EmissionParams {
        epoch_tranche_atoms: args.tranche_atoms,
        seed_max_fid: args.seed_max_fid,
        mutuality_mode: args.mutuality.into(),
        min_per_recipient_atoms: args.min_per_recipient_atoms,
        crediter_trust_floor: args.crediter_trust_floor,
        min_active_days: 7,
    };

    let inputs = EmissionComputeInputs {
        follows,
        engagement,
        seeds,
        epoch: args.epoch,
    };

    eprintln!("[compute_emissions] running PoQ pipeline …");
    let result = compute_epoch_emissions(inputs, &params);
    eprintln!(
        "[compute_emissions] epoch={} recipients={} total_atoms={}",
        result.epoch,
        result.allocations.len(),
        result.total_atoms
    );

    let out_file = File::create(&args.output)?;
    let mut writer = BufWriter::new(out_file);
    writeln!(writer, "fid,atoms")?;
    for (fid, atoms) in &result.allocations {
        writeln!(writer, "{},{}", fid, atoms)?;
    }
    eprintln!("[compute_emissions] wrote {}", args.output.display());
    Ok(())
}
