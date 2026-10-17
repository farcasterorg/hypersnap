//! v6 composite reproduction (plan R1 gate 2, N5).
//!
//! Streams `retro_rewards_final_v6/eligibility.csv` (673 MB; never
//! loaded whole), takes the first `POQ_V6_ROWS` (default 20 000; `all`
//! for the whole file) rows with a non-zero `composite_harmonic`, feeds
//! the fixed-point composite ([`composite_score`]) the row's
//! `credibility_weight`, `trust_score` (as `trust_fp`, exact: the CSV has
//! 6 decimals), `engager_entropy`, `interaction_entropy`,
//! `new_user_engagement_share` and `growth_harmonic`, and counts the rows
//! whose fixed-point composite is within 0.1% of `composite_harmonic`.
//!
//! The CSV stores every value rounded to 6 decimals, so a 0.1% match is
//! not always achievable even for the exact formula; the f64 formula on
//! the same inputs is reported as the baseline. Two diagnostics show the
//! alternatives that were rejected: the written product order (growth
//! last) and the earlier u16 trust rule (`trust_enc = trust_fp / 100` in
//! the composite).
//!
//! Run: `cargo test -p proof-of-quality v6 -- --ignored --nocapture`
//! (path override: `POQ_V6_CSV`).

#![allow(clippy::float_arithmetic)]
#![allow(clippy::disallowed_types)]

use crate::fixed::{fp_mul, FP_SCALE};
use crate::scoring::{composite_from_parts, composite_score, CompositeInputs};
use crate::ScoringParams;
use std::io::{BufRead, BufReader};

const DEFAULT_CSV: &str =
    "/Users/caheart/src/hypersnap-retro-rewards-analysis/retro_rewards_final_v6/eligibility.csv";

/// Parse a non-negative decimal string into 6-decimal fixed point
/// exactly (truncating digits beyond the 6th). No floats involved.
fn parse_fp6(s: &str) -> Option<u128> {
    let s = s.trim();
    let (int, frac) = match s.split_once('.') {
        Some((i, f)) => (i, f),
        None => (s, ""),
    };
    let int: u128 = if int.is_empty() { 0 } else { int.parse().ok()? };
    let mut frac_digits: String = frac.chars().take(6).collect();
    while frac_digits.len() < 6 {
        frac_digits.push('0');
    }
    let frac: u128 = frac_digits.parse().ok()?;
    Some(int * FP_SCALE + frac)
}

struct Row {
    fid: u64,
    cred: u128,
    trust: u128,
    eg: u128,
    ie: u128,
    share: u128,
    growth: u128,
    composite: u128,
    eligible: bool,
    f64s: [f64; 7],
}

/// Composite with the five factors multiplied in the written order
/// `cred^k · trust^j · sym^p · nu^q · growth^g` (diagnostic only; the
/// consensus order is growth first, see `composite_score`).
fn composite_written_order(r: &Row, trust_fp: u128, p: &ScoringParams) -> u128 {
    let c = p.credibility_exponent.apply(r.cred);
    let t = p.trust_exponent.apply(trust_fp);
    let s = p.ring_symmetry_exponent.apply(fp_mul(r.eg, r.ie));
    let n = p
        .new_user_share_exponent
        .apply(r.share + u128::from(p.new_user_share_epsilon_fp));
    let g = p.growth_exponent.apply(r.growth);
    fp_mul(fp_mul(fp_mul(fp_mul(c, t), s), n), g)
}

/// Measured consensus-path match count on the first 20 000 rows
/// (regression floor).
const CONSENSUS_PATH_MATCHES_20K: usize = 19_873;

fn within(x: f64, target: f64, rel: f64) -> bool {
    (x - target).abs() <= rel * target
}

#[test]
#[ignore]
fn v6_composite_reproduction() {
    let path = std::env::var("POQ_V6_CSV").unwrap_or_else(|_| DEFAULT_CSV.to_string());
    let limit: usize = match std::env::var("POQ_V6_ROWS").ok().as_deref() {
        Some("all") => usize::MAX,
        Some(v) => v.parse().unwrap_or(20_000),
        None => 20_000,
    };
    let Ok(file) = std::fs::File::open(&path) else {
        eprintln!("v6 CSV not found at {path}; skipping");
        return;
    };
    let mut lines = BufReader::with_capacity(1 << 20, file).lines();
    let header = lines.next().unwrap().unwrap();
    let cols: Vec<&str> = header.split(',').collect();
    let idx = |name: &str| cols.iter().position(|&c| c == name).unwrap();
    let (i_fid, i_cred, i_trust, i_eg, i_ie, i_share, i_growth, i_comp, i_elig) = (
        idx("fid"),
        idx("credibility_weight"),
        idx("trust_score"),
        idx("engager_entropy"),
        idx("interaction_entropy"),
        idx("new_user_engagement_share"),
        idx("growth_harmonic"),
        idx("composite_harmonic"),
        idx("eligible"),
    );
    let p = ScoringParams::default();

    let mut n = 0usize;
    let (mut m_fixed, mut m_f64, mut m_written, mut m_u16) = (0usize, 0usize, 0usize, 0usize);
    // Relative-error histogram of the consensus path:
    // <1e-5, <1e-4, <1e-3, <1e-2, <1e-1, ≥1e-1.
    let mut hist = [0usize; 6];
    let mut fixed_zero = 0usize;
    let mut worst: Vec<(f64, u64, u128, u128, f64)> = Vec::new();
    // Pool shares over eligible rows: (v6, f64 formula, fixed point).
    let mut alloc: Vec<(f64, f64, f64)> = Vec::new();
    let mut alloc_u16: Vec<(f64, f64)> = Vec::new(); // (v6, previous u16 rule)
    let (mut below_floor, mut below_floor_eligible) = (0usize, 0usize);
    let mut v6_mass_below_floor = 0.0_f64;

    for line in lines {
        if n >= limit {
            break;
        }
        let line = line.unwrap();
        let f: Vec<&str> = line.split(',').collect();
        let composite = parse_fp6(f[i_comp]).unwrap_or(0);
        if composite == 0 {
            continue;
        }
        let pf = |i: usize| f[i].parse::<f64>().unwrap();
        let row = Row {
            fid: f[i_fid].parse().unwrap(),
            cred: parse_fp6(f[i_cred]).unwrap(),
            trust: parse_fp6(f[i_trust]).unwrap(),
            eg: parse_fp6(f[i_eg]).unwrap(),
            ie: parse_fp6(f[i_ie]).unwrap(),
            share: parse_fp6(f[i_share]).unwrap(),
            growth: parse_fp6(f[i_growth]).unwrap(),
            composite,
            eligible: f[i_elig] == "true",
            f64s: [
                pf(i_cred),
                pf(i_trust),
                pf(i_eg),
                pf(i_ie),
                pf(i_share),
                pf(i_growth),
                pf(i_comp),
            ],
        };
        n += 1;
        let target = row.f64s[6];
        // Consensus path: trust_fp (6 decimals), growth-first order.
        let trust_fp = u32::try_from(row.trust).unwrap();
        let fixed = composite_score(
            &CompositeInputs {
                credibility_weight_fp: row.cred as u64,
                trust_fp,
                engager_entropy_fp: row.eg as u64,
                interaction_entropy_fp: row.ie as u64,
                new_user_share_fp: row.share as u64,
                growth_fp: row.growth,
            },
            &p,
        );
        let fixed_f = fixed as f64 / 1e6;
        if fixed == 0 {
            fixed_zero += 1;
        }
        let rel = (fixed_f - target).abs() / target;
        let bucket = [1e-5, 1e-4, 1e-3, 1e-2, 1e-1]
            .iter()
            .position(|&b| rel < b)
            .unwrap_or(5);
        hist[bucket] += 1;
        if within(fixed_f, target, 1e-3) {
            m_fixed += 1;
        } else {
            worst.push((rel, row.fid, fixed, row.composite, row.f64s[1]));
        }
        // Diagnostic: written product order (growth last).
        let wo = composite_written_order(&row, row.trust, &p);
        if within(wo as f64 / 1e6, target, 1e-3) {
            m_written += 1;
        }
        // Diagnostic: the earlier u16 rule, trust_enc = trust_fp / 100.
        let u16_trust = u128::from(crate::fixed::trust_enc_from_fp(trust_fp)) * 100;
        let old = composite_from_parts(
            row.cred, u16_trust, row.eg, row.ie, row.share, row.growth, &p,
        );
        if within(old as f64 / 1e6, target, 1e-3) {
            m_u16 += 1;
        }
        // Baseline: the f64 formula on the same (rounded) inputs.
        let [c, t, eg, ie, s, g, _] = row.f64s;
        let f64c = c.powi(4) * t.sqrt() * (eg * ie).powi(3) * (s + 0.001).sqrt() * g.sqrt();
        if within(f64c, target, 1e-3) {
            m_f64 += 1;
        }
        if trust_fp < crate::CREDITER_TRUST_FLOOR_FP {
            below_floor += 1;
            if row.eligible {
                below_floor_eligible += 1;
                v6_mass_below_floor += target;
            }
        }
        if row.eligible {
            alloc.push((target, f64c, fixed_f));
            alloc_u16.push((target, old as f64 / 1e6));
        }
    }

    worst.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap());
    eprintln!("v6 composite reproduction over {n} rows with non-zero composite_harmonic:");
    eprintln!("  fixed point (consensus: trust_fp, growth first) within 0.1%: {m_fixed}/{n}");
    eprintln!("  f64 formula on the same CSV inputs within 0.1%:              {m_f64}/{n}");
    eprintln!("  diagnostic: written product order (growth last):             {m_written}/{n}");
    eprintln!("  diagnostic: previous u16 trust rule (trust_fp / 100):        {m_u16}/{n}");
    eprintln!("  consensus-path rel-error histogram <1e-5,<1e-4,<1e-3,<1e-2,<1e-1,≥1e-1: {hist:?}");
    eprintln!("  fixed composite = 0 (below 1 ulp): {fixed_zero}");
    for (rel, fid, fixed, v6, trust) in worst.iter().take(5) {
        eprintln!("    fid {fid}: fixed {fixed} v6 {v6} (rel {rel:.2e}, trust {trust})");
    }
    let tv = |rows: &[(f64, f64, f64)],
              a: fn(&(f64, f64, f64)) -> f64,
              b: fn(&(f64, f64, f64)) -> f64| {
        let sa: f64 = rows.iter().map(a).sum();
        let sb: f64 = rows.iter().map(b).sum();
        0.5 * rows
            .iter()
            .map(|x| (a(x) / sa - b(x) / sb).abs())
            .sum::<f64>()
    };
    if !alloc.is_empty() {
        let v6_mass: f64 = alloc.iter().map(|x| x.0).sum();
        eprintln!(
            "  rows with trust_fp < 100 (not crediters; composite still counts): {below_floor} ({below_floor_eligible} eligible, {:.3}% of the eligible v6 composite mass)",
            100.0 * v6_mass_below_floor / v6_mass
        );
        let old: Vec<(f64, f64, f64)> = alloc_u16.iter().map(|&(a, b)| (a, 0.0, b)).collect();
        eprintln!(
            "  pool-share total variation over {} eligible rows: fixed vs v6 {:.3e}, f64 vs v6 {:.3e}, fixed vs f64 {:.3e} (previous u16 rule vs v6: {:.3e})",
            alloc.len(),
            tv(&alloc, |x| x.2, |x| x.0),
            tv(&alloc, |x| x.1, |x| x.0),
            tv(&alloc, |x| x.2, |x| x.1),
            tv(&old, |x| x.2, |x| x.0),
        );
    }
    if limit == 20_000 && n == 20_000 {
        // Regression guards on the measured rates (see the crate report).
        assert!(m_f64 * 1000 >= n * 995, "f64 baseline {m_f64}/{n}");
        assert!(
            m_fixed >= CONSENSUS_PATH_MATCHES_20K,
            "consensus path {m_fixed}/{n}"
        );
    }
}

#[test]
fn parse_fp6_is_exact() {
    assert_eq!(parse_fp6("0.874020"), Some(874_020));
    assert_eq!(parse_fp6("4079.263727"), Some(4_079_263_727));
    assert_eq!(parse_fp6("1"), Some(1_000_000));
    assert_eq!(parse_fp6("0.0000005"), Some(0));
    assert_eq!(parse_fp6("x"), None);
}
