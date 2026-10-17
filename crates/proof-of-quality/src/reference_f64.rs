//! Test-only f64 reference implementation of the scoring pipeline.
//!
//! This is the pre-port f64 implementation of the crate (same structure,
//! same `ln`/`log2`/`sqrt`/`powi` calls), updated with the FIP changes
//! that the fixed-point port implements, so that the two can be compared
//! on the same algorithm:
//! - crediter floor `trust ≥ 0.0001` (N3);
//! - vouch boost on `contribution(f, u)` for `f`'s vouch of an eligible
//!   `u`, saturating at `VOUCH_MATURITY_AMOUNT` (B3);
//! - stake factor = credibility stake + vouch stake received over
//!   `STAKE_MATURITY_AMOUNT` (B3 option (b), B4);
//! - trust-gated F5 with the absolute floor and the trust escape (N4);
//! - DA epoch boundary from `PIVOT_HEIGHT_0` (A6).
//!
//! Trust is used at full f64 precision (as before the port) unless it is
//! pinned to the fixed-point `trust_fp`.
//!
//! It reads the [`SnapchainStateReader`] directly (it does not reuse
//! `build_metrics`), so the integer-input plumbing is checked too.
//!
//! [`Pins`] lets a comparison pin trust and/or the eligibility flags to
//! the fixed-point values. Pinning trust removes crediter-floor flips at
//! trust ≈ 0.0001; pinning eligibility removes near-threshold flips from
//! the downstream (growth, composite, allocation) comparison.

#![allow(clippy::float_arithmetic)]
#![allow(clippy::disallowed_types)]

use crate::fixed::Exponent;
use crate::reader::SnapchainStateReader;
use crate::{
    epoch_boundary_height, Eligibility, RewardEntry, ScoringParams, WorkMarket,
    AGE_MATURITY_SECONDS, EIGENTRUST_ITERATIONS, EIGENTRUST_NORM_TOP_N, STAKE_MATURITY_AMOUNT,
    VOUCH_MATURITY_AMOUNT,
};
use std::collections::{BTreeMap, BTreeSet};

/// f64 crediter floor (`trust ≥ 0.0001`).
pub const CREDITER_TRUST_FLOOR: f64 = 1e-4;

/// Optional pins (see module docs).
#[derive(Clone, Copy, Default)]
pub struct Pins<'a> {
    /// fid → fixed-point `trust_fp` to use instead of the f64 trust.
    pub trust_fp: Option<&'a BTreeMap<u64, u32>>,
    pub eligibility: Option<&'a BTreeMap<u64, Eligibility>>,
}

#[derive(Clone, Debug, Default)]
pub struct RefFid {
    pub age: f64,
    /// Unpinned f64 trust score.
    pub trust_raw: f64,
    /// Trust used by every formula (`trust_raw`, or the pinned value).
    pub trust: f64,
    pub credibility: f64,
    pub stake_factor: f64,
    pub engager_entropy: f64,
    pub interaction_entropy: f64,
    pub total_engagement: u32,
    pub new_user_count: u32,
    pub new_user_share: f64,
    /// §6.2: new-user events from trusted engagers in the window.
    pub real_new_user_share: f64,
    /// `effective_ts` is within `REAL_NEW_USER_WINDOW` of now.
    pub in_real_window: bool,
    pub unique_engagers: u32,
    pub total_casts: u32,
    pub active_days: u32,
    pub replies_per_cast: f64,
    pub engagement_per_cast: f64,
    pub max_app_signal: u32,
    pub inbound: BTreeMap<u64, u32>,
    /// Outbound totals to other FIDs (interaction-entropy input).
    pub outbound_totals: Vec<f64>,
    pub outbound_first_30d: BTreeMap<u64, u32>,
    pub vouches_from: BTreeMap<u64, u64>,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct RefThresholds {
    pub engager_entropy: f64,
    pub engagement_per_cast: f64,
    pub new_user_share: f64,
    pub replies_per_cast: f64,
}

#[derive(Clone, Debug, Default)]
pub struct RefState {
    pub fids: BTreeMap<u64, RefFid>,
    pub eigentrust: BTreeMap<u64, f64>,
    pub thresholds: RefThresholds,
    pub eligibility: BTreeMap<u64, Eligibility>,
    pub growth: BTreeMap<u64, f64>,
    pub composite: BTreeMap<u64, f64>,
}

#[derive(Clone, Debug, Default)]
pub struct RefOutput {
    pub state: RefState,
    pub markets: BTreeMap<WorkMarket, Vec<RewardEntry>>,
}

/// The original f64 EigenTrust (`alpha = 0.85`), with followee dedup.
pub fn eigentrust(
    follow_graph: &BTreeMap<u64, Vec<u64>>,
    seed_set: &BTreeSet<u64>,
    iterations: u32,
) -> BTreeMap<u64, f64> {
    let alpha = 0.85;
    let mut universe: BTreeSet<u64> = BTreeSet::new();
    for (&j, followees) in follow_graph {
        universe.insert(j);
        universe.extend(followees.iter().copied());
    }
    universe.extend(seed_set.iter().copied());
    if universe.is_empty() || seed_set.is_empty() {
        return BTreeMap::new();
    }
    let seed_weight = 1.0 / seed_set.len() as f64;
    let mut t: BTreeMap<u64, f64> = universe
        .iter()
        .map(|&f| {
            (
                f,
                if seed_set.contains(&f) {
                    seed_weight
                } else {
                    0.0
                },
            )
        })
        .collect();
    let mut reverse: BTreeMap<u64, Vec<u64>> = BTreeMap::new();
    let mut out_degree: BTreeMap<u64, usize> = BTreeMap::new();
    for (&follower, followees) in follow_graph {
        let mut fs = followees.clone();
        fs.sort_unstable();
        fs.dedup();
        out_degree.insert(follower, fs.len());
        for f in fs {
            reverse.entry(f).or_default().push(follower);
        }
    }
    for _ in 0..iterations {
        let mut next: BTreeMap<u64, f64> = BTreeMap::new();
        for &fid in &universe {
            let mut acc = 0.0_f64;
            if let Some(followers) = reverse.get(&fid) {
                for &f in followers {
                    let od = out_degree[&f];
                    acc += t[&f] / od as f64;
                }
            }
            let kick = if seed_set.contains(&fid) {
                seed_weight
            } else {
                0.0
            };
            next.insert(fid, alpha * acc + (1.0 - alpha) * kick);
        }
        t = next;
    }
    t
}

/// Error bound of the fixed-point normalized entropy (§8.5) for these
/// values, in absolute units: each of the `k` terms floors `p_i` (an
/// error of ≤ 1 ulp, amplified by `log2(1/p_i)`), the negated log (≤ 1
/// ulp) and the product (≤ 1 ulp); the final quotient floors once more
/// (1 ulp, plus the error of `log2 k`).
pub fn entropy_error_bound<I: IntoIterator<Item = f64>>(values: I) -> f64 {
    let pos: Vec<f64> = values.into_iter().filter(|&v| v > 0.0).collect();
    if pos.len() < 2 {
        return 1e-6;
    }
    let total: f64 = pos.iter().sum();
    let terms: f64 = pos.iter().map(|&c| (total / c).log2() + 2.0).sum();
    1e-6 * (terms / (pos.len() as f64).log2() + 3.0)
}

/// Normalized Shannon entropy over the positive values (`k` = number of
/// positive values; 0 if `k < 2`), clamped to `[0, 1]`.
pub fn normalized_entropy<I: IntoIterator<Item = f64>>(values: I) -> f64 {
    let pos: Vec<f64> = values.into_iter().filter(|&v| v > 0.0).collect();
    if pos.len() < 2 {
        return 0.0;
    }
    let total: f64 = pos.iter().sum();
    let mut h = 0.0_f64;
    for &v in &pos {
        let p = v / total;
        h -= p * p.log2();
    }
    (h / (pos.len() as f64).log2()).clamp(0.0, 1.0)
}

fn percentile(mut values: Vec<f64>, pct: f64) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    values.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let idx = (values.len() as f64 * pct) as usize;
    values[idx.min(values.len() - 1)]
}

fn pow_exp(x: f64, e: Exponent) -> f64 {
    match e {
        Exponent::Zero => 1.0,
        Exponent::Half => x.max(0.0).sqrt(),
        Exponent::Int(n) => x.max(0.0).powi(n as i32),
    }
}

fn fp_param(x: u64) -> f64 {
    x as f64 / 1e6
}

/// The original f64 proportional allocator: floor of the f64 share,
/// remainder to the highest weight (tie: smaller FID).
pub fn allocate(weights: &BTreeMap<u64, f64>, budget: u128) -> Vec<RewardEntry> {
    if budget == 0 {
        return Vec::new();
    }
    let total: f64 = weights.values().sum();
    if !total.is_finite() || total <= 0.0 {
        return Vec::new();
    }
    let mut entries = Vec::new();
    let mut allocated: u128 = 0;
    for (&fid, &c) in weights {
        let amt = ((c / total) * budget as f64).floor().max(0.0) as u128;
        if amt > 0 {
            entries.push(RewardEntry { fid, amount: amt });
            allocated += amt;
        }
    }
    if allocated < budget {
        let remainder = budget - allocated;
        let top = weights
            .iter()
            .max_by(|(fa, ca), (fb, cb)| match ca.partial_cmp(cb) {
                Some(std::cmp::Ordering::Equal) | None => fb.cmp(fa),
                Some(o) => o,
            })
            .map(|(&f, _)| f);
        if let Some(top) = top {
            if let Some(e) = entries.iter_mut().find(|e| e.fid == top) {
                e.amount += remainder;
            } else {
                entries.push(RewardEntry {
                    fid: top,
                    amount: remainder,
                });
            }
        }
    }
    entries.sort_by_key(|e| e.fid);
    entries
}

/// f64 PoQ + Growth pipeline.
pub fn score<R: SnapchainStateReader + ?Sized>(
    reader: &R,
    now: u64,
    seeds: &BTreeSet<u64>,
    params: &ScoringParams,
    pins: Pins<'_>,
) -> RefState {
    let universe = reader.all_active_fids().unwrap();
    let mut fids: BTreeMap<u64, RefFid> = BTreeMap::new();
    let mut outbound: BTreeMap<u64, BTreeMap<u64, (u32, u32)>> = BTreeMap::new();
    let mut graph: BTreeMap<u64, Vec<u64>> = BTreeMap::new();
    let mut cred_stake: BTreeMap<u64, u64> = BTreeMap::new();
    for &f in &universe {
        let effective_ts = reader.effective_ts(f).unwrap();
        let window = params.real_new_user_window_secs.unwrap_or(0);
        let mut r = RefFid {
            age: match effective_ts {
                None => 0.0,
                Some(ts) => (now.saturating_sub(ts) as f64 / AGE_MATURITY_SECONDS as f64).min(1.0),
            },
            in_real_window: effective_ts.is_some_and(|ts| ts.saturating_add(window) >= now),
            ..RefFid::default()
        };
        r.total_casts = reader.total_casts(f).unwrap();
        r.active_days = reader.active_days(f).unwrap();
        let replies = reader.replies_received(f).unwrap();
        r.replies_per_cast = if r.total_casts > 0 {
            replies as f64 / r.total_casts as f64
        } else {
            0.0
        };
        r.max_app_signal = reader
            .signer_authorizations(f)
            .unwrap()
            .max(reader.signer_authorizations_clustered(f).unwrap())
            .max(reader.miniapp_author_count(f).unwrap());
        r.vouches_from = reader.vouches_from(f).unwrap();
        cred_stake.insert(f, reader.credibility_stake(f).unwrap());
        let e = reader.engagement_from(f).unwrap();
        outbound.insert(
            f,
            e.iter()
                .map(|(&t, c)| (t, (c.first_30d, c.total())))
                .collect(),
        );
        let mut fol = reader.followees(f).unwrap();
        fol.sort_unstable();
        fol.dedup();
        if !fol.is_empty() {
            graph.insert(f, fol);
        }
        fids.insert(f, r);
    }
    // Vouch stake received + stake factor.
    let mut received: BTreeMap<u64, u64> = BTreeMap::new();
    for (&v, r) in &fids {
        for (&u, &a) in &r.vouches_from {
            if u != v {
                *received.entry(u).or_default() += a;
            }
        }
    }
    for (&f, r) in fids.iter_mut() {
        let total = cred_stake[&f].saturating_add(received.get(&f).copied().unwrap_or(0));
        r.stake_factor = (total as f64 / STAKE_MATURITY_AMOUNT as f64).min(1.0);
    }
    // Inbound / outbound distributions.
    for (&source, edges) in &outbound {
        for (&target, &(first, total)) in edges {
            if source == target || !fids.contains_key(&target) || total == 0 {
                continue;
            }
            fids.get_mut(&target).unwrap().inbound.insert(source, total);
            if first > 0 {
                fids.get_mut(&source)
                    .unwrap()
                    .outbound_first_30d
                    .insert(target, first);
            }
        }
    }
    for (&f, r) in fids.iter_mut() {
        r.engager_entropy = normalized_entropy(r.inbound.values().map(|&c| c as f64));
        r.outbound_totals = outbound[&f]
            .iter()
            .filter(|(&t, _)| t != f)
            .map(|(_, &(_, total))| total as f64)
            .collect();
        r.interaction_entropy = normalized_entropy(r.outbound_totals.iter().copied());
        r.total_engagement = r.inbound.values().sum();
        r.unique_engagers = r.inbound.len() as u32;
        r.engagement_per_cast = if r.total_casts > 0 {
            r.unique_engagers as f64 / (1.0 + r.total_casts as f64).ln()
        } else {
            0.0
        };
    }

    // EigenTrust, trust, credibility.
    let et = eigentrust(&graph, seeds, EIGENTRUST_ITERATIONS);
    let mut vals: Vec<f64> = et.values().copied().collect();
    vals.sort_by(|a, b| b.partial_cmp(a).unwrap());
    let take = vals.len().min(EIGENTRUST_NORM_TOP_N);
    let sum: f64 = vals[..take].iter().sum();
    let norm = if take == 0 || sum == 0.0 {
        1.0
    } else {
        sum / take as f64
    };
    for (&f, r) in fids.iter_mut() {
        let raw = et.get(&f).copied().unwrap_or(0.0);
        r.trust_raw = ((raw / norm).min(1.0) * r.age).clamp(0.0, 1.0);
        r.trust = match pins.trust_fp {
            Some(p) => p[&f] as f64 / 1e6,
            None => r.trust_raw,
        };
        r.credibility = 0.25 * r.age
            + 0.35 * r.trust
            + 0.20 * r.interaction_entropy
            + 0.10 * r.stake_factor
            + 0.10 * 1.0;
    }

    // Gated new-user share (F5), and the share of new users who became
    // real (the composite, §6.2).
    let mut nu: BTreeMap<u64, u32> = BTreeMap::new();
    let mut real: BTreeMap<u64, u32> = BTreeMap::new();
    for r in fids.values() {
        let into = if r.trust < CREDITER_TRUST_FLOOR {
            &mut nu
        } else if r.in_real_window {
            &mut real
        } else {
            continue;
        };
        for (&t, &c) in &r.outbound_first_30d {
            *into.entry(t).or_default() += c;
        }
    }
    for (&f, r) in fids.iter_mut() {
        let share = |n: u32| {
            if r.total_engagement > 0 {
                n.min(r.total_engagement) as f64 / r.total_engagement as f64
            } else {
                0.0
            }
        };
        r.new_user_count = nu.get(&f).copied().unwrap_or(0).min(r.total_engagement);
        r.new_user_share = share(r.new_user_count);
        r.real_new_user_share = share(real.get(&f).copied().unwrap_or(0));
    }

    // Eligibility.
    let ep = &params.eligibility;
    let cohort: Vec<&RefFid> = fids
        .values()
        .filter(|r| {
            r.total_casts >= ep.calibration_min_casts
                && r.active_days >= ep.calibration_min_active_days
        })
        .collect();
    let pct = fp_param(ep.threshold_percentile_fp);
    let thresholds = RefThresholds {
        engager_entropy: percentile(cohort.iter().map(|r| r.engager_entropy).collect(), pct),
        engagement_per_cast: percentile(
            cohort.iter().map(|r| r.engagement_per_cast).collect(),
            pct,
        ),
        new_user_share: percentile(cohort.iter().map(|r| r.new_user_share).collect(), 1.0 - pct),
        replies_per_cast: percentile(cohort.iter().map(|r| r.replies_per_cast).collect(), pct),
    };
    let mut eligibility: BTreeMap<u64, Eligibility> = BTreeMap::new();
    for (&f, r) in &fids {
        let mut e = Eligibility::default();
        e.set(0, r.max_app_signal < ep.app_threshold);
        e.set(1, r.total_casts > 0);
        e.set(2, r.unique_engagers >= ep.min_engagers);
        e.set(3, r.engager_entropy >= thresholds.engager_entropy);
        e.set(
            4,
            !ep.enable_f4 || r.engagement_per_cast >= thresholds.engagement_per_cast,
        );
        e.set(
            5,
            r.new_user_share < thresholds.new_user_share
                || r.new_user_share < fp_param(ep.new_user_share_absolute_floor_fp)
                || r.trust >= CREDITER_TRUST_FLOOR,
        );
        e.set(6, r.replies_per_cast >= thresholds.replies_per_cast);
        eligibility.insert(f, e);
    }
    let gate = pins.eligibility.unwrap_or(&eligibility);

    // Growth.
    let mut growth: BTreeMap<u64, f64> = BTreeMap::new();
    for (&f, r_f) in &fids {
        if r_f.credibility <= 0.0 {
            continue;
        }
        let mut contributions: Vec<f64> = Vec::new();
        for (&u, &count_uf) in &r_f.inbound {
            let Some(r_u) = fids.get(&u) else { continue };
            let count_fu = r_u.inbound.get(&f).copied().unwrap_or(0);
            if count_fu == 0 || count_uf == 0 {
                continue;
            }
            if r_u.trust < CREDITER_TRUST_FLOOR || r_u.credibility <= 0.0 {
                continue;
            }
            let (a, b) = (count_fu as f64, count_uf as f64);
            let harmonic = 2.0 * a * b / (a + b);
            let eligible_u = gate.get(&u).map(|e| e.passes_all()).unwrap_or(false);
            let boost = match r_f.vouches_from.get(&u) {
                Some(&s) if eligible_u => 1.0 + (s as f64 / VOUCH_MATURITY_AMOUNT as f64).min(1.0),
                _ => 1.0,
            };
            contributions.push((1.0 + harmonic).ln() * r_u.credibility * boost);
        }
        let n = contributions.len();
        if n == 0 || n < params.min_distinct_crediters {
            continue;
        }
        let count_damping = (n as f64).sqrt() / n as f64;
        let damping = if params.growth_distribution_skew_exponent > 0 {
            let h = normalized_entropy(contributions.iter().copied());
            (1.0 - h)
                .max(0.0)
                .powi(params.growth_distribution_skew_exponent as i32)
                .max(fp_param(params.growth_distribution_min_damping_fp))
        } else {
            1.0
        };
        let raw_sum: f64 = contributions.iter().sum();
        let g = raw_sum * count_damping * damping;
        if g > 0.0 {
            growth.insert(f, g);
        }
    }

    // Composite.
    let mut composite: BTreeMap<u64, f64> = BTreeMap::new();
    for (&f, r) in &fids {
        let Some(&g) = growth.get(&f) else { continue };
        let c = composite_f64(
            r.credibility,
            r.trust,
            r.engager_entropy,
            r.interaction_entropy,
            match params.real_new_user_window_secs {
                Some(_) => r.real_new_user_share,
                None => r.new_user_share,
            },
            g,
            params,
        );
        if c > 0.0 {
            composite.insert(f, c);
        }
    }

    RefState {
        fids,
        eigentrust: et,
        thresholds,
        eligibility,
        growth,
        composite,
    }
}

/// The original f64 composite formula.
pub fn composite_f64(
    cred: f64,
    trust: f64,
    eg: f64,
    ie: f64,
    share: f64,
    growth: f64,
    p: &ScoringParams,
) -> f64 {
    pow_exp(cred, p.credibility_exponent)
        * pow_exp(trust, p.trust_exponent)
        * pow_exp(eg * ie, p.ring_symmetry_exponent)
        * pow_exp(
            share + fp_param(p.new_user_share_epsilon_fp),
            p.new_user_share_exponent,
        )
        * pow_exp(growth, p.growth_exponent)
}

/// f64 DA scores of `epoch`.
pub fn da_weights<R: SnapchainStateReader + ?Sized>(
    reader: &R,
    epoch: u64,
    params: &ScoringParams,
) -> BTreeMap<u64, f64> {
    da_scores(
        &reader.da_answered_counts_for_epoch(epoch).unwrap(),
        &reader.da_response_block_sum_for_epoch(epoch).unwrap(),
        epoch_boundary_height(params.pivot_height_0, epoch, params.epoch_length_blocks),
        params,
    )
}

/// f64 app work of `epoch`.
pub fn app_weights<R: SnapchainStateReader + ?Sized>(
    reader: &R,
    epoch: u64,
    fids: &BTreeMap<u64, RefFid>,
    params: &ScoringParams,
) -> BTreeMap<u64, f64> {
    let cred: BTreeMap<u64, f64> = fids.iter().map(|(&f, r)| (f, r.credibility)).collect();
    app_work(
        &reader.app_receipt_counts_for_epoch(epoch).unwrap(),
        &reader.miniapp_add_events_for_epoch(epoch).unwrap(),
        &cred,
        params,
    )
}

fn da_scores(
    answered: &BTreeMap<u64, u32>,
    block_sum: &BTreeMap<u64, u128>,
    boundary: u64,
    params: &ScoringParams,
) -> BTreeMap<u64, f64> {
    let n = params.da_pow_challenges_per_epoch as f64;
    let mut scores: BTreeMap<u64, f64> = BTreeMap::new();
    for (&fid, &count) in answered {
        if count == 0 || n == 0.0 {
            continue;
        }
        let ratio = (count as f64 / n).min(1.0);
        let sum = block_sum.get(&fid).copied().unwrap_or(0) as f64;
        let avg = (sum / count as f64 - boundary as f64).max(0.0);
        let latency =
            (1.0 - avg / crate::da_pow::CHALLENGE_RESPONSE_WINDOW_BLOCKS as f64).clamp(0.0, 1.0);
        let s = ratio * latency;
        if s > 0.0 {
            scores.insert(fid, s);
        }
    }
    scores
}

fn app_work(
    receipts: &BTreeMap<(u64, u64), u32>,
    adds: &BTreeMap<(u64, u64), u32>,
    cred: &BTreeMap<u64, f64>,
    params: &ScoringParams,
) -> BTreeMap<u64, f64> {
    let mut work: BTreeMap<u64, f64> = BTreeMap::new();
    for (stream, w) in [
        (receipts, fp_param(params.app_pow_receipt_weight_fp)),
        (adds, fp_param(params.app_pow_add_weight_fp)),
    ] {
        for (&(app, user), &count) in stream {
            let c = cred.get(&user).copied().unwrap_or(0.0);
            if count > 0 && c > 0.0 {
                *work.entry(app).or_default() += count as f64 * w * c;
            }
        }
    }
    work
}

/// f64 DA-PoW (§5.4), same semantics as the fixed-point version.
pub fn da_pow(
    answered: &BTreeMap<u64, u32>,
    block_sum: &BTreeMap<u64, u128>,
    boundary: u64,
    params: &ScoringParams,
    budget: u128,
) -> Vec<RewardEntry> {
    allocate(&da_scores(answered, block_sum, boundary, params), budget)
}

/// f64 App-PoW (§7.4) without a cap.
pub fn app_pow(
    receipts: &BTreeMap<(u64, u64), u32>,
    adds: &BTreeMap<(u64, u64), u32>,
    cred: &BTreeMap<u64, f64>,
    params: &ScoringParams,
    budget: u128,
) -> Vec<RewardEntry> {
    allocate(&app_work(receipts, adds, cred, params), budget)
}

/// f64 `evaluate_epoch`.
pub fn evaluate<R: SnapchainStateReader + ?Sized>(
    reader: &R,
    epoch: u64,
    now: u64,
    seeds: &BTreeSet<u64>,
    params: &ScoringParams,
    pins: Pins<'_>,
) -> RefOutput {
    let state = score(reader, now, seeds, params, pins);
    let gate = pins.eligibility.unwrap_or(&state.eligibility);
    let gated: BTreeMap<u64, f64> = state
        .composite
        .iter()
        .filter(|(f, _)| gate.get(f).map(|e| e.passes_all()).unwrap_or(false))
        .map(|(&f, &c)| (f, c))
        .collect();
    let cred: BTreeMap<u64, f64> = state
        .fids
        .iter()
        .map(|(&f, r)| (f, r.credibility))
        .collect();
    let budget = |m| params.market_budgets.get(&m).copied().unwrap_or(0);
    let mut markets = BTreeMap::new();
    markets.insert(
        WorkMarket::Growth,
        allocate(&gated, budget(WorkMarket::Growth)),
    );
    markets.insert(
        WorkMarket::AppUsage,
        app_pow(
            &reader.app_receipt_counts_for_epoch(epoch).unwrap(),
            &reader.miniapp_add_events_for_epoch(epoch).unwrap(),
            &cred,
            params,
            budget(WorkMarket::AppUsage),
        ),
    );
    markets.insert(
        WorkMarket::DataAvailability,
        da_pow(
            &reader.da_answered_counts_for_epoch(epoch).unwrap(),
            &reader.da_response_block_sum_for_epoch(epoch).unwrap(),
            epoch_boundary_height(params.pivot_height_0, epoch, params.epoch_length_blocks),
            params,
            budget(WorkMarket::DataAvailability),
        ),
    );
    RefOutput { state, markets }
}
