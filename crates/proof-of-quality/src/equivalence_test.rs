//! Property tests: fixed-point pipeline vs the f64 reference
//! ([`crate::reference_f64`]) on random small universes.
//!
//! ## Tolerance policy
//!
//! The fixed-point pipeline is the consensus definition; the f64
//! reference only shows that the port computes the same algorithm. Every
//! fixed-point operation floors to 1 ulp (10^-6, or 10^-30 for
//! EigenTrust mass), so the errors are bounded by the number of floors
//! along each path divided by the magnitude of the intermediates:
//!
//! | Quantity | Policy |
//! |---|---|
//! | EigenTrust mass | abs error ≤ 1e-12 (of total mass 1) |
//! | `trust_fp` (independent) | abs error < 3e-6 (floors of `ratio`, `age` and `ratio · age`); the crediter floor `trust ≥ 0.0001` may only flip inside that window |
//! | shares, ratios, age, stake factor | abs error ≤ 5e-6 |
//! | entropies | abs error ≤ the per-FID bound [`reference_f64::entropy_error_bound`]: `10^-6 · (Σ_i (log2(T/c_i) + 2) / log2 k + 3)` (each term floors `p_i`, amplified by `log2(1/p_i)`, the log and the product) |
//! | credibility | abs error ≤ 5e-6 + 0.2 · (interaction-entropy bound) |
//! | F4 metric | abs error ≤ 2e-5 |
//! | eligibility bits | equal, except where the f64 metric is within the metric's error window of the f64 threshold (F3: 2 × the entropy bound, F4: 2e-5, F5/F6: 2e-6); F0–F2 and the F5 trust escape exactly |
//! | growth | rel error ≤ 1e-4 (≥ 1e-2), else abs ≤ 5e-6 |
//! | composite | rel error ≤ 1e-3 for composites ≥ 1e-2; abs error ≤ 1e-5 below |
//! | allocations | the fixed-point total equals the budget exactly; per FID, the error implied by the weight bounds: `|Δ| ≤ B·(ε_f + w_f·Σε/W)/W + 2` base units for budget `B`, f64 weights `w` (`W = Σw`) and per-weight bounds `ε` (composite: the composite bound; DA score: 5e-6; app work: 1e-4 relative) |
//!
//! Growth, composite and allocations are compared with trust and
//! eligibility pinned to the fixed-point values (so a near-threshold
//! eligibility flip, which legitimately changes an allocation, does not
//! count as an arithmetic error); eligibility is compared with trust
//! pinned; trust is compared independently. The observed maxima are
//! printed with `--nocapture`.

#![allow(clippy::float_arithmetic)]
#![allow(clippy::disallowed_types)]

use crate::reader::{EngagementCount, InMemoryReader};
use crate::reference_f64::{self, Pins};
use crate::scoring::{evaluate_epoch, score_fids, ScoringState};
use crate::{
    EpochScoringOutput, ScoringParams, WorkMarket, EPOCH_LENGTH, STAKE_MATURITY_AMOUNT,
    VOUCH_MATURITY_AMOUNT,
};
use std::collections::{BTreeMap, BTreeSet};

/// SplitMix64: a tiny deterministic PRNG (no dependency).
pub(crate) struct SplitMix64(pub u64);

impl SplitMix64 {
    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    pub fn below(&mut self, n: u64) -> u64 {
        if n == 0 {
            0
        } else {
            self.next_u64() % n
        }
    }
    pub fn chance(&mut self, pct: u64) -> bool {
        self.below(100) < pct
    }
}

pub(crate) const NOW: u64 = 1_750_000_000;
pub(crate) const DAY: u64 = 86_400;
pub(crate) const EPOCH: u64 = 1;
pub(crate) const PIVOT: u64 = 10_000_000;

pub(crate) fn params() -> ScoringParams {
    let mut p = ScoringParams {
        pivot_height_0: PIVOT,
        ..ScoringParams::default()
    };
    p.market_budgets
        .insert(WorkMarket::Growth, 1_370_000_000_000);
    p.market_budgets
        .insert(WorkMarket::AppUsage, 2_055_000_000_000);
    p.market_budgets
        .insert(WorkMarket::DataAvailability, 3_425_000_000_000);
    p
}

/// A random universe of `n` FIDs (plus an optional sybil ring).
pub(crate) fn random_universe(seed: u64, n: usize) -> (InMemoryReader, BTreeSet<u64>) {
    let mut rng = SplitMix64(seed);
    let mut r = InMemoryReader::new();
    let mut fids: Vec<u64> = (0..n as u64).map(|i| 1 + i * 10 + rng.below(10)).collect();
    let n_seeds = (n / 5).max(1);
    let seeds: BTreeSet<u64> = fids[..n_seeds].iter().copied().collect();
    // Optional sybil ring: young, mutually engaged, followed by nobody
    // outside the ring.
    let ring: Vec<u64> = if rng.chance(40) {
        let k = 4 + rng.below(8) as usize;
        (0..k as u64).map(|i| 900_000 + i).collect()
    } else {
        Vec::new()
    };
    fids.extend(ring.iter().copied());
    let young = |rng: &mut SplitMix64| NOW - (1 + rng.below(170)) * DAY;
    for &f in &fids {
        if ring.contains(&f) {
            r.add_fid(f, young(&mut rng));
        } else if rng.chance(5) {
            r.fids.insert(f); // no registration known → age 0
        } else if rng.chance(25) {
            r.add_fid(f, young(&mut rng));
        } else {
            r.add_fid(f, NOW - (181 + rng.below(900)) * DAY);
        }
        let casts = if rng.chance(10) {
            0
        } else {
            rng.below(300) as u32
        };
        r.set_total_casts(f, casts);
        r.set_active_days(f, rng.below(60) as u32);
        r.set_replies_received(f, rng.below(u64::from(casts) / 2 + 1) as u32);
        if rng.chance(4) {
            r.set_signer_authorizations(f, 100 + rng.below(50) as u32);
        }
        if rng.chance(20) {
            r.set_credibility_stake(f, rng.below(2 * STAKE_MATURITY_AMOUNT));
        }
    }
    let core: Vec<u64> = fids.iter().copied().filter(|f| !ring.contains(f)).collect();
    // Follows: seeds follow more; the ring follows core FIDs and itself.
    for &f in &fids {
        let k = if seeds.contains(&f) {
            3 + rng.below(8)
        } else {
            rng.below(6)
        };
        let mut fol = Vec::new();
        for _ in 0..k {
            fol.push(core[rng.below(core.len() as u64) as usize]);
        }
        if ring.contains(&f) {
            fol.extend(ring.iter().copied().filter(|&x| x != f));
        }
        fol.retain(|&x| x != f);
        r.add_follows(f, fol);
    }
    // Engagement among core FIDs.
    let density = 10 + rng.below(25);
    for &a in &core {
        for &b in &core {
            if a == b || !rng.chance(density) {
                continue;
            }
            let later = rng.below(40) as u32;
            let first = if rng.chance(30) {
                rng.below(10) as u32
            } else {
                0
            };
            if later + first > 0 {
                r.add_engagement(
                    a,
                    b,
                    EngagementCount {
                        first_30d: first,
                        later,
                    },
                );
            }
        }
    }
    // Ring: uniform heavy mutual engagement, and new-user events into a
    // farm target.
    if !ring.is_empty() {
        let target = core[rng.below(core.len() as u64) as usize];
        for &a in &ring {
            for &b in &ring {
                if a != b {
                    r.add_engagement(
                        a,
                        b,
                        EngagementCount {
                            first_30d: 5,
                            later: 20,
                        },
                    );
                }
            }
            r.add_engagement(
                a,
                target,
                EngagementCount {
                    first_30d: 30,
                    later: 0,
                },
            );
        }
    }
    // Vouches.
    for _ in 0..rng.below(1 + n as u64 / 4) {
        let v = fids[rng.below(fids.len() as u64) as usize];
        let u = fids[rng.below(fids.len() as u64) as usize];
        if v != u {
            r.add_vouch(v, u, rng.below(2 * VOUCH_MATURITY_AMOUNT));
        }
    }
    // App PoW.
    for _ in 0..rng.below(4) {
        let app = core[rng.below(core.len() as u64) as usize];
        for _ in 0..rng.below(6) {
            let user = fids[rng.below(fids.len() as u64) as usize];
            r.set_app_receipt_count(EPOCH, app, user, 1 + rng.below(100) as u32);
            if rng.chance(30) {
                r.set_miniapp_add_events(EPOCH, app, user, 1 + rng.below(3) as u32);
            }
        }
    }
    // DA PoW.
    let boundary = PIVOT + (EPOCH - 1) * EPOCH_LENGTH;
    for _ in 0..rng.below(6) {
        let v = core[rng.below(core.len() as u64) as usize];
        let answered = rng.below(120) as u32;
        let mut sum: u128 = 0;
        for _ in 0..answered {
            sum += u128::from(boundary + rng.below(30));
        }
        r.set_da_answered(EPOCH, v, answered);
        r.set_da_response_block_sum(EPOCH, v, sum);
    }
    (r, seeds)
}

#[derive(Default, Debug)]
pub(crate) struct Stats {
    pub universes: usize,
    pub fids: usize,
    pub eigentrust_abs: f64,
    pub trust_abs: f64,
    pub trust_floor_flips: usize,
    pub credibility_abs: f64,
    pub share_abs: f64,
    pub ratio_abs: f64,
    pub entropy_abs: f64,
    pub entropy_bound_max: f64,
    pub epc_abs: f64,
    pub elig_mismatch_bits: usize,
    pub growth_rel: f64,
    pub growth_abs_small: f64,
    pub growth_n: usize,
    pub composite_rel: f64,
    pub composite_abs_small: f64,
    pub composite_n: usize,
    pub composite_big_n: usize,
    pub alloc_abs_max: u128,
    pub alloc_rel_max: f64,
    pub alloc_budget_rel_max: f64,
    /// Same, restricted to markets whose f64 total weight is ≥ 1e-2
    /// (≥ 10^4 ulp at 6 decimals).
    pub alloc_budget_rel_max_resolved: f64,
    pub alloc_n: usize,
    /// Eligible FIDs whose f64 composite is positive but whose
    /// fixed-point composite floors to 0 (below 1e-6).
    pub composite_underflow: usize,
    /// Universes where the fixed-point Growth market is empty (every
    /// eligible composite floors to 0) but the f64 one is not.
    pub growth_pool_unallocated: usize,
}

fn fp(x: u64) -> f64 {
    x as f64 / 1e6
}

fn fp128(x: u128) -> f64 {
    x as f64 / 1e6
}

/// Compare one universe; panics on a policy violation.
pub(crate) fn compare_universe(
    r: &InMemoryReader,
    seeds: &BTreeSet<u64>,
    p: &ScoringParams,
    epoch: u64,
    st: &mut Stats,
) -> (ScoringState, EpochScoringOutput) {
    let fixed = score_fids(r, NOW, seeds, p).unwrap();
    let out = evaluate_epoch(r, epoch, NOW, seeds, p).unwrap();
    st.universes += 1;
    st.fids += fixed.metrics.len();

    // A. Independent: EigenTrust + trust_fp.
    let free = reference_f64::score(r, NOW, seeds, p, Pins::default());
    for (f, &raw) in &fixed.eigentrust_raw {
        let x = raw as f64 / 1e30;
        let y = free.eigentrust[f];
        let d = (x - y).abs();
        st.eigentrust_abs = st.eigentrust_abs.max(d);
        assert!(d <= 1e-12, "eigentrust fid {f}: fixed {x} f64 {y}");
    }
    for (f, m) in &fixed.metrics {
        let rf = &free.fids[f];
        let x = f64::from(m.trust_fp) / 1e6;
        let d = (x - rf.trust_raw).abs();
        st.trust_abs = st.trust_abs.max(d);
        assert!(d < 3e-6, "trust fid {f}: fixed {x} f64 {}", rf.trust_raw);
        let fixed_crediter = m.trust_fp >= crate::CREDITER_TRUST_FLOOR_FP;
        let f64_crediter = rf.trust_raw >= reference_f64::CREDITER_TRUST_FLOOR;
        if fixed_crediter != f64_crediter {
            st.trust_floor_flips += 1;
            assert!(
                (rf.trust_raw - 1e-4).abs() < 3e-6,
                "floor flip far from 1e-4: fid {f}"
            );
        }
    }

    // B. Trust pinned: per-FID metrics + eligibility.
    let trust: BTreeMap<u64, u32> = fixed
        .metrics
        .iter()
        .map(|(&f, m)| (f, m.trust_fp))
        .collect();
    let pinned_t = reference_f64::score(
        r,
        NOW,
        seeds,
        p,
        Pins {
            trust_fp: Some(&trust),
            eligibility: None,
        },
    );
    let check = |name: &str, f: u64, x: f64, y: f64, tol: f64, acc: &mut f64| {
        let d = (x - y).abs();
        *acc = acc.max(d);
        assert!(d <= tol, "{name} fid {f}: fixed {x} f64 {y} (|Δ| = {d})");
    };
    for (&f, m) in &fixed.metrics {
        let rf = &pinned_t.fids[&f];
        let tol_ie = reference_f64::entropy_error_bound(rf.outbound_totals.iter().copied());
        let tol_eg = reference_f64::entropy_error_bound(rf.inbound.values().map(|&c| c as f64));
        check(
            "credibility",
            f,
            fp(m.credibility_weight_fp),
            rf.credibility,
            5e-6 + 0.2 * tol_ie,
            &mut st.credibility_abs,
        );
        check(
            "new_user_share",
            f,
            fp(m.new_user_engagement_share_fp),
            rf.new_user_share,
            5e-6,
            &mut st.share_abs,
        );
        check(
            "replies_per_cast",
            f,
            fp(m.replies_per_cast_fp),
            rf.replies_per_cast,
            5e-6,
            &mut st.ratio_abs,
        );
        check(
            "stake_factor",
            f,
            fp(m.stake_factor_fp),
            rf.stake_factor,
            5e-6,
            &mut st.ratio_abs,
        );
        check(
            "age_factor",
            f,
            fp(m.age_factor_fp),
            rf.age,
            5e-6,
            &mut st.ratio_abs,
        );
        check(
            "engager_entropy",
            f,
            fp(m.engager_entropy_fp),
            rf.engager_entropy,
            tol_eg,
            &mut st.entropy_abs,
        );
        check(
            "interaction_entropy",
            f,
            fp(m.interaction_entropy_fp),
            rf.interaction_entropy,
            tol_ie,
            &mut st.entropy_abs,
        );
        st.entropy_bound_max = st.entropy_bound_max.max(tol_eg).max(tol_ie);
        check(
            "engagement_per_cast",
            f,
            fp(m.engagement_per_cast_fp),
            rf.engagement_per_cast,
            2e-5,
            &mut st.epc_abs,
        );
        assert_eq!(m.new_user_engagement_count, rf.new_user_count, "fid {f}");
        assert_eq!(m.unique_engagers, rf.unique_engagers, "fid {f}");
    }
    let t = &pinned_t.thresholds;
    let ft = &fixed.thresholds;
    // The F3 threshold is itself an entropy of some cohort member.
    let entropy_bound_cohort = pinned_t
        .fids
        .values()
        .map(|rf| reference_f64::entropy_error_bound(rf.inbound.values().map(|&c| c as f64)))
        .fold(0.0_f64, f64::max);
    for (&f, e_fixed) in &fixed.eligibility {
        let e_ref = pinned_t.eligibility[&f];
        if *e_fixed == e_ref {
            continue;
        }
        let rf = &pinned_t.fids[&f];
        for bit in 0..7u8 {
            if e_fixed.get(bit) == e_ref.get(bit) {
                continue;
            }
            st.elig_mismatch_bits += 1;
            let near = match bit {
                3 => {
                    let w = 2.0
                        * reference_f64::entropy_error_bound(
                            rf.inbound.values().map(|&c| c as f64),
                        )
                        .max(entropy_bound_cohort);
                    (rf.engager_entropy - t.engager_entropy).abs() <= w
                }
                4 => (rf.engagement_per_cast - t.engagement_per_cast).abs() <= 2e-5,
                5 => {
                    rf.trust < reference_f64::CREDITER_TRUST_FLOOR
                        && ((rf.new_user_share - t.new_user_share).abs() <= 2e-6
                            || (rf.new_user_share - 0.1).abs() <= 2e-6)
                }
                6 => (rf.replies_per_cast - t.replies_per_cast).abs() <= 2e-6,
                _ => false,
            };
            assert!(
                near,
                "eligibility bit F{bit} fid {f}: fixed {:07b} f64 {:07b}; thresholds fixed {ft:?} f64 {t:?}",
                e_fixed.0, e_ref.0
            );
        }
    }

    // C. Trust + eligibility pinned: growth, composite, allocations.
    let refo = reference_f64::evaluate(
        r,
        epoch,
        NOW,
        seeds,
        p,
        Pins {
            trust_fp: Some(&trust),
            eligibility: Some(&fixed.eligibility),
        },
    );
    let rs = &refo.state;
    let keys: BTreeSet<u64> = fixed
        .growth
        .keys()
        .chain(rs.growth.keys())
        .copied()
        .collect();
    for f in keys {
        let x = fixed.growth.get(&f).map(|&g| fp128(g)).unwrap_or(0.0);
        let y = rs.growth.get(&f).copied().unwrap_or(0.0);
        st.growth_n += 1;
        if y >= 1e-2 {
            let rel = (x - y).abs() / y;
            st.growth_rel = st.growth_rel.max(rel);
            assert!(rel <= 1e-4, "growth fid {f}: fixed {x} f64 {y}");
        } else {
            let d = (x - y).abs();
            st.growth_abs_small = st.growth_abs_small.max(d);
            assert!(d <= 5e-6, "small growth fid {f}: fixed {x} f64 {y}");
        }
    }
    let keys: BTreeSet<u64> = fixed
        .composite
        .keys()
        .chain(rs.composite.keys())
        .copied()
        .collect();
    for f in keys {
        let x = fixed.composite.get(&f).map(|&c| fp128(c)).unwrap_or(0.0);
        let y = rs.composite.get(&f).copied().unwrap_or(0.0);
        st.composite_n += 1;
        if y >= 1e-2 {
            st.composite_big_n += 1;
            let rel = (x - y).abs() / y;
            st.composite_rel = st.composite_rel.max(rel);
            assert!(
                rel <= 1e-3,
                "composite fid {f}: fixed {x} f64 {y} (rel {rel})"
            );
        } else {
            let d = (x - y).abs();
            st.composite_abs_small = st.composite_abs_small.max(d);
            assert!(d <= 1e-5, "small composite fid {f}: fixed {x} f64 {y}");
        }
    }
    for m in &out.markets {
        let budget = p.market_budgets[&m.market];
        let fixed_total: u128 = m.entries.iter().map(|e| e.amount).sum();
        if !m.entries.is_empty() && p.app_pow_max_per_epoch_atoms == 0 {
            assert_eq!(fixed_total, budget, "{:?} total", m.market);
        }
        // Weights of the f64 reference and their per-weight error bound
        // from the policy table (composite: max(1e-3·c, 1e-5); DA score:
        // 5e-6; app work: 1e-4 relative).
        let weights: BTreeMap<u64, (f64, f64)> = match m.market {
            WorkMarket::Growth => rs
                .composite
                .iter()
                .filter(|(f, _)| fixed.eligibility[f].passes_all())
                .map(|(&f, &c)| (f, (c, (1e-3 * c).max(1e-5))))
                .collect(),
            WorkMarket::DataAvailability => reference_f64::da_weights(r, epoch, p)
                .into_iter()
                .map(|(f, w)| (f, (w, 5e-6)))
                .collect(),
            WorkMarket::AppUsage => reference_f64::app_weights(r, epoch, &rs.fids, p)
                .into_iter()
                .map(|(f, w)| (f, (w, 1e-4 * w)))
                .collect(),
        };
        let total_w: f64 = weights.values().map(|&(w, _)| w).sum();
        if m.market == WorkMarket::Growth {
            st.composite_underflow += weights
                .keys()
                .filter(|f| !fixed.composite.contains_key(f))
                .count();
            if m.entries.is_empty() && !refo.markets[&m.market].is_empty() {
                st.growth_pool_unallocated += 1;
            }
        }
        let total_e: f64 = weights.values().map(|&(_, e)| e).sum();
        let reference = &refo.markets[&m.market];
        let fa: BTreeMap<u64, u128> = m.entries.iter().map(|e| (e.fid, e.amount)).collect();
        let ra: BTreeMap<u64, u128> = reference.iter().map(|e| (e.fid, e.amount)).collect();
        let keys: BTreeSet<u64> = fa.keys().chain(ra.keys()).copied().collect();
        for f in keys {
            let x = fa.get(&f).copied().unwrap_or(0);
            let y = ra.get(&f).copied().unwrap_or(0);
            let d = x.abs_diff(y);
            st.alloc_n += 1;
            st.alloc_abs_max = st.alloc_abs_max.max(d);
            if y > 0 {
                st.alloc_rel_max = st.alloc_rel_max.max(d as f64 / y as f64);
            }
            st.alloc_budget_rel_max = st.alloc_budget_rel_max.max(d as f64 / budget as f64);
            if total_w >= 1e-2 {
                st.alloc_budget_rel_max_resolved = st
                    .alloc_budget_rel_max_resolved
                    .max(d as f64 / budget as f64);
            }
            // |Δ(B·w/W)| ≤ B·(ε_f + w_f·Σε/W)/W, plus 2 units of rounding.
            let (w, e) = weights.get(&f).copied().unwrap_or((0.0, 0.0));
            let tol = budget as f64 * (e + w * total_e / total_w) / total_w + 2.0;
            assert!(
                (d as f64) <= tol,
                "{:?} allocation fid {f}: fixed {x} f64 {y} (tol {tol})",
                m.market
            );
        }
    }
    (fixed, out)
}

#[test]
fn fixed_point_matches_f64_reference_on_random_universes() {
    let p = params();
    let mut st = Stats::default();
    // POQ_EQUIV_UNIVERSES widens the sweep (e.g. 20000 in --release).
    let count: u64 = std::env::var("POQ_EQUIV_UNIVERSES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(300);
    for seed in 0..count {
        let n = 8 + (seed as usize * 7) % 53;
        let (r, seeds) = random_universe(0x5EED_0000 + seed, n);
        compare_universe(&r, &seeds, &p, EPOCH, &mut st);
    }
    eprintln!(
        "fixed vs f64 over {} universes / {} FIDs:",
        st.universes, st.fids
    );
    eprintln!("  eigentrust max abs err        {:.3e}", st.eigentrust_abs);
    eprintln!(
        "  trust max abs err             {:.3e} (crediter-floor flips: {})",
        st.trust_abs, st.trust_floor_flips
    );
    eprintln!("  credibility max abs err       {:.3e}", st.credibility_abs);
    eprintln!("  new-user share max abs err    {:.3e}", st.share_abs);
    eprintln!("  age/stake/replies max abs err {:.3e}", st.ratio_abs);
    eprintln!(
        "  entropy max abs err           {:.3e} (largest per-FID bound {:.3e})",
        st.entropy_abs, st.entropy_bound_max
    );
    eprintln!("  F4 metric max abs err         {:.3e}", st.epc_abs);
    eprintln!(
        "  eligibility bit mismatches    {} (all near threshold)",
        st.elig_mismatch_bits
    );
    eprintln!(
        "  growth: n={} max rel err (≥1e-2) {:.3e}, max abs err (<1e-2) {:.3e}",
        st.growth_n, st.growth_rel, st.growth_abs_small
    );
    eprintln!(
        "  composite: n={} (≥1e-2: {}) max rel err {:.3e}, max abs err (<1e-2) {:.3e}",
        st.composite_n, st.composite_big_n, st.composite_rel, st.composite_abs_small
    );
    eprintln!(
        "  allocations: n={} max err/budget {:.3e} (markets with Σweight ≥ 1e-2: {:.3e}), max rel err {:.3e}",
        st.alloc_n, st.alloc_budget_rel_max, st.alloc_budget_rel_max_resolved, st.alloc_rel_max
    );
    eprintln!(
        "  composite underflow (f64 > 0, fixed = 0, eligible): {} FIDs; Growth pool unallocated in fixed point: {} universes",
        st.composite_underflow, st.growth_pool_unallocated
    );
    assert!(
        st.composite_big_n > 100,
        "too few large composites exercised"
    );
}

/// The equivalence also holds with the F009 layers off (the v6 retro
/// shape: no crediter-count gate, no skew damping).
#[test]
fn fixed_point_matches_f64_reference_without_f009_layers() {
    let mut p = params();
    p.min_distinct_crediters = 0;
    p.growth_distribution_skew_exponent = 0;
    let mut st = Stats::default();
    for seed in 0..100u64 {
        let n = 10 + (seed as usize * 11) % 47;
        let (r, seeds) = random_universe(0xF009_0000 + seed, n);
        compare_universe(&r, &seeds, &p, EPOCH, &mut st);
    }
    eprintln!(
        "F009 off: composite max rel err {:.3e} (n≥1e-2 = {}), alloc max rel err {:.3e}",
        st.composite_rel, st.composite_big_n, st.alloc_rel_max
    );
}
