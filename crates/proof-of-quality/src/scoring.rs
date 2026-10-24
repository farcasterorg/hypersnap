//! Per-epoch scoring pipeline in fixed point (FIP §5–§8.5). Top-level
//! entry: [`evaluate_epoch`].
//!
//! Order of the pipeline ([`score_fids`]):
//!
//! 1. [`build_metrics`]: raw reader inputs, age factor, entropies,
//!    ratios, stake factor (credibility stake + vouch stake received).
//! 2. [`compute_eigentrust`] over the post-transfer follow graph
//!    (`EIGENTRUST_SCALE = 10^30`, exactly 30 iterations).
//! 3. [`apply_trust_and_credibility`]: `trust_fp` and credibility.
//! 4. [`apply_new_user_share`]: the F5 new-user count from engagers
//!    below the crediter floor (needs trust).
//! 5. [`compute_eligibility`]: F0–F6 (needs the gated share and trust).
//! 6. [`compute_growth_harmonic`]: §6.1 growth score (needs
//!    eligibility for the §6.7 vouch boost).
//! 7. [`compute_composite`]: §6.2 five-factor composite.
//!
//! [`evaluate_epoch`] then allocates the three market budgets.

use crate::eligibility::{compute_eligibility, EligibilityThresholds};
use crate::fixed::{
    fp_div, fp_ln_ge_one, fp_mul, fp_pow, fp_ratio_capped, fp_sqrt, mul_div_floor, sat_u32,
    EIGENTRUST_SCALE, FP_ONE, FP_SCALE,
};
use crate::metrics::{
    apply_new_user_share, build_metrics, compute_credibility_weight_fp,
    normalized_entropy_of_values, FidMetrics,
};
use crate::reader::SnapchainStateReader;
use crate::{
    epoch_boundary_height, Eligibility, EpochScoringOutput, MarketReward, RewardEntry,
    ScoringError, ScoringParams, WorkMarket, CREDITER_TRUST_FLOOR_FP, EIGENTRUST_DAMPING_DEN,
    EIGENTRUST_DAMPING_NUM, EIGENTRUST_ITERATIONS, EIGENTRUST_NORM_TOP_N, VOUCH_BOOST_MAX_FP,
    VOUCH_MATURITY_AMOUNT,
};
use std::collections::{BTreeMap, BTreeSet};

/// §8.2.2 EigenTrust in fixed point (`EIGENTRUST_SCALE = 10^30`):
///
/// ```text
/// seed(i)    = floor(10^30 / |S|)              if i ∈ S, else 0
/// t_0(i)     = seed(i)
/// t_{n+1}(i) = floor(Σ_j floor(t_n(j) / out_degree(j)) · 85 / 100)
///            + floor(seed(i) · 15 / 100)
/// ```
///
/// `j` runs over the followers of `i` in ascending FID order;
/// `out_degree(j)` is the number of distinct FIDs that `j` follows.
/// Exactly `iterations` rounds, no convergence test. Returns the raw
/// mass of every FID of the universe (graph FIDs ∪ seeds); empty when
/// the universe or the seed set is empty.
pub fn compute_eigentrust(
    follow_graph: &BTreeMap<u64, Vec<u64>>,
    seed_set: &BTreeSet<u64>,
    iterations: u32,
) -> BTreeMap<u64, u128> {
    let mut universe: BTreeSet<u64> = BTreeSet::new();
    for (&j, followees) in follow_graph {
        universe.insert(j);
        universe.extend(followees.iter().copied());
    }
    universe.extend(seed_set.iter().copied());
    if universe.is_empty() || seed_set.is_empty() {
        return BTreeMap::new();
    }
    // Dense indices in ascending FID order: index order == FID order,
    // so every per-node reduction below runs in FID order.
    let fids: Vec<u64> = universe.into_iter().collect();
    let index_of = |f: u64| fids.binary_search(&f).unwrap_or(0);
    let n = fids.len();
    let mut out_degree: Vec<u128> = vec![0; n];
    let mut followers: Vec<Vec<usize>> = vec![Vec::new(); n];
    for (&j, followees) in follow_graph {
        let mut fs = followees.clone();
        fs.sort_unstable();
        fs.dedup();
        let jj = index_of(j);
        out_degree[jj] = fs.len() as u128;
        for i in fs {
            // `follow_graph` iterates j ascending, so each follower list
            // is built in ascending FID order.
            followers[index_of(i)].push(jj);
        }
    }

    let seed_mass = EIGENTRUST_SCALE / seed_set.len() as u128;
    let seed_kick =
        seed_mass * (EIGENTRUST_DAMPING_DEN - EIGENTRUST_DAMPING_NUM) / EIGENTRUST_DAMPING_DEN;
    let is_seed: Vec<bool> = fids.iter().map(|f| seed_set.contains(f)).collect();
    let mut t: Vec<u128> = is_seed
        .iter()
        .map(|&s| if s { seed_mass } else { 0 })
        .collect();
    let mut next: Vec<u128> = vec![0; n];
    for _ in 0..iterations {
        for i in 0..n {
            let mut acc: u128 = 0;
            for &j in &followers[i] {
                // out_degree(j) ≥ 1: j follows i.
                acc = acc.saturating_add(t[j] / out_degree[j]);
            }
            let mut v = acc.saturating_mul(EIGENTRUST_DAMPING_NUM) / EIGENTRUST_DAMPING_DEN;
            if is_seed[i] {
                v = v.saturating_add(seed_kick);
            }
            next[i] = v;
        }
        std::mem::swap(&mut t, &mut next);
    }
    fids.into_iter().zip(t).collect()
}

/// §8.2.3 `trust_norm`: the average of the top `n` raw values (all
/// values if fewer; `10^30` = 1.0 if the sum is 0), as a floor division.
pub fn trust_normalizer(raw: &BTreeMap<u64, u128>, n: usize) -> u128 {
    let mut vals: Vec<u128> = raw.values().copied().collect();
    if vals.is_empty() {
        return EIGENTRUST_SCALE;
    }
    vals.sort_unstable_by(|a, b| b.cmp(a));
    let take = vals.len().min(n.max(1));
    let sum = vals[..take].iter().fold(0u128, |a, &v| a.saturating_add(v));
    if sum == 0 {
        EIGENTRUST_SCALE
    } else {
        (sum / take as u128).max(1)
    }
}

/// §8.2.3 trust score in 6-decimal fixed point:
///
/// ```text
/// ratio    = min(1, floor(raw · 10^6 / trust_norm))
/// trust_fp = floor(ratio · age_factor / 10^6)          (0..=1_000_000)
/// ```
pub fn trust_fp_from_raw(raw: u128, trust_norm: u128, age_factor_fp: u64) -> u32 {
    if trust_norm == 0 {
        return 0;
    }
    let ratio = mul_div_floor(raw, FP_SCALE, trust_norm).min(FP_SCALE);
    sat_u32(fp_mul(ratio, u128::from(age_factor_fp)).min(FP_SCALE))
}

/// Apply the EigenTrust normalization + age adjustment (`trust_fp`)
/// and the §8.4 credibility blend in one sweep.
pub fn apply_trust_and_credibility(
    metrics: &mut BTreeMap<u64, FidMetrics>,
    eigentrust_raw: &BTreeMap<u64, u128>,
) {
    let norm = trust_normalizer(eigentrust_raw, EIGENTRUST_NORM_TOP_N);
    for (fid, m) in metrics.iter_mut() {
        let raw = eigentrust_raw.get(fid).copied().unwrap_or(0);
        m.trust_fp = trust_fp_from_raw(raw, norm, m.age_factor_fp);
        m.credibility_weight_fp = compute_credibility_weight_fp(
            m.age_factor_fp,
            m.trust_fp,
            m.interaction_entropy_fp,
            m.stake_factor_fp,
        );
    }
}

/// §6.1 `harmonic(a, b) = 2ab / (a + b)` as a 6-dp quotient; 0 if
/// either side is 0.
pub fn harmonic_fp(a: u32, b: u32) -> u128 {
    if a == 0 || b == 0 {
        return 0;
    }
    let (a, b) = (u128::from(a), u128::from(b));
    fp_div(2 * a * b, a + b)
}

/// §6.7 `vouch_boost = 1 + VOUCH_BOOST_MAX · min(1, stake /
/// VOUCH_MATURITY_AMOUNT)` for an eligible vouchee (6-dp). The caller
/// applies the eligibility gate.
pub fn vouch_boost_fp(vouch_stake: u64) -> u64 {
    let ratio = fp_ratio_capped(u128::from(vouch_stake), u128::from(VOUCH_MATURITY_AMOUNT));
    let extra = fp_mul(u128::from(VOUCH_BOOST_MAX_FP), ratio);
    FP_ONE.saturating_add(u64::try_from(extra).unwrap_or(u64::MAX))
}

/// §6.1 one contribution, as products from left to right:
/// `ln(1 + harmonic(a, b)) · credibility(u) · vouch_boost(f, u)`, with
/// `ln(1 + h) = q32_to_fp(ln_q32(10^6 + h_fp, 10^6))`.
pub fn contribution_fp(count_fu: u32, count_uf: u32, credibility_u_fp: u64, boost_fp: u64) -> u128 {
    let h = harmonic_fp(count_fu, count_uf);
    if h == 0 {
        return 0;
    }
    let ln = fp_ln_ge_one(FP_SCALE + h);
    let c = fp_mul(ln, u128::from(credibility_u_fp));
    fp_mul(c, u128::from(boost_fp))
}

/// §6.1 `1 / √n` as 6-dp: `floor(10^6 · 10^6 / isqrt(n · 10^12))`.
pub fn inv_sqrt_count_fp(n: usize) -> u128 {
    let sqrt_n = fp_sqrt((n as u128).saturating_mul(FP_SCALE));
    fp_div(FP_SCALE, sqrt_n)
}

/// §6.1 growth score in fixed point (harmonic mutuality):
///
/// ```text
/// contribution(f, u) = ln(1 + harmonic(count(f→u), count(u→f)))
///                    · credibility(u) · vouch_boost(f, u)
/// growth(f)          = 0                                   if n(f) < MIN_DISTINCT_CREDITERS
///                      Σ C(f) · (1/√n(f)) · skew_damping(f)  otherwise
/// skew_damping(f)    = max((1 − H(C(f)))^GROWTH_SKEW_EXPONENT, GROWTH_MIN_DAMPING)
/// ```
///
/// `u` is a crediter of `f` iff `count(f→u) > 0`, `count(u→f) > 0`,
/// `trust_fp(u) ≥ CREDITER_TRUST_FLOOR_FP` (trust ≥ 0.0001) and
/// `credibility(u) > 0`.
/// `vouch_boost(f, u)` uses the vouch stake of `f` for `u`
/// (`metrics[f].vouches_from[u]`) and applies only if `u` passes all
/// eligibility filters; otherwise it is 1.0. `C(f)` is in crediter-FID
/// order. The three products are evaluated left to right.
///
/// `growth_distribution_skew_exponent = 0` disables the skew damping.
pub fn compute_growth_harmonic(
    metrics: &BTreeMap<u64, FidMetrics>,
    eligibility: &BTreeMap<u64, Eligibility>,
    params: &ScoringParams,
) -> BTreeMap<u64, u128> {
    let mut growth: BTreeMap<u64, u128> = BTreeMap::new();
    for (&f, m_f) in metrics.iter() {
        if m_f.credibility_weight_fp == 0 {
            continue;
        }
        // `all_time_engagement` is a BTreeMap → crediter-FID order.
        let mut contributions: Vec<u128> = Vec::new();
        for (&u, &count_uf) in m_f.all_time_engagement.iter() {
            if u == f || count_uf == 0 {
                continue;
            }
            let m_u = match metrics.get(&u) {
                Some(m) => m,
                None => continue,
            };
            let count_fu = m_u.all_time_engagement.get(&f).copied().unwrap_or(0);
            if count_fu == 0 {
                continue;
            }
            if m_u.trust_fp < CREDITER_TRUST_FLOOR_FP || m_u.credibility_weight_fp == 0 {
                continue;
            }
            let vouchee_eligible = eligibility.get(&u).map(|e| e.passes_all()).unwrap_or(false);
            let boost = match m_f.vouches_from.get(&u) {
                Some(&stake) if vouchee_eligible => vouch_boost_fp(stake),
                _ => FP_ONE,
            };
            contributions.push(contribution_fp(
                count_fu,
                count_uf,
                m_u.credibility_weight_fp,
                boost,
            ));
        }
        let n = contributions.len();
        if n == 0 || n < params.min_distinct_crediters {
            continue;
        }
        let sum = contributions
            .iter()
            .fold(0u128, |acc, &c| acc.saturating_add(c));
        let damping = if params.growth_distribution_skew_exponent == 0 {
            FP_SCALE
        } else {
            let h = u128::from(normalized_entropy_of_values(&contributions));
            let skew = FP_SCALE.saturating_sub(h);
            fp_pow(skew, params.growth_distribution_skew_exponent)
                .max(u128::from(params.growth_distribution_min_damping_fp))
        };
        let g = fp_mul(fp_mul(sum, inv_sqrt_count_fp(n)), damping);
        if g > 0 {
            growth.insert(f, g);
        }
    }
    growth
}

/// The six inputs of the §6.2 composite, in fixed point.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CompositeInputs {
    pub credibility_weight_fp: u64,
    pub trust_fp: u32,
    pub engager_entropy_fp: u64,
    pub interaction_entropy_fp: u64,
    pub new_user_share_fp: u64,
    pub growth_fp: u128,
}

impl CompositeInputs {
    /// The new-user share is `real_new_user_share_fp`, or the F5 share
    /// under the v6 rule (`real_new_user_window_secs = None`).
    pub fn from_metrics(m: &FidMetrics, growth_fp: u128, p: &ScoringParams) -> Self {
        Self {
            credibility_weight_fp: m.credibility_weight_fp,
            trust_fp: m.trust_fp,
            engager_entropy_fp: m.engager_entropy_fp,
            interaction_entropy_fp: m.interaction_entropy_fp,
            new_user_share_fp: match p.real_new_user_window_secs {
                Some(_) => m.real_new_user_share_fp,
                None => m.new_user_engagement_share_fp,
            },
            growth_fp,
        }
    }
}

/// §6.2 composite of one FID, 6-dp:
///
/// ```text
/// credibility^k · trust^j · (engager_entropy · interaction_entropy)^p
///     · (new_user_share + ε)^q · growth^g
/// ```
///
/// with `trust = trust_fp / 10^6`. Each factor uses [`Exponent::apply`]
/// (`x^4`, `x^3` as left-to-right products, `x^(1/2) = isqrt(x · 10^6)`).
/// See [`composite_from_parts`] for the normative product order.
///
/// [`Exponent::apply`]: crate::fixed::Exponent::apply
pub fn composite_score(inputs: &CompositeInputs, p: &ScoringParams) -> u128 {
    composite_from_parts(
        u128::from(inputs.credibility_weight_fp),
        u128::from(inputs.trust_fp),
        u128::from(inputs.engager_entropy_fp),
        u128::from(inputs.interaction_entropy_fp),
        u128::from(inputs.new_user_share_fp),
        inputs.growth_fp,
        p,
    )
}

/// §6.2 composite from its six 6-dp inputs.
///
/// **Normative product order.** The five factors are multiplied as
///
/// ```text
/// composite = ((((growth^g · credibility^k) · trust^j) · symmetry^p) · new_user^q)
/// ```
///
/// each `·` being one fixed-point product `floor(a · b / 10^6)`: the
/// growth factor first, then the other four in the order of the §6.2
/// formula. `growth^g` is usually > 1 and the other factors are ≤ 1
/// (`new_user^q ≤ √1.001`), so the partial products do not increase and
/// each floor costs at most 1 ulp of a value ≥ the result. (Multiplying
/// `growth^g` last amplifies the earlier floors by `growth^g`: 0.26% on
/// a v6 composite of 0.031.) Every implementation must use this order.
pub fn composite_from_parts(
    credibility_fp: u128,
    trust_fp: u128,
    engager_entropy_fp: u128,
    interaction_entropy_fp: u128,
    new_user_share_fp: u128,
    growth_fp: u128,
    p: &ScoringParams,
) -> u128 {
    let cred = p.credibility_exponent.apply(credibility_fp);
    let trust = p.trust_exponent.apply(trust_fp);
    let symmetry = p
        .ring_symmetry_exponent
        .apply(fp_mul(engager_entropy_fp, interaction_entropy_fp));
    let new_user = p
        .new_user_share_exponent
        .apply(new_user_share_fp.saturating_add(u128::from(p.new_user_share_epsilon_fp)));
    let growth = p.growth_exponent.apply(growth_fp);
    fp_mul(
        fp_mul(fp_mul(fp_mul(growth, cred), trust), symmetry),
        new_user,
    )
}

/// §6.2 composite for every FID with positive growth.
pub fn compute_composite(
    metrics: &BTreeMap<u64, FidMetrics>,
    growth: &BTreeMap<u64, u128>,
    p: &ScoringParams,
) -> BTreeMap<u64, u128> {
    let mut out = BTreeMap::new();
    for (fid, m) in metrics {
        let g = match growth.get(fid) {
            Some(&v) if v > 0 => v,
            _ => continue,
        };
        let score = composite_score(&CompositeInputs::from_metrics(m, g, p), p);
        if score > 0 {
            out.insert(*fid, score);
        }
    }
    out
}

/// §6.2 allocation: `emission(f) = floor(composite(f) · budget /
/// Σ composite)` (one floor of the exact ratio, 256-bit intermediate).
/// The rounding remainder goes to the highest composite (tie: smaller
/// FID), so the total equals `budget` exactly.
///
/// If `Σ composite = 0` (no eligible FID has a composite ≥ 1 ulp), the
/// result is empty: the market's budget for the epoch is **not minted**
/// and does not roll over to a later epoch. The same rule applies to
/// the DA (`Σ score_int = 0`) and App (`Σ app_work = 0`) markets.
pub fn allocate_budget(composite: &BTreeMap<u64, u128>, budget: u128) -> Vec<RewardEntry> {
    allocate_proportional(composite, budget)
}

/// Shared proportional allocator: `floor(w · budget / Σ w)` per key in
/// FID order, remainder to the largest weight (tie: smaller FID).
pub(crate) fn allocate_proportional(
    weights: &BTreeMap<u64, u128>,
    budget: u128,
) -> Vec<RewardEntry> {
    if budget == 0 {
        return Vec::new();
    }
    let total = weights.values().fold(0u128, |a, &w| a.saturating_add(w));
    if total == 0 {
        return Vec::new();
    }
    let mut entries: Vec<RewardEntry> = Vec::with_capacity(weights.len());
    let mut allocated: u128 = 0;
    let mut top: Option<(u64, u128)> = None;
    for (&fid, &w) in weights {
        if w == 0 {
            continue;
        }
        let amt = mul_div_floor(w, budget, total);
        if amt > 0 {
            entries.push(RewardEntry { fid, amount: amt });
            allocated = allocated.saturating_add(amt);
        }
        // Ascending FID iteration + strict `>` keeps the smaller FID on ties.
        if top.map(|(_, best)| w > best).unwrap_or(true) {
            top = Some((fid, w));
        }
    }
    if allocated < budget {
        let remainder = budget - allocated;
        if let Some((top_fid, _)) = top {
            if let Some(e) = entries.iter_mut().find(|e| e.fid == top_fid) {
                e.amount = e.amount.saturating_add(remainder);
            } else {
                entries.push(RewardEntry {
                    fid: top_fid,
                    amount: remainder,
                });
            }
        }
    }
    entries.sort_by_key(|e| e.fid);
    entries
}

/// Intermediate results of [`score_fids`]. Exposed for diagnostics,
/// golden tests and the vouch evaluation glue.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScoringState {
    /// Per-FID metrics with trust, credibility and the gated F5 share.
    pub metrics: BTreeMap<u64, FidMetrics>,
    /// Raw EigenTrust mass at `EIGENTRUST_SCALE`.
    pub eigentrust_raw: BTreeMap<u64, u128>,
    pub eligibility: BTreeMap<u64, Eligibility>,
    pub thresholds: EligibilityThresholds,
    /// §6.1 growth score (6-dp), FIDs with positive growth only.
    pub growth: BTreeMap<u64, u128>,
    /// §6.2 composite (6-dp), FIDs with positive composite only, before
    /// the eligibility gate.
    pub composite: BTreeMap<u64, u128>,
}

/// Build the post-transfer follow graph for the FIDs of `metrics`.
fn follow_graph<R: SnapchainStateReader + Sync + ?Sized>(
    reader: &R,
    fids: impl Iterator<Item = u64>,
) -> Result<BTreeMap<u64, Vec<u64>>, ScoringError> {
    let fids: Vec<u64> = fids.collect();
    let reads = crate::reader::read_per_fid(&fids, |f| {
        let mut followees = reader.followees(f)?;
        followees.sort_unstable();
        followees.dedup();
        Ok(followees)
    })?;
    Ok(reads
        .into_iter()
        .filter(|(_, followees)| !followees.is_empty())
        .collect())
}

/// Run the PoQ + Growth pipeline (steps 1–7 of the module docs).
pub fn score_fids<R: SnapchainStateReader + Sync + ?Sized>(
    reader: &R,
    now_unix: u64,
    seed_set: &BTreeSet<u64>,
    params: &ScoringParams,
) -> Result<ScoringState, ScoringError> {
    let mut metrics = build_metrics(reader, now_unix)?;
    let graph = follow_graph(reader, metrics.keys().copied())?;
    let eigentrust_raw = compute_eigentrust(&graph, seed_set, EIGENTRUST_ITERATIONS);
    apply_trust_and_credibility(&mut metrics, &eigentrust_raw);
    apply_new_user_share(
        &mut metrics,
        now_unix,
        params.real_new_user_window_secs.unwrap_or(0),
    );
    let (eligibility, thresholds) = compute_eligibility(&metrics, &params.eligibility);
    let growth = compute_growth_harmonic(&metrics, &eligibility, params);
    let composite = compute_composite(&metrics, &growth, params);
    Ok(ScoringState {
        metrics,
        eigentrust_raw,
        eligibility,
        thresholds,
        growth,
        composite,
    })
}

/// Top-level pipeline: [`score_fids`] → per-market allocation. Returns
/// the [`EpochScoringOutput`] that goes into the `ScoringResult`.
///
/// - Growth: [`allocate_budget`] over the composites of eligible FIDs.
/// - AppUsage: [`crate::app_pow::compute_app_pow_rewards`] (§7.4).
/// - DataAvailability: [`crate::da_pow::compute_da_pow_rewards`] with
///   `boundary_height = PIVOT_HEIGHT_0 + (epoch − 1) · EPOCH_LENGTH`
///   from `params.pivot_height_0` / `params.epoch_length_blocks`.
pub fn evaluate_epoch<R: SnapchainStateReader + Sync + ?Sized>(
    reader: &R,
    epoch: u64,
    now_unix: u64,
    seed_set: &BTreeSet<u64>,
    params: &ScoringParams,
) -> Result<EpochScoringOutput, ScoringError> {
    let state = score_fids(reader, now_unix, seed_set, params)?;

    // §6.5: only eligible FIDs share the Growth pool.
    let gated: BTreeMap<u64, u128> = state
        .composite
        .iter()
        .filter(|(fid, &c)| {
            c > 0
                && state
                    .eligibility
                    .get(fid)
                    .map(|e| e.passes_all())
                    .unwrap_or(false)
        })
        .map(|(&fid, &c)| (fid, c))
        .collect();

    let mut filter_pass_counts = [0u64; 7];
    for flags in state.eligibility.values() {
        for i in 0..7u8 {
            if flags.get(i) {
                filter_pass_counts[i as usize] = filter_pass_counts[i as usize].saturating_add(1);
            }
        }
    }

    let app_receipt_counts = reader.app_receipt_counts_for_epoch(epoch)?;
    let miniapp_add_events = reader.miniapp_add_events_for_epoch(epoch)?;
    let da_answered = reader.da_answered_counts_for_epoch(epoch)?;
    let da_block_sum = reader.da_response_block_sum_for_epoch(epoch)?;
    let boundary_height =
        epoch_boundary_height(params.pivot_height_0, epoch, params.epoch_length_blocks);

    let mut markets: Vec<MarketReward> = Vec::with_capacity(WorkMarket::ALL.len());
    for &market in WorkMarket::ALL.iter() {
        let budget = params.market_budgets.get(&market).copied().unwrap_or(0);
        let entries = match market {
            WorkMarket::AppUsage => crate::app_pow::compute_app_pow_rewards(
                &app_receipt_counts,
                &miniapp_add_events,
                &state.metrics,
                params,
                budget,
            ),
            WorkMarket::DataAvailability => crate::da_pow::compute_da_pow_rewards(
                &da_answered,
                &da_block_sum,
                boundary_height,
                params,
                budget,
            ),
            WorkMarket::Growth => allocate_budget(&gated, budget),
        };
        markets.push(MarketReward {
            market,
            epoch,
            entries,
        });
    }

    let trust_snapshot: BTreeMap<u64, u32> = state
        .metrics
        .iter()
        .map(|(&f, m)| (f, m.trust_fp))
        .collect();

    Ok(EpochScoringOutput {
        epoch,
        markets,
        trust_snapshot,
        eligibility: state.eligibility,
        filter_pass_counts,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reader::{EngagementCount, InMemoryReader};
    use crate::STAKE_MATURITY_AMOUNT;

    fn ec(first_30d: u32, later: u32) -> EngagementCount {
        EngagementCount { first_30d, later }
    }

    fn amount(out: &EpochScoringOutput, market: WorkMarket, fid: u64) -> u128 {
        out.markets
            .iter()
            .find(|m| m.market == market)
            .unwrap()
            .entries
            .iter()
            .find(|e| e.fid == fid)
            .map(|e| e.amount)
            .unwrap_or(0)
    }

    /// Tiny canonical scenario:
    /// - FIDs 1, 2, 3 are seeds.
    /// - FID 100 is a real account: follows + is followed by all seeds,
    ///   reciprocal engagement with each seed.
    /// - FID 999 is a sybil: follows seeds but isn't followed back.
    ///
    /// Expected: FID 100 gets a healthy reward, FID 999 gets 0.
    #[test]
    fn end_to_end_real_vs_sybil() {
        let mut r = InMemoryReader::new();
        let now = 1_700_000_000;
        let old = now - 60 * 60 * 24 * 365;
        for &fid in &[1u64, 2, 3, 100, 999] {
            r.add_fid(fid, old);
            r.set_total_casts(fid, 100);
            r.set_active_days(fid, 200);
            r.set_replies_received(fid, 10);
        }
        for pad in 800u64..810 {
            r.add_fid(pad, old);
            r.set_total_casts(pad, 100);
            r.set_active_days(pad, 200);
            r.set_replies_received(pad, 10);
            r.add_engagement(1, pad, ec(100, 0));
        }
        for &s in &[1u64, 2, 3] {
            r.add_follows(s, vec![1, 2, 3, 100].into_iter().filter(|&x| x != s));
        }
        r.add_follows(100, vec![1u64, 2, 3]);
        r.add_follows(999, vec![1u64, 2, 3]);
        for &s in &[1u64, 2, 3] {
            r.add_engagement_pair(100, s, ec(0, 30), ec(0, 30));
        }
        for &(a, b) in [(1u64, 2u64), (2, 3), (1, 3)].iter() {
            r.add_engagement_pair(a, b, ec(0, 5), ec(0, 5));
        }

        let mut params = ScoringParams::default();
        params
            .market_budgets
            .insert(WorkMarket::Growth, 1_000_000_000);
        let seeds: BTreeSet<u64> = [1u64, 2, 3].into_iter().collect();

        let out = evaluate_epoch(&r, 1, now, &seeds, &params).unwrap();
        assert_eq!(out.epoch, 1);
        assert_eq!(out.markets.len(), 3);

        let trust_100 = out.trust_snapshot[&100];
        let trust_999 = out.trust_snapshot[&999];
        assert!(trust_100 > trust_999, "{trust_100} vs {trust_999}");
        assert_eq!(trust_999, 0);

        assert!(
            amount(&out, WorkMarket::Growth, 100) > 0,
            "real account got zero"
        );
        assert_eq!(
            amount(&out, WorkMarket::Growth, 999),
            0,
            "sybil got non-zero"
        );

        let total: u128 = out.markets[1].entries.iter().map(|e| e.amount).sum();
        assert_eq!(total, 1_000_000_000);
        assert!(out.eligibility[&100].passes_all());
    }

    #[test]
    fn deterministic_across_repeated_evaluations() {
        let mut r = InMemoryReader::new();
        let now = 1_700_000_000;
        for &fid in &[1u64, 2, 3, 4, 5, 100] {
            r.add_fid(fid, now - 60 * 60 * 24 * 365);
        }
        for &s in &[1u64, 2, 3, 4, 5] {
            r.add_follows(s, vec![100]);
            r.add_engagement_pair(s, 100, ec(0, 10), ec(0, 10));
        }
        let mut params = ScoringParams::default();
        params.market_budgets.insert(WorkMarket::Growth, 1_000);
        let seeds: BTreeSet<u64> = (1u64..=5).collect();
        let a = evaluate_epoch(&r, 0, now, &seeds, &params).unwrap();
        let b = evaluate_epoch(&r, 0, now, &seeds, &params).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn empty_reader_produces_empty_output() {
        let r = InMemoryReader::new();
        let params = ScoringParams::default();
        let seeds = BTreeSet::new();
        let out = evaluate_epoch(&r, 0, 0, &seeds, &params).unwrap();
        assert_eq!(out.epoch, 0);
        assert!(out.trust_snapshot.is_empty());
        for m in out.markets {
            assert!(m.entries.is_empty());
        }
    }

    #[test]
    fn eigentrust_fixed_point_basics() {
        // Two-node cycle: seed 1 ↔ 100. Mass is conserved up to floors.
        let graph: BTreeMap<u64, Vec<u64>> =
            [(1u64, vec![100]), (100u64, vec![1])].into_iter().collect();
        let seeds: BTreeSet<u64> = [1u64].into_iter().collect();
        let t = compute_eigentrust(&graph, &seeds, 30);
        let total = t[&1] + t[&100];
        assert!(total <= EIGENTRUST_SCALE && total > EIGENTRUST_SCALE - 1_000);
        assert!(t[&1] > t[&100]);
        // Empty seed set → empty output.
        assert!(compute_eigentrust(&graph, &BTreeSet::new(), 30).is_empty());
        // Duplicate followees count once in the out-degree.
        let dup: BTreeMap<u64, Vec<u64>> = [(1u64, vec![100, 100]), (100u64, vec![1])]
            .into_iter()
            .collect();
        assert_eq!(compute_eigentrust(&dup, &seeds, 30), t);
    }

    #[test]
    fn trust_fp_floors_and_caps() {
        let s = EIGENTRUST_SCALE;
        assert_eq!(trust_fp_from_raw(s, s, FP_ONE), 1_000_000);
        assert_eq!(trust_fp_from_raw(2 * s, s, FP_ONE), 1_000_000);
        assert_eq!(trust_fp_from_raw(s / 2, s, FP_ONE), 500_000);
        assert_eq!(trust_fp_from_raw(s / 2, s, 500_000), 250_000);
        // 0.0001 exactly → 100 (the crediter floor); just below → 99.
        assert_eq!(trust_fp_from_raw(s / 10_000, s, FP_ONE), 100);
        assert_eq!(trust_fp_from_raw(s / 10_000 - 1, s, FP_ONE), 99);
        // Full 6-decimal resolution, no 4-decimal quantization.
        assert_eq!(
            trust_fp_from_raw(s / 1_000_000 * 123_457, s, FP_ONE),
            123_457
        );
        assert_eq!(trust_fp_from_raw(0, s, FP_ONE), 0);
    }

    #[test]
    fn harmonic_and_contribution_fixed_point() {
        assert_eq!(harmonic_fp(0, 5), 0);
        assert_eq!(harmonic_fp(10, 10), 10_000_000);
        assert_eq!(harmonic_fp(1, 2), 1_333_333);
        // ln(1 + 10) = 2.397895 → × cred 1.0 × boost 1.0.
        assert_eq!(contribution_fp(10, 10, FP_ONE, FP_ONE), 2_397_895);
        assert_eq!(contribution_fp(10, 10, FP_ONE, 2 * FP_ONE), 4_795_790);
        assert_eq!(inv_sqrt_count_fp(1), 1_000_000);
        assert_eq!(inv_sqrt_count_fp(4), 500_000);
        assert_eq!(inv_sqrt_count_fp(2), 707_107);
    }

    #[test]
    fn vouch_boost_curve() {
        assert_eq!(vouch_boost_fp(0), FP_ONE);
        assert_eq!(vouch_boost_fp(VOUCH_MATURITY_AMOUNT / 2), 1_500_000);
        assert_eq!(vouch_boost_fp(VOUCH_MATURITY_AMOUNT), 2_000_000);
        assert_eq!(vouch_boost_fp(VOUCH_MATURITY_AMOUNT * 10), 2_000_000);
    }

    /// Hand-built metrics: recipient `f` with crediters `(fid, count(f→u),
    /// count(u→f))`. Every FID has trust 1.0 and credibility 1.0.
    fn shape(f: u64, crediters: &[(u64, u32, u32)]) -> BTreeMap<u64, FidMetrics> {
        let mut metrics: BTreeMap<u64, FidMetrics> = BTreeMap::new();
        let mut m_f = FidMetrics::new(f);
        m_f.trust_fp = 1_000_000;
        m_f.credibility_weight_fp = FP_ONE;
        for &(u, _f_to_u, u_to_f) in crediters {
            m_f.all_time_engagement.insert(u, u_to_f);
        }
        metrics.insert(f, m_f);
        for &(u, f_to_u, _u_to_f) in crediters {
            let mut m_u = FidMetrics::new(u);
            m_u.trust_fp = 1_000_000;
            m_u.credibility_weight_fp = FP_ONE;
            m_u.all_time_engagement.insert(f, f_to_u);
            metrics.insert(u, m_u);
        }
        metrics
    }

    fn all_eligible(m: &BTreeMap<u64, FidMetrics>) -> BTreeMap<u64, Eligibility> {
        m.keys()
            .map(|&f| (f, Eligibility(Eligibility::ALL_PASS)))
            .collect()
    }

    /// Params with the F009 count gate and skew damping off, so a
    /// single-crediter growth equals the raw contribution.
    fn plain_params() -> ScoringParams {
        ScoringParams {
            min_distinct_crediters: 0,
            growth_distribution_skew_exponent: 0,
            ..ScoringParams::default()
        }
    }

    /// §6.7: a vouch of f for u boosts contribution(f, u) — the
    /// voucher's own growth — by `1 + min(1, stake / 250 tokens)`.
    #[test]
    fn vouch_boosts_voucher_growth_from_eligible_vouchee() {
        let base = shape(100, &[(1, 10, 10)]);
        let elig = all_eligible(&base);
        let p = plain_params();
        let g = |stake: Option<u64>| {
            let mut m = base.clone();
            if let Some(s) = stake {
                m.get_mut(&100).unwrap().vouches_from.insert(1, s);
            }
            compute_growth_harmonic(&m, &elig, &p)[&100]
        };
        let g0 = g(None);
        assert_eq!(g0, contribution_fp(10, 10, FP_ONE, FP_ONE));
        assert_eq!(g(Some(0)), g0);
        assert_eq!(g(Some(VOUCH_MATURITY_AMOUNT / 2)), g0 * 3 / 2);
        assert_eq!(g(Some(VOUCH_MATURITY_AMOUNT)), g0 * 2);
        assert_eq!(g(Some(VOUCH_MATURITY_AMOUNT * 10)), g0 * 2);
    }

    /// §6.7: no boost if the vouchee is not eligible.
    #[test]
    fn vouch_boost_requires_eligible_vouchee() {
        let mut m = shape(100, &[(1, 10, 10)]);
        m.get_mut(&100)
            .unwrap()
            .vouches_from
            .insert(1, VOUCH_MATURITY_AMOUNT);
        let mut elig = all_eligible(&m);
        let p = plain_params();
        let boosted = compute_growth_harmonic(&m, &elig, &p)[&100];
        elig.insert(1, Eligibility(Eligibility::ALL_PASS & !(1 << 5)));
        let unboosted = compute_growth_harmonic(&m, &elig, &p)[&100];
        assert_eq!(boosted, unboosted * 2);
        elig.remove(&1);
        assert_eq!(compute_growth_harmonic(&m, &elig, &p)[&100], unboosted);
    }

    /// The boost follows the vouch direction: u's vouch for f does NOT
    /// boost f's growth (that was the pre-FIP direction).
    #[test]
    fn vouchee_vouching_back_does_not_boost() {
        let mut m = shape(100, &[(1, 10, 10)]);
        m.get_mut(&1)
            .unwrap()
            .vouches_from
            .insert(100, VOUCH_MATURITY_AMOUNT);
        let elig = all_eligible(&m);
        let p = plain_params();
        let base = shape(100, &[(1, 10, 10)]);
        assert_eq!(
            compute_growth_harmonic(&m, &elig, &p)[&100],
            compute_growth_harmonic(&base, &elig, &p)[&100]
        );
        // ...but it boosts FID 1's own growth from crediter 100.
        assert_eq!(
            compute_growth_harmonic(&m, &elig, &p)[&1],
            compute_growth_harmonic(&base, &elig, &p)[&1] * 2
        );
    }

    /// Per-pair: f's vouch for u1 does not change the contribution of u2.
    #[test]
    fn vouch_boost_is_per_pair() {
        let base = shape(100, &[(1, 10, 10), (2, 10, 10)]);
        let elig = all_eligible(&base);
        let p = plain_params();
        let mut one = base.clone();
        one.get_mut(&100)
            .unwrap()
            .vouches_from
            .insert(1, VOUCH_MATURITY_AMOUNT);
        let mut both = one.clone();
        both.get_mut(&100)
            .unwrap()
            .vouches_from
            .insert(2, VOUCH_MATURITY_AMOUNT);
        let c = contribution_fp(10, 10, FP_ONE, FP_ONE);
        let inv = inv_sqrt_count_fp(2);
        let expect = |sum: u128| fp_mul(fp_mul(sum, inv), FP_SCALE);
        assert_eq!(
            compute_growth_harmonic(&base, &elig, &p)[&100],
            expect(2 * c)
        );
        assert_eq!(
            compute_growth_harmonic(&one, &elig, &p)[&100],
            expect(3 * c)
        );
        assert_eq!(
            compute_growth_harmonic(&both, &elig, &p)[&100],
            expect(4 * c)
        );
    }

    /// N3: a crediter with trust_fp 99 (trust 0.000099) contributes
    /// nothing; trust_fp 100 (trust 0.0001) is enough.
    #[test]
    fn crediter_floor_is_trust_fp_100() {
        let mut m = shape(100, &[(1, 10, 10)]);
        let elig = all_eligible(&m);
        let p = plain_params();
        m.get_mut(&1).unwrap().trust_fp = CREDITER_TRUST_FLOOR_FP;
        assert!(compute_growth_harmonic(&m, &elig, &p).contains_key(&100));
        m.get_mut(&1).unwrap().trust_fp = CREDITER_TRUST_FLOOR_FP - 1;
        assert!(!compute_growth_harmonic(&m, &elig, &p).contains_key(&100));
    }

    /// F009 L1: fewer than `min_distinct_crediters` crediters → zero.
    #[test]
    fn min_distinct_crediters_gate() {
        let m = shape(100, &[(1, 10, 10), (2, 10, 10)]);
        let elig = all_eligible(&m);
        let p = ScoringParams::default();
        assert!(!compute_growth_harmonic(&m, &elig, &p).contains_key(&100));
        let m3 = shape(100, &[(1, 10, 10), (2, 10, 10), (3, 10, 10)]);
        assert!(compute_growth_harmonic(&m3, &all_eligible(&m3), &p).contains_key(&100));
    }

    /// FIP §5.4 end-to-end: DA answered counts → 80:20 split at full
    /// uptime (commit signatures = EPOCH_LENGTH).
    #[test]
    fn da_pow_rewards_flow_through_evaluate_epoch() {
        let mut r = InMemoryReader::new();
        r.set_da_answered(1, 42, 80);
        r.set_da_answered(1, 99, 20);
        let mut params = ScoringParams::default();
        params
            .market_budgets
            .insert(WorkMarket::DataAvailability, 1_000_000);
        let out = evaluate_epoch(&r, 1, 1_700_000_000, &BTreeSet::new(), &params).unwrap();
        assert_eq!(amount(&out, WorkMarket::DataAvailability, 42), 800_000);
        assert_eq!(amount(&out, WorkMarket::DataAvailability, 99), 200_000);
    }

    /// A6: the DA latency factor is measured from the §4.3 boundary
    /// height `PIVOT_HEIGHT_0 + (e − 1) · EPOCH_LENGTH`.
    #[test]
    fn da_latency_uses_epoch_boundary_from_params() {
        let mut params = ScoringParams {
            pivot_height_0: 1_000_000,
            ..ScoringParams::default()
        };
        params
            .market_budgets
            .insert(WorkMarket::DataAvailability, 1_000_000);
        let epoch = 3u64;
        let boundary = 1_000_000 + 2 * crate::EPOCH_LENGTH;
        assert_eq!(
            epoch_boundary_height(params.pivot_height_0, epoch, params.epoch_length_blocks),
            boundary
        );
        let mut r = InMemoryReader::new();
        for fid in [42u64, 99] {
            r.set_da_answered(epoch, fid, 100);
        }
        // 42 answers at the boundary (offset 0); 99 at offset 20 →
        // latency 1 − 20/25 = 0.2.
        r.set_da_response_block_sum(epoch, 42, u128::from(boundary) * 100);
        r.set_da_response_block_sum(epoch, 99, u128::from(boundary + 20) * 100);
        let out = evaluate_epoch(&r, epoch, 0, &BTreeSet::new(), &params).unwrap();
        // Scores 1.0 : 0.2 → 833_333 : 166_666 (+1 remainder to 42).
        assert_eq!(amount(&out, WorkMarket::DataAvailability, 42), 833_334);
        assert_eq!(amount(&out, WorkMarket::DataAvailability, 99), 166_666);
    }

    /// FIP §7.2: one miniapp add (5.0) = ten receipts (10 × 0.5).
    #[test]
    fn miniapp_adds_drive_app_pow_rewards() {
        let mut r = InMemoryReader::new();
        let now = 1_700_000_000;
        let old = now - 60 * 60 * 24 * 365;
        for &fid in &[1u64, 7, 42, 99] {
            r.add_fid(fid, old);
            r.set_total_casts(fid, 100);
            r.set_active_days(fid, 200);
            r.set_replies_received(fid, 10);
        }
        r.add_follows(1, vec![7]);
        r.add_follows(7, vec![1]);
        r.add_engagement_pair(1, 7, ec(0, 30), ec(0, 30));
        r.set_app_receipt_count(1, 42, 7, 10);
        r.set_miniapp_add_events(1, 99, 7, 1);

        let mut params = ScoringParams::default();
        params
            .market_budgets
            .insert(WorkMarket::AppUsage, 2_000_000);
        let seeds: BTreeSet<u64> = [1u64].into_iter().collect();
        let out = evaluate_epoch(&r, 1, now, &seeds, &params).unwrap();
        let (a42, a99) = (
            amount(&out, WorkMarket::AppUsage, 42),
            amount(&out, WorkMarket::AppUsage, 99),
        );
        assert!(a42 > 0 && a99 > 0);
        assert_eq!(a42, a99);
    }

    /// FIP §7: apps earn AppUsage even when §8.3-ineligible.
    #[test]
    fn app_pow_rewards_flow_through_evaluate_epoch() {
        let mut r = InMemoryReader::new();
        let now = 1_700_000_000;
        let old = now - 60 * 60 * 24 * 365;
        for &fid in &[1u64, 7, 8, 42, 99] {
            r.add_fid(fid, old);
            r.set_total_casts(fid, 100);
            r.set_active_days(fid, 200);
            r.set_replies_received(fid, 10);
        }
        r.set_signer_authorizations(42, 150);
        r.set_signer_authorizations(99, 150);
        r.add_follows(1, vec![7, 8]);
        r.add_follows(7, vec![1]);
        r.add_follows(8, vec![1]);
        r.add_engagement_pair(1, 7, ec(0, 30), ec(0, 30));
        r.add_engagement_pair(1, 8, ec(0, 30), ec(0, 30));
        r.set_app_receipt_count(1, 42, 7, 30);
        r.set_app_receipt_count(1, 99, 8, 10);

        let mut params = ScoringParams::default();
        params
            .market_budgets
            .insert(WorkMarket::AppUsage, 1_000_000);
        let seeds: BTreeSet<u64> = [1u64].into_iter().collect();
        let out = evaluate_epoch(&r, 1, now, &seeds, &params).unwrap();
        let a42 = amount(&out, WorkMarket::AppUsage, 42);
        let a99 = amount(&out, WorkMarket::AppUsage, 99);
        assert!(a42 > 0 && a99 > 0);
        // Users 7 and 8 have the same credibility → exactly 3:1.
        assert_eq!(a42, 750_000);
        assert_eq!(a99, 250_000);
        assert!(!out.eligibility[&42].get(0));
    }

    /// §8.3 gate: an FID with positive composite gets 0 when it fails a
    /// filter (F0 here).
    #[test]
    fn ineligible_fid_gets_zero_reward_even_with_positive_growth() {
        let mut r = InMemoryReader::new();
        let now = 1_700_000_000;
        let old = now - 60 * 60 * 24 * 365;
        for &fid in &[1u64, 2, 3, 100] {
            r.add_fid(fid, old);
            r.set_total_casts(fid, 100);
            r.set_active_days(fid, 200);
            r.set_replies_received(fid, 10);
        }
        r.set_signer_authorizations(100, 100);
        for &s in &[1u64, 2, 3] {
            r.add_follows(s, vec![100]);
            r.add_engagement_pair(s, 100, ec(0, 10), ec(0, 10));
        }
        r.add_follows(100, vec![1, 2, 3]);
        let mut params = ScoringParams::default();
        params
            .market_budgets
            .insert(WorkMarket::Growth, 1_000_000_000);
        let seeds: BTreeSet<u64> = [1u64, 2, 3].into_iter().collect();
        let state = score_fids(&r, now, &seeds, &params).unwrap();
        assert!(state.composite.get(&100).copied().unwrap_or(0) > 0);
        let out = evaluate_epoch(&r, 1, now, &seeds, &params).unwrap();
        assert_eq!(amount(&out, WorkMarket::Growth, 100), 0);
    }

    /// Option (b) end-to-end: a vouch stake received raises the
    /// vouchee's stake factor and hence its credibility.
    #[test]
    fn vouch_stake_received_raises_vouchee_credibility() {
        let mut r = InMemoryReader::new();
        let now = 1_700_000_000;
        for &fid in &[1u64, 2] {
            r.add_fid(fid, now - 60 * 60 * 24 * 365);
        }
        let before = score_fids(&r, now, &BTreeSet::new(), &ScoringParams::default())
            .unwrap()
            .metrics[&2]
            .credibility_weight_fp;
        r.add_vouch(1, 2, STAKE_MATURITY_AMOUNT);
        let after = score_fids(&r, now, &BTreeSet::new(), &ScoringParams::default())
            .unwrap()
            .metrics[&2]
            .credibility_weight_fp;
        assert_eq!(after - before, crate::metrics::W_STAKE_FP);
    }

    /// F009 L2: skewed (real-user) contributions keep most growth; a
    /// uniform ring is damped.
    #[test]
    fn distribution_aware_damping_penalizes_uniform_rings() {
        let real: Vec<(u64, u32, u32)> = vec![
            (10, 100, 100),
            (11, 20, 20),
            (12, 10, 10),
            (13, 5, 5),
            (14, 5, 5),
            (15, 3, 3),
            (16, 3, 3),
            (17, 2, 2),
            (18, 2, 2),
            (19, 2, 2),
        ];
        let ring: Vec<(u64, u32, u32)> = (10u64..20).map(|c| (c, 5, 5)).collect();
        let m_real = shape(100, &real);
        let m_ring = shape(100, &ring);
        let mut p = ScoringParams {
            growth_distribution_min_damping_fp: 0,
            ..ScoringParams::default()
        };
        let g = |m: &BTreeMap<u64, FidMetrics>, p: &ScoringParams| {
            compute_growth_harmonic(m, &all_eligible(m), p)
                .get(&100)
                .copied()
                .unwrap_or(0)
        };
        let v_real = g(&m_real, &p);
        let v_ring = g(&m_ring, &p);
        assert!(v_real > 0);
        assert!(v_ring < v_real / 10, "real={v_real} ring={v_ring}");
        p.growth_distribution_skew_exponent = 0;
        let v_real_no_l2 = g(&m_real, &p);
        let v_ring_no_l2 = g(&m_ring, &p);
        assert!(v_ring_no_l2 > v_real_no_l2 / 4);
    }

    /// F009 L2 floor: a uniform legit user keeps ≈ 5% of the
    /// count-damped sum.
    #[test]
    fn distribution_min_damping_preserves_uniform_legit_user() {
        let crediters: Vec<(u64, u32, u32)> = (10u64..60).map(|c| (c, 5, 5)).collect();
        let m = shape(100, &crediters);
        let elig = all_eligible(&m);
        let g = |p: &ScoringParams| {
            compute_growth_harmonic(&m, &elig, p)
                .get(&100)
                .copied()
                .unwrap_or(0)
        };
        let no_floor = ScoringParams {
            growth_distribution_min_damping_fp: 0,
            ..ScoringParams::default()
        };
        assert_eq!(g(&no_floor), 0, "uniform → 0 without the floor");
        let with_floor = ScoringParams::default();
        let v_floor = g(&with_floor);
        let no_l2 = ScoringParams {
            growth_distribution_skew_exponent: 0,
            ..ScoringParams::default()
        };
        let v_no_l2 = g(&no_l2);
        assert!(v_floor > 0);
        // floor × no-L2 growth, up to one ulp of rounding.
        assert!(fp_mul(v_no_l2, 50_000).abs_diff(v_floor) <= 1);
    }

    #[test]
    fn allocate_budget_remainder_and_ties() {
        let c: BTreeMap<u64, u128> = [(5u64, 1u128), (3, 1), (9, 1)].into_iter().collect();
        let out = allocate_budget(&c, 100);
        // 33 each, remainder 1 to the smallest FID among the tied top.
        assert_eq!(
            out,
            vec![
                RewardEntry { fid: 3, amount: 34 },
                RewardEntry { fid: 5, amount: 33 },
                RewardEntry { fid: 9, amount: 33 },
            ]
        );
        assert!(allocate_budget(&c, 0).is_empty());
        assert!(allocate_budget(&BTreeMap::new(), 10).is_empty());
        // Large budget × large composite uses the 256-bit path exactly.
        let big: BTreeMap<u64, u128> = [(1u64, u128::MAX / 3), (2, u128::MAX / 3)]
            .into_iter()
            .collect();
        let out = allocate_budget(&big, u128::MAX / 2);
        assert_eq!(out[0].amount + out[1].amount, u128::MAX / 2);
    }

    /// Σ composite = 0 → the Growth budget is not minted (empty
    /// allocation, nothing rolls over).
    #[test]
    fn zero_total_composite_mints_nothing() {
        let zero: BTreeMap<u64, u128> = [(1u64, 0u128), (2, 0)].into_iter().collect();
        assert!(allocate_budget(&zero, 1_000_000).is_empty());
        assert!(allocate_budget(&BTreeMap::new(), 1_000_000).is_empty());

        // End to end: FIDs whose composites are all below 1 ulp (here:
        // no FID has growth) leave the Growth market empty even with a
        // budget, while the other markets are unaffected.
        let mut r = InMemoryReader::new();
        r.add_fid(1, 0);
        r.add_fid(2, 0);
        r.set_da_answered(1, 2, 100);
        let mut params = ScoringParams::default();
        params.market_budgets.insert(WorkMarket::Growth, 1_000_000);
        params
            .market_budgets
            .insert(WorkMarket::DataAvailability, 1_000_000);
        let seeds: BTreeSet<u64> = [1u64].into_iter().collect();
        let out = evaluate_epoch(&r, 1, 1_000, &seeds, &params).unwrap();
        let growth = out
            .markets
            .iter()
            .find(|m| m.market == WorkMarket::Growth)
            .unwrap();
        assert!(
            growth.entries.is_empty(),
            "unallocated budget is not minted"
        );
        assert_eq!(amount(&out, WorkMarket::DataAvailability, 2), 1_000_000);
    }
}
