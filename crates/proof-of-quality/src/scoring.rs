//! Per-epoch scoring pipeline. Top-level entry: [`evaluate_epoch`].
//!
//! Mirrors the Phase 3–6 pipeline of `retro_rewards_finalize.rs`, but
//! deterministic (BTreeMap iteration everywhere) and scoped to the
//! in-protocol composite formula with `harmonic` mutuality.

use crate::metrics::{
    build_metrics, compute_credibility_weight, stake_factor_from_atoms, FidMetrics, W_AGE,
    W_DIVERSITY, W_ENTROPY, W_STAKE, W_TRUST,
};
use crate::reader::SnapchainStateReader;
use crate::{
    EpochScoringOutput, MarketReward, RewardEntry, ScoringError, ScoringParams, WorkMarket,
};
use std::collections::{BTreeMap, BTreeSet};

/// EigenTrust propagation: given a follow graph and a seed set, return
/// per-FID raw trust scores. Iterative Markov-chain solver, bounded
/// iteration count for determinism.
///
/// Mirrors `compute_eigentrust` from the offline tool. Uses BTreeMap
/// iteration order so the reduction is deterministic regardless of
/// hash randomness.
pub fn compute_eigentrust(
    follow_graph: &BTreeMap<u64, Vec<u64>>,
    seed_set: &BTreeSet<u64>,
    iterations: u32,
    alpha: f64,
) -> BTreeMap<u64, f64> {
    let mut universe: BTreeSet<u64> = BTreeSet::new();
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
        return BTreeMap::new();
    }

    let seed_weight = 1.0 / seed_set.len() as f64;
    let mut t: BTreeMap<u64, f64> = BTreeMap::new();
    for &fid in &universe {
        if seed_set.contains(&fid) {
            t.insert(fid, seed_weight);
        } else {
            t.insert(fid, 0.0);
        }
    }

    // Pre-compute reverse follower edges: for each followee, who follows
    // them. Used to push trust along incoming edges.
    let mut reverse: BTreeMap<u64, Vec<u64>> = BTreeMap::new();
    for (&follower, followees) in follow_graph {
        for &followee in followees {
            reverse.entry(followee).or_default().push(follower);
        }
    }
    // Sort followers for determinism (BTreeMap iteration is already
    // ordered, but the inner Vec needs an explicit sort).
    for v in reverse.values_mut() {
        v.sort_unstable();
        v.dedup();
    }

    // Each follower distributes their trust uniformly across their
    // followees. Cache out-degrees for the propagation step.
    let mut out_degree: BTreeMap<u64, usize> = BTreeMap::new();
    for (&follower, followees) in follow_graph {
        out_degree.insert(follower, followees.len());
    }

    for _ in 0..iterations {
        let mut next: BTreeMap<u64, f64> = BTreeMap::new();
        for &fid in &universe {
            let mut acc = 0.0_f64;
            if let Some(followers) = reverse.get(&fid) {
                for &f in followers {
                    let od = *out_degree.get(&f).unwrap_or(&0);
                    if od == 0 {
                        continue;
                    }
                    let cur = *t.get(&f).unwrap_or(&0.0);
                    acc += cur / od as f64;
                }
            }
            // Random restart toward the seed set.
            let seed_kick = if seed_set.contains(&fid) {
                seed_weight
            } else {
                0.0
            };
            next.insert(fid, alpha * acc + (1.0 - alpha) * seed_kick);
        }
        t = next;
    }
    t
}

/// Normalize raw EigenTrust scores against the average of the top-N
/// (gives the seeds trust ≈ 1.0 and tails trust ≈ 0). Mirrors the
/// retro tool's `top_n_avg_norm`.
fn top_n_avg(scores: &BTreeMap<u64, f64>, n: usize) -> f64 {
    let mut vals: Vec<f64> = scores.values().copied().collect();
    if vals.is_empty() {
        return 1.0;
    }
    vals.sort_by(|a, b| b.partial_cmp(a).unwrap_or(std::cmp::Ordering::Equal));
    let take = vals.len().min(n.max(1));
    let sum: f64 = vals[..take].iter().sum();
    if sum == 0.0 {
        1.0
    } else {
        sum / take as f64
    }
}

/// Apply EigenTrust + age normalization + credibility blend in one
/// sweep. After this call, `metrics[fid].trust_score` and
/// `metrics[fid].credibility_weight` are populated.
pub fn apply_trust_and_credibility(
    metrics: &mut BTreeMap<u64, FidMetrics>,
    eigentrust_raw: &BTreeMap<u64, f64>,
) {
    let norm = top_n_avg(eigentrust_raw, 100);
    for (fid, m) in metrics.iter_mut() {
        let raw = eigentrust_raw.get(fid).copied().unwrap_or(0.0);
        let normalized = (raw / norm).min(1.0);
        m.trust_score = (normalized * m.age_factor).clamp(0.0, 1.0);
        m.credibility_weight = compute_credibility_weight(
            m.age_factor,
            m.trust_score,
            m.interaction_entropy,
            m.stake_factor,
        );
        let _ = (W_AGE, W_TRUST, W_ENTROPY, W_STAKE, W_DIVERSITY); // doc cross-reference
    }
}

/// Per-mode growth scoring (harmonic-only in the in-protocol path).
/// Mirrors `compute_growth_scores` from the offline tool. Each pair's
/// contribution is `ln(1 + harmonic_mean(a, b)) · credibility(crediter)`,
/// gated on the crediter's trust being above the floor.
///
/// FIP §12 vouch boost: when crediter `u` has staked a vouch on
/// vouchee `f` with `atoms` atoms, `u`'s contribution to `f`'s growth
/// is multiplied by `1 + stake_factor_from_atoms(atoms)`. A
/// fully-saturated vouch doubles the contribution; no vouch leaves it
/// unchanged. Per-pair, so `u → f` and `u → g` are independent.
///
/// The boost is additionally gated on the vouchee's own trust
/// (`vouch_boost_min_vouchee_trust`): the multiplier only applies
/// when `metrics[f].trust_score ≥ threshold`. Below the threshold
/// the boost is forced to `1.0` regardless of atoms — this closes
/// the puppet-sybil pump where a high-trust voucher amplifies their
/// engagement with a low-trust sybil.
pub fn compute_growth_harmonic(
    metrics: &BTreeMap<u64, FidMetrics>,
    crediter_trust_threshold: f64,
    vouch_boost_min_vouchee_trust: f64,
) -> BTreeMap<u64, f64> {
    let mut growth: BTreeMap<u64, f64> = BTreeMap::new();
    // Snapshot all_time_engagement per FID for borrow-friendly iteration.
    for (&f, m_f) in metrics.iter() {
        if m_f.credibility_weight <= 0.0 {
            continue;
        }
        let mut acc = 0.0_f64;
        // m_f.all_time_engagement is the inbound side: source u → count(u→f).
        // We need both count(f→u) and count(u→f). Look up count(f→u)
        // from u's entry (where it appears as inbound from f).
        for (&u, &count_uf) in m_f.all_time_engagement.iter() {
            let count_fu = metrics
                .get(&u)
                .and_then(|m_u| m_u.all_time_engagement.get(&f))
                .copied()
                .unwrap_or(0);
            if count_fu == 0 {
                continue;
            }
            let m_u = match metrics.get(&u) {
                Some(m) => m,
                None => continue,
            };
            if m_u.trust_score < crediter_trust_threshold {
                continue;
            }
            let cred_u = m_u.credibility_weight;
            if cred_u <= 0.0 {
                continue;
            }
            let a = count_fu as f64;
            let b = count_uf as f64;
            let harmonic = if a + b > 0.0 {
                2.0 * a * b / (a + b)
            } else {
                0.0
            };
            if harmonic <= 0.0 {
                continue;
            }
            // §12 vouch boost: u's per-pair vouch on f multiplies
            // u's contribution by `1 + vouch_factor` (∈ [1, 2]),
            // ONLY when the vouchee's own trust meets the floor —
            // otherwise the boost is suppressed (anti-puppet-pump).
            let vouch_atoms = m_u.vouches_from.get(&f).copied().unwrap_or(0);
            let vouch_boost = if m_f.trust_score >= vouch_boost_min_vouchee_trust {
                1.0 + stake_factor_from_atoms(vouch_atoms)
            } else {
                1.0
            };
            acc += (1.0 + harmonic).ln() * cred_u * vouch_boost;
        }
        if acc > 0.0 {
            growth.insert(f, acc);
        }
    }
    growth
}

/// `composite(f) = credibility^k · trust^j · (eg·int)^p · (share+ε)^q · growth^g`.
pub fn compute_composite(
    metrics: &BTreeMap<u64, FidMetrics>,
    growth: &BTreeMap<u64, f64>,
    p: &ScoringParams,
) -> BTreeMap<u64, f64> {
    let mut out = BTreeMap::new();
    for (fid, m) in metrics {
        let g = match growth.get(fid) {
            Some(&v) if v > 0.0 => v,
            _ => continue,
        };
        let cred = m.credibility_weight.max(0.0).powf(p.credibility_exponent);
        let trust = if p.trust_exponent > 0.0 {
            m.trust_score.max(0.0).powf(p.trust_exponent)
        } else {
            1.0
        };
        let entropy_prod = m.engager_entropy * m.interaction_entropy;
        let symmetry = if p.ring_symmetry_exponent > 0.0 {
            entropy_prod.max(0.0).powf(p.ring_symmetry_exponent)
        } else {
            1.0
        };
        let new_user_factor = if p.new_user_share_exponent > 0.0 {
            (m.new_user_engagement_share.max(0.0) + p.new_user_share_smoothing)
                .powf(p.new_user_share_exponent)
        } else {
            1.0
        };
        let compressed_growth = if p.growth_exponent != 1.0 && p.growth_exponent > 0.0 {
            g.max(0.0).powf(p.growth_exponent)
        } else {
            g
        };
        let score = cred * trust * symmetry * new_user_factor * compressed_growth;
        if score > 0.0 {
            out.insert(*fid, score);
        }
    }
    out
}

/// Allocate `budget` across FIDs in proportion to their composite
/// scores. Deterministic rounding (truncation) leaves a small
/// remainder; we hand it to the highest-composite FID so the totals
/// always equal `budget` exactly.
pub fn allocate_budget(composite: &BTreeMap<u64, f64>, budget: u128) -> Vec<RewardEntry> {
    if budget == 0 {
        return Vec::new();
    }
    let total: f64 = composite.values().sum();
    if !(total.is_finite()) || total <= 0.0 {
        return Vec::new();
    }
    let budget_f = budget as f64;
    let mut entries: Vec<RewardEntry> = Vec::with_capacity(composite.len());
    let mut allocated: u128 = 0;
    for (&fid, &c) in composite {
        let share = (c / total) * budget_f;
        let amt = share.floor().max(0.0) as u128;
        if amt > 0 {
            entries.push(RewardEntry { fid, amount: amt });
            allocated = allocated.saturating_add(amt);
        }
    }
    // Hand the rounding remainder to the highest-composite FID. Tie-break
    // by smaller fid so the result is deterministic across validators.
    if allocated < budget {
        let remainder = budget - allocated;
        if let Some((&top_fid, _)) =
            composite
                .iter()
                .max_by(|(fa, ca), (fb, cb)| match ca.partial_cmp(cb) {
                    Some(std::cmp::Ordering::Equal) | None => fb.cmp(fa),
                    Some(o) => o,
                })
        {
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

/// Top-level pipeline: build metrics → eigentrust → growth → composite →
/// per-market allocation. Returns a fully-formed [`EpochScoringOutput`]
/// ready to be canonically encoded and threshold-signed.
pub fn evaluate_epoch<R: SnapchainStateReader + ?Sized>(
    reader: &R,
    epoch: u64,
    now_unix: u64,
    seed_set: &BTreeSet<u64>,
    params: &ScoringParams,
) -> Result<EpochScoringOutput, ScoringError> {
    let mut metrics = build_metrics(reader, now_unix)?;

    // Build the follow graph for EigenTrust (post-transfer follows).
    let fids = reader.all_active_fids()?;
    let mut graph: BTreeMap<u64, Vec<u64>> = BTreeMap::new();
    for &f in &fids {
        let mut followees = reader.followees(f)?;
        followees.sort_unstable();
        followees.dedup();
        if !followees.is_empty() {
            graph.insert(f, followees);
        }
    }

    let eigentrust = compute_eigentrust(&graph, seed_set, 30, 0.85);
    apply_trust_and_credibility(&mut metrics, &eigentrust);

    let growth = compute_growth_harmonic(
        &metrics,
        params.crediter_trust_threshold,
        params.vouch_boost_min_vouchee_trust,
    );
    let composite = compute_composite(&metrics, &growth, params);

    // FIP §8.3 / §6.5: zero composite for FIDs failing eligibility
    // filters BEFORE allocating budget. F0–F6 are pre-computed in
    // one pass; the result is also exposed on `EpochScoringOutput`
    // for surfacing to wallets and indexers.
    let (eligibility, _thresholds) =
        crate::eligibility::compute_eligibility(&metrics, &params.eligibility);
    let gated: BTreeMap<u64, f64> = composite
        .iter()
        .filter_map(|(&fid, &c)| {
            let pass = eligibility
                .get(&fid)
                .map(|e| e.passes_all())
                .unwrap_or(false);
            if pass && c > 0.0 {
                Some((fid, c))
            } else {
                None
            }
        })
        .collect();

    let mut filter_pass_counts = [0u64; 7];
    for flags in eligibility.values() {
        for i in 0..7u8 {
            if flags.get(i) {
                filter_pass_counts[i as usize] = filter_pass_counts[i as usize].saturating_add(1);
            }
        }
    }

    // FIP §7 App-PoW: AppUsage is allocated per the §7.4 reward
    // function (app_work-weighted, with optional per-app cap), NOT
    // by the §6 composite.
    // FIP §5 DA-PoW: DataAvailability is allocated proportional to
    // per-validator answered counts, NOT by the §6 composite.
    let app_receipt_counts = reader.app_receipt_counts_for_epoch(epoch)?;
    let miniapp_add_events = reader.miniapp_add_events_for_epoch(epoch)?;
    let da_answered = reader.da_answered_counts_for_epoch(epoch)?;
    let da_block_sum = reader.da_response_block_sum_for_epoch(epoch)?;
    let da_commit_sigs = reader.validator_commit_signatures_for_epoch(epoch)?;
    // Epoch-start block height: needed to compute the per-validator
    // average response-block height relative to the boundary for
    // the §5.4 latency factor. EPOCH_LENGTH lives in the hypersnap
    // crate; mirror its definition here to avoid a cross-crate
    // dependency. (Validators MUST agree on this constant.)
    const EPOCH_LENGTH_BLOCKS: u64 = 432_000;
    let epoch_start_block = epoch.saturating_mul(EPOCH_LENGTH_BLOCKS);

    let mut markets: Vec<MarketReward> = Vec::with_capacity(WorkMarket::ALL.len());
    for &market in WorkMarket::ALL.iter() {
        let budget = params.market_budgets.get(&market).copied().unwrap_or(0);
        let entries = match market {
            WorkMarket::AppUsage => crate::app_pow::compute_app_pow_rewards(
                &app_receipt_counts,
                &miniapp_add_events,
                &metrics,
                params,
                budget,
            ),
            WorkMarket::DataAvailability => crate::da_pow::compute_da_pow_rewards(
                &da_answered,
                &da_block_sum,
                &da_commit_sigs,
                epoch_start_block,
                EPOCH_LENGTH_BLOCKS,
                params,
                budget,
            ),
            _ => allocate_budget(&gated, budget),
        };
        markets.push(MarketReward {
            market,
            epoch,
            entries,
        });
    }

    let trust_snapshot: BTreeMap<u64, f64> =
        metrics.iter().map(|(&f, m)| (f, m.trust_score)).collect();

    Ok(EpochScoringOutput {
        epoch,
        markets,
        trust_snapshot,
        filter_pass_counts,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reader::EngagementCount;
    use crate::reader::InMemoryReader;

    /// Tiny canonical scenario:
    /// - FIDs 1, 2, 3 are seeds (low FIDs).
    /// - FID 100 is a real account: follows + is followed by all seeds, has
    ///   reciprocal engagement with each seed.
    /// - FID 999 is a sybil: follows seeds but isn't followed back, only
    ///   engaged-with by other low-trust sybils (none in this scenario).
    /// Expected: FID 100 gets a healthy reward, FID 999 gets 0.
    #[test]
    fn end_to_end_real_vs_sybil() {
        let mut r = InMemoryReader::new();
        let now = 1_700_000_000;
        let old = now - 60 * 60 * 24 * 365; // 1 year old

        for &fid in &[1u64, 2, 3, 100, 999] {
            r.add_fid(fid, old);
            r.set_total_casts(fid, 100);
            r.set_active_days(fid, 200);
            // Seed enough replies-received that F6 has non-trivial
            // data; uniform value means the percentile threshold is
            // 10 and `replies_per_cast = 0.1` passes for all.
            r.set_replies_received(fid, 10);
        }
        // Add a handful of pad FIDs with high new-user share so
        // F5's upper-tail calibration produces a non-trivial
        // threshold (otherwise everyone's `share = 0 < 0` fails).
        for pad in 800u64..810 {
            r.add_fid(pad, old);
            r.set_total_casts(pad, 100);
            r.set_active_days(pad, 200);
            r.set_replies_received(pad, 10);
            // These pads receive high-new-user share so the cohort
            // upper-tail rises above the test FIDs' zero shares.
            r.add_engagement(
                1,
                pad,
                EngagementCount {
                    first_30d: 100,
                    later: 0,
                },
            );
        }

        // Follow graph: seeds follow each other + 100; 100 follows seeds.
        // 999 follows seeds but no one follows 999.
        for &s in &[1u64, 2, 3] {
            r.add_follows(s, vec![1, 2, 3, 100].into_iter().filter(|&x| x != s));
        }
        r.add_follows(100, vec![1u64, 2, 3]);
        r.add_follows(999, vec![1u64, 2, 3]);

        // Reciprocal engagement between 100 and each seed.
        for &s in &[1u64, 2, 3] {
            r.add_engagement_pair(
                100,
                s,
                EngagementCount {
                    first_30d: 0,
                    later: 30,
                },
                EngagementCount {
                    first_30d: 0,
                    later: 30,
                },
            );
        }
        // Seeds engage with each other a bit so they get growth too.
        for &(a, b) in [(1u64, 2u64), (2, 3), (1, 3)].iter() {
            r.add_engagement_pair(
                a,
                b,
                EngagementCount {
                    first_30d: 0,
                    later: 5,
                },
                EngagementCount {
                    first_30d: 0,
                    later: 5,
                },
            );
        }

        let mut params = ScoringParams::default();
        params
            .market_budgets
            .insert(WorkMarket::Growth, 1_000_000_000);
        let mut seeds = BTreeSet::new();
        seeds.insert(1u64);
        seeds.insert(2);
        seeds.insert(3);

        let out = evaluate_epoch(&r, 1, now, &seeds, &params).unwrap();
        assert_eq!(out.epoch, 1);
        assert_eq!(out.markets.len(), 3);

        // Trust snapshot: seeds and 100 all positive, 999 stays near zero.
        let trust_100 = out.trust_snapshot.get(&100).copied().unwrap_or(0.0);
        let trust_999 = out.trust_snapshot.get(&999).copied().unwrap_or(0.0);
        assert!(
            trust_100 > trust_999,
            "real account trust ({}) should exceed sybil ({})",
            trust_100,
            trust_999
        );

        // Growth market: 100 gets a non-zero allocation, 999 doesn't.
        let growth_market = out
            .markets
            .iter()
            .find(|m| m.market == WorkMarket::Growth)
            .unwrap();
        let amount_100 = growth_market
            .entries
            .iter()
            .find(|e| e.fid == 100)
            .map(|e| e.amount)
            .unwrap_or(0);
        let amount_999 = growth_market
            .entries
            .iter()
            .find(|e| e.fid == 999)
            .map(|e| e.amount)
            .unwrap_or(0);
        assert!(amount_100 > 0, "real account got zero reward");
        assert_eq!(amount_999, 0, "sybil got non-zero reward");

        // Total allocated equals the budget exactly (rounding remainder
        // handled).
        let total: u128 = growth_market.entries.iter().map(|e| e.amount).sum();
        assert_eq!(total, 1_000_000_000);
    }

    #[test]
    fn deterministic_across_repeated_evaluations() {
        // Same input twice → identical output (canonical iteration
        // order is the property we're testing).
        let mut r = InMemoryReader::new();
        let now = 1_700_000_000;
        for &fid in &[1u64, 2, 3, 4, 5, 100] {
            r.add_fid(fid, now - 60 * 60 * 24 * 365);
        }
        for &s in &[1u64, 2, 3, 4, 5] {
            r.add_follows(s, vec![100]);
            r.add_engagement_pair(
                s,
                100,
                EngagementCount {
                    first_30d: 0,
                    later: 10,
                },
                EngagementCount {
                    first_30d: 0,
                    later: 10,
                },
            );
        }
        let mut params = ScoringParams::default();
        params.market_budgets.insert(WorkMarket::Growth, 1_000);
        let mut seeds = BTreeSet::new();
        for s in 1u64..=5 {
            seeds.insert(s);
        }

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

    /// FIP §12 Phase 5d-scoring: a fully-saturated vouch from u→f
    /// doubles u's contribution to f's growth. Compare two
    /// otherwise-identical universes: one with vouch, one without.
    /// Build a minimal scenario so the ratio is clean.
    #[test]
    fn vouch_doubles_voucher_contribution_at_saturation() {
        use crate::metrics::STAKE_MATURITY_ATOMS;
        use crate::reader::EngagementCount;

        let build = |with_vouch: bool| {
            let mut r = InMemoryReader::new();
            let now = 1_700_000_000;
            let old = now - 60 * 60 * 24 * 365;
            for &fid in &[1u64, 2, 100] {
                r.add_fid(fid, old);
            }
            // Make 1 the seed, follow graph: 1↔100, 2 isolated.
            r.add_follows(1, vec![100]);
            r.add_follows(100, vec![1]);
            // Reciprocal engagement 1 ↔ 100 only.
            r.add_engagement_pair(
                1,
                100,
                EngagementCount {
                    first_30d: 0,
                    later: 10,
                },
                EngagementCount {
                    first_30d: 0,
                    later: 10,
                },
            );
            if with_vouch {
                r.add_vouch(1, 100, STAKE_MATURITY_ATOMS);
            }
            (r, now)
        };

        let (r_no, now) = build(false);
        let (r_yes, _) = build(true);

        let mut seeds = BTreeSet::new();
        seeds.insert(1u64);

        let metrics_no = {
            let mut m = build_metrics(&r_no, now).unwrap();
            // Apply the same eigentrust output to both runs.
            let graph: BTreeMap<u64, Vec<u64>> =
                [(1u64, vec![100]), (100u64, vec![1])].into_iter().collect();
            let et = compute_eigentrust(&graph, &seeds, 30, 0.85);
            apply_trust_and_credibility(&mut m, &et);
            m
        };
        let metrics_yes = {
            let mut m = build_metrics(&r_yes, now).unwrap();
            let graph: BTreeMap<u64, Vec<u64>> =
                [(1u64, vec![100]), (100u64, vec![1])].into_iter().collect();
            let et = compute_eigentrust(&graph, &seeds, 30, 0.85);
            apply_trust_and_credibility(&mut m, &et);
            m
        };

        let growth_no = compute_growth_harmonic(&metrics_no, 0.0, 0.0);
        let growth_yes = compute_growth_harmonic(&metrics_yes, 0.0, 0.0);

        let g_no = growth_no.get(&100).copied().unwrap_or(0.0);
        let g_yes = growth_yes.get(&100).copied().unwrap_or(0.0);
        assert!(g_no > 0.0, "baseline growth must be positive");
        // Saturated vouch from u=1 (the only crediter) doubles the
        // single contribution → factor of 2.
        let ratio = g_yes / g_no;
        assert!(
            (ratio - 2.0).abs() < 1e-9,
            "expected 2x boost, got ratio={ratio} (no={g_no}, yes={g_yes})"
        );
    }

    /// Half-saturation gives a 1.5x boost; no vouch is 1.0x.
    #[test]
    fn vouch_boost_scales_linearly_in_atoms() {
        use crate::metrics::STAKE_MATURITY_ATOMS;
        use crate::reader::EngagementCount;
        let build = |atoms: u64| {
            let mut r = InMemoryReader::new();
            let now = 1_700_000_000;
            let old = now - 60 * 60 * 24 * 365;
            for &fid in &[1u64, 100] {
                r.add_fid(fid, old);
            }
            r.add_follows(1, vec![100]);
            r.add_follows(100, vec![1]);
            r.add_engagement_pair(
                1,
                100,
                EngagementCount {
                    first_30d: 0,
                    later: 10,
                },
                EngagementCount {
                    first_30d: 0,
                    later: 10,
                },
            );
            if atoms > 0 {
                r.add_vouch(1, 100, atoms);
            }
            (r, now)
        };
        let mut seeds = BTreeSet::new();
        seeds.insert(1u64);
        let graph: BTreeMap<u64, Vec<u64>> =
            [(1u64, vec![100]), (100u64, vec![1])].into_iter().collect();

        let g_for = |atoms: u64| -> f64 {
            let (r, now) = build(atoms);
            let mut m = build_metrics(&r, now).unwrap();
            let et = compute_eigentrust(&graph, &seeds, 30, 0.85);
            apply_trust_and_credibility(&mut m, &et);
            let g = compute_growth_harmonic(&m, 0.0, 0.0);
            g.get(&100).copied().unwrap_or(0.0)
        };

        let g0 = g_for(0);
        let g_half = g_for(STAKE_MATURITY_ATOMS / 2);
        let g_full = g_for(STAKE_MATURITY_ATOMS);
        let g_over = g_for(STAKE_MATURITY_ATOMS * 10);
        assert!((g_half / g0 - 1.5).abs() < 1e-9);
        assert!((g_full / g0 - 2.0).abs() < 1e-9);
        // Saturates at 2.0x.
        assert!((g_over / g0 - 2.0).abs() < 1e-9);
    }

    /// Vouch is per-pair: u's vouch on f does NOT boost u's
    /// contribution toward g (a different vouchee).
    #[test]
    fn vouch_boost_is_per_pair_not_per_voucher() {
        use crate::metrics::STAKE_MATURITY_ATOMS;
        use crate::reader::EngagementCount;
        let build = |with_vouch_on_f: bool| {
            let mut r = InMemoryReader::new();
            let now = 1_700_000_000;
            let old = now - 60 * 60 * 24 * 365;
            for &fid in &[1u64, 100, 200] {
                r.add_fid(fid, old);
            }
            r.add_follows(1, vec![100, 200]);
            r.add_follows(100, vec![1]);
            r.add_follows(200, vec![1]);
            r.add_engagement_pair(
                1,
                100,
                EngagementCount {
                    first_30d: 0,
                    later: 10,
                },
                EngagementCount {
                    first_30d: 0,
                    later: 10,
                },
            );
            r.add_engagement_pair(
                1,
                200,
                EngagementCount {
                    first_30d: 0,
                    later: 10,
                },
                EngagementCount {
                    first_30d: 0,
                    later: 10,
                },
            );
            if with_vouch_on_f {
                r.add_vouch(1, 100, STAKE_MATURITY_ATOMS);
            }
            (r, now)
        };

        let mut seeds = BTreeSet::new();
        seeds.insert(1u64);
        let graph: BTreeMap<u64, Vec<u64>> =
            [(1u64, vec![100, 200]), (100u64, vec![1]), (200u64, vec![1])]
                .into_iter()
                .collect();

        let g_for = |with: bool, fid: u64| -> f64 {
            let (r, now) = build(with);
            let mut m = build_metrics(&r, now).unwrap();
            let et = compute_eigentrust(&graph, &seeds, 30, 0.85);
            apply_trust_and_credibility(&mut m, &et);
            let g = compute_growth_harmonic(&m, 0.0, 0.0);
            g.get(&fid).copied().unwrap_or(0.0)
        };

        let g100_no = g_for(false, 100);
        let g100_yes = g_for(true, 100);
        let g200_no = g_for(false, 200);
        let g200_yes = g_for(true, 200);

        // f (100) gets the boost.
        assert!((g100_yes / g100_no - 2.0).abs() < 1e-9);
        // g (200) is unchanged — vouch on f doesn't leak into f' g's score.
        assert!((g200_yes / g200_no - 1.0).abs() < 1e-12);
    }

    /// FIP §5a end-to-end: DA-PoW answered counts surface
    /// DataAvailability rewards proportional to validator answers.
    #[test]
    fn da_pow_rewards_flow_through_evaluate_epoch() {
        let mut r = InMemoryReader::new();
        let now = 1_700_000_000;
        // Validators 42 and 99 answer 80 and 20 challenges
        // respectively → 80:20 split of the DA budget.
        r.set_da_answered(1, 42, 80);
        r.set_da_answered(1, 99, 20);
        // Both validators have full uptime (commit_signatures =
        // EPOCH_LENGTH_BLOCKS) so the uptime_factor cancels out
        // of the ratio.
        r.set_validator_commit_signatures(1, 42, 432_000);
        r.set_validator_commit_signatures(1, 99, 432_000);

        let mut params = ScoringParams::default();
        params
            .market_budgets
            .insert(WorkMarket::DataAvailability, 1_000_000);
        let seeds = BTreeSet::new();

        let out = evaluate_epoch(&r, 1, now, &seeds, &params).unwrap();
        let da_market = out
            .markets
            .iter()
            .find(|m| m.market == WorkMarket::DataAvailability)
            .unwrap();
        let amt_42 = da_market
            .entries
            .iter()
            .find(|e| e.fid == 42)
            .unwrap()
            .amount;
        let amt_99 = da_market
            .entries
            .iter()
            .find(|e| e.fid == 99)
            .unwrap()
            .amount;
        assert_eq!(amt_42, 800_000);
        assert_eq!(amt_99, 200_000);
        let total: u128 = da_market.entries.iter().map(|e| e.amount).sum();
        assert_eq!(total, 1_000_000);
    }

    /// FIP §7c end-to-end: MiniappAdd events surface AppUsage
    /// rewards weighted 10× a single receipt. Two apps: one earning
    /// via 10 receipts, one earning via 1 add — should receive
    /// equal payouts.
    #[test]
    fn miniapp_adds_drive_app_pow_rewards() {
        use crate::reader::EngagementCount;
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
        r.add_engagement_pair(
            1,
            7,
            EngagementCount {
                first_30d: 0,
                later: 30,
            },
            EngagementCount {
                first_30d: 0,
                later: 30,
            },
        );
        // App 42 via 10 receipts; app 99 via 1 add.
        r.set_app_receipt_count(1, 42, 7, 10);
        r.set_miniapp_add_events(1, 99, 7, 1);

        let mut params = ScoringParams::default();
        params
            .market_budgets
            .insert(WorkMarket::AppUsage, 2_000_000);
        let mut seeds = BTreeSet::new();
        seeds.insert(1u64);

        let out = evaluate_epoch(&r, 1, now, &seeds, &params).unwrap();
        let app_market = out
            .markets
            .iter()
            .find(|m| m.market == WorkMarket::AppUsage)
            .unwrap();
        let amt_42 = app_market
            .entries
            .iter()
            .find(|e| e.fid == 42)
            .map(|e| e.amount)
            .unwrap_or(0);
        let amt_99 = app_market
            .entries
            .iter()
            .find(|e| e.fid == 99)
            .map(|e| e.amount)
            .unwrap_or(0);
        assert!(amt_42 > 0 && amt_99 > 0);
        // Equal work (10 × 0.5 vs 1 × 5.0) → equal payouts.
        assert_eq!(amt_42, amt_99);
    }

    /// FIP §7 end-to-end: receipts logged in the epoch surface
    /// AppUsage rewards proportional to user credibility, while
    /// Growth allocation is untouched. App owners receive payouts
    /// even if they would fail §8.3 (apps live in the §7 lane,
    /// not §6).
    #[test]
    fn app_pow_rewards_flow_through_evaluate_epoch() {
        use crate::reader::EngagementCount;
        let mut r = InMemoryReader::new();
        let now = 1_700_000_000;
        let old = now - 60 * 60 * 24 * 365;
        // Two users with positive credibility, two apps. Both apps
        // would otherwise fail F0 (signer_authorizations >= 100)
        // — they should still earn AppUsage rewards.
        for &fid in &[1u64, 7, 8, 42, 99] {
            r.add_fid(fid, old);
            r.set_total_casts(fid, 100);
            r.set_active_days(fid, 200);
            r.set_replies_received(fid, 10);
        }
        // Apps tagged as apps via signer_authorizations.
        r.set_signer_authorizations(42, 150);
        r.set_signer_authorizations(99, 150);
        // Trust seed.
        r.add_follows(1, vec![7, 8]);
        r.add_follows(7, vec![1]);
        r.add_follows(8, vec![1]);
        // Seed reciprocal engagement so users have credibility.
        r.add_engagement_pair(
            1,
            7,
            EngagementCount {
                first_30d: 0,
                later: 30,
            },
            EngagementCount {
                first_30d: 0,
                later: 30,
            },
        );
        r.add_engagement_pair(
            1,
            8,
            EngagementCount {
                first_30d: 0,
                later: 30,
            },
            EngagementCount {
                first_30d: 0,
                later: 30,
            },
        );

        // App 42: 30 receipts from user 7. App 99: 10 receipts from user 8.
        r.set_app_receipt_count(/*epoch=*/ 1, /*app=*/ 42, /*user=*/ 7, 30);
        r.set_app_receipt_count(1, 99, 8, 10);

        let mut params = ScoringParams::default();
        params
            .market_budgets
            .insert(WorkMarket::AppUsage, 1_000_000);
        let mut seeds = BTreeSet::new();
        seeds.insert(1u64);

        let out = evaluate_epoch(&r, 1, now, &seeds, &params).unwrap();
        let app_market = out
            .markets
            .iter()
            .find(|m| m.market == WorkMarket::AppUsage)
            .unwrap();
        // Both apps should receive non-zero payouts despite being
        // §6-ineligible.
        let amt_42 = app_market
            .entries
            .iter()
            .find(|e| e.fid == 42)
            .map(|e| e.amount)
            .unwrap_or(0);
        let amt_99 = app_market
            .entries
            .iter()
            .find(|e| e.fid == 99)
            .map(|e| e.amount)
            .unwrap_or(0);
        assert!(amt_42 > 0, "app 42 earned AppUsage despite F0 fail");
        assert!(amt_99 > 0, "app 99 earned AppUsage despite F0 fail");
        // App 42 has 3× the receipts, with equal-cred users, so
        // it should receive ~3× the share.
        let ratio = amt_42 as f64 / amt_99 as f64;
        assert!(
            (ratio - 3.0).abs() < 0.05,
            "expected ~3× ratio, got {ratio} (42={amt_42}, 99={amt_99})"
        );
        // Sum equals budget (no cap → rounding remainder
        // redistributes).
        let total: u128 = app_market.entries.iter().map(|e| e.amount).sum();
        assert_eq!(total, 1_000_000);
    }

    /// FIP §8.3 Phase: an FID with positive growth/composite still
    /// gets 0 reward when it fails an eligibility filter. We force
    /// F0 to fail by setting `signer_authorizations >=
    /// APP_THRESHOLD`; the rest of the metrics are healthy.
    #[test]
    fn ineligible_fid_gets_zero_reward_even_with_positive_growth() {
        use crate::reader::EngagementCount;
        let mut r = InMemoryReader::new();
        let now = 1_700_000_000;
        let old = now - 60 * 60 * 24 * 365;
        for &fid in &[1u64, 2, 100] {
            r.add_fid(fid, old);
            r.set_total_casts(fid, 100);
            r.set_active_days(fid, 200);
            r.set_replies_received(fid, 10);
        }
        // FID 100 looks like an app (≥ APP_THRESHOLD signer auths).
        r.set_signer_authorizations(100, 100);
        for &s in &[1u64, 2] {
            r.add_follows(s, vec![100]);
            r.add_engagement_pair(
                s,
                100,
                EngagementCount {
                    first_30d: 0,
                    later: 10,
                },
                EngagementCount {
                    first_30d: 0,
                    later: 10,
                },
            );
        }
        r.add_follows(100, vec![1, 2]);
        // Pads for F5 variance.
        for pad in 800u64..810 {
            r.add_fid(pad, old);
            r.set_total_casts(pad, 100);
            r.set_active_days(pad, 200);
            r.set_replies_received(pad, 10);
            r.add_engagement(
                1,
                pad,
                EngagementCount {
                    first_30d: 100,
                    later: 0,
                },
            );
        }

        let mut params = ScoringParams::default();
        params
            .market_budgets
            .insert(WorkMarket::Growth, 1_000_000_000);
        let mut seeds = BTreeSet::new();
        seeds.insert(1u64);
        seeds.insert(2);

        let out = evaluate_epoch(&r, 1, now, &seeds, &params).unwrap();
        let growth_market = out
            .markets
            .iter()
            .find(|m| m.market == WorkMarket::Growth)
            .unwrap();
        let amount_100 = growth_market
            .entries
            .iter()
            .find(|e| e.fid == 100)
            .map(|e| e.amount)
            .unwrap_or(0);
        assert_eq!(amount_100, 0, "app-flagged FID must get zero reward");
    }

    /// Two distinct vouchers each get their own per-pair boost;
    /// boosts do not stack on each other (independent per
    /// crediter).
    #[test]
    fn distinct_vouchers_get_independent_boosts() {
        use crate::metrics::STAKE_MATURITY_ATOMS;
        use crate::reader::EngagementCount;
        let build = |vouch_a: u64, vouch_b: u64| {
            let mut r = InMemoryReader::new();
            let now = 1_700_000_000;
            let old = now - 60 * 60 * 24 * 365;
            for &fid in &[1u64, 2, 100] {
                r.add_fid(fid, old);
            }
            r.add_follows(1, vec![100]);
            r.add_follows(2, vec![100]);
            r.add_follows(100, vec![1, 2]);
            r.add_engagement_pair(
                1,
                100,
                EngagementCount {
                    first_30d: 0,
                    later: 10,
                },
                EngagementCount {
                    first_30d: 0,
                    later: 10,
                },
            );
            r.add_engagement_pair(
                2,
                100,
                EngagementCount {
                    first_30d: 0,
                    later: 10,
                },
                EngagementCount {
                    first_30d: 0,
                    later: 10,
                },
            );
            if vouch_a > 0 {
                r.add_vouch(1, 100, vouch_a);
            }
            if vouch_b > 0 {
                r.add_vouch(2, 100, vouch_b);
            }
            (r, now)
        };
        let mut seeds = BTreeSet::new();
        seeds.insert(1u64);
        seeds.insert(2u64);
        let graph: BTreeMap<u64, Vec<u64>> =
            [(1u64, vec![100]), (2u64, vec![100]), (100u64, vec![1, 2])]
                .into_iter()
                .collect();
        let g_for = |va: u64, vb: u64| -> f64 {
            let (r, now) = build(va, vb);
            let mut m = build_metrics(&r, now).unwrap();
            let et = compute_eigentrust(&graph, &seeds, 30, 0.85);
            apply_trust_and_credibility(&mut m, &et);
            let g = compute_growth_harmonic(&m, 0.0, 0.0);
            g.get(&100).copied().unwrap_or(0.0)
        };

        let base = g_for(0, 0);
        let only_a = g_for(STAKE_MATURITY_ATOMS, 0);
        let only_b = g_for(0, STAKE_MATURITY_ATOMS);
        let both = g_for(STAKE_MATURITY_ATOMS, STAKE_MATURITY_ATOMS);

        // The two crediters contribute equal credibility-weighted
        // logs (mirror scenario), so each saturation contributes
        // +50% of base. Both saturated → 2x.
        assert!((only_a / base - 1.5).abs() < 1e-9, "{}", only_a / base);
        assert!((only_b / base - 1.5).abs() < 1e-9);
        assert!((both / base - 2.0).abs() < 1e-9);
    }

    /// Anti-puppet-sybil-pump: when the vouchee's own trust_score
    /// is below `vouch_boost_min_vouchee_trust`, the boost
    /// collapses to 1.0 regardless of how many atoms the voucher
    /// has staked. Identical metrics, just toggling the threshold,
    /// should give identical growth scores when the vouchee fails
    /// the trust floor.
    #[test]
    fn vouch_boost_gated_by_vouchee_trust_floor() {
        use crate::metrics::STAKE_MATURITY_ATOMS;
        let mut metrics: BTreeMap<u64, FidMetrics> = BTreeMap::new();
        // u = 1 (voucher, high trust + cred). f = 100 (vouchee, LOW trust).
        let mut m_u = FidMetrics::new(1);
        m_u.trust_score = 0.9;
        m_u.credibility_weight = 0.9;
        // Reciprocal engagement counts.
        m_u.all_time_engagement.insert(100, 10);
        m_u.vouches_from.insert(100, STAKE_MATURITY_ATOMS);
        metrics.insert(1, m_u);

        let mut m_f = FidMetrics::new(100);
        m_f.trust_score = 0.10; // below the gate threshold
        m_f.credibility_weight = 0.10;
        m_f.all_time_engagement.insert(1, 10);
        metrics.insert(100, m_f);

        // Ungated: full 2× boost applies.
        let g_open = compute_growth_harmonic(&metrics, 0.0, 0.0);
        // Gated at 0.5: vouchee's 0.10 < 0.5 → boost suppressed.
        let g_gated = compute_growth_harmonic(&metrics, 0.0, 0.5);

        let v_open = g_open.get(&100).copied().unwrap_or(0.0);
        let v_gated = g_gated.get(&100).copied().unwrap_or(0.0);
        // Ungated growth has the 2× boost; gated growth is the
        // half-magnitude baseline (no boost). Ratio ≈ 2.
        assert!(
            (v_open / v_gated - 2.0).abs() < 1e-9,
            "expected 2× ratio: ungated={v_open}, gated={v_gated}"
        );
    }

    /// Confirm the floor only blocks the boost when the vouchee
    /// FAILS the threshold. A high-trust vouchee still gets the
    /// boost even with the gate on.
    #[test]
    fn vouch_boost_applies_when_vouchee_passes_trust_floor() {
        use crate::metrics::STAKE_MATURITY_ATOMS;
        let mut metrics: BTreeMap<u64, FidMetrics> = BTreeMap::new();
        let mut m_u = FidMetrics::new(1);
        m_u.trust_score = 0.9;
        m_u.credibility_weight = 0.9;
        m_u.all_time_engagement.insert(100, 10);
        m_u.vouches_from.insert(100, STAKE_MATURITY_ATOMS);
        metrics.insert(1, m_u);

        let mut m_f = FidMetrics::new(100);
        m_f.trust_score = 0.6; // above the 0.5 gate
        m_f.credibility_weight = 0.6;
        m_f.all_time_engagement.insert(1, 10);
        metrics.insert(100, m_f);

        let g_open = compute_growth_harmonic(&metrics, 0.0, 0.0);
        let g_gated = compute_growth_harmonic(&metrics, 0.0, 0.5);
        // Identical (vouchee passes floor → boost identical).
        let v_open = g_open.get(&100).copied().unwrap_or(0.0);
        let v_gated = g_gated.get(&100).copied().unwrap_or(0.0);
        assert!((v_open - v_gated).abs() < 1e-12);
    }
}
