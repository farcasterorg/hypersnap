//! Per-pair mutuality scoring.
//!
//! For each (a, b) pair where `a` and `b` engaged with each other after their
//! transfer-eligible time, compute a mutuality contribution to `b`'s growth
//! score. The contribution is gated by `a`'s EigenTrust score (the crediter
//! trust floor): low-trust accounts contribute zero, eliminating the spam
//! amplification path.
//!
//! Symmetric formulation: each pair (a, b) yields contributions in BOTH
//! directions (a→b and b→a), each gated by the *other* party's trust score.

use crate::emission::params::{EmissionParams, MutualityMode};
use std::collections::HashMap;

/// Per-pair engagement counts. `a_to_b` is the count of engagements where `a`
/// is the originator and `b` is the recipient (e.g. `a` replied to a cast of
/// `b`'s, or liked it). `b_to_a` is the reverse.
#[derive(Clone, Copy, Debug)]
pub struct PairEngagement {
    pub a_to_b: u64,
    pub b_to_a: u64,
}

impl PairEngagement {
    pub fn new(a_to_b: u64, b_to_a: u64) -> Self {
        Self { a_to_b, b_to_a }
    }
}

/// Compute the mutuality scalar for a pair, applying the configured mode and
/// log saturation. This is the raw quantity that gets weighted by the
/// crediter's trust score before being added to the growth tally.
pub fn mutuality_score(engagement: PairEngagement, mode: MutualityMode) -> f64 {
    mode.apply(engagement.a_to_b as f64, engagement.b_to_a as f64)
}

/// Tally per-FID growth scores from an iterator of (a, b, engagement) tuples.
///
/// For each pair:
///   - If trust_scores[a] < crediter_floor: contribution to b is 0
///   - Else: contribution to b is `trust_scores[a] * mutuality_score(...)`
/// And symmetrically for the (b, a) direction.
///
/// Final growth scores are then scalable into emission amounts by the caller.
pub fn tally_growth_scores<I>(
    pairs: I,
    trust_scores: &HashMap<u64, f64>,
    params: &EmissionParams,
) -> HashMap<u64, f64>
where
    I: IntoIterator<Item = (u64, u64, PairEngagement)>,
{
    let mut growth: HashMap<u64, f64> = HashMap::new();
    for (a, b, eng) in pairs {
        let m = mutuality_score(eng, params.mutuality_mode);
        if m == 0.0 {
            continue;
        }

        let trust_a = *trust_scores.get(&a).unwrap_or(&0.0);
        let trust_b = *trust_scores.get(&b).unwrap_or(&0.0);

        if trust_a >= params.crediter_trust_floor {
            *growth.entry(b).or_insert(0.0) += trust_a * m;
        }
        if trust_b >= params.crediter_trust_floor {
            *growth.entry(a).or_insert(0.0) += trust_b * m;
        }
    }
    growth
}

/// Allocate per-FID atom amounts proportional to growth scores, summing
/// exactly to `tranche_atoms`. Floors below `min_per_recipient_atoms` are
/// dropped (their share goes to the largest recipient to preserve total).
pub fn allocate_emissions(
    growth_scores: &HashMap<u64, f64>,
    tranche_atoms: u64,
    min_per_recipient_atoms: u64,
) -> HashMap<u64, u64> {
    let total: f64 = growth_scores.values().sum();
    if total <= 0.0 || tranche_atoms == 0 {
        return HashMap::new();
    }

    // First pass: proportional allocation, rounding down to atoms.
    let mut allocations: Vec<(u64, u64)> = growth_scores
        .iter()
        .map(|(fid, score)| {
            let proportion = score / total;
            let atoms = (proportion * tranche_atoms as f64).floor() as u64;
            (*fid, atoms)
        })
        .filter(|(_, atoms)| *atoms >= min_per_recipient_atoms)
        .collect();

    // Reconcile rounding loss: assign remainder to the largest recipient.
    let allocated: u64 = allocations.iter().map(|(_, a)| *a).sum();
    if allocated < tranche_atoms && !allocations.is_empty() {
        allocations.sort_by(|a, b| b.1.cmp(&a.1));
        let leftover = tranche_atoms - allocated;
        allocations[0].1 += leftover;
    }

    allocations.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params_with_floor(floor: f64) -> EmissionParams {
        EmissionParams {
            crediter_trust_floor: floor,
            mutuality_mode: MutualityMode::Sum,
            ..Default::default()
        }
    }

    #[test]
    fn mutuality_zero_engagement_returns_zero() {
        let m = mutuality_score(PairEngagement::new(0, 0), MutualityMode::Sum);
        assert!((m - 0.0).abs() < 1e-12);
    }

    #[test]
    fn mutuality_increases_with_volume() {
        let a = mutuality_score(PairEngagement::new(10, 10), MutualityMode::Sum);
        let b = mutuality_score(PairEngagement::new(100, 100), MutualityMode::Sum);
        assert!(b > a);
    }

    #[test]
    fn growth_score_attributed_to_each_party() {
        let mut trust = HashMap::new();
        trust.insert(1u64, 0.9);
        trust.insert(2u64, 0.8);
        let p = params_with_floor(0.05);
        let pairs = vec![(1u64, 2u64, PairEngagement::new(50, 50))];
        let growth = tally_growth_scores(pairs, &trust, &p);
        // Both 1 and 2 receive contributions (bidirectional).
        assert!(growth.get(&1).copied().unwrap_or(0.0) > 0.0);
        assert!(growth.get(&2).copied().unwrap_or(0.0) > 0.0);
    }

    #[test]
    fn low_trust_crediter_does_not_contribute() {
        let mut trust = HashMap::new();
        trust.insert(1u64, 0.9); // honest crediter
        trust.insert(2u64, 0.01); // below floor
        let p = params_with_floor(0.05);
        let pairs = vec![(1u64, 2u64, PairEngagement::new(50, 50))];
        let growth = tally_growth_scores(pairs, &trust, &p);
        // 2 receives credit from honest 1.
        assert!(growth.get(&2).copied().unwrap_or(0.0) > 0.0);
        // 1 does NOT receive credit from low-trust 2.
        assert!(growth.get(&1).copied().unwrap_or(0.0).abs() < 1e-12);
    }

    #[test]
    fn no_engagement_yields_empty_growth() {
        let mut trust = HashMap::new();
        trust.insert(1u64, 0.9);
        let p = params_with_floor(0.05);
        let pairs: Vec<(u64, u64, PairEngagement)> = vec![];
        let growth = tally_growth_scores(pairs, &trust, &p);
        assert!(growth.is_empty());
    }

    #[test]
    fn allocate_distributes_total() {
        let mut growth = HashMap::new();
        growth.insert(1u64, 1.0);
        growth.insert(2u64, 2.0);
        growth.insert(3u64, 7.0);
        let allocations = allocate_emissions(&growth, 1_000_000, 1);
        let total: u64 = allocations.values().sum();
        assert_eq!(total, 1_000_000, "all atoms allocated");
        // Roughly proportional: 3 should get ~70%, 2 ~20%, 1 ~10%.
        assert!(allocations[&3] > allocations[&2]);
        assert!(allocations[&2] > allocations[&1]);
    }

    #[test]
    fn allocate_filters_below_min() {
        let mut growth = HashMap::new();
        growth.insert(1u64, 0.001); // very small share
        growth.insert(2u64, 100.0); // dominant
        let allocations = allocate_emissions(&growth, 1_000, 100);
        // FID 1's share is ~0.000001 of the tranche → 0 atoms after floor → filtered.
        assert!(!allocations.contains_key(&1));
        // FID 2 receives all 1000 atoms.
        assert_eq!(allocations[&2], 1_000);
    }

    #[test]
    fn allocate_zero_total_returns_empty() {
        let mut growth = HashMap::new();
        growth.insert(1u64, 0.0);
        growth.insert(2u64, 0.0);
        let allocations = allocate_emissions(&growth, 1_000, 1);
        assert!(allocations.is_empty());
    }

    #[test]
    fn allocate_zero_tranche_returns_empty() {
        let mut growth = HashMap::new();
        growth.insert(1u64, 1.0);
        let allocations = allocate_emissions(&growth, 0, 1);
        assert!(allocations.is_empty());
    }
}
