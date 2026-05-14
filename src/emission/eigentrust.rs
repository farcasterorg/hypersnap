//! EigenTrust core algorithm for emission scoring.
//!
//! Power iteration over the post-transfer follow graph, seeded by the first
//! `seed_max_fid` accounts (per FIP-proof-of-quality §calibration). After
//! convergence, raw scores are normalized via a top-N average so spam
//! accounts with concentrated trust mass don't saturate to 1.0. The
//! resulting trust scores are used as a gate ("crediter trust floor")
//! when computing per-pair mutuality contributions to growth scores.
//!
//! This module is the algorithmic core. The driver that walks the per-epoch
//! social graph and engagement state lives in a separate module so this
//! piece can be tested independently with synthetic graphs.

use std::collections::{BTreeMap, HashMap};

/// One node's outgoing trust distribution. The values are normalized so they
/// sum to 1.0; if a node has no outgoing trust, the iteration treats it as a
/// uniform sink (its mass is redistributed to the seed set).
pub type TrustOut = HashMap<u64, f64>;

/// Power-iteration parameters.
#[derive(Clone, Debug)]
pub struct EigenTrustParams {
    /// Damping factor — fraction of mass that PROPAGATES through trust edges
    /// each iteration. The remaining `1 - damping` is the teleport factor
    /// that returns mass to the seed set. Standard PageRank uses 0.85 here.
    pub damping: f64,
    /// Power-iteration convergence threshold (L1 difference between successive
    /// score vectors).
    pub epsilon: f64,
    /// Maximum number of iterations before forced exit.
    pub max_iter: u32,
}

impl Default for EigenTrustParams {
    fn default() -> Self {
        Self {
            damping: 0.85,
            epsilon: 1e-7,
            max_iter: 200,
        }
    }
}

/// Run EigenTrust power iteration over `outgoing` with the seed set `seeds`.
///
/// Each entry in `outgoing` maps a source FID to its outgoing trust
/// distribution (values summing to 1.0). The seed mass is uniformly
/// distributed over `seeds`. Returns the converged score vector.
pub fn run_eigentrust(
    outgoing: &HashMap<u64, TrustOut>,
    seeds: &[u64],
    params: &EigenTrustParams,
) -> HashMap<u64, f64> {
    if seeds.is_empty() {
        return HashMap::new();
    }
    let seed_mass = 1.0 / seeds.len() as f64;
    let seed_set: BTreeMap<u64, f64> = seeds.iter().map(|fid| (*fid, seed_mass)).collect();

    // Discover the universe = all FIDs that appear as a source or target.
    let mut universe: BTreeMap<u64, f64> = BTreeMap::new();
    for (src, dist) in outgoing {
        universe.entry(*src).or_insert(0.0);
        for tgt in dist.keys() {
            universe.entry(*tgt).or_insert(0.0);
        }
    }
    for fid in seeds {
        universe.entry(*fid).or_insert(0.0);
    }
    if universe.is_empty() {
        return HashMap::new();
    }

    // Initialize scores: all mass on seeds.
    let mut scores: HashMap<u64, f64> = universe.iter().map(|(k, _)| (*k, 0.0)).collect();
    for (fid, mass) in &seed_set {
        scores.insert(*fid, *mass);
    }

    for _ in 0..params.max_iter {
        let mut next: HashMap<u64, f64> = universe.iter().map(|(k, _)| (*k, 0.0)).collect();

        // Propagate `damping` of mass through the trust edges.
        for (src, dist) in outgoing {
            let src_mass = *scores.get(src).unwrap_or(&0.0);
            if src_mass <= 0.0 {
                continue;
            }
            for (tgt, weight) in dist {
                *next.entry(*tgt).or_insert(0.0) += params.damping * src_mass * weight;
            }
        }

        // Teleport: `1 - damping` fraction of total mass goes to seeds.
        let teleport = (1.0 - params.damping) * 1.0; // total mass is normalized to 1
        for (fid, _) in &seed_set {
            *next.entry(*fid).or_insert(0.0) += teleport * seed_mass;
        }

        // Mass loss correction: nodes without outgoing edges leak mass.
        // Redistribute leaked mass to seeds.
        let total_after: f64 = next.values().sum();
        if total_after < 1.0 - 1e-12 {
            let leak = 1.0 - total_after;
            for (fid, _) in &seed_set {
                *next.entry(*fid).or_insert(0.0) += leak * seed_mass;
            }
        }

        // Convergence check via L1.
        let l1: f64 = scores
            .iter()
            .map(|(k, v)| {
                let nv = *next.get(k).unwrap_or(&0.0);
                (nv - v).abs()
            })
            .sum();
        scores = next;
        if l1 < params.epsilon {
            break;
        }
    }

    scores
}

/// Normalize a raw score vector by the average of its top-N values. This
/// prevents a single concentrated cluster from saturating the [0, 1] range,
/// which `retro_rewards_finalize.rs` discovered was the failure mode that
/// allowed spam accounts to climb the leaderboard.
pub fn top_n_avg_normalize(scores: &HashMap<u64, f64>, top_n: usize) -> HashMap<u64, f64> {
    if scores.is_empty() || top_n == 0 {
        return scores.clone();
    }
    let mut values: Vec<f64> = scores.values().copied().collect();
    values.sort_by(|a, b| b.partial_cmp(a).unwrap_or(std::cmp::Ordering::Equal));
    let n = values.len().min(top_n);
    if n == 0 {
        return scores.clone();
    }
    let avg: f64 = values[..n].iter().sum::<f64>() / n as f64;
    if avg <= 0.0 {
        return scores.clone();
    }
    scores
        .iter()
        .map(|(k, v)| (*k, (v / avg).min(1.0)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn edge(from_to: &[(u64, u64)]) -> HashMap<u64, TrustOut> {
        // Build outgoing trust where each source's edges sum to 1.0.
        let mut edges_by_src: HashMap<u64, Vec<u64>> = HashMap::new();
        for (s, t) in from_to {
            edges_by_src.entry(*s).or_default().push(*t);
        }
        edges_by_src
            .into_iter()
            .map(|(s, ts)| {
                let w = 1.0 / ts.len() as f64;
                let dist: TrustOut = ts.into_iter().map(|t| (t, w)).collect();
                (s, dist)
            })
            .collect()
    }

    #[test]
    fn empty_graph_produces_empty_scores() {
        let scores = run_eigentrust(&HashMap::new(), &[], &EigenTrustParams::default());
        assert!(scores.is_empty());
    }

    #[test]
    fn single_seed_self_loop_holds_mass() {
        // Seed: {1}. Edge: 1 → 2. With damping 0.85, mass returns to seed.
        let outgoing = edge(&[(1, 2)]);
        let scores = run_eigentrust(&outgoing, &[1], &EigenTrustParams::default());
        // Seed retains most mass; some mass propagates to 2.
        assert!(scores[&1] > scores[&2]);
        // Total mass conserves (within ε).
        let total: f64 = scores.values().sum();
        assert!((total - 1.0).abs() < 1e-3);
    }

    #[test]
    fn high_in_degree_node_accumulates_score() {
        // 4 nodes (1, 2, 3, 4) all trust node 99. Seed {1, 2, 3, 4}.
        let outgoing = edge(&[(1, 99), (2, 99), (3, 99), (4, 99)]);
        let scores = run_eigentrust(&outgoing, &[1, 2, 3, 4], &EigenTrustParams::default());
        // Node 99 should rank above any individual seed.
        for s in [1, 2, 3, 4] {
            assert!(
                scores[&99] > scores[&s],
                "high-in-degree should outrank seed {}",
                s
            );
        }
    }

    #[test]
    fn unreachable_node_gets_zero() {
        // Seed {1}, edges 1→2. Node 99 not in graph → no score.
        let outgoing = edge(&[(1, 2)]);
        let scores = run_eigentrust(&outgoing, &[1], &EigenTrustParams::default());
        assert!(!scores.contains_key(&99));
    }

    #[test]
    fn top_n_avg_normalizes_into_unit_range() {
        let mut s = HashMap::new();
        s.insert(1, 0.001);
        s.insert(2, 0.002);
        s.insert(3, 0.003);
        s.insert(4, 0.0001);
        s.insert(5, 0.00005);

        let n = top_n_avg_normalize(&s, 3);
        // Top 3 average = (0.003 + 0.002 + 0.001) / 3 = 0.002.
        // Each value clamps to min(v / 0.002, 1.0).
        assert!((n[&1] - 0.5).abs() < 1e-9);
        assert!((n[&2] - 1.0).abs() < 1e-9); // 0.002 / 0.002 = 1.0
        assert!((n[&3] - 1.0).abs() < 1e-9); // 0.003 / 0.002 = 1.5 → clamped
        assert!(n[&4] < 0.1);
    }

    #[test]
    fn top_n_avg_handles_uniform_scores() {
        let s: HashMap<u64, f64> = (1..=10).map(|i| (i, 0.5)).collect();
        let n = top_n_avg_normalize(&s, 3);
        // All equal → all map to 1.0
        for v in n.values() {
            assert!((v - 1.0).abs() < 1e-9);
        }
    }

    #[test]
    fn top_n_avg_zero_input_unchanged() {
        let s: HashMap<u64, f64> = (1..=5).map(|i| (i, 0.0)).collect();
        let n = top_n_avg_normalize(&s, 3);
        for v in n.values() {
            assert_eq!(*v, 0.0);
        }
    }

    #[test]
    fn convergence_within_max_iter() {
        // With reasonable damping, EigenTrust converges in <100 iterations
        // on small graphs.
        let outgoing = edge(&[(1, 2), (2, 3), (3, 1), (1, 4)]);
        let params = EigenTrustParams {
            damping: 0.85,
            epsilon: 1e-9,
            max_iter: 100,
        };
        let scores = run_eigentrust(&outgoing, &[1], &params);
        let total: f64 = scores.values().sum();
        assert!(
            (total - 1.0).abs() < 1e-3,
            "mass should be conserved (got total={})",
            total
        );
    }
}
