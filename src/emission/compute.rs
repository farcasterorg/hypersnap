//! End-to-end emission compute, tying together EigenTrust + mutuality +
//! allocation into a single per-epoch pipeline.
//!
//! Inputs:
//!  - Follow graph (post-transfer): map FID → set of FIDs they trust
//!  - Engagement counts: list of (fid_a, fid_b, PairEngagement)
//!  - Seeds: FIDs ≤ SEED_MAX_FID that anchor the trust computation
//!  - Tranche: total atoms to distribute this epoch
//!
//! Output:
//!  - `EpochEmission { epoch, allocations, total_atoms }` with per-FID
//!    atomic amounts summing to `tranche_atoms`.

use crate::emission::eigentrust::{
    run_eigentrust, top_n_avg_normalize, EigenTrustParams, TrustOut,
};
use crate::emission::mutuality::{allocate_emissions, tally_growth_scores, PairEngagement};
use crate::emission::{EmissionParams, EpochEmission};
use std::collections::HashMap;

/// Default top-N for trust-score normalization. Matches the value
/// `retro_rewards_finalize.rs` settled on.
pub const DEFAULT_TRUST_NORMALIZER_TOP_N: usize = 100;

pub struct EmissionComputeInputs {
    /// FID → list of FIDs they trust (post-transfer follow graph).
    pub follows: HashMap<u64, Vec<u64>>,
    /// Per-pair engagement counts. Each entry contributes once.
    pub engagement: Vec<(u64, u64, PairEngagement)>,
    /// Seeds for EigenTrust. Typically FID ≤ SEED_MAX_FID = 50_000.
    pub seeds: Vec<u64>,
    /// Target epoch for the resulting EpochEmission.
    pub epoch: u64,
}

pub fn compute_epoch_emissions(
    inputs: EmissionComputeInputs,
    params: &EmissionParams,
) -> EpochEmission {
    if inputs.seeds.is_empty() || params.epoch_tranche_atoms == 0 {
        return EpochEmission::empty(inputs.epoch);
    }

    // 1. Convert follow graph into outgoing trust distributions.
    let outgoing: HashMap<u64, TrustOut> = inputs
        .follows
        .into_iter()
        .map(|(src, targets)| {
            if targets.is_empty() {
                (src, HashMap::new())
            } else {
                let w = 1.0 / targets.len() as f64;
                let dist: TrustOut = targets.into_iter().map(|t| (t, w)).collect();
                (src, dist)
            }
        })
        .collect();

    // 2. Run EigenTrust.
    let raw_scores = run_eigentrust(&outgoing, &inputs.seeds, &EigenTrustParams::default());

    // 3. Normalize via top-N average so concentrated trust mass doesn't saturate.
    let trust_scores = top_n_avg_normalize(&raw_scores, DEFAULT_TRUST_NORMALIZER_TOP_N);

    // 4. Tally growth scores from engagement, gated by crediter trust floor.
    let growth = tally_growth_scores(inputs.engagement, &trust_scores, params);

    // 5. Allocate the tranche proportionally.
    let allocations_map = allocate_emissions(
        &growth,
        params.epoch_tranche_atoms,
        params.min_per_recipient_atoms,
    );

    let mut allocations: Vec<(u64, u64)> = allocations_map.into_iter().collect();
    allocations.sort_by(|a, b| b.1.cmp(&a.1));
    let total_atoms: u64 = allocations.iter().map(|(_, a)| *a).sum();

    EpochEmission {
        epoch: inputs.epoch,
        allocations,
        total_atoms,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::emission::params::SEED_MAX_FID;
    use crate::emission::MutualityMode;

    fn params_with_tranche(tranche: u64) -> EmissionParams {
        EmissionParams {
            epoch_tranche_atoms: tranche,
            seed_max_fid: SEED_MAX_FID,
            mutuality_mode: MutualityMode::Sum,
            min_per_recipient_atoms: 1,
            crediter_trust_floor: 0.05,
            min_active_days: 7,
        }
    }

    #[test]
    fn empty_inputs_produce_empty_emission() {
        let inputs = EmissionComputeInputs {
            follows: HashMap::new(),
            engagement: Vec::new(),
            seeds: vec![1, 2, 3],
            epoch: 5,
        };
        let p = params_with_tranche(1_000_000);
        let result = compute_epoch_emissions(inputs, &p);
        assert_eq!(result.epoch, 5);
        assert_eq!(result.total_atoms, 0);
        assert!(result.allocations.is_empty());
    }

    #[test]
    fn zero_tranche_produces_empty_emission() {
        let inputs = EmissionComputeInputs {
            follows: {
                let mut m = HashMap::new();
                m.insert(1u64, vec![2u64]);
                m
            },
            engagement: vec![(1, 2, PairEngagement::new(50, 50))],
            seeds: vec![1, 2],
            epoch: 7,
        };
        let p = params_with_tranche(0);
        let result = compute_epoch_emissions(inputs, &p);
        assert!(result.allocations.is_empty());
    }

    #[test]
    fn end_to_end_simple_emission() {
        // Three seed validators (1, 2, 3) form a trust ring and engage with
        // each other. Each receives a non-zero allocation summing to the tranche.
        let mut follows = HashMap::new();
        follows.insert(1u64, vec![2, 3]);
        follows.insert(2u64, vec![1, 3]);
        follows.insert(3u64, vec![1, 2]);

        let engagement = vec![
            (1u64, 2u64, PairEngagement::new(20, 20)),
            (2u64, 3u64, PairEngagement::new(15, 15)),
            (1u64, 3u64, PairEngagement::new(10, 10)),
        ];

        let inputs = EmissionComputeInputs {
            follows,
            engagement,
            seeds: vec![1, 2, 3],
            epoch: 10,
        };
        let p = params_with_tranche(1_000_000);
        let result = compute_epoch_emissions(inputs, &p);
        assert_eq!(result.epoch, 10);
        assert_eq!(result.total_atoms, 1_000_000);
        assert_eq!(result.allocations.len(), 3);
        // All three FIDs should receive non-zero allocations.
        for (_, atoms) in &result.allocations {
            assert!(*atoms > 0);
        }
    }

    #[test]
    fn high_trust_recipients_dominate() {
        // Seeds {1, 2}; 99 receives massive engagement only from low-trust 50.
        // 50's trust starts at 0 (not a seed, no incoming trust) → engagement
        // contributes nothing. 99 should NOT dominate.
        let mut follows = HashMap::new();
        follows.insert(1u64, vec![2]);
        follows.insert(2u64, vec![1]);

        let engagement = vec![
            (50u64, 99u64, PairEngagement::new(10_000, 10_000)),
            (1u64, 2u64, PairEngagement::new(10, 10)),
        ];

        let inputs = EmissionComputeInputs {
            follows,
            engagement,
            seeds: vec![1, 2],
            epoch: 1,
        };
        let p = params_with_tranche(1_000_000);
        let result = compute_epoch_emissions(inputs, &p);

        // 99 should not appear in allocations because 50's trust is below floor.
        let received_99: u64 = result
            .allocations
            .iter()
            .filter(|(fid, _)| *fid == 99)
            .map(|(_, a)| *a)
            .sum();
        assert_eq!(
            received_99, 0,
            "high-engagement-with-low-trust-crediter must not get emission"
        );
    }
}
