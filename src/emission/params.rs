//! Emission parameters per FIP-proof-of-work-tokenization §15.

/// Number of decimal places used for HYPER token amounts. 6 decimals matches
/// USDC and gives sufficient granularity for fee-of-fees-of-tip use cases.
pub const EMISSION_DECIMALS: u32 = 6;

/// Maximum FID treated as part of the EigenTrust seed cohort. Chosen as a
/// fixed cutoff so the seed is stable across runs and can't be manipulated by
/// new registrations. FIP §15 fixes this at 50_000.
pub const SEED_MAX_FID: u64 = 50_000;

/// Total HYPER supply, in atoms (10^6 atoms per HYPER). FIP §15: 2,000,000,000.
pub const TOTAL_SUPPLY_ATOMS: u128 = 2_000_000_000 * 1_000_000;

/// Atoms allocated to the retroactive distribution pool. FIP §15: 200,000,000.
pub const RETRO_POOL_ATOMS: u128 = 200_000_000 * 1_000_000;

/// Mutuality function applied to engagement counts before normalization.
/// Wrapped in `ln(1 + x)` after applying the inner reduction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MutualityMode {
    /// `min(a, b)` — penalises one-sided engagement aggressively.
    Min,
    /// `sqrt(a · b)` — geometric mean.
    Geom,
    /// `2ab/(a+b)` — harmonic mean.
    Harmonic,
    /// `(a + b) / 2`.
    Avg,
    /// `a + b` — favors total volume; FIP-default.
    Sum,
}

impl Default for MutualityMode {
    fn default() -> Self {
        Self::Sum
    }
}

impl MutualityMode {
    pub fn apply(self, a: f64, b: f64) -> f64 {
        let raw = match self {
            Self::Min => a.min(b),
            Self::Geom => (a * b).sqrt(),
            Self::Harmonic => {
                if a + b == 0.0 {
                    0.0
                } else {
                    2.0 * a * b / (a + b)
                }
            }
            Self::Avg => (a + b) * 0.5,
            Self::Sum => a + b,
        };
        (1.0 + raw).ln()
    }
}

/// Aggregated parameters governing one emission run.
#[derive(Debug, Clone)]
pub struct EmissionParams {
    /// Atoms emitted in this single epoch tranche.
    pub epoch_tranche_atoms: u64,
    /// EigenTrust seed cutoff. Defaults to `SEED_MAX_FID`.
    pub seed_max_fid: u64,
    /// Mutuality reduction function. Defaults to `MutualityMode::Sum`.
    pub mutuality_mode: MutualityMode,
    /// Minimum total emission a single FID can receive in atoms. Floors small
    /// allocations to avoid dust.
    pub min_per_recipient_atoms: u64,
    /// Below this trust score (after top-N average normalization), the FID is
    /// excluded from the credit graph. FIP-proof-of-quality §calibration.
    pub crediter_trust_floor: f64,
    /// Number of recent activity days an FID needs to count as live for emission.
    pub min_active_days: u32,
}

impl Default for EmissionParams {
    fn default() -> Self {
        Self {
            epoch_tranche_atoms: 0,
            seed_max_fid: SEED_MAX_FID,
            mutuality_mode: MutualityMode::Sum,
            min_per_recipient_atoms: 1, // 0.000001 HYPER floor
            crediter_trust_floor: 0.05,
            min_active_days: 7,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retro_pool_is_ten_percent_of_supply() {
        assert_eq!(RETRO_POOL_ATOMS * 10, TOTAL_SUPPLY_ATOMS);
    }

    #[test]
    fn mutuality_min_is_lower_bound() {
        for &mode in &[
            MutualityMode::Geom,
            MutualityMode::Harmonic,
            MutualityMode::Avg,
            MutualityMode::Sum,
        ] {
            let m = mode.apply(10.0, 90.0);
            let min_v = MutualityMode::Min.apply(10.0, 90.0);
            assert!(m >= min_v, "{:?} should be >= Min", mode);
        }
    }

    #[test]
    fn mutuality_zero_inputs_yield_zero() {
        for mode in [
            MutualityMode::Min,
            MutualityMode::Geom,
            MutualityMode::Harmonic,
            MutualityMode::Avg,
            MutualityMode::Sum,
        ] {
            assert!(mode.apply(0.0, 0.0).abs() < 1e-12);
        }
    }

    #[test]
    fn default_params_match_fip() {
        let p = EmissionParams::default();
        assert_eq!(p.seed_max_fid, 50_000);
        assert_eq!(p.mutuality_mode, MutualityMode::Sum);
    }

    #[test]
    fn sum_mode_dominates_for_high_volume() {
        // Two engagements (a=1000, b=10) vs (a=500, b=500). Sum gives same
        // total to both (1010 vs 1000). Min gives 10 vs 500.
        let asym = MutualityMode::Sum.apply(1000.0, 10.0);
        let sym = MutualityMode::Sum.apply(500.0, 500.0);
        let min_asym = MutualityMode::Min.apply(1000.0, 10.0);
        let min_sym = MutualityMode::Min.apply(500.0, 500.0);

        assert!((asym - sym).abs() < 0.5, "Sum is symmetric in total volume");
        assert!(min_asym < min_sym, "Min punishes asymmetry");
    }
}
