//! Forward emission per FIP-proof-of-work-tokenization §6 / §10.5.
//!
//! At each epoch boundary, emission allocates a tranche of HYPER to qualified
//! accounts based on their PoQ trust score and post-transfer mutual engagement.
//! The algorithm mirrors `src/bin/retro_rewards_finalize.rs` (the offline
//! retro-distribution computation) so that forward emission and retro pool
//! produce comparable distributions over comparable inputs.
//!
//! Token amounts use fixed-point u64 with 6 decimal places: `1 HYPER ==
//! 1_000_000 atoms`. With u64 we can represent up to ~18,446 trillion HYPER
//! atoms, more than 9000× the FIP-specified 2B total supply.

pub mod compute;
pub mod eigentrust;
pub mod mutuality;
pub mod params;
pub mod schedule;

pub use compute::{compute_epoch_emissions, EmissionComputeInputs};
pub use params::{EmissionParams, MutualityMode, EMISSION_DECIMALS};
pub use schedule::{emission_per_epoch, market_budget};

#[derive(Debug, Clone)]
pub struct EpochEmission {
    pub epoch: u64,
    /// (fid, atoms) — recipients and the atomic amount each receives.
    pub allocations: Vec<(u64, u64)>,
    /// Total atoms allocated this epoch. Must equal sum(allocations).second.
    pub total_atoms: u64,
}

impl EpochEmission {
    pub fn empty(epoch: u64) -> Self {
        Self {
            epoch,
            allocations: Vec::new(),
            total_atoms: 0,
        }
    }
}

/// Convert a HYPER amount expressed as a decimal string to atoms. Fails if the
/// number has more than 6 decimal places or is negative.
pub fn parse_hyper_to_atoms(s: &str) -> Result<u64, EmissionError> {
    let s = s.trim();
    if s.is_empty() {
        return Err(EmissionError::ParseAmount("empty"));
    }
    let (whole, frac) = match s.split_once('.') {
        Some((w, f)) => (w, f),
        None => (s, ""),
    };
    if frac.len() > 6 {
        return Err(EmissionError::ParseAmount("too many decimal places"));
    }
    let whole_atoms: u64 = whole
        .parse()
        .map_err(|_| EmissionError::ParseAmount("invalid whole part"))?;
    let mut frac_padded = frac.to_string();
    while frac_padded.len() < 6 {
        frac_padded.push('0');
    }
    let frac_atoms: u64 = if frac_padded.is_empty() {
        0
    } else {
        frac_padded
            .parse()
            .map_err(|_| EmissionError::ParseAmount("invalid fractional part"))?
    };
    let whole_to_atoms = whole_atoms
        .checked_mul(1_000_000)
        .ok_or(EmissionError::ParseAmount("overflow"))?;
    whole_to_atoms
        .checked_add(frac_atoms)
        .ok_or(EmissionError::ParseAmount("overflow"))
}

/// Render atoms as a decimal HYPER string with up to 6 fractional digits.
pub fn format_atoms_as_hyper(atoms: u64) -> String {
    let whole = atoms / 1_000_000;
    let frac = atoms % 1_000_000;
    if frac == 0 {
        format!("{}", whole)
    } else {
        let frac_str = format!("{:06}", frac);
        let trimmed = frac_str.trim_end_matches('0');
        format!("{}.{}", whole, trimmed)
    }
}

#[derive(thiserror::Error, Debug, PartialEq)]
pub enum EmissionError {
    #[error("invalid amount: {0}")]
    ParseAmount(&'static str),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_whole_hyper() {
        assert_eq!(parse_hyper_to_atoms("1").unwrap(), 1_000_000);
        assert_eq!(parse_hyper_to_atoms("100").unwrap(), 100_000_000);
        assert_eq!(parse_hyper_to_atoms("0").unwrap(), 0);
    }

    #[test]
    fn parse_with_decimals() {
        assert_eq!(parse_hyper_to_atoms("0.5").unwrap(), 500_000);
        assert_eq!(parse_hyper_to_atoms("0.000001").unwrap(), 1);
        assert_eq!(parse_hyper_to_atoms("1.5").unwrap(), 1_500_000);
        assert_eq!(parse_hyper_to_atoms("123.456789").unwrap(), 123_456_789);
    }

    #[test]
    fn parse_rejects_too_precise() {
        assert!(matches!(
            parse_hyper_to_atoms("1.0000001"),
            Err(EmissionError::ParseAmount(_))
        ));
    }

    #[test]
    fn format_round_trips() {
        for atoms in [
            0u64,
            1,
            999_999,
            1_000_000,
            1_500_000,
            123_456_789,
            u64::MAX,
        ] {
            let s = format_atoms_as_hyper(atoms);
            if atoms <= 18_446_744_073_709 {
                let parsed = parse_hyper_to_atoms(&s).unwrap();
                assert_eq!(parsed, atoms, "round-trip failed for {}", atoms);
            }
        }
    }

    #[test]
    fn format_compactly() {
        assert_eq!(format_atoms_as_hyper(1_000_000), "1");
        assert_eq!(format_atoms_as_hyper(1_500_000), "1.5");
        assert_eq!(format_atoms_as_hyper(0), "0");
        assert_eq!(format_atoms_as_hyper(1), "0.000001");
    }
}
