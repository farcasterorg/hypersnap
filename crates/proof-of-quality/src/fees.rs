//! Message-fee schedule and discount formula (FIP §4, adapted).
//!
//! Per the calibration accepted in implementation review (see
//! FIP-proof-of-work-tokenization §12 deviations), the discount combines
//! trust and uniqueness via `max()` rather than the originally proposed
//! multiplicative form. This makes either signal *alone* sufficient to
//! waive the fee — so high-trust users repeating common replies pay
//! nothing, and new users posting novel content pay nothing.
//!
//! ```text
//!   effective_fee = base_fee × max(0, 1 − max(trust, uniqueness))
//! ```
//!
//! Fees are denominated in **micro-units** (1 token = 1_000_000 micro-units)
//! so the schedule fits in `u64` and integer arithmetic stays exact at the
//! deduction site.

/// Base-fee schedule in micro-units (1.0 token = 1_000_000).
pub const BASE_FEE_CAST_ADD: u64 = 1_000_000; // 1.0
pub const BASE_FEE_LINK_ADD: u64 = 100_000; //   0.1
pub const BASE_FEE_REACTION_ADD: u64 = 100_000; // 0.1
pub const BASE_FEE_USER_DATA_ADD: u64 = 500_000; // 0.5
pub const BASE_FEE_VERIFICATION_ADD: u64 = 500_000; // 0.5

/// Caps on each discount component. Both at 1.0 so a single fully-saturated
/// signal can waive the fee entirely.
pub const MAX_TRUST_DISCOUNT: f64 = 1.0;
pub const MAX_UNIQUENESS_DISCOUNT: f64 = 1.0;

/// Message classes that incur a base fee. Removes and protocol housekeeping
/// messages incur no fee.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FeeClass {
    CastAdd,
    LinkAdd,
    ReactionAdd,
    UserDataAdd,
    VerificationAdd,
    /// Anything else (removes, protocol messages) — no fee.
    NoFee,
}

impl FeeClass {
    pub fn base_fee_micro(self) -> u64 {
        match self {
            FeeClass::CastAdd => BASE_FEE_CAST_ADD,
            FeeClass::LinkAdd => BASE_FEE_LINK_ADD,
            FeeClass::ReactionAdd => BASE_FEE_REACTION_ADD,
            FeeClass::UserDataAdd => BASE_FEE_USER_DATA_ADD,
            FeeClass::VerificationAdd => BASE_FEE_VERIFICATION_ADD,
            FeeClass::NoFee => 0,
        }
    }
}

/// `trust` and `uniqueness` are each clamped to `[0, 1]` before use.
/// Returns the fee in micro-units.
pub fn compute_effective_fee_micro(base_micro: u64, trust: f64, uniqueness: f64) -> u64 {
    if base_micro == 0 {
        return 0;
    }
    let trust = trust.clamp(0.0, 1.0);
    let uniqueness = uniqueness.clamp(0.0, 1.0);
    let trust_discount = MAX_TRUST_DISCOUNT * trust;
    let uniqueness_discount = MAX_UNIQUENESS_DISCOUNT * uniqueness;
    let larger_discount = trust_discount.max(uniqueness_discount);
    let multiplier = (1.0 - larger_discount).max(0.0);
    // Deterministic integer rounding: floor — under-charging on the last
    // micro is preferable to over-charging across validators with float drift.
    (base_micro as f64 * multiplier).floor() as u64
}

/// Burn/proposer split in basis points. 60% burn / 40% proposer per
/// FIP-proof-of-work-tokenization §12.
pub const BURN_BPS: u64 = 6_000;
pub const PROPOSER_BPS: u64 = 4_000;
pub const TOTAL_BPS: u64 = 10_000;

/// Split a collected fee total into (burn, proposer) micro-units.
/// Burn gets the floor, proposer receives the remainder so rounding never
/// loses a micro-unit.
pub fn split_burn_proposer(total_micro: u64) -> (u64, u64) {
    let burn = total_micro.saturating_mul(BURN_BPS) / TOTAL_BPS;
    let proposer = total_micro - burn;
    (burn, proposer)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn high_trust_zeroes_fee_even_when_duplicate() {
        let fee = compute_effective_fee_micro(BASE_FEE_CAST_ADD, 1.0, 0.0);
        assert_eq!(fee, 0);
    }

    #[test]
    fn novel_content_zeroes_fee_for_new_user() {
        let fee = compute_effective_fee_micro(BASE_FEE_CAST_ADD, 0.0, 1.0);
        assert_eq!(fee, 0);
    }

    #[test]
    fn low_trust_duplicate_pays_full_base() {
        let fee = compute_effective_fee_micro(BASE_FEE_CAST_ADD, 0.0, 0.0);
        assert_eq!(fee, BASE_FEE_CAST_ADD);
    }

    #[test]
    fn larger_signal_wins() {
        // trust 0.5 vs uniqueness 0.8 → uniqueness wins, 20% of base
        let fee = compute_effective_fee_micro(BASE_FEE_CAST_ADD, 0.5, 0.8);
        let expected = (BASE_FEE_CAST_ADD as f64 * 0.2).floor() as u64;
        assert_eq!(fee, expected);
    }

    #[test]
    fn split_sums_to_total() {
        for total in [0u64, 1, 7, 100, BASE_FEE_CAST_ADD, u64::MAX / 2] {
            let (burn, proposer) = split_burn_proposer(total);
            assert_eq!(burn + proposer, total);
        }
    }

    #[test]
    fn split_ratio_is_60_40() {
        let (burn, proposer) = split_burn_proposer(1_000_000);
        assert_eq!(burn, 600_000);
        assert_eq!(proposer, 400_000);
    }
}
