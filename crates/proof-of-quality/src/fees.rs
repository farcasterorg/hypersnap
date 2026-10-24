//! Message-fee schedule and discount formula (FIP §12), in fixed point
//! (§8.5).
//!
//! Either signal alone can waive the fee: `max()` of trust and
//! uniqueness, not a product.
//!
//! ```text
//! effective_fee = floor(base_fee · (10000 − max(trust_enc, uniqueness_enc)) / 10000)
//! ```
//!
//! The caller passes the sender's consensus trust `trust_fp` (6-decimal
//! fixed point, 0–1 000 000, as stored in the `ScoringResult`). The fee
//! formula works on the 0–10 000 scale of §12, so it converts once:
//! `trust_enc = floor(trust_fp / 100)` ([`crate::fixed::trust_enc_from_fp`]).
//! This is the only place in the crate where trust is reduced to 4
//! decimals. `uniqueness_enc = max(0, 10000 − 1250 · near_duplicates)` for
//! a `CastAdd` ([`crate::uniqueness::uniqueness_enc_from_neighbor_count`]),
//! or [`UNIQUENESS_ENC_FULL`] for every other fee class. Fees are in
//! micro-units (1 token = 1_000_000).

/// Base-fee schedule in micro-units (1.0 token = 1_000_000).
pub const BASE_FEE_CAST_ADD: u64 = 1_000_000; // 1.0
pub const BASE_FEE_LINK_ADD: u64 = 100_000; //   0.1
pub const BASE_FEE_REACTION_ADD: u64 = 100_000; // 0.1
pub const BASE_FEE_USER_DATA_ADD: u64 = 500_000; // 0.5
pub const BASE_FEE_VERIFICATION_ADD: u64 = 500_000; // 0.5

/// Encoding scale of trust and uniqueness: `10000` = 1.0.
pub const DISCOUNT_ENC_SCALE: u16 = 10_000;

/// §12: `uniqueness = 1.0` for every fee class other than `CastAdd`
/// (their merge stores already deduplicate by identity).
pub const UNIQUENESS_ENC_FULL: u16 = DISCOUNT_ENC_SCALE;

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

/// §12 effective fee in micro-units, from the sender's `trust_fp`
/// (0–1 000 000) and the cast's `uniqueness_enc` (0–10 000).
/// `trust_fp` is converted to the §12 scale with `trust_enc =
/// floor(trust_fp / 100)`; both encodings are clamped to `0..=10000`.
pub fn compute_effective_fee_micro(base_micro: u64, trust_fp: u32, uniqueness_enc: u16) -> u64 {
    if base_micro == 0 {
        return 0;
    }
    // The one explicit trust conversion of the crate (§12 scale).
    let trust_enc = crate::fixed::trust_enc_from_fp(trust_fp);
    let discount = trust_enc
        .min(DISCOUNT_ENC_SCALE)
        .max(uniqueness_enc.min(DISCOUNT_ENC_SCALE));
    let multiplier = u128::from(DISCOUNT_ENC_SCALE - discount);
    let fee = u128::from(base_micro) * multiplier / u128::from(DISCOUNT_ENC_SCALE);
    // fee ≤ base_micro, so it always fits.
    u64::try_from(fee).unwrap_or(base_micro)
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
        assert_eq!(
            compute_effective_fee_micro(BASE_FEE_CAST_ADD, 1_000_000, 0),
            0
        );
    }

    #[test]
    fn novel_content_zeroes_fee_for_new_user() {
        assert_eq!(compute_effective_fee_micro(BASE_FEE_CAST_ADD, 0, 10_000), 0);
    }

    #[test]
    fn low_trust_duplicate_pays_full_base() {
        assert_eq!(
            compute_effective_fee_micro(BASE_FEE_CAST_ADD, 0, 0),
            BASE_FEE_CAST_ADD
        );
    }

    #[test]
    fn larger_signal_wins_exactly() {
        // trust 0.5 vs uniqueness 0.8 → uniqueness wins → exactly 20%.
        assert_eq!(
            compute_effective_fee_micro(BASE_FEE_CAST_ADD, 500_000, 8_000),
            200_000
        );
        // trust 0.0001 (trust_fp 100 → trust_enc 1) → floor(1e6 · 9999 / 1e4).
        assert_eq!(
            compute_effective_fee_micro(BASE_FEE_CAST_ADD, 100, 0),
            999_900
        );
        // The /100 conversion floors: trust_fp 199 → trust_enc 1; 99 → 0.
        assert_eq!(
            compute_effective_fee_micro(BASE_FEE_CAST_ADD, 199, 0),
            999_900
        );
        assert_eq!(
            compute_effective_fee_micro(BASE_FEE_CAST_ADD, 99, 0),
            BASE_FEE_CAST_ADD
        );
        // Floors: 100_000 · 3 / 10_000 = 30; 7 · 9_999 / 10_000 = 6.
        assert_eq!(
            compute_effective_fee_micro(BASE_FEE_LINK_ADD, 999_700, 0),
            30
        );
        assert_eq!(compute_effective_fee_micro(7, 100, 0), 6);
    }

    #[test]
    fn non_cast_classes_are_free() {
        for class in [
            FeeClass::LinkAdd,
            FeeClass::ReactionAdd,
            FeeClass::UserDataAdd,
            FeeClass::VerificationAdd,
        ] {
            assert_eq!(
                compute_effective_fee_micro(class.base_fee_micro(), 0, UNIQUENESS_ENC_FULL),
                0
            );
        }
    }

    #[test]
    fn out_of_range_encodings_clamp() {
        assert_eq!(
            compute_effective_fee_micro(BASE_FEE_CAST_ADD, u32::MAX, 0),
            0
        );
        assert_eq!(
            compute_effective_fee_micro(BASE_FEE_CAST_ADD, 0, u16::MAX),
            0
        );
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
