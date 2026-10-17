//! FIP-proof-of-work-tokenization §5.4 DA-PoW per-epoch budget
//! allocation, in fixed point (§8.5).
//!
//! ```text
//! da_score(v, e) = min(1, answered / DA_CHALLENGES_PER_EPOCH)
//!                × latency_factor
//! latency_factor = clamp(1 − avg_offset / CHALLENGE_RESPONSE_WINDOW, 0, 1)
//! score_int(v)   = floor(da_score · 10^12)
//! reward(v)      = floor(DA_EMISSION_POOL · score_int(v) / Σ score_int)
//! ```
//!
//! `avg_offset` is the average of `response_height − boundary_height`
//! over the answered challenges, `boundary_height = PIVOT_HEIGHT_0 +
//! (e − 1) · EPOCH_LENGTH` (§4.3). The challenge responses are the
//! uptime measure. Every factor is 6-decimal fixed point; the two factors
//! multiply; `score_int = da_score_fp · 10^6`.

use crate::fixed::{fp_div, fp_mul, fp_ratio_capped, FP_SCALE};
use crate::scoring::allocate_proportional;
use crate::{RewardEntry, ScoringParams};
use std::collections::BTreeMap;

/// FIP §5.1 / §15 `CHALLENGE_RESPONSE_WINDOW` in blocks. Equal to
/// `Shard0Params::challenge_response_window` of the node.
pub const CHALLENGE_RESPONSE_WINDOW_BLOCKS: u64 = 25;

/// `score_int = da_score_fp · DA_SCORE_INT_FACTOR` (= floor(da_score ·
/// 10^12) for a 6-dp `da_score`).
pub const DA_SCORE_INT_FACTOR: u128 = 1_000_000;

/// §5.4 `da_score` of one validator in 6-dp fixed point.
///
/// - `answered`: valid responses; `block_sum`: Σ response heights over
///   those responses.
/// - `avg_offset = floor((block_sum − answered · boundary_height) ·
///   10^6 / answered)` (0 if the sum is below the boundary).
pub fn da_score_fp(
    answered: u32,
    block_sum: u128,
    boundary_height: u64,
    challenges_per_epoch: u32,
) -> u128 {
    if answered == 0 || challenges_per_epoch == 0 {
        return 0;
    }
    let answered_ratio = fp_ratio_capped(u128::from(answered), u128::from(challenges_per_epoch));
    let n = u128::from(answered);
    let offset_sum = block_sum.saturating_sub(n.saturating_mul(u128::from(boundary_height)));
    let avg_offset_fp = fp_div(offset_sum, n);
    let window_fp = u128::from(CHALLENGE_RESPONSE_WINDOW_BLOCKS) * FP_SCALE;
    let latency = FP_SCALE - fp_div(avg_offset_fp, window_fp).min(FP_SCALE);
    fp_mul(answered_ratio, latency)
}

/// Allocate the DA budget across validators. Returns one entry per
/// `fid` with a positive `score_int`, sorted by `fid`. The rounding
/// remainder goes to the highest `score_int` (tie: smaller FID), so the
/// total equals `budget` whenever any validator scored.
///
/// `boundary_height` is the §4.3 epoch boundary height
/// ([`crate::epoch_boundary_height`]).
pub fn compute_da_pow_rewards(
    answered: &BTreeMap<u64, u32>,
    block_sum: &BTreeMap<u64, u128>,
    boundary_height: u64,
    params: &ScoringParams,
    budget: u128,
) -> Vec<RewardEntry> {
    if budget == 0 || params.da_pow_challenges_per_epoch == 0 {
        return Vec::new();
    }
    let mut scores: BTreeMap<u64, u128> = BTreeMap::new();
    for (&fid, &count) in answered.iter() {
        let score = da_score_fp(
            count,
            block_sum.get(&fid).copied().unwrap_or(0),
            boundary_height,
            params.da_pow_challenges_per_epoch,
        );
        if score > 0 {
            scores.insert(fid, score * DA_SCORE_INT_FACTOR);
        }
    }
    allocate_proportional(&scores, budget)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_answers_yields_no_entries() {
        let answered = BTreeMap::new();
        let p = ScoringParams::default();
        assert!(compute_da_pow_rewards(&answered, &BTreeMap::new(), 0, &p, 1_000).is_empty());
    }

    #[test]
    fn zero_budget_yields_no_entries() {
        let mut answered = BTreeMap::new();
        answered.insert(42, 50);
        let p = ScoringParams::default();
        assert!(compute_da_pow_rewards(&answered, &BTreeMap::new(), 0, &p, 0).is_empty());
    }

    #[test]
    fn single_validator_takes_full_budget() {
        let mut answered = BTreeMap::new();
        answered.insert(42, 100);
        let p = ScoringParams::default();
        let out = compute_da_pow_rewards(&answered, &BTreeMap::new(), 0, &p, 1_000);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].fid, 42);
        assert_eq!(out[0].amount, 1_000);
    }

    /// Two validators with equal answered counts split the budget
    /// in half.
    #[test]
    fn two_validators_split_evenly_when_equal() {
        let mut answered = BTreeMap::new();
        answered.insert(42, 50);
        answered.insert(99, 50);
        let p = ScoringParams::default();
        let out = compute_da_pow_rewards(&answered, &BTreeMap::new(), 0, &p, 1_000);
        assert_eq!(out.len(), 2);
        let amt_42 = out.iter().find(|e| e.fid == 42).unwrap().amount;
        let amt_99 = out.iter().find(|e| e.fid == 99).unwrap().amount;
        assert_eq!(amt_42, 500);
        assert_eq!(amt_99, 500);
    }

    /// Proportional split: 80% answered vs 20% answered yields
    /// 800:200 of budget.
    #[test]
    fn validators_split_proportionally_to_answered() {
        let mut answered = BTreeMap::new();
        answered.insert(42, 80);
        answered.insert(99, 20);
        let p = ScoringParams::default();
        let out = compute_da_pow_rewards(&answered, &BTreeMap::new(), 0, &p, 1_000);
        let amt_42 = out.iter().find(|e| e.fid == 42).unwrap().amount;
        let amt_99 = out.iter().find(|e| e.fid == 99).unwrap().amount;
        assert_eq!(amt_42, 800);
        assert_eq!(amt_99, 200);
    }

    /// Validators that answer 0 challenges are dropped entirely.
    #[test]
    fn zero_answered_validators_dropped() {
        let mut answered = BTreeMap::new();
        answered.insert(42, 0);
        answered.insert(99, 100);
        let p = ScoringParams::default();
        let out = compute_da_pow_rewards(&answered, &BTreeMap::new(), 0, &p, 1_000);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].fid, 99);
        assert_eq!(out[0].amount, 1_000);
    }

    /// Rounding remainder is handed to the highest-score
    /// validator so the total equals budget exactly.
    #[test]
    fn rounding_remainder_goes_to_top_score() {
        let mut answered = BTreeMap::new();
        // 3 validators, equal scores → 1000/3 = 333 each, 1
        // remainder atom goes to the smallest-fid winner.
        answered.insert(7, 30);
        answered.insert(8, 30);
        answered.insert(9, 30);
        let p = ScoringParams::default();
        let out = compute_da_pow_rewards(&answered, &BTreeMap::new(), 0, &p, 1_000);
        let total: u128 = out.iter().map(|e| e.amount).sum();
        assert_eq!(total, 1_000);
        // FID 7 wins the tiebreak.
        let amt_7 = out.iter().find(|e| e.fid == 7).unwrap().amount;
        assert_eq!(amt_7, 334);
    }

    /// FIP §5b: a validator that responds at the boundary gets
    /// full latency credit (factor ≈ 1); a validator that responds
    /// at the deadline gets ~0. With equal answered counts, the
    /// fast validator earns more.
    #[test]
    fn latency_factor_favors_early_responders() {
        let mut answered = BTreeMap::new();
        // Both answer all 100 challenges.
        answered.insert(7, 100);
        answered.insert(8, 100);
        let mut block_sum = BTreeMap::new();
        // FID 7 averages block 1000 (immediately at boundary).
        // FID 8 averages block 1024 (right before deadline of 1025).
        let epoch_start = 1000u64;
        block_sum.insert(7, (epoch_start as u128) * 100);
        block_sum.insert(8, (epoch_start as u128 + 24) * 100);
        let p = ScoringParams::default();
        let out = compute_da_pow_rewards(&answered, &block_sum, epoch_start, &p, 1_000_000);
        let amt_7 = out.iter().find(|e| e.fid == 7).unwrap().amount;
        let amt_8 = out.iter().find(|e| e.fid == 8).unwrap().amount;
        // Latency factor: 7 → 1.0 (relative=0). 8 → 1 - 24/25 = 0.04.
        // Ratio 1.0 / 0.04 = 25× preference for 7.
        assert!(
            amt_7 > amt_8 * 20,
            "fast responder should outearn slow by 20x+: 7={amt_7}, 8={amt_8}"
        );
        // Total = budget (no clipping).
        let total: u128 = out.iter().map(|e| e.amount).sum();
        assert_eq!(total, 1_000_000);
    }

    /// FIP §5b: response at or past the deadline yields zero
    /// latency factor → validator earns nothing.
    #[test]
    fn latency_factor_zero_at_deadline() {
        let mut answered = BTreeMap::new();
        answered.insert(7, 100);
        answered.insert(8, 100);
        let mut block_sum = BTreeMap::new();
        let epoch_start = 1000u64;
        block_sum.insert(7, (epoch_start as u128) * 100);
        block_sum.insert(
            8,
            (epoch_start as u128 + CHALLENGE_RESPONSE_WINDOW_BLOCKS as u128) * 100,
        );
        let p = ScoringParams::default();
        let out = compute_da_pow_rewards(&answered, &block_sum, epoch_start, &p, 1_000_000);
        // FID 8's avg_relative = 25 = window → latency_factor = 0
        // → score = 0 → dropped from entries.
        assert!(out.iter().find(|e| e.fid == 8).is_none());
        let amt_7 = out.iter().find(|e| e.fid == 7).unwrap().amount;
        assert_eq!(amt_7, 1_000_000);
    }

    #[test]
    fn over_answer_is_clamped_to_per_validator() {
        // Should never happen in practice (each validator gets
        // exactly 100 challenges) but defend against off-by-one
        // counter bugs.
        let mut answered = BTreeMap::new();
        answered.insert(42, 200);
        answered.insert(99, 100);
        let p = ScoringParams::default();
        let out = compute_da_pow_rewards(&answered, &BTreeMap::new(), 0, &p, 2_000);
        let amt_42 = out.iter().find(|e| e.fid == 42).unwrap().amount;
        let amt_99 = out.iter().find(|e| e.fid == 99).unwrap().amount;
        // Both clamped to 100 → equal split.
        assert_eq!(amt_42, 1_000);
        assert_eq!(amt_99, 1_000);
    }
}
