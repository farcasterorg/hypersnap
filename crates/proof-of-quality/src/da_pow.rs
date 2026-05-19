//! FIP-proof-of-work-tokenization §5 DA-PoW per-epoch budget
//! allocation.
//!
//! Phase 5a: consumes the per-(fid) answered count for the epoch
//! and allocates the DataAvailability budget proportional to
//! `score = answered_count / challenges_per_epoch`.
//!
//! Phase 5b: adds the FIP §5.4 latency factor
//! `latency_factor = max(0, 1 - avg_response_blocks_relative_to_boundary / window)`
//! so a validator that responds early gets more credit than one
//! that pads against the deadline.
//!
//! Phase 5c (future) will add the uptime factor via the validator
//! score tracker's commit-signature count.

use crate::{RewardEntry, ScoringParams};
use std::collections::BTreeMap;

/// FIP §5 — response window in blocks. Mirrors
/// `hypersnap::hyper::da_pow::CHALLENGE_RESPONSE_WINDOW_BLOCKS`.
/// Duplicated here so the in-protocol scoring crate doesn't
/// reach back into the hypersnap binary crate.
pub const CHALLENGE_RESPONSE_WINDOW_BLOCKS: u64 = 25;

/// Allocate the DA budget across validators. Returns one entry
/// per `fid` whose per-validator score (= `min(1, answered/N) *
/// latency_factor * uptime_factor`) is positive. Entries are
/// sorted by `fid` ascending so the canonical encoding is
/// deterministic.
///
/// Rounding remainder is awarded to the highest-score `fid` (tie
/// broken by smaller `fid`) so totals match `budget` exactly when
/// at least one validator scored above zero.
///
/// `epoch_start_block` is needed to compute the per-validator
/// average response-block height *relative to the boundary* for
/// `latency_factor`.
/// `epoch_length_blocks` is the denominator of `uptime_factor` —
/// callers pass the protocol's `EPOCH_LENGTH` so each validator's
/// commit-signature count is normalized to `[0, 1]`. Passing 0
/// disables the uptime factor (treat as 1.0); useful for tests
/// and migrations before commit-signature tracking is wired.
pub fn compute_da_pow_rewards(
    answered: &BTreeMap<u64, u32>,
    block_sum: &BTreeMap<u64, u128>,
    commit_signatures: &BTreeMap<u64, u64>,
    epoch_start_block: u64,
    epoch_length_blocks: u64,
    params: &ScoringParams,
    budget: u128,
) -> Vec<RewardEntry> {
    if budget == 0 {
        return Vec::new();
    }
    if params.da_pow_challenges_per_epoch == 0 {
        return Vec::new();
    }
    let per_validator = params.da_pow_challenges_per_epoch as u64;
    let window_f = CHALLENGE_RESPONSE_WINDOW_BLOCKS as f64;

    // Per-validator score = (answered/N) × latency_factor.
    // Latency factor: 1 - avg_relative_response/window, clamped to
    // [0, 1]. We work in floats and convert to fixed-point u128 at
    // the end for proportional allocation.
    //
    // Quantize the final score to a u128 by multiplying by a large
    // SCALE so the proportional split avoids floating-point
    // determinism issues during the integer-floor division.
    const SCALE: u128 = 1_000_000_000_000;
    let mut scores: BTreeMap<u64, u128> = BTreeMap::new();
    let mut total: u128 = 0;
    for (&fid, &count) in answered.iter() {
        if count == 0 {
            continue;
        }
        let bounded = (count as u64).min(per_validator);
        let answered_ratio = bounded as f64 / per_validator as f64;
        let sum = block_sum.get(&fid).copied().unwrap_or(0);
        // avg_relative = (sum / count) - epoch_start_block. Guard
        // against `sum / count` being lower than `epoch_start_block`
        // (shouldn't happen — responses can only be created at
        // blocks at-or-after the epoch boundary — but stay
        // saturating just in case).
        let avg_block = (sum as f64) / (bounded as f64);
        let avg_relative = (avg_block - epoch_start_block as f64).max(0.0);
        let latency_factor = (1.0 - avg_relative / window_f).clamp(0.0, 1.0);
        // §5c uptime factor: validator participation as measured
        // by commit signatures. Disabled when epoch_length_blocks
        // is 0 (factor = 1.0).
        let uptime_factor = if epoch_length_blocks == 0 {
            1.0
        } else {
            let sigs = commit_signatures.get(&fid).copied().unwrap_or(0) as f64;
            (sigs / epoch_length_blocks as f64).clamp(0.0, 1.0)
        };
        let score_f = answered_ratio * latency_factor * uptime_factor;
        if score_f <= 0.0 {
            continue;
        }
        let score = (score_f * SCALE as f64) as u128;
        if score == 0 {
            continue;
        }
        scores.insert(fid, score);
        total = total.saturating_add(score);
    }
    if total == 0 {
        return Vec::new();
    }

    let mut entries: Vec<RewardEntry> = Vec::with_capacity(scores.len());
    let mut allocated: u128 = 0;
    let mut top: Option<(u64, u128)> = None;
    for (&fid, &score) in scores.iter() {
        let raw = budget.saturating_mul(score) / total;
        if raw > 0 {
            entries.push(RewardEntry { fid, amount: raw });
            allocated = allocated.saturating_add(raw);
        }
        match top {
            None => top = Some((fid, score)),
            Some((_, best)) if score > best => top = Some((fid, score)),
            Some((best_fid, best)) if score == best && fid < best_fid => {
                top = Some((fid, score));
            }
            _ => {}
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_answers_yields_no_entries() {
        let answered = BTreeMap::new();
        let p = ScoringParams::default();
        assert!(compute_da_pow_rewards(
            &answered,
            &BTreeMap::new(),
            &BTreeMap::new(),
            0,
            0,
            &p,
            1_000
        )
        .is_empty());
    }

    #[test]
    fn zero_budget_yields_no_entries() {
        let mut answered = BTreeMap::new();
        answered.insert(42, 50);
        let p = ScoringParams::default();
        assert!(
            compute_da_pow_rewards(&answered, &BTreeMap::new(), &BTreeMap::new(), 0, 0, &p, 0)
                .is_empty()
        );
    }

    #[test]
    fn single_validator_takes_full_budget() {
        let mut answered = BTreeMap::new();
        answered.insert(42, 100);
        let p = ScoringParams::default();
        let out = compute_da_pow_rewards(
            &answered,
            &BTreeMap::new(),
            &BTreeMap::new(),
            0,
            0,
            &p,
            1_000,
        );
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
        let out = compute_da_pow_rewards(
            &answered,
            &BTreeMap::new(),
            &BTreeMap::new(),
            0,
            0,
            &p,
            1_000,
        );
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
        let out = compute_da_pow_rewards(
            &answered,
            &BTreeMap::new(),
            &BTreeMap::new(),
            0,
            0,
            &p,
            1_000,
        );
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
        let out = compute_da_pow_rewards(
            &answered,
            &BTreeMap::new(),
            &BTreeMap::new(),
            0,
            0,
            &p,
            1_000,
        );
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
        let out = compute_da_pow_rewards(
            &answered,
            &BTreeMap::new(),
            &BTreeMap::new(),
            0,
            0,
            &p,
            1_000,
        );
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
        let out = compute_da_pow_rewards(
            &answered,
            &block_sum,
            &BTreeMap::new(),
            epoch_start,
            0,
            &p,
            1_000_000,
        );
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
        let out = compute_da_pow_rewards(
            &answered,
            &block_sum,
            &BTreeMap::new(),
            epoch_start,
            0,
            &p,
            1_000_000,
        );
        // FID 8's avg_relative = 25 = window → latency_factor = 0
        // → score = 0 → dropped from entries.
        assert!(out.iter().find(|e| e.fid == 8).is_none());
        let amt_7 = out.iter().find(|e| e.fid == 7).unwrap().amount;
        assert_eq!(amt_7, 1_000_000);
    }

    /// FIP §5c: with equal answered counts + equal latency, a
    /// 100%-online validator outearns a 50%-online one by 2x.
    #[test]
    fn uptime_factor_scales_payouts() {
        let mut answered = BTreeMap::new();
        answered.insert(7, 100);
        answered.insert(8, 100);
        let mut commit_sigs = BTreeMap::new();
        commit_sigs.insert(7, 1_000);
        commit_sigs.insert(8, 500);
        let p = ScoringParams::default();
        // epoch_length = 1000 → uptime 7 = 1.0, uptime 8 = 0.5.
        let out = compute_da_pow_rewards(
            &answered,
            &BTreeMap::new(),
            &commit_sigs,
            0,
            1_000,
            &p,
            300_000,
        );
        let amt_7 = out.iter().find(|e| e.fid == 7).unwrap().amount;
        let amt_8 = out.iter().find(|e| e.fid == 8).unwrap().amount;
        assert_eq!(amt_7, 200_000);
        assert_eq!(amt_8, 100_000);
    }

    /// FIP §5c: zero commit signatures → zero score → dropped.
    #[test]
    fn uptime_zero_disqualifies_validator() {
        let mut answered = BTreeMap::new();
        answered.insert(7, 100);
        answered.insert(8, 100);
        let mut commit_sigs = BTreeMap::new();
        commit_sigs.insert(7, 1_000);
        // 8 missing → treated as 0.
        let p = ScoringParams::default();
        let out = compute_da_pow_rewards(
            &answered,
            &BTreeMap::new(),
            &commit_sigs,
            0,
            1_000,
            &p,
            100_000,
        );
        assert!(out.iter().find(|e| e.fid == 8).is_none());
        let amt_7 = out.iter().find(|e| e.fid == 7).unwrap().amount;
        assert_eq!(amt_7, 100_000);
    }

    /// FIP §5c: `epoch_length_blocks = 0` disables the uptime
    /// factor (factor=1.0) — useful during migration before
    /// commit-signature tracking is wired.
    #[test]
    fn uptime_disabled_when_epoch_length_zero() {
        let mut answered = BTreeMap::new();
        answered.insert(7, 100);
        answered.insert(8, 100);
        let p = ScoringParams::default();
        // Pass commit_sigs = empty + epoch_length = 0 → uptime=1.
        let out = compute_da_pow_rewards(
            &answered,
            &BTreeMap::new(),
            &BTreeMap::new(),
            0,
            0,
            &p,
            2_000,
        );
        let amt_7 = out.iter().find(|e| e.fid == 7).unwrap().amount;
        let amt_8 = out.iter().find(|e| e.fid == 8).unwrap().amount;
        assert_eq!(amt_7, 1_000);
        assert_eq!(amt_8, 1_000);
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
        let out = compute_da_pow_rewards(
            &answered,
            &BTreeMap::new(),
            &BTreeMap::new(),
            0,
            0,
            &p,
            2_000,
        );
        let amt_42 = out.iter().find(|e| e.fid == 42).unwrap().amount;
        let amt_99 = out.iter().find(|e| e.fid == 99).unwrap().amount;
        // Both clamped to 100 → equal split.
        assert_eq!(amt_42, 1_000);
        assert_eq!(amt_99, 1_000);
    }
}
