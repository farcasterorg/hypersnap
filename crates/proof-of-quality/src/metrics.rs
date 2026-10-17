//! Per-FID metrics derived from the [`SnapchainStateReader`] view, in
//! fixed point (FIP §8.5).
//!
//! [`build_metrics`] reads the raw integer inputs and derives every
//! value that does not depend on trust (age factor, entropies, ratios,
//! stake factor). Two values need trust and are finished later in the
//! pipeline ([`crate::scoring::score_fids`]):
//! - `trust_fp` and `credibility_weight_fp`
//!   ([`crate::scoring::apply_trust_and_credibility`]);
//! - the trust-gated F5 new-user share ([`apply_new_user_share`]).

use crate::fixed::{
    fp_div, fp_ln_ge_one, fp_mul, fp_ratio_capped, normalized_entropy_fp, sat_u64, FP_ONE,
    FP_SCALE, TRUST_FP_MAX,
};
use crate::reader::{EngagementCount, SnapchainStateReader};
use crate::{ScoringError, AGE_MATURITY_SECONDS, CREDITER_TRUST_FLOOR_FP, STAKE_MATURITY_AMOUNT};
use std::collections::BTreeMap;

/// Per-FID inputs to the composite formula. Real values are 6-decimal
/// fixed point (`_fp`, `1.0 = 1_000_000`); trust is `trust_fp: u32`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FidMetrics {
    pub fid: u64,
    pub effective_ts: Option<u64>,
    /// §2 `age_factor = min(1, effective_age / AGE_MATURITY_SECONDS)`.
    pub age_factor_fp: u64,
    /// §8.2.3 / §8.5 trust, 6-decimal fixed point `floor(trust · 10^6)`
    /// (0–1 000 000). Set by
    /// [`crate::scoring::apply_trust_and_credibility`].
    pub trust_fp: u32,
    /// §8.4 credibility scalar. Set by
    /// [`crate::scoring::apply_trust_and_credibility`].
    pub credibility_weight_fp: u64,
    /// §8.4 credibility stake (micro-units), from the reader.
    pub credibility_stake: u64,
    /// §6.7 option (b): Σ of the vouch stakes this FID receives from
    /// FIDs of the universe (micro-units).
    pub vouch_stake_received: u64,
    /// §8.4 `stake_factor = min(1, (credibility_stake +
    /// vouch_stake_received) / STAKE_MATURITY_AMOUNT)`.
    pub stake_factor_fp: u64,

    /// Inbound count totals (likes + recasts + replies) across all
    /// engagers, post-transfer.
    pub total_engagement_count: u32,
    /// §8.3 F5: inbound new-user events from engagers with
    /// `trust_fp < CREDITER_TRUST_FLOOR_FP`. Set by
    /// [`apply_new_user_share`] (0 until then).
    pub new_user_engagement_count: u32,
    /// `new_user_engagement_count / total_engagement_count` (0 if no
    /// engagement). Used by F5, and by the composite under the v6 rule.
    pub new_user_engagement_share_fp: u64,
    /// §6.2: inbound new-user events from engagers with `trust_fp ≥
    /// CREDITER_TRUST_FLOOR_FP` whose `effective_ts` is within
    /// `REAL_NEW_USER_WINDOW` of now. Set by [`apply_new_user_share`].
    pub real_new_user_engagement_count: u32,
    /// `real_new_user_engagement_count / total_engagement_count`. Used by
    /// the composite.
    pub real_new_user_share_fp: u64,

    /// Normalized Shannon entropy of the inbound engager distribution.
    pub engager_entropy_fp: u64,
    /// Normalized Shannon entropy of the outbound interaction
    /// distribution (to other FIDs).
    pub interaction_entropy_fp: u64,

    /// Inbound all-time engagement: `engager → count(engager → self)`
    /// (post-transfer, non-zero only).
    pub all_time_engagement: BTreeMap<u64, u32>,

    /// Outbound new-user events: `target → first_30d(self → target)`
    /// (non-zero only, targets in the universe, `target ≠ self`).
    /// Consumed by [`apply_new_user_share`] when this FID's trust is
    /// below the crediter floor.
    pub outbound_first_30d: BTreeMap<u64, u32>,

    /// §6.7 outgoing vouches: `vouchee → amount` (micro-units).
    pub vouches_from: BTreeMap<u64, u64>,

    /// Total post-transfer cast count.
    pub total_casts: u32,
    /// Distinct active days post-transfer.
    pub active_days: u32,
    /// Number of this FID's casts with ≥ 1 post-transfer reply (F6).
    pub replies_received: u32,
    /// §8.3 F0 input.
    pub signer_authorizations: u32,
    /// §8.3 F0 input (threat-model #295).
    pub signer_authorizations_clustered: u32,
    /// §8.3 F0 input (threat-model #296).
    pub miniapp_author_count: u32,
    /// §8.3 F2: distinct other FIDs whose engagement reaches this FID.
    pub unique_engagers: u32,
    /// §8.3 F6: `replies_received / total_casts` (0 when no casts).
    pub replies_per_cast_fp: u64,
    /// §8.3 F4: `unique_engagers / ln(1 + total_casts)` (0 when no casts).
    pub engagement_per_cast_fp: u64,
}

impl FidMetrics {
    pub fn new(fid: u64) -> Self {
        Self {
            fid,
            effective_ts: None,
            age_factor_fp: 0,
            trust_fp: 0,
            credibility_weight_fp: 0,
            credibility_stake: 0,
            vouch_stake_received: 0,
            stake_factor_fp: 0,
            total_engagement_count: 0,
            new_user_engagement_count: 0,
            new_user_engagement_share_fp: 0,
            real_new_user_engagement_count: 0,
            real_new_user_share_fp: 0,
            engager_entropy_fp: 0,
            interaction_entropy_fp: 0,
            all_time_engagement: BTreeMap::new(),
            outbound_first_30d: BTreeMap::new(),
            vouches_from: BTreeMap::new(),
            total_casts: 0,
            active_days: 0,
            replies_received: 0,
            signer_authorizations: 0,
            signer_authorizations_clustered: 0,
            miniapp_author_count: 0,
            unique_engagers: 0,
            replies_per_cast_fp: 0,
            engagement_per_cast_fp: 0,
        }
    }
}

/// §8.4 credibility weights, 6-decimal fixed point. They sum to 1.0.
pub const W_AGE_FP: u64 = 250_000;
pub const W_TRUST_FP: u64 = 350_000;
pub const W_ENTROPY_FP: u64 = 200_000;
pub const W_STAKE_FP: u64 = 100_000;
pub const W_DIVERSITY_FP: u64 = 100_000;
/// §8.4 `client_diversity`: the constant 1.0 for each FID.
pub const CLIENT_DIVERSITY_FP: u64 = FP_ONE;

/// §8.4 `stake_factor = min(1, total_stake / STAKE_MATURITY_AMOUNT)`
/// where `total_stake = credibility_stake + vouch_stake_received`
/// (micro-units). 6-decimal fixed point.
pub fn stake_factor_fp(total_stake: u64) -> u64 {
    sat_u64(fp_ratio_capped(
        u128::from(total_stake),
        u128::from(STAKE_MATURITY_AMOUNT),
    ))
}

/// §2 `age_factor = min(1, (now − effective_ts) / AGE_MATURITY_SECONDS)`.
/// `None` (no registration) → 0.
pub fn compute_age_factor_fp(effective_ts: Option<u64>, now_unix: u64) -> u64 {
    match effective_ts {
        None => 0,
        Some(ts) => sat_u64(fp_ratio_capped(
            u128::from(now_unix.saturating_sub(ts)),
            u128::from(AGE_MATURITY_SECONDS),
        )),
    }
}

/// §8.4 credibility scalar, 6-decimal fixed point:
///
/// ```text
/// 0.25·age_factor + 0.35·trust + 0.20·interaction_entropy
///     + 0.10·stake_factor + 0.10·client_diversity
/// ```
///
/// with `trust = trust_fp / 10^6`. Each term is one fixed-point
/// product; the terms are added in the order written.
pub fn compute_credibility_weight_fp(
    age_factor_fp: u64,
    trust_fp: u32,
    interaction_entropy_fp: u64,
    stake_factor_fp: u64,
) -> u64 {
    let trust_fp = trust_fp.min(TRUST_FP_MAX);
    let terms = [
        fp_mul(u128::from(W_AGE_FP), u128::from(age_factor_fp)),
        fp_mul(u128::from(W_TRUST_FP), u128::from(trust_fp)),
        fp_mul(u128::from(W_ENTROPY_FP), u128::from(interaction_entropy_fp)),
        fp_mul(u128::from(W_STAKE_FP), u128::from(stake_factor_fp)),
        fp_mul(u128::from(W_DIVERSITY_FP), u128::from(CLIENT_DIVERSITY_FP)),
    ];
    sat_u64(terms.iter().fold(0u128, |acc, &t| acc.saturating_add(t)))
}

/// Normalized Shannon entropy (§8.5) of a count distribution, over the
/// positive counts, in key (FID) order.
pub fn normalized_entropy(counts: &BTreeMap<u64, u32>) -> u64 {
    normalized_entropy_fp(counts.values().map(|&c| u128::from(c)))
}

/// Normalized Shannon entropy (§8.5) of non-negative fixed-point values
/// (e.g. the growth contributions `C(f)` of §6.1). Zero values are
/// ignored; `H = 0` with fewer than two positive values.
pub fn normalized_entropy_of_values(values: &[u128]) -> u64 {
    normalized_entropy_fp(values.iter().copied())
}

/// §8.3 F4 metric: `unique_engagers / ln(1 + total_casts)`; 0 when
/// `total_casts == 0`.
pub fn engagement_per_cast_fp(unique_engagers: u32, total_casts: u32) -> u64 {
    if total_casts == 0 {
        return 0;
    }
    let ln = fp_ln_ge_one((1 + u128::from(total_casts)) * FP_SCALE);
    if ln == 0 {
        return 0;
    }
    sat_u64(fp_div(u128::from(unique_engagers) * FP_SCALE, ln))
}

/// Build per-FID metrics from the reader state. The returned map is
/// keyed by FID (BTreeMap → ascending iteration). Trust-dependent
/// fields (`trust_fp`, `credibility_weight_fp`, the F5 new-user count
/// and share) are left at 0; see the module docs.
pub fn build_metrics<R: SnapchainStateReader + ?Sized>(
    reader: &R,
    now_unix: u64,
) -> Result<BTreeMap<u64, FidMetrics>, ScoringError> {
    let fids = reader.all_active_fids()?;
    let mut out: BTreeMap<u64, FidMetrics> = BTreeMap::new();

    // First pass: per-FID reads.
    let mut outbound: BTreeMap<u64, BTreeMap<u64, EngagementCount>> = BTreeMap::new();
    for &fid in &fids {
        let mut m = FidMetrics::new(fid);
        m.effective_ts = reader.effective_ts(fid)?;
        m.age_factor_fp = compute_age_factor_fp(m.effective_ts, now_unix);
        m.credibility_stake = reader.credibility_stake(fid)?;
        m.vouches_from = reader.vouches_from(fid)?;
        m.total_casts = reader.total_casts(fid)?;
        m.active_days = reader.active_days(fid)?;
        m.replies_received = reader.replies_received(fid)?;
        m.signer_authorizations = reader.signer_authorizations(fid)?;
        m.signer_authorizations_clustered = reader.signer_authorizations_clustered(fid)?;
        m.miniapp_author_count = reader.miniapp_author_count(fid)?;
        out.insert(fid, m);
        outbound.insert(fid, reader.engagement_from(fid)?);
    }

    // §6.7 option (b): vouch stake received, summed over the vouchers
    // of the universe in voucher-FID order.
    let mut vouch_received: BTreeMap<u64, u64> = BTreeMap::new();
    for m in out.values() {
        for (&vouchee, &amount) in &m.vouches_from {
            if vouchee == m.fid {
                continue;
            }
            let e = vouch_received.entry(vouchee).or_insert(0);
            *e = e.saturating_add(amount);
        }
    }

    // Inbound side: invert the outbound maps (sources in FID order).
    let mut inbound: BTreeMap<u64, BTreeMap<u64, u32>> = BTreeMap::new();
    for (&source, edges) in &outbound {
        for (&target, c) in edges {
            if source == target || !out.contains_key(&target) {
                continue;
            }
            let t = c.total();
            if t > 0 {
                inbound.entry(target).or_default().insert(source, t);
            }
        }
    }

    for (&fid, m) in out.iter_mut() {
        m.vouch_stake_received = vouch_received.get(&fid).copied().unwrap_or(0);
        m.stake_factor_fp =
            stake_factor_fp(m.credibility_stake.saturating_add(m.vouch_stake_received));

        let edges = outbound.get(&fid);
        // interaction_entropy: outbound counts to OTHER FIDs (§8.4).
        let outbound_dist: BTreeMap<u64, u32> = edges
            .map(|e| {
                e.iter()
                    .filter(|(&k, _)| k != fid)
                    .map(|(&k, c)| (k, c.total()))
                    .collect()
            })
            .unwrap_or_default();
        m.interaction_entropy_fp = normalized_entropy(&outbound_dist);
        m.outbound_first_30d = edges
            .map(|e| {
                e.iter()
                    .filter(|(&k, c)| k != fid && c.first_30d > 0 && fids.contains(&k))
                    .map(|(&k, c)| (k, c.first_30d))
                    .collect()
            })
            .unwrap_or_default();

        let inbound_counts = inbound.remove(&fid).unwrap_or_default();
        m.engager_entropy_fp = normalized_entropy(&inbound_counts);
        m.total_engagement_count = inbound_counts
            .values()
            .fold(0u32, |acc, &c| acc.saturating_add(c));
        m.unique_engagers = u32::try_from(inbound_counts.len()).unwrap_or(u32::MAX);
        m.replies_per_cast_fp = if m.total_casts > 0 {
            sat_u64(fp_div(
                u128::from(m.replies_received),
                u128::from(m.total_casts),
            ))
        } else {
            0
        };
        m.engagement_per_cast_fp = engagement_per_cast_fp(m.unique_engagers, m.total_casts);
        m.all_time_engagement = inbound_counts;
    }

    Ok(out)
}

/// §8.3 F5 and the §6.2 composite factor. F5: count the new-user events
/// that each FID receives from engagers `u` with `trust_fp(u) <
/// CREDITER_TRUST_FLOOR_FP`, then set `new_user_engagement_share_fp =
/// new_user_count / total_engagement_count`. Composite: count the
/// new-user events from engagers at or above the floor whose
/// `effective_ts` is at most `real_window_secs` before `now_unix` (users
/// who became real), as `real_new_user_share_fp`. Requires `trust_fp` to
/// be set ([`crate::scoring::apply_trust_and_credibility`]).
pub fn apply_new_user_share(
    metrics: &mut BTreeMap<u64, FidMetrics>,
    now_unix: u64,
    real_window_secs: u64,
) {
    let mut received: BTreeMap<u64, u32> = BTreeMap::new();
    let mut received_real: BTreeMap<u64, u32> = BTreeMap::new();
    for m in metrics.values() {
        let into = if m.trust_fp < CREDITER_TRUST_FLOOR_FP {
            &mut received
        } else if m
            .effective_ts
            .is_some_and(|t| t.saturating_add(real_window_secs) >= now_unix)
        {
            &mut received_real
        } else {
            continue;
        };
        for (&target, &c) in &m.outbound_first_30d {
            let e = into.entry(target).or_insert(0);
            *e = e.saturating_add(c);
        }
    }
    let share = |n: u32, total: u32| {
        if total > 0 {
            sat_u64(fp_div(u128::from(n), u128::from(total)))
        } else {
            0
        }
    };
    for (fid, m) in metrics.iter_mut() {
        // A new-user event is also counted in total_engagement_count,
        // so the share is ≤ 1 for consistent readers; cap defensively.
        let n = received
            .get(fid)
            .copied()
            .unwrap_or(0)
            .min(m.total_engagement_count);
        m.new_user_engagement_count = n;
        m.new_user_engagement_share_fp = share(n, m.total_engagement_count);
        let r = received_real
            .get(fid)
            .copied()
            .unwrap_or(0)
            .min(m.total_engagement_count);
        m.real_new_user_engagement_count = r;
        m.real_new_user_share_fp = share(r, m.total_engagement_count);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stake_factor_saturates_at_maturity() {
        assert_eq!(stake_factor_fp(0), 0);
        assert_eq!(stake_factor_fp(STAKE_MATURITY_AMOUNT / 2), 499_999);
        assert_eq!(stake_factor_fp(STAKE_MATURITY_AMOUNT), FP_ONE);
        assert_eq!(stake_factor_fp(STAKE_MATURITY_AMOUNT * 2), FP_ONE);
        assert_eq!(stake_factor_fp(u64::MAX), FP_ONE);
    }

    /// §8.4 bounds: everything except diversity = 0 → 0.10; everything
    /// saturated → 1.00 (weights sum to 1.0).
    #[test]
    fn credibility_weight_bounds() {
        assert_eq!(compute_credibility_weight_fp(0, 0, 0, 0), 100_000);
        assert_eq!(
            compute_credibility_weight_fp(FP_ONE, TRUST_FP_MAX, FP_ONE, FP_ONE),
            FP_ONE
        );
        assert_eq!(
            W_AGE_FP + W_TRUST_FP + W_ENTROPY_FP + W_STAKE_FP + W_DIVERSITY_FP,
            FP_ONE
        );
    }

    #[test]
    fn credibility_weight_increases_monotonically_with_stake() {
        let without = compute_credibility_weight_fp(500_000, 500_000, 500_000, 0);
        let partial = compute_credibility_weight_fp(500_000, 500_000, 500_000, 500_000);
        let full = compute_credibility_weight_fp(500_000, 500_000, 500_000, FP_ONE);
        assert!(without < partial && partial < full);
        assert_eq!(full - without, W_STAKE_FP);
    }

    #[test]
    fn age_factor_fixed_point() {
        assert_eq!(compute_age_factor_fp(None, 1_000), 0);
        assert_eq!(compute_age_factor_fp(Some(1_000), 1_000), 0);
        assert_eq!(
            compute_age_factor_fp(Some(0), AGE_MATURITY_SECONDS / 2),
            500_000
        );
        assert_eq!(
            compute_age_factor_fp(Some(0), AGE_MATURITY_SECONDS * 3),
            FP_ONE
        );
        // Future timestamps saturate to age 0.
        assert_eq!(compute_age_factor_fp(Some(2_000), 1_000), 0);
    }

    #[test]
    fn engagement_per_cast_uses_fixed_point_ln() {
        assert_eq!(engagement_per_cast_fp(10, 0), 0);
        // ln(2) = 0.693147 (6-dp) → floor(1 / 0.693147) = 1.442695
        assert_eq!(engagement_per_cast_fp(1, 1), 1_442_695);
    }

    /// Option (b): vouch stake received counts toward the vouchee's
    /// stake factor, summed over vouchers.
    #[test]
    fn vouch_stake_received_feeds_stake_factor() {
        let mut r = crate::reader::InMemoryReader::new();
        for f in [1u64, 2, 3] {
            r.add_fid(f, 0);
        }
        r.add_vouch(1, 3, STAKE_MATURITY_AMOUNT / 4);
        r.add_vouch(2, 3, STAKE_MATURITY_AMOUNT / 4);
        r.set_credibility_stake(3, STAKE_MATURITY_AMOUNT / 4);
        let m = build_metrics(&r, 0).unwrap();
        assert_eq!(m[&3].vouch_stake_received, 2 * (STAKE_MATURITY_AMOUNT / 4));
        assert_eq!(m[&3].stake_factor_fp, 749_999);
        assert_eq!(m[&1].stake_factor_fp, 0);
    }

    /// N4: only new-user events from engagers below the crediter floor
    /// count toward the F5 share.
    #[test]
    fn new_user_share_counts_only_low_trust_engagers() {
        let mut r = crate::reader::InMemoryReader::new();
        for f in [1u64, 2, 3] {
            r.add_fid(f, 0);
        }
        let c = |first_30d, later| EngagementCount { first_30d, later };
        r.add_engagement(1, 3, c(10, 10)); // engager 1 will be trusted
        r.add_engagement(2, 3, c(20, 0)); // engager 2 stays untrusted
        let mut m = build_metrics(&r, 0).unwrap();
        m.get_mut(&1).unwrap().trust_fp = CREDITER_TRUST_FLOOR_FP;
        m.get_mut(&2).unwrap().trust_fp = CREDITER_TRUST_FLOOR_FP - 1;
        apply_new_user_share(&mut m, 0, crate::REAL_NEW_USER_WINDOW_SECS);
        assert_eq!(m[&3].total_engagement_count, 40);
        assert_eq!(m[&3].new_user_engagement_count, 20);
        assert_eq!(m[&3].new_user_engagement_share_fp, 500_000);
        // Engager 1 is trusted and new: its events count for the composite.
        assert_eq!(m[&3].real_new_user_engagement_count, 10);
        assert_eq!(m[&3].real_new_user_share_fp, 250_000);
    }

    /// §6.2: a trusted engager counts for the composite only while its
    /// `effective_ts` is within `REAL_NEW_USER_WINDOW`; an untrusted one
    /// (a ring) never does.
    #[test]
    fn real_new_user_share_counts_trusted_engagers_in_the_window() {
        let window = crate::REAL_NEW_USER_WINDOW_SECS;
        let now = 10 * window;
        let mut r = crate::reader::InMemoryReader::new();
        r.add_fid(1, now - window); // trusted, at the end of the window
        r.add_fid(2, now - window - 1); // trusted, after the window
        r.add_fid(3, now); // untrusted
        r.add_fid(4, 0);
        let c = |first_30d, later| EngagementCount { first_30d, later };
        r.add_engagement(1, 4, c(10, 0));
        r.add_engagement(2, 4, c(20, 0));
        r.add_engagement(3, 4, c(30, 0));
        let mut m = build_metrics(&r, now).unwrap();
        for f in [1, 2] {
            m.get_mut(&f).unwrap().trust_fp = CREDITER_TRUST_FLOOR_FP;
        }
        apply_new_user_share(&mut m, now, window);
        assert_eq!(m[&4].total_engagement_count, 60);
        assert_eq!(m[&4].real_new_user_engagement_count, 10);
        assert_eq!(m[&4].new_user_engagement_count, 30);
    }
}
