//! FIP-proof-of-work-tokenization §8.3 eligibility classifier.
//!
//! Pure-function pipeline that derives a bit-packed [`Eligibility`]
//! flag per FID from the metrics already computed in
//! [`crate::metrics::build_metrics`]. Calibration thresholds for
//! F3/F4/F5/F6 are computed over a fixed cohort
//! `(total_casts ≥ CALIBRATION_MIN_CASTS AND active_days ≥
//! CALIBRATION_MIN_ACTIVE_DAYS)` so that data-dependent thresholds
//! are anchored to "typical active users" rather than the noise
//! floor or the seed cohort.
//!
//! All metrics and thresholds are 6-decimal fixed point (§8.5), so the
//! comparisons are exact integer comparisons.
//!
//! Determinism: every reduction walks a `BTreeMap` in ascending FID
//! order; the cohort vector is sorted before percentile lookup.

use crate::fixed::{FP_ONE, FP_SCALE};
use crate::metrics::FidMetrics;
use crate::{Eligibility, EligibilityParams, CREDITER_TRUST_FLOOR_FP};
use std::collections::BTreeMap;

/// Calibrated thresholds for the data-derived filters (6-decimal fixed
/// point). Computed once per epoch by [`compute_thresholds`] over the
/// calibration cohort.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EligibilityThresholds {
    /// F3 lower-tail threshold: pass if `engager_entropy ≥` this.
    pub engager_entropy_fp: u64,
    /// F4 lower-tail threshold (only when `enable_f4`).
    pub engagement_per_cast_fp: u64,
    /// F5 upper-tail threshold `T5`: one of the F5 pass conditions is
    /// `new_user_share < T5`.
    pub new_user_share_fp: u64,
    /// F6 lower-tail threshold: pass if `replies_per_cast ≥` this.
    pub replies_per_cast_fp: u64,
    /// Size of the calibration cohort. An empty cohort gives all-zero
    /// thresholds.
    pub cohort_size: usize,
}

/// §8.3: sort the `N` values ascending; the percentile `P` is the value
/// at index `floor(N · P)` (the last value if past the end; 0 for an
/// empty cohort). `percentile_fp` is 6-decimal fixed point.
pub fn percentile_value(mut values: Vec<u64>, percentile_fp: u64) -> u64 {
    if values.is_empty() {
        return 0;
    }
    values.sort_unstable();
    let p = u128::from(percentile_fp.min(FP_ONE));
    let idx = (values.len() as u128).saturating_mul(p) / FP_SCALE;
    let idx = usize::try_from(idx).unwrap_or(usize::MAX);
    values[idx.min(values.len() - 1)]
}

/// Membership test for the calibration cohort.
fn in_calibration_cohort(m: &FidMetrics, p: &EligibilityParams) -> bool {
    m.total_casts >= p.calibration_min_casts && m.active_days >= p.calibration_min_active_days
}

/// Compute the data-derived thresholds for F3/F4/F5/F6 from the
/// calibration cohort. F5 uses the upper tail `1 − THRESHOLD_PERCENTILE`.
/// Requires the trust-gated new-user share
/// ([`crate::metrics::apply_new_user_share`]).
pub fn compute_thresholds(
    metrics: &BTreeMap<u64, FidMetrics>,
    p: &EligibilityParams,
) -> EligibilityThresholds {
    let cohort: Vec<&FidMetrics> = metrics
        .values()
        .filter(|m| in_calibration_cohort(m, p))
        .collect();
    let pct = p.threshold_percentile_fp.min(FP_ONE);
    let upper = FP_ONE - pct;
    EligibilityThresholds {
        engager_entropy_fp: percentile_value(
            cohort.iter().map(|m| m.engager_entropy_fp).collect(),
            pct,
        ),
        engagement_per_cast_fp: percentile_value(
            cohort.iter().map(|m| m.engagement_per_cast_fp).collect(),
            pct,
        ),
        new_user_share_fp: percentile_value(
            cohort
                .iter()
                .map(|m| m.new_user_engagement_share_fp)
                .collect(),
            upper,
        ),
        replies_per_cast_fp: percentile_value(
            cohort.iter().map(|m| m.replies_per_cast_fp).collect(),
            pct,
        ),
        cohort_size: cohort.len(),
    }
}

/// §8.3 F5: passes if one or more of
/// - `new_user_share < T5`,
/// - `new_user_share < NEW_USER_SHARE_ABSOLUTE_FLOOR`,
/// - `trust_fp ≥ CREDITER_TRUST_FLOOR_FP` (trust ≥ 0.0001).
pub fn f5_passes(m: &FidMetrics, p: &EligibilityParams, t: &EligibilityThresholds) -> bool {
    m.new_user_engagement_share_fp < t.new_user_share_fp
        || m.new_user_engagement_share_fp < p.new_user_share_absolute_floor_fp
        || m.trust_fp >= CREDITER_TRUST_FLOOR_FP
}

/// Apply the seven filters to a single FID. F4 auto-passes when
/// `enable_f4` is false so the all-bits-set mask still holds.
pub fn classify_one(
    m: &FidMetrics,
    p: &EligibilityParams,
    t: &EligibilityThresholds,
) -> Eligibility {
    let mut flags = Eligibility::default();
    // F0 (app detection): trips if ANY of the app signals reaches the
    // threshold (signer authorizations, clustered over shared custody
    // — #295 — and authored miniapps — #296).
    let max_app_signal = m
        .signer_authorizations
        .max(m.signer_authorizations_clustered)
        .max(m.miniapp_author_count);
    flags.set(0, max_app_signal < p.app_threshold);
    flags.set(1, m.total_casts > 0);
    flags.set(2, m.unique_engagers >= p.min_engagers);
    flags.set(3, m.engager_entropy_fp >= t.engager_entropy_fp);
    flags.set(
        4,
        if p.enable_f4 {
            m.engagement_per_cast_fp >= t.engagement_per_cast_fp
        } else {
            true
        },
    );
    flags.set(5, f5_passes(m, p, t));
    flags.set(6, m.replies_per_cast_fp >= t.replies_per_cast_fp);
    flags
}

/// Compute eligibility for every FID in `metrics`. Requires `trust_fp`
/// and the trust-gated new-user share. Returns the per-FID flags and
/// the thresholds used.
pub fn compute_eligibility(
    metrics: &BTreeMap<u64, FidMetrics>,
    p: &EligibilityParams,
) -> (BTreeMap<u64, Eligibility>, EligibilityThresholds) {
    let thresholds = compute_thresholds(metrics, p);
    let mut out = BTreeMap::new();
    for (&fid, m) in metrics.iter() {
        out.insert(fid, classify_one(m, p, &thresholds));
    }
    (out, thresholds)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::EligibilityParams;

    fn base_metrics(fid: u64) -> FidMetrics {
        let mut m = FidMetrics::new(fid);
        // Defaults that pass F1, F2, F3, F4(disabled), F5, F6 with
        // empty-cohort thresholds (all zero).
        m.total_casts = 50;
        m.active_days = 10;
        m.unique_engagers = 5;
        m.engager_entropy_fp = 500_000;
        m.new_user_engagement_share_fp = 50_000;
        m.replies_received = 25;
        m.replies_per_cast_fp = 500_000;
        m.engagement_per_cast_fp = 1_200_000;
        m
    }

    #[test]
    fn empty_cohort_thresholds_default_to_zero() {
        let metrics: BTreeMap<u64, FidMetrics> = BTreeMap::new();
        let p = EligibilityParams::default();
        let t = compute_thresholds(&metrics, &p);
        assert_eq!(t, EligibilityThresholds::default());
    }

    #[test]
    fn percentile_index_is_floor_n_p() {
        let v: Vec<u64> = (1..=9).collect();
        assert_eq!(percentile_value(v.clone(), 100_000), 1); // floor(0.9) = 0
        assert_eq!(percentile_value(v.clone(), 900_000), 9); // floor(8.1) = 8
        assert_eq!(percentile_value(v.clone(), FP_ONE), 9); // past the end
        let v: Vec<u64> = (1..=10).collect();
        assert_eq!(percentile_value(v.clone(), 100_000), 2); // floor(1.0) = 1
        assert_eq!(percentile_value(v, 900_000), 10); // floor(9.0) = 9
        assert_eq!(percentile_value(Vec::new(), 500_000), 0);
    }

    #[test]
    fn all_pass_yields_passes_all() {
        let mut metrics = BTreeMap::new();
        metrics.insert(7, base_metrics(7));
        for (i, share) in [100_000u64, 200_000, 300_000, 400_000, 500_000]
            .iter()
            .enumerate()
        {
            let mut m = base_metrics(100 + i as u64);
            m.new_user_engagement_share_fp = *share;
            metrics.insert(100 + i as u64, m);
        }
        let p = EligibilityParams::default();
        let (e, _) = compute_eligibility(&metrics, &p);
        let elig = e.get(&7).copied().unwrap();
        assert_eq!(elig.0, Eligibility::ALL_PASS, "flags=0b{:07b}", elig.0);
        assert!(elig.passes_all());
    }

    #[test]
    fn f0_fails_when_signer_auths_at_threshold() {
        let mut metrics = BTreeMap::new();
        let mut m = base_metrics(7);
        m.signer_authorizations = 100; // == APP_THRESHOLD → fails (< requirement)
        metrics.insert(7, m);
        let p = EligibilityParams::default();
        let (e, _) = compute_eligibility(&metrics, &p);
        let elig = e.get(&7).copied().unwrap();
        assert!(!elig.get(0), "F0 must fail at threshold");
        assert!(!elig.passes_all());
    }

    /// Threat-model #295: F0 trips on the CLUSTERED signer-auth count.
    #[test]
    fn f0_fails_when_clustered_signer_auths_at_threshold() {
        let mut metrics = BTreeMap::new();
        let mut m = base_metrics(7);
        m.signer_authorizations = 30;
        m.signer_authorizations_clustered = 100;
        metrics.insert(7, m);
        let p = EligibilityParams::default();
        let (e, _) = compute_eligibility(&metrics, &p);
        assert!(!e[&7].get(0), "F0 must fail on clustered signal");
    }

    /// Threat-model #296: F0 trips when the FID has registered miniapps.
    #[test]
    fn f0_fails_when_fid_authored_miniapps_at_threshold() {
        let mut metrics = BTreeMap::new();
        let mut m = base_metrics(7);
        m.miniapp_author_count = 100;
        metrics.insert(7, m);
        let p = EligibilityParams::default();
        let (e, _) = compute_eligibility(&metrics, &p);
        assert!(!e[&7].get(0), "F0 must fail on miniapp-author signal");
    }

    #[test]
    fn f1_fails_with_no_casts() {
        let mut metrics = BTreeMap::new();
        let mut m = base_metrics(7);
        m.total_casts = 0;
        m.replies_received = 0;
        m.replies_per_cast_fp = 0;
        m.engagement_per_cast_fp = 0;
        metrics.insert(7, m);
        let p = EligibilityParams::default();
        let (e, _) = compute_eligibility(&metrics, &p);
        assert!(!e[&7].get(1));
        assert!(!e[&7].passes_all());
    }

    #[test]
    fn f2_fails_below_min_engagers() {
        let mut metrics = BTreeMap::new();
        let mut m = base_metrics(7);
        m.unique_engagers = 2; // < MIN_ENGAGERS = 3
        metrics.insert(7, m);
        let p = EligibilityParams::default();
        let (e, _) = compute_eligibility(&metrics, &p);
        assert!(!e[&7].get(2));
        assert!(!e[&7].passes_all());
    }

    #[test]
    fn f3_uses_calibration_percentile() {
        // Cohort engager entropy 0.1..0.9; P10 index floor(0.9) = 0 →
        // threshold 0.1. A target outside the cohort with 0.05 fails.
        let mut metrics = BTreeMap::new();
        for i in 0..9u64 {
            let mut m = base_metrics(100 + i);
            m.engager_entropy_fp = (i + 1) * 100_000;
            metrics.insert(100 + i, m);
        }
        let mut target = base_metrics(7);
        target.engager_entropy_fp = 50_000;
        target.total_casts = 1;
        target.active_days = 1;
        metrics.insert(7, target);

        let p = EligibilityParams::default();
        let (e, t) = compute_eligibility(&metrics, &p);
        assert_eq!(t.engager_entropy_fp, 100_000);
        assert!(!e[&7].get(3), "low-entropy FID must fail F3");
        assert!(e[&108].get(3));
    }

    #[test]
    fn f5_uses_upper_tail_threshold() {
        // Cohort shares 0.01..0.09; P90 index floor(8.1) = 8 → 0.09.
        let mut metrics = BTreeMap::new();
        for i in 0..9u64 {
            let mut m = base_metrics(100 + i);
            m.new_user_engagement_share_fp = (i + 1) * 10_000;
            metrics.insert(100 + i, m);
        }
        let mut target = base_metrics(7);
        target.new_user_engagement_share_fp = 500_000;
        target.total_casts = 1;
        target.active_days = 1;
        metrics.insert(7, target);

        let p = EligibilityParams::default();
        let (e, t) = compute_eligibility(&metrics, &p);
        assert_eq!(t.new_user_share_fp, 90_000);
        assert!(!e[&7].get(5), "untrusted high-share FID fails F5");
        assert!(e[&100].get(5));
    }

    /// N4: F5 has three pass conditions; `share < T5` is strict.
    #[test]
    fn f5_three_conditions() {
        let p = EligibilityParams::default();
        let t = EligibilityThresholds {
            new_user_share_fp: 300_000,
            ..Default::default()
        };
        let mut m = base_metrics(7);
        m.trust_fp = CREDITER_TRUST_FLOOR_FP - 1;
        // share < T5 → pass.
        m.new_user_engagement_share_fp = 299_999;
        assert!(f5_passes(&m, &p, &t));
        // share == T5, above the absolute floor, untrusted → fail
        // (strict `<`).
        m.new_user_engagement_share_fp = 300_000;
        assert!(!f5_passes(&m, &p, &t));
        // Trust escape: trust_fp ≥ 100 passes regardless of share.
        m.trust_fp = CREDITER_TRUST_FLOOR_FP;
        m.new_user_engagement_share_fp = FP_ONE;
        assert!(f5_passes(&m, &p, &t));
        // Absolute floor: share < 0.10 passes even when T5 is lower.
        m.trust_fp = 0;
        let t_low = EligibilityThresholds {
            new_user_share_fp: 10_000,
            ..Default::default()
        };
        m.new_user_engagement_share_fp = 99_999;
        assert!(f5_passes(&m, &p, &t_low));
        m.new_user_engagement_share_fp = 100_000;
        assert!(!f5_passes(&m, &p, &t_low));
    }

    #[test]
    fn f4_optional_bit_auto_passes_when_disabled() {
        let mut metrics = BTreeMap::new();
        let mut m = base_metrics(7);
        m.engagement_per_cast_fp = 0;
        m.total_casts = 1;
        m.active_days = 1;
        metrics.insert(7, m);
        for i in 0..5u64 {
            let mut c = base_metrics(100 + i);
            c.engagement_per_cast_fp = 2_000_000 + i * FP_ONE;
            metrics.insert(100 + i, c);
        }
        let mut p = EligibilityParams::default();
        assert!(!p.enable_f4);
        let (e, _) = compute_eligibility(&metrics, &p);
        assert!(e[&7].get(4), "F4 must auto-pass when disabled");

        p.enable_f4 = true;
        let (e2, _) = compute_eligibility(&metrics, &p);
        assert!(!e2[&7].get(4));
    }

    #[test]
    fn calibration_cohort_filters_by_activity_floors() {
        let mut metrics = BTreeMap::new();
        for i in 0..5u64 {
            let mut m = base_metrics(100 + i);
            m.engager_entropy_fp = 500_000;
            metrics.insert(100 + i, m);
        }
        for i in 0..5u64 {
            let mut m = base_metrics(200 + i);
            m.total_casts = 1; // < CALIBRATION_MIN_CASTS = 10
            m.active_days = 1; // < CALIBRATION_MIN_ACTIVE_DAYS = 5
            m.engager_entropy_fp = FP_ONE;
            metrics.insert(200 + i, m);
        }
        let p = EligibilityParams::default();
        let t = compute_thresholds(&metrics, &p);
        assert_eq!(t.cohort_size, 5, "only the 5 active FIDs are in-cohort");
        assert_eq!(t.engager_entropy_fp, 500_000);
    }
}
