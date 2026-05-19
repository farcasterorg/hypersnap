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
//! Determinism: every reduction walks a `BTreeMap` in ascending FID
//! order; the cohort vector is sorted before percentile lookup;
//! ties are resolved by the deterministic vector index after sort.

use crate::metrics::FidMetrics;
use crate::{Eligibility, EligibilityParams};
use std::collections::BTreeMap;

/// Calibrated thresholds for the data-derived filters. Computed
/// once per epoch by [`compute_thresholds`] over the calibration
/// cohort. Exposed publicly so callers (canonical encoders,
/// debugging surfaces) can record them alongside the
/// per-FID flags.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct EligibilityThresholds {
    /// Lower-tail threshold for F3 (engager entropy). Pass if
    /// `engager_entropy ≥ engager_entropy`.
    pub engager_entropy: f64,
    /// Lower-tail threshold for F4 (engagement per cast). Only
    /// consulted when `EligibilityParams::enable_f4`.
    pub engagement_per_cast: f64,
    /// Upper-tail threshold for F5 (new-user engagement share).
    /// Pass if `new_user_engagement_share < new_user_share`.
    pub new_user_share: f64,
    /// Lower-tail threshold for F6 (replies per cast). Pass if
    /// `replies_per_cast ≥ replies_per_cast`.
    pub replies_per_cast: f64,
    /// Size of the cohort used to derive the above thresholds.
    /// Reported for diagnostics; an empty cohort means thresholds
    /// fall to 0 and the corresponding filters effectively pass
    /// everyone (handled by the percentile function below).
    pub cohort_size: usize,
}

/// Sort `values` ascending and return the value at fractional
/// `percentile` ∈ [0, 1]. Mirrors `cohort_percentile_threshold` in
/// the retro tool; deterministic for equal inputs.
fn percentile_value(mut values: Vec<f64>, percentile: f64) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    values.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let idx = (values.len() as f64 * percentile) as usize;
    values[idx.min(values.len() - 1)]
}

/// Membership test for the calibration cohort.
fn in_calibration_cohort(m: &FidMetrics, p: &EligibilityParams) -> bool {
    m.total_casts >= p.calibration_min_casts && m.active_days >= p.calibration_min_active_days
}

/// Compute the data-derived thresholds for F3/F4/F5/F6 from the
/// calibration cohort. F5 uses the upper-tail
/// `1.0 - threshold_percentile`. Returns zeros for an empty
/// cohort.
pub fn compute_thresholds(
    metrics: &BTreeMap<u64, FidMetrics>,
    p: &EligibilityParams,
) -> EligibilityThresholds {
    let cohort: Vec<&FidMetrics> = metrics
        .values()
        .filter(|m| in_calibration_cohort(m, p))
        .collect();
    let cohort_size = cohort.len();
    let pct = p.threshold_percentile.clamp(0.0, 1.0);
    let upper = (1.0 - pct).clamp(0.0, 1.0);
    EligibilityThresholds {
        engager_entropy: percentile_value(cohort.iter().map(|m| m.engager_entropy).collect(), pct),
        engagement_per_cast: percentile_value(
            cohort.iter().map(|m| m.engagement_per_cast).collect(),
            pct,
        ),
        new_user_share: percentile_value(
            cohort.iter().map(|m| m.new_user_engagement_share).collect(),
            upper,
        ),
        replies_per_cast: percentile_value(
            cohort.iter().map(|m| m.replies_per_cast).collect(),
            pct,
        ),
        cohort_size,
    }
}

/// Apply the seven filters to a single FID. F4 auto-passes when
/// `enable_f4` is false so the all-bits-set mask still holds for
/// the disabled-F4 default.
pub fn classify_one(
    m: &FidMetrics,
    p: &EligibilityParams,
    t: &EligibilityThresholds,
) -> Eligibility {
    let mut flags = Eligibility::default();
    // F0 (app detection): trips if ANY of the available signals
    // is at-or-above the threshold. Three signals composed:
    //   - signer_authorizations: managed-signer flow (gasless + on-chain)
    //   - signer_authorizations_clustered: aggregated over shared-custody
    //     FIDs (threat-model #295 anti-fragmentation)
    //   - miniapp_author_count: self-declared via MiniappRegister
    //     (threat-model #296 — direct-sign-app catcher)
    let max_app_signal = m
        .signer_authorizations
        .max(m.signer_authorizations_clustered)
        .max(m.miniapp_author_count);
    flags.set(0, max_app_signal < p.app_threshold);
    flags.set(1, m.total_casts > 0);
    flags.set(2, m.unique_engagers >= p.min_engagers);
    flags.set(3, m.engager_entropy >= t.engager_entropy);
    flags.set(
        4,
        if p.enable_f4 {
            m.engagement_per_cast >= t.engagement_per_cast
        } else {
            true
        },
    );
    flags.set(5, m.new_user_engagement_share < t.new_user_share);
    flags.set(6, m.replies_per_cast >= t.replies_per_cast);
    flags
}

/// Compute eligibility for every FID in `metrics`. Returns the
/// per-FID bit-packed flags alongside the thresholds used (caller
/// may want both for canonical encoding).
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
        m.engager_entropy = 0.5;
        m.new_user_engagement_share = 0.05;
        m.replies_received = 25;
        m.replies_per_cast = 0.5;
        m.engagement_per_cast = 1.2;
        m
    }

    #[test]
    fn empty_cohort_thresholds_default_to_zero() {
        let metrics: BTreeMap<u64, FidMetrics> = BTreeMap::new();
        let p = EligibilityParams::default();
        let t = compute_thresholds(&metrics, &p);
        assert_eq!(t.cohort_size, 0);
        assert_eq!(t.engager_entropy, 0.0);
        assert_eq!(t.engagement_per_cast, 0.0);
        assert_eq!(t.new_user_share, 0.0);
        assert_eq!(t.replies_per_cast, 0.0);
    }

    #[test]
    fn all_pass_yields_passes_all() {
        // A FID alone in the cohort can never pass F5 (`<` against
        // its own value). Build a 6-element cohort with diverse
        // shares so the upper-tail threshold sits strictly above
        // the target's share.
        let mut metrics = BTreeMap::new();
        metrics.insert(7, base_metrics(7));
        for (i, share) in [0.10f64, 0.20, 0.30, 0.40, 0.50].iter().enumerate() {
            let mut m = base_metrics(100 + i as u64);
            m.new_user_engagement_share = *share;
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

    /// Threat-model #295: F0 trips on the CLUSTERED signer-auth
    /// count even when the individual count is below threshold —
    /// fragmenting an app across many sub-FIDs doesn't help.
    #[test]
    fn f0_fails_when_clustered_signer_auths_at_threshold() {
        let mut metrics = BTreeMap::new();
        let mut m = base_metrics(7);
        m.signer_authorizations = 30; // below threshold individually
        m.signer_authorizations_clustered = 100; // cluster sums to threshold
        metrics.insert(7, m);
        let p = EligibilityParams::default();
        let (e, _) = compute_eligibility(&metrics, &p);
        let elig = e.get(&7).copied().unwrap();
        assert!(!elig.get(0), "F0 must fail on clustered signal");
    }

    /// Threat-model #296: F0 trips when the FID has registered
    /// miniapps (direct-sign app catcher), even with zero signer
    /// authorizations of either flavor.
    #[test]
    fn f0_fails_when_fid_authored_miniapps_at_threshold() {
        let mut metrics = BTreeMap::new();
        let mut m = base_metrics(7);
        m.signer_authorizations = 0;
        m.signer_authorizations_clustered = 0;
        m.miniapp_author_count = 100; // self-declared as app
        metrics.insert(7, m);
        let p = EligibilityParams::default();
        let (e, _) = compute_eligibility(&metrics, &p);
        let elig = e.get(&7).copied().unwrap();
        assert!(!elig.get(0), "F0 must fail on miniapp-author signal");
    }

    #[test]
    fn f1_fails_with_no_casts() {
        let mut metrics = BTreeMap::new();
        let mut m = base_metrics(7);
        m.total_casts = 0;
        m.unique_engagers = 5;
        m.replies_received = 0;
        m.replies_per_cast = 0.0;
        m.engagement_per_cast = 0.0;
        metrics.insert(7, m);
        let p = EligibilityParams::default();
        let (e, _) = compute_eligibility(&metrics, &p);
        let elig = e.get(&7).copied().unwrap();
        assert!(!elig.get(1));
        assert!(!elig.passes_all());
    }

    #[test]
    fn f2_fails_below_min_engagers() {
        let mut metrics = BTreeMap::new();
        let mut m = base_metrics(7);
        m.unique_engagers = 2; // < MIN_ENGAGERS = 3
        metrics.insert(7, m);
        let p = EligibilityParams::default();
        let (e, _) = compute_eligibility(&metrics, &p);
        let elig = e.get(&7).copied().unwrap();
        assert!(!elig.get(2));
        assert!(!elig.passes_all());
    }

    #[test]
    fn f3_uses_calibration_percentile() {
        // Build a cohort with engager entropy values 0.1..0.9 in
        // steps of 0.1. With THRESHOLD_PERCENTILE = 0.10, the 10th
        // percentile (idx = 0.9 → 0) is 0.1. A target FID with
        // engager_entropy = 0.05 fails F3.
        let mut metrics = BTreeMap::new();
        for (i, ent) in [0.1f64, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9]
            .iter()
            .enumerate()
        {
            let mut m = base_metrics(100 + i as u64);
            m.engager_entropy = *ent;
            // Ensure they're all in the cohort.
            m.total_casts = 50;
            m.active_days = 10;
            metrics.insert(100 + i as u64, m);
        }
        // Target FID with very low entropy, OUTSIDE the
        // calibration cohort so its own value doesn't influence
        // the percentile.
        let mut target = base_metrics(7);
        target.engager_entropy = 0.05;
        target.total_casts = 1;
        target.active_days = 1;
        metrics.insert(7, target);

        let p = EligibilityParams::default();
        let (e, t) = compute_eligibility(&metrics, &p);
        // Calibration threshold ≈ 0.1 (the 10th percentile of the
        // cohort, idx 0 after sort).
        assert!(
            (t.engager_entropy - 0.1).abs() < 1e-9,
            "got {}",
            t.engager_entropy
        );
        let target_e = e.get(&7).copied().unwrap();
        assert!(!target_e.get(3), "low-entropy FID must fail F3");
        // High-entropy cohort members all pass F3.
        let high_e = e.get(&108).copied().unwrap();
        assert!(high_e.get(3));
    }

    #[test]
    fn f5_uses_upper_tail_threshold() {
        // Cohort of new_user_engagement_share values 0.01..0.09.
        // Upper-tail threshold (90th percentile) ≈ 0.09. A target
        // FID with share = 0.5 must fail F5; cohort members with
        // 0.01 must pass.
        let mut metrics = BTreeMap::new();
        for (i, share) in [0.01f64, 0.02, 0.03, 0.04, 0.05, 0.06, 0.07, 0.08, 0.09]
            .iter()
            .enumerate()
        {
            let mut m = base_metrics(100 + i as u64);
            m.new_user_engagement_share = *share;
            metrics.insert(100 + i as u64, m);
        }
        let mut target = base_metrics(7);
        target.new_user_engagement_share = 0.5;
        target.total_casts = 1;
        target.active_days = 1;
        metrics.insert(7, target);

        let p = EligibilityParams::default();
        let (e, t) = compute_eligibility(&metrics, &p);
        // Upper-tail percentile at 0.90 maps to idx=8 → value 0.09.
        assert!(
            (t.new_user_share - 0.09).abs() < 1e-9,
            "got {}",
            t.new_user_share
        );
        let target_e = e.get(&7).copied().unwrap();
        assert!(!target_e.get(5));
        let low = e.get(&100).copied().unwrap();
        assert!(low.get(5));
    }

    #[test]
    fn f4_optional_bit_auto_passes_when_disabled() {
        // engagement_per_cast = 0.0, cohort threshold > 0, but F4
        // is disabled → bit auto-passes.
        let mut metrics = BTreeMap::new();
        let mut m = base_metrics(7);
        m.engagement_per_cast = 0.0;
        // Exclude target from calibration cohort so its own value
        // doesn't anchor the threshold to 0.0.
        m.total_casts = 1;
        m.active_days = 1;
        metrics.insert(7, m);
        // Add cohort with high engagement_per_cast so threshold > 0.
        for i in 0..5 {
            let mut c = base_metrics(100 + i);
            c.engagement_per_cast = 2.0 + i as f64;
            metrics.insert(100 + i, c);
        }
        let mut p = EligibilityParams::default();
        assert!(!p.enable_f4);
        let (e, _) = compute_eligibility(&metrics, &p);
        let elig = e.get(&7).copied().unwrap();
        assert!(elig.get(4), "F4 must auto-pass when disabled");

        // Enable F4 → target fails.
        p.enable_f4 = true;
        let (e2, _) = compute_eligibility(&metrics, &p);
        let elig2 = e2.get(&7).copied().unwrap();
        assert!(!elig2.get(4));
    }

    #[test]
    fn calibration_cohort_filters_by_activity_floors() {
        // Two cohorts: one passes calibration criteria (high
        // total_casts + active_days), one doesn't (low). The
        // low-activity FIDs MUST be excluded from threshold
        // computation.
        let mut metrics = BTreeMap::new();
        // Active cohort with engager_entropy clustered at 0.5.
        for i in 0..5 {
            let mut m = base_metrics(100 + i);
            m.engager_entropy = 0.5;
            metrics.insert(100 + i, m);
        }
        // Inactive accounts with very high entropy (1.0) — must
        // NOT influence the threshold.
        for i in 0..5 {
            let mut m = base_metrics(200 + i);
            m.total_casts = 1; // < CALIBRATION_MIN_CASTS = 10
            m.active_days = 1; // < CALIBRATION_MIN_ACTIVE_DAYS = 5
            m.engager_entropy = 1.0;
            metrics.insert(200 + i, m);
        }
        let p = EligibilityParams::default();
        let t = compute_thresholds(&metrics, &p);
        assert_eq!(t.cohort_size, 5, "only the 5 active FIDs are in-cohort");
        // Threshold is the 10th percentile of the active cohort
        // (all 0.5) → 0.5, NOT influenced by the 1.0 inactives.
        assert!((t.engager_entropy - 0.5).abs() < 1e-9);
    }
}
