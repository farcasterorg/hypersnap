//! Per-FID metrics derived from the [`SnapchainStateReader`] view.
//!
//! Mirrors `FidMetrics` from `retro_rewards_finalize.rs`, but stripped
//! to the fields used by the in-protocol composite formula. CSV-only
//! columns (engagement_per_cast, replies_per_cast, etc.) are computed
//! here when the composite formula references them; everything else is
//! out of scope for the in-protocol path.

use crate::reader::{EngagementCount, SnapchainStateReader};
use crate::ScoringError;
use std::collections::BTreeMap;

/// Per-FID inputs to the composite formula. All values deterministically
/// computable from the reader state.
#[derive(Clone, Debug)]
pub struct FidMetrics {
    pub fid: u64,
    pub effective_ts: Option<u64>,
    pub age_factor: f64,
    pub trust_score: f64,
    pub credibility_weight: f64,
    /// FIP §8.4 stake_factor component (∈ [0, 1]). Populated by
    /// `build_metrics` from `SnapchainStateReader::stake_factor_for_fid`.
    pub stake_factor: f64,

    /// Inbound count totals (likes + recasts + replies) across all
    /// engagers, post-transfer.
    pub total_engagement_count: u32,
    /// Inbound count from engagers who were within their first 30
    /// days at the time of engagement.
    pub new_user_engagement_count: u32,
    /// `new_user_engagement_count / total_engagement_count` (0 if no
    /// engagement). Quality signal.
    pub new_user_engagement_share: f64,

    /// Normalized Shannon entropy of the inbound engager distribution.
    pub engager_entropy: f64,
    /// Normalized Shannon entropy of the outbound interaction
    /// distribution.
    pub interaction_entropy: f64,

    /// All-time engagement counts: `engager → total interactions
    /// (post-transfer)`.
    pub all_time_engagement: BTreeMap<u64, u32>,

    /// FIP §12 outgoing vouches: `vouchee → atoms` this FID has
    /// staked endorsing each vouchee. Populated by `build_metrics`
    /// from `SnapchainStateReader::vouches_from`. Consumed by
    /// `compute_growth_harmonic` to multiplicatively boost the
    /// voucher's contribution toward the vouchee.
    pub vouches_from: BTreeMap<u64, u64>,

    /// Total post-transfer cast count. Cached on the metrics so
    /// per-pass filters (F1, F6, calibration cohort) can read it
    /// without re-querying.
    pub total_casts: u32,

    /// Distinct active days post-transfer. Cached for calibration
    /// cohort membership (`active_days ≥ CALIBRATION_MIN_ACTIVE_DAYS`).
    pub active_days: u32,

    /// Replies-received: count of this FID's casts that got ≥ 1
    /// reply. Used by F6.
    pub replies_received: u32,

    /// FIP §8.3 F0 input. Number of OTHER FIDs whose signer
    /// metadata names this FID as their `requestFid`. High values
    /// indicate the FID is acting as an app (managed-signer
    /// requester) and should be excluded from Growth (apps earn
    /// through §7 App-PoW, not §6 Growth).
    pub signer_authorizations: u32,

    /// FIP threat-model #295: clustered `signer_authorizations`
    /// summed across FIDs sharing this FID's custody address.
    /// Catches the app-fragmentation evasion. Populated by
    /// `build_metrics`; F0 uses MAX(individual, clustered,
    /// miniapp_author_count) against `app_threshold`.
    pub signer_authorizations_clustered: u32,

    /// FIP threat-model #296: number of miniapps this FID has
    /// registered as `author_fid`. Any FID that registered ≥1
    /// miniapp is by definition an app and trips F0 alongside
    /// the signer-authorization signals.
    pub miniapp_author_count: u32,

    /// FIP §8.3 derived: count of distinct OTHER FIDs whose
    /// inbound engagement reaches this FID. F2 threshold uses this.
    pub unique_engagers: u32,

    /// FIP §8.3 derived: `replies_received / total_casts` (0 when
    /// no casts). F6 threshold uses this.
    pub replies_per_cast: f64,

    /// FIP §8.3 derived: `unique_engagers / ln(1 + total_casts)`
    /// (0 when no casts). F4 threshold uses this when F4 is
    /// enabled.
    pub engagement_per_cast: f64,
}

impl FidMetrics {
    pub fn new(fid: u64) -> Self {
        Self {
            fid,
            effective_ts: None,
            age_factor: 0.0,
            trust_score: 0.0,
            credibility_weight: 0.0,
            stake_factor: 0.0,
            total_engagement_count: 0,
            new_user_engagement_count: 0,
            new_user_engagement_share: 0.0,
            engager_entropy: 0.0,
            interaction_entropy: 0.0,
            all_time_engagement: BTreeMap::new(),
            vouches_from: BTreeMap::new(),
            total_casts: 0,
            active_days: 0,
            replies_received: 0,
            signer_authorizations: 0,
            signer_authorizations_clustered: 0,
            miniapp_author_count: 0,
            unique_engagers: 0,
            replies_per_cast: 0.0,
            engagement_per_cast: 0.0,
        }
    }
}

/// Constants shared with `retro_rewards_finalize.rs`: weights for the
/// linear `credibility_weight` blend.
pub const W_AGE: f64 = 0.25;
pub const W_TRUST: f64 = 0.35;
pub const W_ENTROPY: f64 = 0.20;
pub const W_DIVERSITY: f64 = 0.10;
pub const W_STAKE: f64 = 0.10;

/// FIP-proof-of-work-tokenization §15 `STAKE_MATURITY_AMOUNT` —
/// staked atoms above this threshold saturate `stake_factor` at
/// 1.0. Calibrated as 100 HYPER (= 100_000_000 atoms at 6
/// decimals): low enough that committed credibility stakers can
/// hit the cap, high enough that it's not free.
///
/// All validators MUST agree on this constant for the
/// in-protocol scoring output to be byte-exactly reproducible.
pub const STAKE_MATURITY_ATOMS: u64 = 100_000_000;

/// FIP §8.4: `stake_factor = min(1.0, staked_atoms / STAKE_MATURITY_ATOMS)`.
/// Floor at 0.0 for safety.
pub fn stake_factor_from_atoms(atoms: u64) -> f64 {
    (atoms as f64 / STAKE_MATURITY_ATOMS as f64)
        .min(1.0)
        .max(0.0)
}

const SIX_MONTHS_SECS: u64 = 60 * 60 * 24 * 30 * 6;

pub fn compute_age_factor(effective_ts: Option<u64>, now_unix: u64) -> f64 {
    match effective_ts {
        None => 0.0,
        Some(ts) => {
            let age_secs = now_unix.saturating_sub(ts);
            (age_secs as f64 / SIX_MONTHS_SECS as f64).min(1.0)
        }
    }
}

/// Linear-blend credibility (matches the offline tool).
///
/// `stake_factor` ∈ [0, 1] is derived from the FID's staked
/// `STAKE_TYPE_CREDIBILITY` atoms saturated against
/// `STAKE_MATURITY_ATOMS`. See `stake_factor_from_atoms`.
pub fn compute_credibility_weight(
    age_factor: f64,
    trust_score: f64,
    interaction_entropy: f64,
    stake_factor: f64,
) -> f64 {
    W_AGE * age_factor
        + W_TRUST * trust_score
        + W_ENTROPY * interaction_entropy
        + W_STAKE * stake_factor
        + W_DIVERSITY * 1.0
}

/// Normalized Shannon entropy of a count distribution. Returns 0 if the
/// distribution has fewer than 2 entries, 1.0 when uniformly distributed
/// across all entries.
pub fn normalized_entropy(counts: &BTreeMap<u64, u32>) -> f64 {
    let total: u64 = counts.values().map(|&c| c as u64).sum();
    if total == 0 {
        return 0.0;
    }
    let n = counts.len();
    if n < 2 {
        return 0.0;
    }
    let t = total as f64;
    let mut h = 0.0_f64;
    // Iterate in BTreeMap key order (canonical) so the floating-point
    // sum is deterministic across validators.
    for (_k, &c) in counts.iter() {
        if c > 0 {
            let p = c as f64 / t;
            h -= p * p.log2();
        }
    }
    h / (n as f64).log2()
}

/// Build per-FID metrics from the reader state. Single pass over every
/// FID; reads are deterministic by trait contract. The returned map is
/// keyed by FID (BTreeMap → ascending iteration).
pub fn build_metrics<R: SnapchainStateReader + ?Sized>(
    reader: &R,
    now_unix: u64,
) -> Result<BTreeMap<u64, FidMetrics>, ScoringError> {
    let fids = reader.all_active_fids()?;
    let mut out: BTreeMap<u64, FidMetrics> = BTreeMap::new();

    // First pass: collect outbound engagement and effective_ts for every
    // FID. The inbound side is derived in a second pass.
    let mut outbound: BTreeMap<u64, BTreeMap<u64, EngagementCount>> = BTreeMap::new();
    for &fid in &fids {
        let mut m = FidMetrics::new(fid);
        m.effective_ts = reader.effective_ts(fid)?;
        m.age_factor = compute_age_factor(m.effective_ts, now_unix);
        m.stake_factor = reader.stake_factor_for_fid(fid)?;
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

    // Second pass: derive inbound counts + entropies.
    for &target in &fids {
        // engager_counts (all_time_engagement, inbound side)
        let mut inbound_counts: BTreeMap<u64, u32> = BTreeMap::new();
        let mut new_user_count: u32 = 0;
        let mut total_count: u32 = 0;
        for (&source, edges) in outbound.iter() {
            if source == target {
                continue;
            }
            if let Some(c) = edges.get(&target) {
                let t = c.total();
                if t > 0 {
                    inbound_counts.insert(source, t);
                    total_count = total_count.saturating_add(t);
                    new_user_count = new_user_count.saturating_add(c.first_30d);
                }
            }
        }

        let engager_entropy = normalized_entropy(&inbound_counts);

        // interaction_entropy: outbound count distribution
        let outbound_dist: BTreeMap<u64, u32> = outbound
            .get(&target)
            .map(|m| m.iter().map(|(&k, c)| (k, c.total())).collect())
            .unwrap_or_default();
        let interaction_entropy = normalized_entropy(&outbound_dist);

        let m = out.get_mut(&target).unwrap();
        m.engager_entropy = engager_entropy;
        m.interaction_entropy = interaction_entropy;
        m.total_engagement_count = total_count;
        m.new_user_engagement_count = new_user_count;
        m.new_user_engagement_share = if total_count > 0 {
            new_user_count as f64 / total_count as f64
        } else {
            0.0
        };
        m.unique_engagers = inbound_counts.len() as u32;
        m.replies_per_cast = if m.total_casts > 0 {
            m.replies_received as f64 / m.total_casts as f64
        } else {
            0.0
        };
        m.engagement_per_cast = if m.total_casts > 0 {
            m.unique_engagers as f64 / (1.0 + m.total_casts as f64).ln()
        } else {
            0.0
        };
        m.all_time_engagement = inbound_counts;
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stake_factor_from_atoms_saturates_at_maturity() {
        assert_eq!(stake_factor_from_atoms(0), 0.0);
        assert_eq!(stake_factor_from_atoms(STAKE_MATURITY_ATOMS / 2), 0.5);
        assert_eq!(stake_factor_from_atoms(STAKE_MATURITY_ATOMS), 1.0);
        assert_eq!(stake_factor_from_atoms(STAKE_MATURITY_ATOMS * 2), 1.0);
        assert_eq!(stake_factor_from_atoms(u64::MAX), 1.0);
    }

    /// `compute_credibility_weight` mixes the 5 components per FIP
    /// §8.4. With everything except diversity = 0, the floor is
    /// `W_DIVERSITY = 0.10`. With everything saturated, the ceiling
    /// is `1.00` (= sum of all weights).
    #[test]
    fn credibility_weight_bounds() {
        let floor = compute_credibility_weight(0.0, 0.0, 0.0, 0.0);
        // W_DIVERSITY * 1.0 = 0.10
        assert!((floor - 0.10).abs() < 1e-9, "got {floor}");
        let ceiling = compute_credibility_weight(1.0, 1.0, 1.0, 1.0);
        let expected = W_AGE + W_TRUST + W_ENTROPY + W_STAKE + W_DIVERSITY;
        assert!((ceiling - expected).abs() < 1e-9, "got {ceiling}");
        assert!((expected - 1.0).abs() < 1e-9, "weights must sum to 1.0");
    }

    /// Adding stake to an FID with otherwise-identical metrics
    /// produces a strictly higher credibility weight.
    #[test]
    fn credibility_weight_increases_monotonically_with_stake() {
        let without = compute_credibility_weight(0.5, 0.5, 0.5, 0.0);
        let with_partial = compute_credibility_weight(0.5, 0.5, 0.5, 0.5);
        let with_full = compute_credibility_weight(0.5, 0.5, 0.5, 1.0);
        assert!(without < with_partial);
        assert!(with_partial < with_full);
        // Stake contributes exactly W_STAKE * stake_factor to the
        // total.
        assert!((with_full - without - W_STAKE).abs() < 1e-9);
    }
}
