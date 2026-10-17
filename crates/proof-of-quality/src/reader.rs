//! Deterministic read-only view over the state needed by the scoring
//! pipeline.
//!
//! Production wires this to the node's stores at the epoch boundary
//! (FIP §17.7: the boundary state fixes the inputs). Tests use
//! [`InMemoryReader`].
//!
//! The trait is intentionally narrow: every read needed by the scoring
//! pipeline is enumerated here, so production wiring can be reviewed for
//! "every validator returns the same thing for the same inputs."
//!
//! ## Post-transfer filter (FIP §8.1)
//!
//! Every engagement / follow input is post-transfer: an event with
//! timestamp `ts` between FIDs `(a, b)` counts only if
//! `ts > max(a.effective_ts, b.effective_ts)`. One-sided metrics (cast
//! count, active days) use only the FID's own `effective_ts`. The
//! implementation applies the filter; the crate trusts it.
//!
//! ## Amounts
//!
//! All stake amounts are integer token base units (micro-units, §12).
//! The crate computes every derived factor (stake factor, vouch boost)
//! itself in fixed point; readers never return reals.

use crate::ScoringError;
use std::collections::{BTreeMap, BTreeSet};

/// Per-FID engagement counts toward another FID, partitioned into
/// new-user events (FIP §8.1: timestamp `≤ source.effective_ts + 30
/// days`) and all other events. Together they sum to the total directed
/// post-transfer engagement count from `source` → `target`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EngagementCount {
    pub first_30d: u32,
    pub later: u32,
}

impl EngagementCount {
    pub fn total(&self) -> u32 {
        self.first_30d.saturating_add(self.later)
    }
}

/// Required reads. Implementations must be deterministic: identical input
/// state must yield identical output across any number of calls.
pub trait SnapchainStateReader {
    /// The scoring universe. FIP §8.2.1: every registered FID
    /// (Optimism-registered and hyper-native). Returned as a `BTreeSet`
    /// so the caller can iterate in canonical order.
    ///
    /// The universe must contain every FID that holds a vouch stake:
    /// the crate derives each FID's `vouch_stake_received` (§8.4
    /// `stake_factor`, option (b) of §6.7) by summing
    /// [`vouches_from`](Self::vouches_from) over the universe.
    fn all_active_fids(&self) -> Result<BTreeSet<u64>, ScoringError>;

    /// FID's `effective_ts` (FIP §2): the latest non-exempt custody
    /// change, or the registration timestamp if there is none. `None`
    /// if no registration is known (age 0). Used for the age factor;
    /// the post-transfer filter and the new-user partition are applied
    /// by the reader itself.
    fn effective_ts(&self, fid: u64) -> Result<Option<u64>, ScoringError>;

    /// The follow graph: for each FID, the FIDs they follow. A follow
    /// edge `j → i` is included only if its `followed_at` is
    /// post-transfer for `j` and for `i` (FIP §8.2.2). Used for
    /// EigenTrust.
    fn followees(&self, fid: u64) -> Result<Vec<u64>, ScoringError>;

    /// Engagement counts directed `from → to` (likes + recasts +
    /// replies to casts of `to`), post-transfer for both FIDs,
    /// partitioned into new-user events (`ts ≤ from.effective_ts + 30
    /// days`) and the remainder. Sparse — implementations may return
    /// only entries with non-zero `total()`.
    fn engagement_from(&self, from: u64) -> Result<BTreeMap<u64, EngagementCount>, ScoringError>;

    /// Total post-transfer cast count for `fid` (one-sided filter).
    fn total_casts(&self, fid: u64) -> Result<u32, ScoringError>;

    /// Distinct days with one or more post-transfer casts (one-sided
    /// filter). Used by the calibration cohort.
    fn active_days(&self, fid: u64) -> Result<u32, ScoringError>;

    /// Replies-received (FIP §8.3 F6): the number of casts of `fid`
    /// with one or more post-transfer replies — not the number of
    /// replies.
    fn replies_received(&self, fid: u64) -> Result<u32, ScoringError>;

    /// FIP §8.4 / §12 credibility stake (`STAKE_TYPE_CREDIBILITY`) of
    /// `fid`, in micro-units. The crate adds the vouch stake the FID
    /// receives and saturates against `STAKE_MATURITY_AMOUNT`. Default
    /// 0 so test readers and retro tools don't have to opt in.
    fn credibility_stake(&self, _fid: u64) -> Result<u64, ScoringError> {
        Ok(0)
    }

    /// FIP §6.7 vouch graph: ordered map `vouchee → amount` (micro-units)
    /// of the `STAKE_TYPE_VOUCH` stakes that `voucher` holds. Used two
    /// ways: (1) the vouch boost on `contribution(voucher, vouchee)`
    /// and (2) summed over all vouchers into the vouchee's
    /// `stake_factor`. Default empty.
    fn vouches_from(&self, _voucher: u64) -> Result<BTreeMap<u64, u64>, ScoringError> {
        Ok(BTreeMap::new())
    }

    /// FIP §8.3 F0 input: count of distinct other FIDs that name
    /// `fid` as their `requestFid` in signer metadata. Required
    /// — no default; F0 (app detection) breaks silently if a
    /// reader returns 0 when there's a real reverse index it
    /// should consult.
    fn signer_authorizations(&self, fid: u64) -> Result<u32, ScoringError>;

    /// FIP threat-model #295: clustered `signer_authorizations`
    /// across FIDs sharing `fid`'s custody address. Catches the
    /// app-fragmentation evasion where one organization splits
    /// across many sub-FIDs each individually below
    /// `app_threshold`. Default delegates to non-clustered
    /// `signer_authorizations` (retro tools + InMemoryReader
    /// don't need clustering).
    fn signer_authorizations_clustered(&self, fid: u64) -> Result<u32, ScoringError> {
        self.signer_authorizations(fid)
    }

    /// FIP threat-model #296: number of miniapps registered with
    /// `fid` as `author_fid` in `MiniappState`. An FID that has
    /// registered ≥1 miniapp is by definition an app — even if
    /// they don't use managed signers. Default 0 so test readers
    /// don't have to opt in.
    fn miniapp_author_count(&self, _fid: u64) -> Result<u32, ScoringError> {
        Ok(0)
    }

    /// FIP §7 App-PoW input: map `(app_owner_fid, user_fid)` →
    /// count of valid `APP_USAGE_RECEIPT`s of `epoch` (already limited
    /// to `MAX_RECEIPTS_PER_APP_PER_EPOCH` per user and app, §7.5). The
    /// owner FID is resolved from the miniapp registry (§7.3). Default
    /// empty so non-prod readers don't have to opt in.
    fn app_receipt_counts_for_epoch(
        &self,
        _epoch: u64,
    ) -> Result<BTreeMap<(u64, u64), u32>, ScoringError> {
        Ok(BTreeMap::new())
    }

    /// FIP §7c App-PoW input: map `(app_owner_fid, user_fid)` →
    /// count of MiniappAdd events logged in `epoch`. Each event
    /// contributes `5.0 × credibility(user_fid)` to
    /// `app_work[app_owner_fid]`. Reads from
    /// `HyperMiniappAddByEpoch[epoch][*]` in production. Default
    /// empty so non-prod readers don't have to opt in.
    fn miniapp_add_events_for_epoch(
        &self,
        _epoch: u64,
    ) -> Result<BTreeMap<(u64, u64), u32>, ScoringError> {
        Ok(BTreeMap::new())
    }

    /// FIP §5.4 DA-PoW input: map `validator fid → answered(v, e)`, the
    /// number of valid responses to the challenges of `epoch`. Default
    /// empty.
    fn da_answered_counts_for_epoch(
        &self,
        _epoch: u64,
    ) -> Result<BTreeMap<u64, u32>, ScoringError> {
        Ok(BTreeMap::new())
    }

    /// FIP §5.4 DA-PoW input: map `validator fid → Σ response_height`
    /// over the answered challenges of `epoch`, where `response_height`
    /// is the height of the shard-0 block that includes the response.
    /// The crate derives `avg_offset = Σ / answered − boundary_height`
    /// with `boundary_height = PIVOT_HEIGHT_0 + (epoch − 1) ·
    /// EPOCH_LENGTH` (§4.3). Default empty.
    fn da_response_block_sum_for_epoch(
        &self,
        _epoch: u64,
    ) -> Result<BTreeMap<u64, u128>, ScoringError> {
        Ok(BTreeMap::new())
    }
}

/// Pure in-memory reader for testing the scoring pipeline end-to-end
/// without booting snapchain. Builders mirror the trait method shape.
#[derive(Default, Clone, Debug)]
pub struct InMemoryReader {
    pub fids: BTreeSet<u64>,
    pub effective_ts: BTreeMap<u64, u64>,
    pub follow_graph: BTreeMap<u64, Vec<u64>>,
    pub engagement: BTreeMap<u64, BTreeMap<u64, EngagementCount>>,
    pub total_casts: BTreeMap<u64, u32>,
    pub active_days: BTreeMap<u64, u32>,
    pub replies_received: BTreeMap<u64, u32>,
    /// FIP §8.4 credibility stake per FID (micro-units).
    pub credibility_stake: BTreeMap<u64, u64>,
    /// FIP §6.7 vouch graph: `voucher → (vouchee → amount)`.
    pub vouches: BTreeMap<u64, BTreeMap<u64, u64>>,
    /// FIP §8.3 F0 input: per-FID count of signer authorizations
    /// pointing at this FID as `requestFid`.
    pub signer_auths: BTreeMap<u64, u32>,
    /// FIP threat-model #295 test input: per-FID clustered signer
    /// auth count (overrides plain `signer_auths` for clustered
    /// reads). When unset, clustered reads fall back to
    /// `signer_auths`.
    pub signer_auths_clustered: BTreeMap<u64, u32>,
    /// FIP threat-model #296 test input: per-FID count of miniapps
    /// authored by that FID.
    pub miniapp_author_counts: BTreeMap<u64, u32>,
    /// FIP §7 App-PoW: `epoch → ((app_fid, user_fid) → count)`.
    pub app_receipts: BTreeMap<u64, BTreeMap<(u64, u64), u32>>,
    /// FIP §7c App-PoW: `epoch → ((app_fid, user_fid) → add events)`.
    pub miniapp_add_events: BTreeMap<u64, BTreeMap<(u64, u64), u32>>,
    /// FIP §5.4 DA-PoW: `epoch → (fid → answered_count)`.
    pub da_answered: BTreeMap<u64, BTreeMap<u64, u32>>,
    /// FIP §5.4 DA-PoW: `epoch → (fid → Σ response_height)`.
    pub da_response_block_sum: BTreeMap<u64, BTreeMap<u64, u128>>,
}

impl InMemoryReader {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_fid(&mut self, fid: u64, effective_ts: u64) {
        self.fids.insert(fid);
        self.effective_ts.insert(fid, effective_ts);
    }

    pub fn add_follows(&mut self, from: u64, followees: impl IntoIterator<Item = u64>) {
        let v = self.follow_graph.entry(from).or_default();
        for f in followees {
            if !v.contains(&f) {
                v.push(f);
            }
        }
    }

    /// Symmetric helper: register a directional engagement edge with the
    /// given counts. Most tests use `add_engagement_pair` to create
    /// reciprocal engagement.
    pub fn add_engagement(&mut self, from: u64, to: u64, count: EngagementCount) {
        self.engagement.entry(from).or_default().insert(to, count);
    }

    pub fn add_engagement_pair(
        &mut self,
        a: u64,
        b: u64,
        a_to_b: EngagementCount,
        b_to_a: EngagementCount,
    ) {
        self.add_engagement(a, b, a_to_b);
        self.add_engagement(b, a, b_to_a);
    }

    pub fn set_total_casts(&mut self, fid: u64, n: u32) {
        self.total_casts.insert(fid, n);
    }

    pub fn set_active_days(&mut self, fid: u64, n: u32) {
        self.active_days.insert(fid, n);
    }

    pub fn set_replies_received(&mut self, fid: u64, n: u32) {
        self.replies_received.insert(fid, n);
    }

    /// Set the credibility stake (micro-units) of `fid`.
    pub fn set_credibility_stake(&mut self, fid: u64, amount: u64) {
        self.credibility_stake.insert(fid, amount);
    }

    /// Add a vouch stake of `amount` (micro-units) from `voucher →
    /// vouchee`. Overwrites any prior amount for that pair.
    pub fn add_vouch(&mut self, voucher: u64, vouchee: u64, amount: u64) {
        self.vouches
            .entry(voucher)
            .or_default()
            .insert(vouchee, amount);
    }

    /// Set the FIP §8.3 F0 input: number of other FIDs whose
    /// signer metadata names `fid` as `requestFid`.
    pub fn set_signer_authorizations(&mut self, fid: u64, n: u32) {
        self.signer_auths.insert(fid, n);
    }

    /// Override the clustered signer-auth count for `fid` (FIP
    /// threat-model #295). When unset, clustered reads fall back
    /// to `set_signer_authorizations`.
    pub fn set_signer_authorizations_clustered(&mut self, fid: u64, n: u32) {
        self.signer_auths_clustered.insert(fid, n);
    }

    /// Set the FIP threat-model #296 input: number of miniapps
    /// authored by `fid`.
    pub fn set_miniapp_author_count(&mut self, fid: u64, n: u32) {
        self.miniapp_author_counts.insert(fid, n);
    }

    /// Set the FIP §7 App-PoW receipt count for
    /// `(epoch, app_fid, user_fid)`. Overwrites any prior value.
    pub fn set_app_receipt_count(&mut self, epoch: u64, app_fid: u64, user_fid: u64, count: u32) {
        self.app_receipts
            .entry(epoch)
            .or_default()
            .insert((app_fid, user_fid), count);
    }

    /// Set the FIP §7c MiniappAdd event count for
    /// `(epoch, app_fid, user_fid)`. Overwrites any prior value.
    pub fn set_miniapp_add_events(&mut self, epoch: u64, app_fid: u64, user_fid: u64, count: u32) {
        self.miniapp_add_events
            .entry(epoch)
            .or_default()
            .insert((app_fid, user_fid), count);
    }

    /// Set the FIP §5 DA-PoW answered count for `(epoch, fid)`.
    pub fn set_da_answered(&mut self, epoch: u64, fid: u64, count: u32) {
        self.da_answered
            .entry(epoch)
            .or_default()
            .insert(fid, count);
    }

    /// Set the FIP §5b DA-PoW response-block sum for `(epoch, fid)`.
    pub fn set_da_response_block_sum(&mut self, epoch: u64, fid: u64, sum: u128) {
        self.da_response_block_sum
            .entry(epoch)
            .or_default()
            .insert(fid, sum);
    }
}

impl SnapchainStateReader for InMemoryReader {
    fn all_active_fids(&self) -> Result<BTreeSet<u64>, ScoringError> {
        Ok(self.fids.clone())
    }

    fn effective_ts(&self, fid: u64) -> Result<Option<u64>, ScoringError> {
        Ok(self.effective_ts.get(&fid).copied())
    }

    fn followees(&self, fid: u64) -> Result<Vec<u64>, ScoringError> {
        Ok(self.follow_graph.get(&fid).cloned().unwrap_or_default())
    }

    fn engagement_from(&self, from: u64) -> Result<BTreeMap<u64, EngagementCount>, ScoringError> {
        Ok(self.engagement.get(&from).cloned().unwrap_or_default())
    }

    fn total_casts(&self, fid: u64) -> Result<u32, ScoringError> {
        Ok(self.total_casts.get(&fid).copied().unwrap_or(0))
    }

    fn active_days(&self, fid: u64) -> Result<u32, ScoringError> {
        Ok(self.active_days.get(&fid).copied().unwrap_or(0))
    }

    fn replies_received(&self, fid: u64) -> Result<u32, ScoringError> {
        Ok(self.replies_received.get(&fid).copied().unwrap_or(0))
    }

    fn credibility_stake(&self, fid: u64) -> Result<u64, ScoringError> {
        Ok(self.credibility_stake.get(&fid).copied().unwrap_or(0))
    }

    fn vouches_from(&self, voucher: u64) -> Result<BTreeMap<u64, u64>, ScoringError> {
        Ok(self.vouches.get(&voucher).cloned().unwrap_or_default())
    }

    fn signer_authorizations(&self, fid: u64) -> Result<u32, ScoringError> {
        Ok(self.signer_auths.get(&fid).copied().unwrap_or(0))
    }

    fn signer_authorizations_clustered(&self, fid: u64) -> Result<u32, ScoringError> {
        Ok(self
            .signer_auths_clustered
            .get(&fid)
            .copied()
            .or_else(|| self.signer_auths.get(&fid).copied())
            .unwrap_or(0))
    }

    fn miniapp_author_count(&self, fid: u64) -> Result<u32, ScoringError> {
        Ok(self.miniapp_author_counts.get(&fid).copied().unwrap_or(0))
    }

    fn app_receipt_counts_for_epoch(
        &self,
        epoch: u64,
    ) -> Result<BTreeMap<(u64, u64), u32>, ScoringError> {
        Ok(self.app_receipts.get(&epoch).cloned().unwrap_or_default())
    }

    fn miniapp_add_events_for_epoch(
        &self,
        epoch: u64,
    ) -> Result<BTreeMap<(u64, u64), u32>, ScoringError> {
        Ok(self
            .miniapp_add_events
            .get(&epoch)
            .cloned()
            .unwrap_or_default())
    }

    fn da_answered_counts_for_epoch(&self, epoch: u64) -> Result<BTreeMap<u64, u32>, ScoringError> {
        Ok(self.da_answered.get(&epoch).cloned().unwrap_or_default())
    }

    fn da_response_block_sum_for_epoch(
        &self,
        epoch: u64,
    ) -> Result<BTreeMap<u64, u128>, ScoringError> {
        Ok(self
            .da_response_block_sum
            .get(&epoch)
            .cloned()
            .unwrap_or_default())
    }
}
