//! Deterministic read-only view over the snapchain state needed by the
//! scoring pipeline.
//!
//! Production wires this to snapchain's stores (`OnchainEventStore`,
//! `LinkStore`, `ReactionStore`, `CastStore`) at the snapchain anchor
//! block. Tests use [`InMemoryReader`].
//!
//! The trait is intentionally narrow: every read needed by the scoring
//! pipeline is enumerated here, so production wiring can be reviewed for
//! "every validator returns the same thing for the same inputs."

use crate::ScoringError;
use std::collections::{BTreeMap, BTreeSet};

/// Per-FID engagement counts toward another FID, partitioned into
/// "first-30-days from the source's `effective_ts`" and "all other".
/// Together they sum to the total directed engagement count from
/// `source` → `target` post-transfer.
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
    /// Universe of FIDs that have any post-transfer activity within the
    /// scoring window (the snapchain anchor block range). Returned as a
    /// `BTreeSet` so the caller can iterate in canonical order.
    fn all_active_fids(&self) -> Result<BTreeSet<u64>, ScoringError>;

    /// FID's `effective_ts` — the later of (registration timestamp,
    /// most-recent custody-transfer timestamp). Used to gate engagement
    /// counts to "post-transfer" only and to determine whether an
    /// engagement source counts as a "new user" (within 30 days of their
    /// own effective_ts).
    fn effective_ts(&self, fid: u64) -> Result<Option<u64>, ScoringError>;

    /// The follow graph: for each FID, the FIDs they follow. Edges are
    /// post-transfer only. Used to seed EigenTrust.
    fn followees(&self, fid: u64) -> Result<Vec<u64>, ScoringError>;

    /// Engagement counts directed `from → to` (likes + recasts + replies),
    /// post-transfer, partitioned into "first 30 days from `from`'s
    /// `effective_ts`" and the remainder. Sparse — implementations may
    /// return only entries with non-zero `total()`.
    fn engagement_from(&self, from: u64) -> Result<BTreeMap<u64, EngagementCount>, ScoringError>;

    /// Total post-transfer cast count for `fid`.
    fn total_casts(&self, fid: u64) -> Result<u32, ScoringError>;

    /// Distinct active days for `fid`. Used by some filter calibrations.
    fn active_days(&self, fid: u64) -> Result<u32, ScoringError>;

    /// Replies-received count: how many casts authored by `fid` got
    /// at least one reply. Used as a quality signal in filter 6.
    fn replies_received(&self, fid: u64) -> Result<u32, ScoringError>;

    /// FIP §8.4 stake_factor component. Default implementation
    /// returns `0.0` so test readers (`InMemoryReader`, retro
    /// offline tools) don't have to opt in until they need to.
    /// The production hyper-side reader overrides this to read
    /// the FID's `STAKE_TYPE_CREDIBILITY` balance and saturate
    /// against `STAKE_MATURITY_ATOMS`.
    fn stake_factor_for_fid(&self, _fid: u64) -> Result<f64, ScoringError> {
        Ok(0.0)
    }

    /// FIP §12 vouch graph: ordered map `vouchee → atoms` of all
    /// vouches `voucher` has staked. Used to boost the voucher's
    /// growth-score contribution toward each vouchee in
    /// `compute_growth_harmonic`. Default empty so test readers
    /// and retro tools don't have to opt in.
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
    /// count of receipts logged in `epoch`. Reads from
    /// `HyperAppReceiptCount[epoch][*]` in production. Default
    /// empty so non-prod readers (retro tools, narrow tests)
    /// don't have to opt in.
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

    /// FIP §5 DA-PoW input: map `fid → answered_count` for
    /// `epoch`. Reads from `HyperDaAnsweredCount[epoch][*]` in
    /// production. Default empty.
    fn da_answered_counts_for_epoch(
        &self,
        _epoch: u64,
    ) -> Result<BTreeMap<u64, u32>, ScoringError> {
        Ok(BTreeMap::new())
    }

    /// FIP §5b DA-PoW input: map `fid → sum_of_response_block_heights`
    /// for `epoch`. Divided by `da_answered_counts_for_epoch[fid]`
    /// at scoring time to derive the validator's average response
    /// block, which feeds the latency factor. Default empty.
    fn da_response_block_sum_for_epoch(
        &self,
        _epoch: u64,
    ) -> Result<BTreeMap<u64, u128>, ScoringError> {
        Ok(BTreeMap::new())
    }

    /// FIP §5c DA-PoW input: map `fid → commit_signatures_in_epoch`,
    /// reflecting validator block-participation. Feeds the uptime
    /// factor `uptime = clamp(commit_signatures / EPOCH_LENGTH, 0, 1)`.
    /// Production reads via the validator score tracker; default
    /// empty so non-prod readers don't have to opt in.
    fn validator_commit_signatures_for_epoch(
        &self,
        _epoch: u64,
    ) -> Result<BTreeMap<u64, u64>, ScoringError> {
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
    pub stake_atoms: BTreeMap<u64, u64>,
    /// FIP §12 vouch graph: `voucher → (vouchee → atoms)`.
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
    /// FIP §5 DA-PoW: `epoch → (fid → answered_count)`.
    pub da_answered: BTreeMap<u64, BTreeMap<u64, u32>>,
    /// FIP §5b DA-PoW: `epoch → (fid → sum_of_response_block_heights)`.
    pub da_response_block_sum: BTreeMap<u64, BTreeMap<u64, u128>>,
    /// FIP §5c DA-PoW: `epoch → (fid → commit_signatures)`.
    pub validator_commit_signatures: BTreeMap<u64, BTreeMap<u64, u64>>,
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

    pub fn set_stake_atoms(&mut self, fid: u64, atoms: u64) {
        self.stake_atoms.insert(fid, atoms);
    }

    /// Add a vouch stake of `atoms` from `voucher → vouchee`. Overwrites
    /// any prior amount for that pair.
    pub fn add_vouch(&mut self, voucher: u64, vouchee: u64, atoms: u64) {
        self.vouches
            .entry(voucher)
            .or_default()
            .insert(vouchee, atoms);
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

    /// Set the FIP §5c DA-PoW commit-signature count for `(epoch, fid)`.
    pub fn set_validator_commit_signatures(&mut self, epoch: u64, fid: u64, sigs: u64) {
        self.validator_commit_signatures
            .entry(epoch)
            .or_default()
            .insert(fid, sigs);
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

    fn stake_factor_for_fid(&self, fid: u64) -> Result<f64, ScoringError> {
        let atoms = self.stake_atoms.get(&fid).copied().unwrap_or(0);
        Ok(crate::metrics::stake_factor_from_atoms(atoms))
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

    fn validator_commit_signatures_for_epoch(
        &self,
        epoch: u64,
    ) -> Result<BTreeMap<u64, u64>, ScoringError> {
        Ok(self
            .validator_commit_signatures
            .get(&epoch)
            .cloned()
            .unwrap_or_default())
    }
}
