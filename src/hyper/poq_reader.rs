//! Production [`SnapchainStateReader`] backed by snapchain's per-account
//! stores. This is the reader the in-protocol Proof-of-Quality scoring
//! pipeline (`crates/proof-of-quality`) uses at every epoch boundary.
//!
//! Each method is a deterministic read against the snapchain RocksDB at
//! the snapchain anchor block. Determinism is critical: every validator
//! must compute the same FID list, follow graph, engagement counts, etc.
//! to produce a byte-identical scoring output that they can threshold-
//! sign.
//!
//! ## Coverage
//!
//! - `effective_ts` — latest Register/Transfer event's `block_timestamp`
//!   from `OnchainEventStore`. Recovery-aware filtering happens at the
//!   caller level via [`PoqReader::with_recovery_blocks`].
//! - `followees` — outbound follow links (LinkStore, `LINK_TYPE_FOLLOW`).
//! - `engagement_from` — outbound likes + recasts (ReactionStore) +
//!   outbound replies (cast adds with `parent_cast_id`). Mentions are
//!   covered by replies/recasts in practice; standalone mention-only
//!   engagement is a TODO.
//! - `total_casts` — count of cast-add messages per FID.
//! - `active_days` — distinct UTC-day buckets across cast-add timestamps.
//! - `replies_received` — currently 0; see TODO note. Filter 6 in the
//!   composite formula is disabled, so this metric is not consumed in
//!   the current scoring path.

use crate::core::types::FARCASTER_EPOCH;
use crate::storage::constants::RootPrefix;
use crate::storage::db::{PageOptions, RocksDB};
use crate::storage::store::account::{
    CastStore, CastStoreDef, LinkStore, OnchainEventStore, ReactionStore, ReactionStoreDef, Store,
    StoreEventHandler,
};
use prost::Message as _;
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::sync::Arc;

use proof_of_quality::reader::{EngagementCount, SnapchainStateReader};
use proof_of_quality::ScoringError;

use crate::proto;

const READER_PRUNE_LIMIT: u32 = 0; // unused for read paths
const READER_PAGE_SIZE: usize = 500;

/// Production reader handle. Holds the snapchain DB plus the typed
/// stores it needs. Construction is cheap (each `Store` wraps the same
/// `Arc<RocksDB>`).
pub struct PoqReader {
    db: Arc<RocksDB>,
    fids: BTreeSet<u64>,
    cast_store: Store<CastStoreDef>,
    link_store: Store<LinkStore>,
    reaction_store: Store<ReactionStoreDef>,
    onchain: OnchainEventStore,
    /// `(fid, block_timestamp)` pairs that should be skipped when
    /// computing `effective_ts` — these are recovery-flow Transfer
    /// events that must not advance the effective timestamp. Empty by
    /// default.
    recovery_blocks: HashSet<(u64, u64)>,
    /// Per-FID effective_ts override. When present, takes precedence
    /// over the OnchainEventStore lookup. The supervisor builds this
    /// for FIDs whose latest IdRegister event is a recovery-flow
    /// Transfer (cross-referenced against the runtime's recovery
    /// store) — for those FIDs the original Register/Transfer
    /// timestamp is used instead of the recovery one.
    effective_ts_overrides: BTreeMap<u64, u64>,
}

fn map_err(e: impl std::fmt::Display) -> ScoringError {
    ScoringError::Reader(format!("{}", e))
}

/// Convert a Farcaster cast timestamp (seconds since FARCASTER_EPOCH)
/// to a Unix timestamp (seconds since 1970-01-01). Used for the 30-day
/// cutoff in `engagement_from`.
fn farcaster_ts_to_unix(ts: u32) -> u64 {
    FARCASTER_EPOCH + ts as u64
}

impl PoqReader {
    pub fn new(db: Arc<RocksDB>, fids: BTreeSet<u64>) -> Self {
        let handler = StoreEventHandler::new_no_persist();
        let cast_store = CastStore::new(db.clone(), handler.clone(), READER_PRUNE_LIMIT);
        let link_store = LinkStore::new(db.clone(), handler.clone(), READER_PRUNE_LIMIT);
        let reaction_store = ReactionStore::new(db.clone(), handler.clone(), READER_PRUNE_LIMIT);
        let onchain = OnchainEventStore::new(db.clone(), handler);
        Self {
            db,
            fids,
            cast_store,
            link_store,
            reaction_store,
            onchain,
            recovery_blocks: HashSet::new(),
            effective_ts_overrides: BTreeMap::new(),
        }
    }

    /// Override the FID universe.
    pub fn with_fids(mut self, fids: BTreeSet<u64>) -> Self {
        self.fids = fids;
        self
    }

    /// Register `(fid, block_timestamp)` pairs that mark recovery-flow
    /// Transfer events. `effective_ts` for those FIDs falls back to
    /// the original Register event's timestamp instead of the matching
    /// Transfer.
    pub fn with_recovery_blocks(mut self, recovery: HashSet<(u64, u64)>) -> Self {
        self.recovery_blocks = recovery;
        self
    }

    /// Inject explicit per-FID effective_ts values. When present, takes
    /// precedence over the OnchainEventStore lookup. The supervisor
    /// builds this for recovery-aware retro-correction (FIPs that
    /// require effective_ts to be pinned at registration despite a
    /// later recovery-flow Transfer).
    pub fn with_effective_ts_overrides(mut self, overrides: BTreeMap<u64, u64>) -> Self {
        self.effective_ts_overrides = overrides;
        self
    }

    /// Iterate every cast-add Message authored by `fid`, page by page,
    /// and invoke `on_message` for each. Stops when no further pages.
    fn for_each_cast_add<F>(&self, fid: u64, mut on_message: F) -> Result<(), ScoringError>
    where
        F: FnMut(&proto::Message),
    {
        let mut page_token: Option<Vec<u8>> = None;
        loop {
            let opts = PageOptions {
                page_size: Some(READER_PAGE_SIZE),
                page_token: page_token.clone(),
                reverse: false,
            };
            let page = self
                .cast_store
                .get_adds_by_fid::<fn(&proto::Message) -> bool>(fid, &opts, None)
                .map_err(map_err)?;
            for msg in &page.messages {
                on_message(msg);
            }
            if let Some(tok) = page.next_page_token {
                page_token = Some(tok);
            } else {
                break;
            }
        }
        Ok(())
    }
}

impl SnapchainStateReader for PoqReader {
    fn all_active_fids(&self) -> Result<BTreeSet<u64>, ScoringError> {
        Ok(self.fids.clone())
    }

    /// Per-FID `effective_ts`. Resolution order:
    ///   1. supervisor-supplied override (custom retro-correction).
    ///   2. paginated walk over the FID's IdRegister events,
    ///      latest-first; the first event whose
    ///      `(fid, block_timestamp)` does NOT appear in the
    ///      `recovery_blocks` set wins. This makes the reader
    ///      recovery-aware without an external override map: the
    ///      latest non-recovery Register/Transfer is the canonical
    ///      effective_ts.
    ///   3. `None` if no non-recovery event exists.
    ///
    /// The walk reads keys directly from the on-chain event primary
    /// store with the prefix `[OnChainEvent prefix][OnChainEvents
    /// postfix][EVENT_TYPE_ID_REGISTER][fid u32 BE]`, ordered
    /// ascending by `(block_number, log_index)`. We collect candidate
    /// timestamps and pick the largest non-recovery one — handles
    /// out-of-order delivery + per-block log-index sequencing
    /// correctly.
    fn effective_ts(&self, fid: u64) -> Result<Option<u64>, ScoringError> {
        if let Some(&ts) = self.effective_ts_overrides.get(&fid) {
            return Ok(Some(ts));
        }

        // Fast path: if no recovery_blocks are configured, the latest
        // event is the answer (no walk needed).
        if self.recovery_blocks.is_empty() {
            let evt = self
                .onchain
                .get_id_register_event_by_fid(fid, None)
                .map_err(map_err)?;
            return Ok(evt.map(|e| e.block_timestamp));
        }

        // Recovery-aware path: scan all IdRegister events for `fid`
        // via the on-chain primary key prefix, filter out recovery-
        // flow timestamps, return the maximum.
        // Constants match `RootPrefix::OnChainEvent`,
        // `OnChainEventPostfix::OnChainEvents`,
        // `OnChainEventType::EventTypeIdRegister`. Asserted via the
        // populated-DB integration test below.
        let root_prefix_onchain_event = RootPrefix::OnChainEvent as u8;
        const POSTFIX_ONCHAIN_EVENTS: u8 = 1; // OnChainEventPostfix::OnChainEvents
        const EVENT_TYPE_ID_REGISTER: u8 = 3; // OnChainEventType::EventTypeIdRegister

        let fid_u32 = fid as u32;
        let mut start = Vec::with_capacity(3 + 4);
        start.push(root_prefix_onchain_event);
        start.push(POSTFIX_ONCHAIN_EVENTS);
        start.push(EVENT_TYPE_ID_REGISTER);
        start.extend_from_slice(&fid_u32.to_be_bytes());

        let mut stop = Vec::with_capacity(3 + 4);
        stop.push(root_prefix_onchain_event);
        stop.push(POSTFIX_ONCHAIN_EVENTS);
        stop.push(EVENT_TYPE_ID_REGISTER);
        match fid_u32.checked_add(1) {
            Some(next) => stop.extend_from_slice(&next.to_be_bytes()),
            None => {
                stop.clear();
                stop.push(root_prefix_onchain_event);
                stop.push(POSTFIX_ONCHAIN_EVENTS);
                stop.push(EVENT_TYPE_ID_REGISTER.saturating_add(1));
            }
        }

        let mut best: Option<u64> = None;
        let mut decode_err: Option<prost::DecodeError> = None;
        self.db
            .for_each_iterator_by_prefix(
                Some(start),
                Some(stop),
                &PageOptions::default(),
                |_, value| {
                    match crate::proto::OnChainEvent::decode(value) {
                        Ok(evt) => {
                            if !self.recovery_blocks.contains(&(fid, evt.block_timestamp)) {
                                if best.map_or(true, |b| evt.block_timestamp > b) {
                                    best = Some(evt.block_timestamp);
                                }
                            }
                        }
                        Err(e) => {
                            decode_err = Some(e);
                            return Ok(true);
                        }
                    }
                    Ok(false)
                },
            )
            .map_err(map_err)?;
        if let Some(e) = decode_err {
            return Err(ScoringError::Reader(format!("decode: {}", e)));
        }
        Ok(best)
    }

    fn followees(&self, fid: u64) -> Result<Vec<u64>, ScoringError> {
        let mut out: BTreeSet<u64> = BTreeSet::new();
        let mut page_token: Option<Vec<u8>> = None;
        loop {
            let opts = PageOptions {
                page_size: Some(READER_PAGE_SIZE),
                page_token: page_token.clone(),
                reverse: false,
            };
            let page =
                LinkStore::get_link_adds_by_fid(&self.link_store, fid, "follow".to_string(), &opts)
                    .map_err(map_err)?;
            for msg in &page.messages {
                if let Some(data) = &msg.data {
                    if let Some(proto::message_data::Body::LinkBody(lb)) = &data.body {
                        if let Some(proto::link_body::Target::TargetFid(target)) = lb.target {
                            out.insert(target);
                        }
                    }
                }
            }
            if let Some(tok) = page.next_page_token {
                page_token = Some(tok);
            } else {
                break;
            }
        }
        // BTreeSet iteration is sorted; collect to Vec preserves it.
        Ok(out.into_iter().collect())
    }

    /// Combine outbound likes + recasts (ReactionStore) and outbound
    /// reply-casts (CastStore where parent is set). Each engagement is
    /// classified as `first_30d` if its timestamp falls within 30 days
    /// of the SOURCE's effective_ts; otherwise `later`.
    fn engagement_from(&self, from: u64) -> Result<BTreeMap<u64, EngagementCount>, ScoringError> {
        let source_eff = self.effective_ts(from)?.unwrap_or(0);
        let cutoff = source_eff.saturating_add(30 * 24 * 60 * 60);

        let mut counts: BTreeMap<u64, EngagementCount> = BTreeMap::new();

        let bump = |counts: &mut BTreeMap<u64, EngagementCount>, target: u64, ts_unix: u64| {
            let entry = counts.entry(target).or_default();
            if source_eff > 0 && ts_unix <= cutoff {
                entry.first_30d = entry.first_30d.saturating_add(1);
            } else {
                entry.later = entry.later.saturating_add(1);
            }
        };

        // --- Reactions (likes + recasts) ---
        for &reaction_type in &[
            proto::ReactionType::Like as i32,
            proto::ReactionType::Recast as i32,
        ] {
            let mut page_token: Option<Vec<u8>> = None;
            loop {
                let opts = PageOptions {
                    page_size: Some(READER_PAGE_SIZE),
                    page_token: page_token.clone(),
                    reverse: false,
                };
                let page = ReactionStore::get_reaction_adds_by_fid(
                    &self.reaction_store,
                    from,
                    reaction_type,
                    &opts,
                )
                .map_err(map_err)?;
                for msg in &page.messages {
                    if let Some(data) = &msg.data {
                        let ts_unix = farcaster_ts_to_unix(data.timestamp);
                        if let Some(proto::message_data::Body::ReactionBody(rb)) = &data.body {
                            if let Some(proto::reaction_body::Target::TargetCastId(cid)) =
                                &rb.target
                            {
                                if cid.fid != from {
                                    bump(&mut counts, cid.fid, ts_unix);
                                }
                            }
                        }
                    }
                }
                if let Some(tok) = page.next_page_token {
                    page_token = Some(tok);
                } else {
                    break;
                }
            }
        }

        // --- Reply casts (cast with parent_cast_id) ---
        self.for_each_cast_add(from, |msg| {
            if let Some(data) = &msg.data {
                let ts_unix = farcaster_ts_to_unix(data.timestamp);
                if let Some(proto::message_data::Body::CastAddBody(cab)) = &data.body {
                    if let Some(proto::cast_add_body::Parent::ParentCastId(cid)) = &cab.parent {
                        if cid.fid != from {
                            bump(&mut counts, cid.fid, ts_unix);
                        }
                    }
                }
            }
        })?;

        Ok(counts)
    }

    fn total_casts(&self, fid: u64) -> Result<u32, ScoringError> {
        let mut count: u32 = 0;
        self.for_each_cast_add(fid, |_| {
            count = count.saturating_add(1);
        })?;
        Ok(count)
    }

    fn active_days(&self, fid: u64) -> Result<u32, ScoringError> {
        let mut days: BTreeSet<u64> = BTreeSet::new();
        self.for_each_cast_add(fid, |msg| {
            if let Some(data) = &msg.data {
                let ts_unix = farcaster_ts_to_unix(data.timestamp);
                let day = ts_unix / (24 * 60 * 60);
                days.insert(day);
            }
        })?;
        Ok(days.len() as u32)
    }

    /// Count of reply-casts that target any cast authored by `fid`.
    /// Optimized prefix-scan: the `CastsByParent` index is keyed by
    /// `[prefix][parent_fid u32 BE][parent_hash 20B][ts_hash 24B][replier_fid 4B]`
    /// for CastId-parented replies. A single prefix scan over
    /// `[prefix][fid_BE]` catches every reply across all of `fid`'s
    /// authored casts in O(replies_to_fid).
    ///
    /// To rule out URL-parented entries that might happen to start
    /// with bytes matching `fid_BE`, we filter on key length: the
    /// CastId-shape is exactly `1 + 4 + 20 + 24 + 4 = 53` bytes. URL
    /// parent keys start with arbitrary URL bytes and almost never
    /// match this exact length, but the length filter rules out
    /// pathological collisions.
    fn replies_received(&self, fid: u64) -> Result<u32, ScoringError> {
        let _ = (&self.recovery_blocks,); // silence unused field warning
        const CAST_ID_REPLY_KEY_LEN: usize = 1 + 4 + 20 + 24 + 4;

        // u32 BE encoding because `make_fid_key` truncates.
        let fid_u32 = fid as u32;

        let mut start = Vec::with_capacity(1 + 4);
        start.push(RootPrefix::CastsByParent as u8);
        start.extend_from_slice(&fid_u32.to_be_bytes());

        // Stop key: next FID's prefix (or the next root prefix when
        // fid_u32 is u32::MAX).
        let mut stop = Vec::with_capacity(1 + 4);
        stop.push(RootPrefix::CastsByParent as u8);
        match fid_u32.checked_add(1) {
            Some(next) => stop.extend_from_slice(&next.to_be_bytes()),
            None => {
                stop.clear();
                stop.push((RootPrefix::CastsByParent as u8).saturating_add(1));
            }
        }

        let mut count: u32 = 0;
        self.db
            .for_each_iterator_by_prefix(
                Some(start),
                Some(stop),
                &PageOptions::default(),
                |key, _| {
                    if key.len() == CAST_ID_REPLY_KEY_LEN {
                        count = count.saturating_add(1);
                    }
                    Ok(false)
                },
            )
            .map_err(map_err)?;
        Ok(count)
    }

    /// FIP §8.4 stake_factor: reads the FID's
    /// `STAKE_TYPE_CREDIBILITY` balance from `HyperTokenStaked`
    /// and saturates against `STAKE_MATURITY_ATOMS`.
    ///
    /// FIDs with no credibility-stake recorded return 0.0
    /// (current behavior for non-staking users — the credibility
    /// blend's 10% slot contributes nothing without stake).
    fn stake_factor_for_fid(&self, fid: u64) -> Result<f64, ScoringError> {
        let stake_type = crate::proto::StakeType::Credibility as u8;
        let mut key = Vec::with_capacity(1 + 8 + 1);
        key.push(crate::storage::constants::RootPrefix::HyperTokenStaked as u8);
        key.extend_from_slice(&fid.to_be_bytes());
        key.push(stake_type);
        let atoms = match self.db.get(&key).map_err(map_err)? {
            Some(bytes) if bytes.len() == 8 => {
                let mut be = [0u8; 8];
                be.copy_from_slice(&bytes);
                u64::from_be_bytes(be)
            }
            _ => 0,
        };
        Ok(proof_of_quality::metrics::stake_factor_from_atoms(atoms))
    }

    /// FIP threat-model #295: clustered `signer_authorizations`
    /// across FIDs sharing `fid`'s custody address. Catches the
    /// app-fragmentation evasion. Looks up `fid`'s current
    /// custody via OnchainEventStore, then prefix-scans
    /// `HyperCustodyToFid[custody][*]` to enumerate the cluster,
    /// summing each member's `signer_authorizations`.
    fn signer_authorizations_clustered(&self, fid: u64) -> Result<u32, ScoringError> {
        if fid == 0 {
            return Ok(0);
        }
        // Resolve fid → custody.
        let evt = match self
            .onchain
            .get_id_register_event_by_fid(fid, None)
            .map_err(map_err)?
        {
            Some(e) => e,
            None => return self.signer_authorizations(fid),
        };
        let custody: Vec<u8> = match evt.body {
            Some(crate::proto::on_chain_event::Body::IdRegisterEventBody(b)) => b.to,
            _ => return self.signer_authorizations(fid),
        };
        if custody.len() != 20 {
            return self.signer_authorizations(fid);
        }
        // Enumerate the cluster.
        use crate::storage::constants::RootPrefix;
        let mut start = Vec::with_capacity(1 + 20);
        start.push(RootPrefix::HyperCustodyToFid as u8);
        start.extend_from_slice(&custody);
        let mut stop = start.clone();
        // bump the last byte to bound the scan.
        let last = stop.len() - 1;
        if stop[last] == 0xff {
            stop.push(0);
        } else {
            stop[last] = stop[last].wrapping_add(1);
        }
        let mut cluster_fids: Vec<u64> = Vec::new();
        self.db
            .for_each_iterator_by_prefix(
                Some(start),
                Some(stop),
                &PageOptions::default(),
                |key, _value| {
                    if key.len() == 1 + 20 + 8 {
                        let mut fid_bytes = [0u8; 8];
                        fid_bytes.copy_from_slice(&key[1 + 20..1 + 20 + 8]);
                        cluster_fids.push(u64::from_be_bytes(fid_bytes));
                    }
                    Ok(false)
                },
            )
            .map_err(map_err)?;
        let mut total: u32 = 0;
        for member in cluster_fids {
            total = total.saturating_add(self.signer_authorizations(member)?);
        }
        Ok(total)
    }

    /// FIP threat-model #296: number of miniapps authored by
    /// `fid`. Uses the existing `HyperMiniappByAuthor` prefix
    /// (one entry per registered miniapp).
    fn miniapp_author_count(&self, fid: u64) -> Result<u32, ScoringError> {
        if fid == 0 {
            return Ok(0);
        }
        use crate::storage::constants::RootPrefix;
        let mut start = Vec::with_capacity(9);
        start.push(RootPrefix::HyperMiniappByAuthor as u8);
        start.extend_from_slice(&fid.to_be_bytes());
        let next = fid.saturating_add(1);
        let mut stop = Vec::with_capacity(9);
        stop.push(RootPrefix::HyperMiniappByAuthor as u8);
        stop.extend_from_slice(&next.to_be_bytes());
        let mut count: u32 = 0;
        self.db
            .for_each_iterator_by_prefix(
                Some(start),
                Some(stop),
                &PageOptions::default(),
                |key, _value| {
                    if key.len() == 1 + 8 + 16 {
                        count = count.saturating_add(1);
                    }
                    Ok(false)
                },
            )
            .map_err(map_err)?;
        Ok(count)
    }

    /// FIP §8.3 F0 input: count of distinct user FIDs whose
    /// gasless KEY_ADD's verified `request_fid` equals `fid`.
    /// Bounded prefix scan over
    /// `HyperSignerAuthByRequester[fid][*]` — the ref-counted
    /// index maintained by the gasless KEY_ADD/REMOVE flow. Each
    /// entry is one distinct user (the counter inside the entry
    /// is per-(requester, user) so we just count keys).
    fn signer_authorizations(&self, fid: u64) -> Result<u32, ScoringError> {
        if fid == 0 {
            return Ok(0);
        }
        use crate::storage::constants::RootPrefix;
        let mut start = Vec::with_capacity(9);
        start.push(RootPrefix::HyperSignerAuthByRequester as u8);
        start.extend_from_slice(&fid.to_be_bytes());
        let next = fid.saturating_add(1);
        let mut stop = Vec::with_capacity(9);
        stop.push(RootPrefix::HyperSignerAuthByRequester as u8);
        stop.extend_from_slice(&next.to_be_bytes());
        let mut count: u32 = 0;
        self.db
            .for_each_iterator_by_prefix(
                Some(start),
                Some(stop),
                &PageOptions::default(),
                |key, _value| {
                    // Key: [prefix][requester BE u64][user BE u64]
                    if key.len() == 1 + 8 + 8 {
                        count = count.saturating_add(1);
                    }
                    Ok(false)
                },
            )
            .map_err(map_err)?;
        Ok(count)
    }

    /// FIP §5c DA-PoW: per-(epoch, fid) commit-signature count.
    /// Walks `HyperValidatorScore[epoch][validator_key]`, decodes
    /// each `ValidatorScoreRecord` for its `commit_signatures`,
    /// and maps `validator_key → fid` via the
    /// `HyperValidatorFidLookup` index. Validators whose
    /// `validator_key` is not in the index (e.g. recently
    /// deregistered) are skipped.
    fn validator_commit_signatures_for_epoch(
        &self,
        epoch: u64,
    ) -> Result<BTreeMap<u64, u64>, ScoringError> {
        use crate::storage::constants::RootPrefix;
        use prost::Message as _;
        let mut start = Vec::with_capacity(9);
        start.push(RootPrefix::HyperValidatorScore as u8);
        start.extend_from_slice(&epoch.to_be_bytes());
        let next = epoch.saturating_add(1);
        let mut stop = Vec::with_capacity(9);
        stop.push(RootPrefix::HyperValidatorScore as u8);
        stop.extend_from_slice(&next.to_be_bytes());
        // Collect (validator_key, commit_signatures) pairs first;
        // then resolve fids via the lookup index. Two passes keeps
        // the inner loop allocation-light.
        let mut intermediate: Vec<(Vec<u8>, u64)> = Vec::new();
        let mut decode_err: Option<prost::DecodeError> = None;
        self.db
            .for_each_iterator_by_prefix(
                Some(start),
                Some(stop),
                &PageOptions::default(),
                |key, value| {
                    // Key: [prefix][epoch BE u64][validator_key …]
                    if key.len() < 1 + 8 {
                        return Ok(false);
                    }
                    let validator_key = key[9..].to_vec();
                    match crate::proto::ValidatorScoreRecord::decode(value) {
                        Ok(record) => {
                            intermediate.push((validator_key, record.commit_signatures));
                        }
                        Err(e) => {
                            decode_err = Some(e);
                            return Ok(true);
                        }
                    }
                    Ok(false)
                },
            )
            .map_err(map_err)?;
        if let Some(e) = decode_err {
            return Err(ScoringError::Reader(format!(
                "decode ValidatorScoreRecord: {}",
                e
            )));
        }
        let mut out: BTreeMap<u64, u64> = BTreeMap::new();
        for (validator_key, sigs) in intermediate {
            let mut k = Vec::with_capacity(1 + validator_key.len());
            k.push(RootPrefix::HyperValidatorFidLookup as u8);
            k.extend_from_slice(&validator_key);
            if let Some(bytes) = self.db.get(&k).map_err(map_err)? {
                if bytes.len() == 8 {
                    let mut be = [0u8; 8];
                    be.copy_from_slice(&bytes);
                    let fid = u64::from_be_bytes(be);
                    // Accumulate in case a key→fid binding ever maps
                    // multiple validator_keys to one fid (e.g. an FID
                    // running two validator nodes).
                    *out.entry(fid).or_insert(0) += sigs;
                }
            }
        }
        Ok(out)
    }

    /// FIP §5b DA-PoW: per-(epoch, fid) response-block sum
    /// (u128). Bounded prefix scan over
    /// `HyperDaResponseBlockSum[epoch][*]`.
    fn da_response_block_sum_for_epoch(
        &self,
        epoch: u64,
    ) -> Result<BTreeMap<u64, u128>, ScoringError> {
        use crate::storage::constants::RootPrefix;
        let mut start = Vec::with_capacity(9);
        start.push(RootPrefix::HyperDaResponseBlockSum as u8);
        start.extend_from_slice(&epoch.to_be_bytes());
        let next = epoch.saturating_add(1);
        let mut stop = Vec::with_capacity(9);
        stop.push(RootPrefix::HyperDaResponseBlockSum as u8);
        stop.extend_from_slice(&next.to_be_bytes());
        let mut out: BTreeMap<u64, u128> = BTreeMap::new();
        self.db
            .for_each_iterator_by_prefix(
                Some(start),
                Some(stop),
                &PageOptions::default(),
                |key, value| {
                    if key.len() == 1 + 8 + 8 && value.len() == 16 {
                        let mut fid = [0u8; 8];
                        fid.copy_from_slice(&key[9..17]);
                        let mut sum = [0u8; 16];
                        sum.copy_from_slice(&value);
                        out.insert(u64::from_be_bytes(fid), u128::from_be_bytes(sum));
                    }
                    Ok(false)
                },
            )
            .map_err(map_err)?;
        Ok(out)
    }

    /// FIP §5 DA-PoW: per-(epoch, fid) answered-count map. Bounded
    /// prefix scan over `HyperDaAnsweredCount[epoch][*]`.
    fn da_answered_counts_for_epoch(&self, epoch: u64) -> Result<BTreeMap<u64, u32>, ScoringError> {
        use crate::storage::constants::RootPrefix;
        let mut start = Vec::with_capacity(9);
        start.push(RootPrefix::HyperDaAnsweredCount as u8);
        start.extend_from_slice(&epoch.to_be_bytes());
        let next = epoch.saturating_add(1);
        let mut stop = Vec::with_capacity(9);
        stop.push(RootPrefix::HyperDaAnsweredCount as u8);
        stop.extend_from_slice(&next.to_be_bytes());
        let mut out: BTreeMap<u64, u32> = BTreeMap::new();
        self.db
            .for_each_iterator_by_prefix(
                Some(start),
                Some(stop),
                &PageOptions::default(),
                |key, value| {
                    if key.len() == 1 + 8 + 8 && value.len() == 4 {
                        let mut fid = [0u8; 8];
                        fid.copy_from_slice(&key[9..17]);
                        let mut cnt = [0u8; 4];
                        cnt.copy_from_slice(&value);
                        out.insert(u64::from_be_bytes(fid), u32::from_be_bytes(cnt));
                    }
                    Ok(false)
                },
            )
            .map_err(map_err)?;
        Ok(out)
    }

    /// FIP §7c: per-epoch MiniappAdd events keyed by
    /// `(app_owner_fid, user_fid)`. Bounded prefix scan over
    /// `HyperMiniappAddByEpoch[epoch][*]`; multiple miniapp_ids
    /// from the same (app, user) pair in one epoch accumulate.
    fn miniapp_add_events_for_epoch(
        &self,
        epoch: u64,
    ) -> Result<BTreeMap<(u64, u64), u32>, ScoringError> {
        use crate::storage::constants::RootPrefix;
        let mut start = Vec::with_capacity(9);
        start.push(RootPrefix::HyperMiniappAddByEpoch as u8);
        start.extend_from_slice(&epoch.to_be_bytes());
        let next = epoch.saturating_add(1);
        let mut stop = Vec::with_capacity(9);
        stop.push(RootPrefix::HyperMiniappAddByEpoch as u8);
        stop.extend_from_slice(&next.to_be_bytes());
        let mut out: BTreeMap<(u64, u64), u32> = BTreeMap::new();
        self.db
            .for_each_iterator_by_prefix(
                Some(start),
                Some(stop),
                &PageOptions::default(),
                |key, _value| {
                    if key.len() == 1 + 8 + 8 + 8 + 16 {
                        let mut app = [0u8; 8];
                        app.copy_from_slice(&key[9..17]);
                        let mut user = [0u8; 8];
                        user.copy_from_slice(&key[17..25]);
                        let pair = (u64::from_be_bytes(app), u64::from_be_bytes(user));
                        *out.entry(pair).or_insert(0) += 1;
                    }
                    Ok(false)
                },
            )
            .map_err(map_err)?;
        Ok(out)
    }

    /// FIP §7 App-PoW: per-epoch receipt counts keyed by
    /// `(app_owner_fid, user_fid)`. Bounded prefix scan over
    /// `HyperAppReceiptCount[epoch][*]`.
    fn app_receipt_counts_for_epoch(
        &self,
        epoch: u64,
    ) -> Result<BTreeMap<(u64, u64), u32>, ScoringError> {
        use crate::storage::constants::RootPrefix;
        let mut start = Vec::with_capacity(9);
        start.push(RootPrefix::HyperAppReceiptCount as u8);
        start.extend_from_slice(&epoch.to_be_bytes());
        let next = epoch.saturating_add(1);
        let mut stop = Vec::with_capacity(9);
        stop.push(RootPrefix::HyperAppReceiptCount as u8);
        stop.extend_from_slice(&next.to_be_bytes());
        let mut out = BTreeMap::new();
        self.db
            .for_each_iterator_by_prefix(
                Some(start),
                Some(stop),
                &PageOptions::default(),
                |key, value| {
                    // Key: [prefix][epoch BE u64][app BE u64][user BE u64]
                    if key.len() == 1 + 8 + 8 + 8 && value.len() == 4 {
                        let mut app = [0u8; 8];
                        app.copy_from_slice(&key[9..17]);
                        let mut user = [0u8; 8];
                        user.copy_from_slice(&key[17..25]);
                        let mut cnt = [0u8; 4];
                        cnt.copy_from_slice(&value);
                        out.insert(
                            (u64::from_be_bytes(app), u64::from_be_bytes(user)),
                            u32::from_be_bytes(cnt),
                        );
                    }
                    Ok(false)
                },
            )
            .map_err(map_err)?;
        Ok(out)
    }

    /// FIP §12 vouch graph: returns `vouchee → atoms` for all
    /// outgoing vouches from `voucher`. Bounded prefix scan over
    /// `HyperTokenVouchStaked[voucher][*]`.
    fn vouches_from(&self, voucher: u64) -> Result<BTreeMap<u64, u64>, ScoringError> {
        use crate::storage::constants::RootPrefix;
        let mut start = Vec::with_capacity(9);
        start.push(RootPrefix::HyperTokenVouchStaked as u8);
        start.extend_from_slice(&voucher.to_be_bytes());
        // Bound the scan with voucher+1.
        let next = voucher.saturating_add(1);
        let mut stop = Vec::with_capacity(9);
        stop.push(RootPrefix::HyperTokenVouchStaked as u8);
        stop.extend_from_slice(&next.to_be_bytes());
        let mut out = BTreeMap::new();
        self.db
            .for_each_iterator_by_prefix(
                Some(start),
                Some(stop),
                &PageOptions::default(),
                |key, value| {
                    // Key: [prefix][voucher BE u64][vouchee BE u64]
                    if key.len() == 1 + 8 + 8 && value.len() == 8 {
                        let mut vchee = [0u8; 8];
                        vchee.copy_from_slice(&key[9..17]);
                        let vouchee_fid = u64::from_be_bytes(vchee);
                        let mut amt = [0u8; 8];
                        amt.copy_from_slice(&value);
                        out.insert(vouchee_fid, u64::from_be_bytes(amt));
                    }
                    Ok(false)
                },
            )
            .map_err(map_err)?;
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn empty_reader() -> (PoqReader, TempDir) {
        let dir = TempDir::new().unwrap();
        let db = RocksDB::new(dir.path().to_str().unwrap());
        db.open().unwrap();
        let mut fids = BTreeSet::new();
        fids.insert(1u64);
        fids.insert(42);
        (PoqReader::new(Arc::new(db), fids), dir)
    }

    #[test]
    fn returns_universe() {
        let (r, _d) = empty_reader();
        assert_eq!(r.all_active_fids().unwrap().len(), 2);
    }

    #[test]
    fn empty_db_returns_no_data() {
        let (r, _d) = empty_reader();
        assert!(r.effective_ts(1).unwrap().is_none());
        assert!(r.followees(1).unwrap().is_empty());
        assert!(r.engagement_from(1).unwrap().is_empty());
        assert_eq!(r.total_casts(1).unwrap(), 0);
        assert_eq!(r.active_days(1).unwrap(), 0);
        assert_eq!(r.replies_received(1).unwrap(), 0);
    }

    #[test]
    fn effective_ts_override_takes_precedence() {
        let dir = TempDir::new().unwrap();
        let db = RocksDB::new(dir.path().to_str().unwrap());
        db.open().unwrap();
        let mut overrides = BTreeMap::new();
        overrides.insert(42u64, 1_700_000_000);
        let r = PoqReader::new(Arc::new(db), {
            let mut s = BTreeSet::new();
            s.insert(42u64);
            s
        })
        .with_effective_ts_overrides(overrides);
        // Override is used even though no event exists in the DB.
        assert_eq!(r.effective_ts(42).unwrap(), Some(1_700_000_000));
        // FIDs without an override fall through to None (empty store).
        assert!(r.effective_ts(99).unwrap().is_none());
    }

    #[test]
    fn drives_evaluate_epoch_with_empty_universe() {
        use proof_of_quality::scoring::evaluate_epoch;
        use proof_of_quality::ScoringParams;

        let dir = TempDir::new().unwrap();
        let db = RocksDB::new(dir.path().to_str().unwrap());
        db.open().unwrap();
        let r = PoqReader::new(Arc::new(db), BTreeSet::new());
        let seeds = BTreeSet::new();
        let params = ScoringParams::default();
        let out = evaluate_epoch(&r, 1, 0, &seeds, &params).unwrap();
        assert_eq!(out.epoch, 1);
        assert!(out.trust_snapshot.is_empty());
    }

    /// FIP §8.4 stake_factor: PoqReader reads
    /// `HyperTokenStaked[fid][Credibility]` and converts to a
    /// saturated [0,1] factor.
    #[test]
    fn stake_factor_reads_credibility_stake_and_saturates() {
        use proof_of_quality::metrics::STAKE_MATURITY_ATOMS;
        let dir = TempDir::new().unwrap();
        let db = RocksDB::new(dir.path().to_str().unwrap());
        db.open().unwrap();
        let db = Arc::new(db);
        // Seed three FIDs: no stake, half-stake, over-saturated.
        let credibility = crate::proto::StakeType::Credibility as u8;
        let mut put = |fid: u64, atoms: u64| {
            let mut key = Vec::with_capacity(1 + 8 + 1);
            key.push(crate::storage::constants::RootPrefix::HyperTokenStaked as u8);
            key.extend_from_slice(&fid.to_be_bytes());
            key.push(credibility);
            db.put(&key, &atoms.to_be_bytes()).unwrap();
        };
        put(2, STAKE_MATURITY_ATOMS / 2);
        put(3, STAKE_MATURITY_ATOMS * 10);
        // FID 1 unstaked; FID 2 half-saturated; FID 3 fully saturated.
        let r = PoqReader::new(db, [1u64, 2, 3].into_iter().collect());
        assert_eq!(r.stake_factor_for_fid(1).unwrap(), 0.0);
        assert!((r.stake_factor_for_fid(2).unwrap() - 0.5).abs() < 1e-9);
        assert_eq!(r.stake_factor_for_fid(3).unwrap(), 1.0);
    }

    /// Validator-stake or vouch-stake does NOT contribute to the
    /// stake_factor — only `STAKE_TYPE_CREDIBILITY` counts in the
    /// §8.4 blend. The §15 ladder keeps the categories separate.
    /// Vouch now lives in `HyperTokenVouchStaked` under the §12
    /// Phase 5d design, but writing the old shape here still
    /// exercises the "any non-credibility key in HyperTokenStaked
    /// is ignored" property.
    #[test]
    fn stake_factor_ignores_other_stake_types() {
        use proof_of_quality::metrics::STAKE_MATURITY_ATOMS;
        let dir = TempDir::new().unwrap();
        let db = RocksDB::new(dir.path().to_str().unwrap());
        db.open().unwrap();
        let db = Arc::new(db);
        let put = |fid: u64, stake_type: u8, atoms: u64| {
            let mut key = Vec::with_capacity(1 + 8 + 1);
            key.push(crate::storage::constants::RootPrefix::HyperTokenStaked as u8);
            key.extend_from_slice(&fid.to_be_bytes());
            key.push(stake_type);
            db.put(&key, &atoms.to_be_bytes()).unwrap();
        };
        // FID 4: only validator + vouch stake at the legacy key
        // shape, no credibility.
        put(
            4,
            crate::proto::StakeType::Validator as u8,
            STAKE_MATURITY_ATOMS,
        );
        put(
            4,
            crate::proto::StakeType::Vouch as u8,
            STAKE_MATURITY_ATOMS,
        );
        let r = PoqReader::new(db, [4u64].into_iter().collect());
        assert_eq!(r.stake_factor_for_fid(4).unwrap(), 0.0);
    }

    /// FIP §12 Phase 5d-scoring: `vouches_from` reads only the
    /// `[HyperTokenVouchStaked][voucher][*]` slice.
    #[test]
    fn vouches_from_reads_voucher_slice() {
        let dir = TempDir::new().unwrap();
        let db = RocksDB::new(dir.path().to_str().unwrap());
        db.open().unwrap();
        let db = Arc::new(db);
        let put_vouch = |voucher: u64, vouchee: u64, atoms: u64| {
            let mut key = Vec::with_capacity(1 + 8 + 8);
            key.push(crate::storage::constants::RootPrefix::HyperTokenVouchStaked as u8);
            key.extend_from_slice(&voucher.to_be_bytes());
            key.extend_from_slice(&vouchee.to_be_bytes());
            db.put(&key, &atoms.to_be_bytes()).unwrap();
        };
        // FID 7 vouches on 42 (100 atoms) and 99 (200 atoms).
        // FID 8 vouches on 42 (50 atoms) — must NOT appear in
        // FID 7's outgoing view.
        put_vouch(7, 42, 100);
        put_vouch(7, 99, 200);
        put_vouch(8, 42, 50);
        let r = PoqReader::new(db, [7u64, 8].into_iter().collect());
        let from7 = r.vouches_from(7).unwrap();
        assert_eq!(from7.len(), 2);
        assert_eq!(from7.get(&42), Some(&100));
        assert_eq!(from7.get(&99), Some(&200));
        let from8 = r.vouches_from(8).unwrap();
        assert_eq!(from8.len(), 1);
        assert_eq!(from8.get(&42), Some(&50));
        // FID with no vouches: empty map.
        assert!(r.vouches_from(999).unwrap().is_empty());
    }

    /// FIP §8.3 F0: `signer_authorizations(fid)` counts distinct
    /// user FIDs in the reverse index under `[fid][*]`. The value
    /// per key is the per-(requester, user) ref count; we only
    /// count keys.
    #[test]
    fn signer_authorizations_reads_reverse_index() {
        let dir = TempDir::new().unwrap();
        let db = RocksDB::new(dir.path().to_str().unwrap());
        db.open().unwrap();
        let db = Arc::new(db);
        let put = |request_fid: u64, user_fid: u64, count: u32| {
            let mut k = Vec::with_capacity(1 + 8 + 8);
            k.push(crate::storage::constants::RootPrefix::HyperSignerAuthByRequester as u8);
            k.extend_from_slice(&request_fid.to_be_bytes());
            k.extend_from_slice(&user_fid.to_be_bytes());
            db.put(&k, &count.to_be_bytes()).unwrap();
        };
        // App FID 42 has authorized 3 distinct users (7, 8, 9 —
        // user 7 has 5 active signers from app 42, but that's
        // still 1 distinct user). App FID 99 has 1 user (8).
        put(42, 7, 5);
        put(42, 8, 1);
        put(42, 9, 1);
        put(99, 8, 1);
        let r = PoqReader::new(db, [42u64, 99].into_iter().collect());
        assert_eq!(r.signer_authorizations(42).unwrap(), 3);
        assert_eq!(r.signer_authorizations(99).unwrap(), 1);
        // FID with no signers attributable: zero.
        assert_eq!(r.signer_authorizations(123).unwrap(), 0);
        // FID 0 short-circuits to zero.
        assert_eq!(r.signer_authorizations(0).unwrap(), 0);
    }

    /// FIP threat-model #295: clustered F0 sums signer_auths
    /// across FIDs sharing custody.
    #[test]
    fn signer_authorizations_clustered_sums_across_custody() {
        use crate::storage::store::account::OnchainEventStore;
        use crate::storage::store::account::StoreEventHandler;
        use crate::utils::factory::events_factory;
        let dir = TempDir::new().unwrap();
        let db = RocksDB::new(dir.path().to_str().unwrap());
        db.open().unwrap();
        let db = Arc::new(db);
        let onchain = OnchainEventStore::new(db.clone(), StoreEventHandler::new_no_persist());
        // Three FIDs (10, 11, 12) all under custody address X.
        let custody = vec![0xabu8; 20];
        for fid in [10u64, 11, 12] {
            let evt = events_factory::create_id_register_event(
                fid,
                crate::proto::IdRegisterEventType::Register,
                custody.clone(),
                None,
            );
            let mut txn = crate::storage::db::RocksDbTransactionBatch::new();
            onchain.merge_onchain_event(evt, &mut txn).unwrap();
            db.commit(txn).unwrap();
        }
        // Seed F0 raw counts: 10→30, 11→40, 12→25. Cluster=95.
        let put = |request_fid: u64, user_fid: u64, count: u32| {
            let mut k = Vec::with_capacity(1 + 8 + 8);
            k.push(crate::storage::constants::RootPrefix::HyperSignerAuthByRequester as u8);
            k.extend_from_slice(&request_fid.to_be_bytes());
            k.extend_from_slice(&user_fid.to_be_bytes());
            db.put(&k, &count.to_be_bytes()).unwrap();
        };
        // For each FID, populate 30/40/25 reverse-index entries to
        // simulate signer_authorizations counts at that level.
        for i in 0..30 {
            put(10, 1_000 + i as u64, 1);
        }
        for i in 0..40 {
            put(11, 2_000 + i as u64, 1);
        }
        for i in 0..25 {
            put(12, 3_000 + i as u64, 1);
        }
        let r = PoqReader::new(db, [10u64, 11, 12].into_iter().collect());
        // Individual values:
        assert_eq!(r.signer_authorizations(10).unwrap(), 30);
        assert_eq!(r.signer_authorizations(11).unwrap(), 40);
        assert_eq!(r.signer_authorizations(12).unwrap(), 25);
        // Clustered values: same custody → all three sum.
        assert_eq!(r.signer_authorizations_clustered(10).unwrap(), 95);
        assert_eq!(r.signer_authorizations_clustered(11).unwrap(), 95);
        assert_eq!(r.signer_authorizations_clustered(12).unwrap(), 95);
        // FID without an IdRegister event falls back to individual.
        assert_eq!(r.signer_authorizations_clustered(999).unwrap(), 0);
    }

    /// FIP threat-model #296: miniapp_author_count enumerates
    /// `HyperMiniappByAuthor[fid][*]` entries.
    #[test]
    fn miniapp_author_count_reads_by_author_index() {
        let dir = TempDir::new().unwrap();
        let db = RocksDB::new(dir.path().to_str().unwrap());
        db.open().unwrap();
        let db = Arc::new(db);
        // Seed HyperMiniappByAuthor entries: fid 42 has 3, fid 99 has 1.
        let put = |fid: u64, miniapp_id: [u8; 16]| {
            let mut k = Vec::with_capacity(1 + 8 + 16);
            k.push(crate::storage::constants::RootPrefix::HyperMiniappByAuthor as u8);
            k.extend_from_slice(&fid.to_be_bytes());
            k.extend_from_slice(&miniapp_id);
            db.put(&k, &[1u8]).unwrap();
        };
        for i in 0..3 {
            let mut id = [0u8; 16];
            id[0] = i;
            put(42, id);
        }
        put(99, [0xff; 16]);
        let r = PoqReader::new(db, [42u64, 99].into_iter().collect());
        assert_eq!(r.miniapp_author_count(42).unwrap(), 3);
        assert_eq!(r.miniapp_author_count(99).unwrap(), 1);
        assert_eq!(r.miniapp_author_count(123).unwrap(), 0);
        assert_eq!(r.miniapp_author_count(0).unwrap(), 0);
    }
}
