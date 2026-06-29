//! FIP-proof-of-quality §4 + FIP-proof-of-work-tokenization §12: live
//! per-message fee charging hooked into the snapchain merge path.
//!
//! For every CastAdd / LinkAdd / ReactionAdd / UserDataAdd / VerificationAdd
//! the engine merges, this module:
//!   1. Looks up the sender's trust score (PoQ output).
//!   2. Computes a uniqueness score against the rolling fingerprint
//!      window (CastAdd only; other types get uniqueness=1.0 since their
//!      dedup is identity-based by the merge stores).
//!   3. Computes `effective_fee = base × max(0, 1 − max(trust, uniqueness))`.
//!   4. Stages the per-message charge on the merge batch:
//!        debit fee_balance, +60% burn, +40% proposer pot.
//!   5. After a successful merge, inserts the fingerprint so subsequent
//!      casts in the same window see this content as a near-dup.
//!
//! All RocksDB writes are staged on the caller's `RocksDbTransactionBatch`
//! so fee accounting commits atomically with the merge.

use std::sync::Arc;

use proof_of_quality::fees::{compute_effective_fee_micro, FeeClass};

use crate::core::error::HubError;
use crate::hyper::fingerprint_store::FingerprintStore;
use crate::hyper::rewards::{RewardError, RewardStore};
use crate::hyper::trust_store::TrustScoreStore;
use crate::proto;
use crate::storage::db::{RocksDB, RocksDbTransactionBatch};

#[derive(thiserror::Error, Debug)]
pub enum FeeChargeError {
    #[error("missing message data")]
    MissingData,
    #[error(transparent)]
    Hub(#[from] HubError),
    #[error(transparent)]
    Reward(#[from] RewardError),
    #[error("fingerprint store: {0}")]
    Fingerprint(String),
}

pub struct FeeCharger {
    pub reward_store: RewardStore,
    pub fingerprint_store: FingerprintStore,
    pub trust_store: TrustScoreStore,
}

impl FeeCharger {
    pub fn new(db: Arc<RocksDB>) -> Self {
        Self {
            reward_store: RewardStore::new(db.clone()),
            fingerprint_store: FingerprintStore::new(db.clone()),
            trust_store: TrustScoreStore::new(db),
        }
    }

    /// Classify a snapchain message into its fee class. `None` means the
    /// message is not fee-bearing (removes, protocol messages).
    pub fn classify(msg: &proto::Message) -> Option<FeeClass> {
        let data = msg.data.as_ref()?;
        let mt = proto::MessageType::try_from(data.r#type).ok()?;
        let class = match mt {
            proto::MessageType::CastAdd => FeeClass::CastAdd,
            proto::MessageType::LinkAdd => FeeClass::LinkAdd,
            proto::MessageType::ReactionAdd => FeeClass::ReactionAdd,
            proto::MessageType::UserDataAdd => FeeClass::UserDataAdd,
            proto::MessageType::VerificationAddEthAddress => FeeClass::VerificationAdd,
            _ => return None,
        };
        Some(class)
    }

    /// Stage the fee for `msg` on `batch`. No-op for non-fee-bearing
    /// types. Returns `InsufficientBalance` if the sender's fee balance
    /// is below the computed effective fee.
    pub fn stage_fee(
        &self,
        msg: &proto::Message,
        batch: &mut RocksDbTransactionBatch,
    ) -> Result<u64, FeeChargeError> {
        let class = match Self::classify(msg) {
            Some(c) => c,
            None => return Ok(0),
        };
        let data = msg.data.as_ref().ok_or(FeeChargeError::MissingData)?;
        let sender_fid = data.fid;
        if sender_fid == 0 {
            return Ok(0);
        }
        let base = class.base_fee_micro();
        if base == 0 {
            return Ok(0);
        }

        let trust = self
            .trust_store
            .get(sender_fid)
            .map_err(FeeChargeError::from)?
            .unwrap_or(0.0);

        // Uniqueness only applies to CastAdd — the other Add types have
        // identity-based dedup at the merge store layer (LinkAdds key
        // on `(fid, target)`, ReactionAdds key on `(fid, target, type)`,
        // UserDataAdd is per-(fid, field), VerificationAdd is per-address),
        // so resubmitting "the same content" is a no-op write, not a
        // spam vector.
        //
        // F068 fix: derive uniqueness from a CANONICAL content
        // representation, not the raw `text`. Pre-fix an empty-text
        // CastAdd carrying only embeds/mentions/parent always scored
        // `uniqueness == 1.0` (the fingerprint store never stored
        // empty-text entries) → effective fee 0 → unbounded spam.
        // The canonical form folds in embeds + parent + mentions so
        // an embed-only or reply-only cast is fingerprinted under a
        // stable content key.
        let uniqueness = if class == FeeClass::CastAdd {
            let canonical = canonical_cast_content(data);
            self.fingerprint_store
                .uniqueness_score(&canonical, data.timestamp as u64, batch)
                .map_err(|e| FeeChargeError::Fingerprint(e.to_string()))?
        } else {
            1.0
        };

        let fee = compute_effective_fee_micro(base, trust, uniqueness);
        if fee == 0 {
            return Ok(0);
        }
        self.reward_store
            .stage_charge_message_fee(sender_fid, fee, batch)?;
        Ok(fee)
    }

    /// After a CastAdd has been successfully merged, stage the
    /// fingerprint write on the merge `batch` so it commits
    /// atomically. No-op for non-cast types.
    ///
    /// CRITICAL: this must go on the batch, not direct-write. A
    /// direct `db.put` here breaks deterministic state replay —
    /// validators replaying the proposer's block would see the
    /// proposer's fingerprint in the store (since it's already on
    /// disk) and compute a different `uniqueness_score` than the
    /// proposer did at replay time, producing a different effective
    /// fee and a `HashMismatch` against the proposed state root.
    pub fn record_fingerprint_if_cast(
        &self,
        msg: &proto::Message,
        batch: &mut RocksDbTransactionBatch,
    ) -> Result<(), FeeChargeError> {
        let data = match msg.data.as_ref() {
            Some(d) => d,
            None => return Ok(()),
        };
        let mt = match proto::MessageType::try_from(data.r#type) {
            Ok(m) => m,
            Err(_) => return Ok(()),
        };
        if mt != proto::MessageType::CastAdd {
            return Ok(());
        }
        // F068 fix: insert the canonical content fingerprint, matching
        // what `stage_fee` scored. Empty-text casts are now fingerprinted
        // when they carry an embed/parent/mention, so subsequent
        // copies of the same embed/parent/mention combo are detected
        // as near-duplicates and pay the fee.
        let canonical = canonical_cast_content(data);
        if canonical.is_empty() {
            // Truly empty cast (no text, no embeds, no parent, no
            // mentions) — validation rejects this elsewhere, but
            // guard anyway.
            return Ok(());
        }
        self.fingerprint_store
            .stage_insert(data.fid, &canonical, data.timestamp as u64, batch);
        Ok(())
    }
}

/// F068 fix: build a deterministic content string covering text +
/// embeds + parent + mentions. Both fee-scoring and fingerprint
/// insertion use this so the two halves of the uniqueness machinery
/// can never disagree on what content was. Order-stable: embeds and
/// mentions are emitted in proto-declared order; the prefix tags
/// keep the SimHash from collapsing "abc" + embed_X into the same
/// fingerprint as "abc" alone.
fn canonical_cast_content(data: &proto::MessageData) -> String {
    let Some(proto::message_data::Body::CastAddBody(body)) = data.body.as_ref() else {
        return String::new();
    };
    let mut out = String::new();
    if !body.text.is_empty() {
        out.push_str("t:");
        out.push_str(&body.text);
    }
    for e in &body.embeds {
        if let Some(inner) = &e.embed {
            match inner {
                proto::embed::Embed::Url(u) => {
                    out.push_str("|u:");
                    out.push_str(u);
                }
                proto::embed::Embed::CastId(cid) => {
                    out.push_str("|c:");
                    out.push_str(&cid.fid.to_string());
                    out.push(':');
                    out.push_str(&hex::encode(&cid.hash));
                }
            }
        }
    }
    for u in &body.embeds_deprecated {
        out.push_str("|d:");
        out.push_str(u);
    }
    for fid in &body.mentions {
        out.push_str("|m:");
        out.push_str(&fid.to_string());
    }
    if let Some(parent) = &body.parent {
        match parent {
            proto::cast_add_body::Parent::ParentCastId(cid) => {
                out.push_str("|p:");
                out.push_str(&cid.fid.to_string());
                out.push(':');
                out.push_str(&hex::encode(&cid.hash));
            }
            proto::cast_add_body::Parent::ParentUrl(u) => {
                out.push_str("|p:url:");
                out.push_str(u);
            }
        }
    }
    out
}
