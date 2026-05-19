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
        let uniqueness = if class == FeeClass::CastAdd {
            let text = data
                .body
                .as_ref()
                .and_then(|b| match b {
                    proto::message_data::Body::CastAddBody(c) => Some(c.text.as_str()),
                    _ => None,
                })
                .unwrap_or("");
            self.fingerprint_store
                .uniqueness_score(text, data.timestamp as u64)
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

    /// After a CastAdd has been successfully merged, insert its
    /// fingerprint so subsequent casts in the rolling window see this
    /// content as a near-dup. No-op for non-cast types.
    pub fn record_fingerprint_if_cast(&self, msg: &proto::Message) -> Result<(), FeeChargeError> {
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
        let text = data
            .body
            .as_ref()
            .and_then(|b| match b {
                proto::message_data::Body::CastAddBody(c) => Some(c.text.as_str()),
                _ => None,
            })
            .unwrap_or("");
        if text.is_empty() {
            return Ok(());
        }
        self.fingerprint_store
            .insert(data.fid, text, data.timestamp as u64)
            .map_err(|e| FeeChargeError::Fingerprint(e.to_string()))?;
        Ok(())
    }
}
