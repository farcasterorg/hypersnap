//! Per-validator score tracking per FIP-hyper-validator-selection §5.
//!
//! Counters for successful/missed/invalid proposals plus commit-signature
//! contributions, persisted at `[HyperValidatorScore][epoch][validator_key]`.
//! The computed `score` field weights each counter and is used by:
//!   - The next epoch's selector (weighted leader probability)
//!   - Auto-deregistration of validators below the activity threshold
//!
//! Score weights are configurable; the FIP-suggested defaults are encoded as
//! constants below and documented in `ScoreWeights::default()`.

use crate::core::error::HubError;
use crate::proto;
use crate::storage::constants::RootPrefix;
use crate::storage::db::RocksDB;
use prost::Message;
use std::sync::Arc;

/// FIP-suggested score weights. Successful proposals are heavily rewarded;
/// commit participation matters less per event but accumulates; misses and
/// especially invalid proposals are penalized aggressively.
#[derive(Clone, Copy, Debug)]
pub struct ScoreWeights {
    pub proposal: i64,
    pub participation: i64,
    pub miss_penalty: i64,
    pub invalid_penalty: i64,
}

impl Default for ScoreWeights {
    fn default() -> Self {
        Self {
            proposal: 100,
            participation: 1,
            miss_penalty: 50,
            invalid_penalty: 1_000,
        }
    }
}

/// Auto-deregistration threshold per FIP §5.3. A validator that misses this
/// many consecutive proposals is automatically removed at the next epoch
/// boundary. Tracked at the call-site of `record_missed_proposal`.
pub const AUTO_DEREGISTER_CONSECUTIVE_MISSES: u64 = 100;

#[derive(thiserror::Error, Debug)]
pub enum ScoreError {
    #[error("validator_key must be exactly 32 bytes (got {0})")]
    BadValidatorKey(usize),
    #[error(transparent)]
    Hub(#[from] HubError),
    #[error(transparent)]
    Decode(#[from] prost::DecodeError),
}

#[derive(Clone)]
pub struct ValidatorScoreTracker {
    db: Arc<RocksDB>,
    weights: ScoreWeights,
}

impl ValidatorScoreTracker {
    pub fn new(db: Arc<RocksDB>, weights: ScoreWeights) -> Self {
        Self { db, weights }
    }

    pub fn weights(&self) -> ScoreWeights {
        self.weights
    }

    fn make_key(epoch: u64, validator_key: &[u8]) -> Vec<u8> {
        let mut k = Vec::with_capacity(1 + 8 + validator_key.len());
        k.push(RootPrefix::HyperValidatorScore as u8);
        k.extend_from_slice(&epoch.to_be_bytes());
        k.extend_from_slice(validator_key);
        k
    }

    fn fetch(
        &self,
        epoch: u64,
        validator_key: &[u8],
    ) -> Result<proto::ValidatorScoreRecord, ScoreError> {
        let k = Self::make_key(epoch, validator_key);
        match self.db.get(&k).map_err(HubError::from)? {
            Some(bytes) => Ok(proto::ValidatorScoreRecord::decode(bytes.as_slice())?),
            None => Ok(proto::ValidatorScoreRecord {
                validator_key: validator_key.to_vec(),
                epoch,
                successful_proposals: 0,
                missed_proposals: 0,
                invalid_proposals: 0,
                commit_signatures: 0,
                score: 0,
                consecutive_misses: 0,
            }),
        }
    }

    fn persist(&self, record: &proto::ValidatorScoreRecord) -> Result<(), ScoreError> {
        let k = Self::make_key(record.epoch, &record.validator_key);
        self.db
            .put(&k, &record.encode_to_vec())
            .map_err(HubError::from)?;
        Ok(())
    }

    fn recompute_score(&self, record: &mut proto::ValidatorScoreRecord) {
        let s = (record.successful_proposals as i64) * self.weights.proposal
            + (record.commit_signatures as i64) * self.weights.participation
            - (record.missed_proposals as i64) * self.weights.miss_penalty
            - (record.invalid_proposals as i64) * self.weights.invalid_penalty;
        record.score = s;
    }

    fn validate_key(validator_key: &[u8]) -> Result<(), ScoreError> {
        if validator_key.len() != 32 {
            return Err(ScoreError::BadValidatorKey(validator_key.len()));
        }
        Ok(())
    }

    pub fn record_successful_proposal(
        &self,
        epoch: u64,
        validator_key: &[u8],
    ) -> Result<(), ScoreError> {
        Self::validate_key(validator_key)?;
        let mut record = self.fetch(epoch, validator_key)?;
        record.successful_proposals += 1;
        record.consecutive_misses = 0; // reset on success
        self.recompute_score(&mut record);
        self.persist(&record)
    }

    pub fn record_missed_proposal(
        &self,
        epoch: u64,
        validator_key: &[u8],
    ) -> Result<(), ScoreError> {
        Self::validate_key(validator_key)?;
        let mut record = self.fetch(epoch, validator_key)?;
        record.missed_proposals += 1;
        record.consecutive_misses += 1;
        self.recompute_score(&mut record);
        self.persist(&record)
    }

    pub fn record_invalid_proposal(
        &self,
        epoch: u64,
        validator_key: &[u8],
    ) -> Result<(), ScoreError> {
        Self::validate_key(validator_key)?;
        let mut record = self.fetch(epoch, validator_key)?;
        record.invalid_proposals += 1;
        self.recompute_score(&mut record);
        self.persist(&record)
    }

    pub fn record_commit_signature(
        &self,
        epoch: u64,
        validator_key: &[u8],
    ) -> Result<(), ScoreError> {
        Self::validate_key(validator_key)?;
        let mut record = self.fetch(epoch, validator_key)?;
        record.commit_signatures += 1;
        self.recompute_score(&mut record);
        self.persist(&record)
    }

    pub fn get_score(
        &self,
        epoch: u64,
        validator_key: &[u8],
    ) -> Result<proto::ValidatorScoreRecord, ScoreError> {
        Self::validate_key(validator_key)?;
        self.fetch(epoch, validator_key)
    }

    /// Returns true if the validator's `consecutive_misses` counter has
    /// crossed `AUTO_DEREGISTER_CONSECUTIVE_MISSES`. The caller is expected
    /// to construct and submit a deregistration event for this validator
    /// at the next epoch boundary.
    pub fn should_auto_deregister(
        &self,
        epoch: u64,
        validator_key: &[u8],
    ) -> Result<bool, ScoreError> {
        Self::validate_key(validator_key)?;
        let record = self.fetch(epoch, validator_key)?;
        Ok(record.consecutive_misses >= AUTO_DEREGISTER_CONSECUTIVE_MISSES)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn make_tracker() -> (ValidatorScoreTracker, TempDir) {
        let dir = TempDir::new().unwrap();
        let db = RocksDB::new(dir.path().to_str().unwrap());
        db.open().unwrap();
        (
            ValidatorScoreTracker::new(Arc::new(db), ScoreWeights::default()),
            dir,
        )
    }

    fn vk(byte: u8) -> Vec<u8> {
        vec![byte; 32]
    }

    #[test]
    fn fresh_tracker_returns_zero_score() {
        let (t, _dir) = make_tracker();
        let r = t.get_score(1, &vk(1)).unwrap();
        assert_eq!(r.score, 0);
        assert_eq!(r.successful_proposals, 0);
    }

    #[test]
    fn successful_proposal_increases_score() {
        let (t, _dir) = make_tracker();
        t.record_successful_proposal(1, &vk(1)).unwrap();
        let r = t.get_score(1, &vk(1)).unwrap();
        assert_eq!(r.successful_proposals, 1);
        assert_eq!(r.score, 100);
    }

    #[test]
    fn missed_proposal_decreases_score() {
        let (t, _dir) = make_tracker();
        t.record_successful_proposal(1, &vk(1)).unwrap();
        t.record_missed_proposal(1, &vk(1)).unwrap();
        let r = t.get_score(1, &vk(1)).unwrap();
        // 1 successful (+100) − 1 missed (−50) = 50
        assert_eq!(r.score, 50);
    }

    #[test]
    fn invalid_proposal_heavily_penalized() {
        let (t, _dir) = make_tracker();
        t.record_successful_proposal(1, &vk(1)).unwrap();
        t.record_invalid_proposal(1, &vk(1)).unwrap();
        let r = t.get_score(1, &vk(1)).unwrap();
        // 100 − 1000 = −900
        assert_eq!(r.score, -900);
    }

    #[test]
    fn commit_signatures_accumulate() {
        let (t, _dir) = make_tracker();
        for _ in 0..5 {
            t.record_commit_signature(1, &vk(1)).unwrap();
        }
        let r = t.get_score(1, &vk(1)).unwrap();
        assert_eq!(r.commit_signatures, 5);
        assert_eq!(r.score, 5);
    }

    #[test]
    fn distinct_epochs_isolated() {
        let (t, _dir) = make_tracker();
        t.record_successful_proposal(1, &vk(1)).unwrap();
        t.record_successful_proposal(2, &vk(1)).unwrap();
        t.record_successful_proposal(2, &vk(1)).unwrap();
        let r1 = t.get_score(1, &vk(1)).unwrap();
        let r2 = t.get_score(2, &vk(1)).unwrap();
        assert_eq!(r1.successful_proposals, 1);
        assert_eq!(r2.successful_proposals, 2);
    }

    #[test]
    fn distinct_validators_isolated() {
        let (t, _dir) = make_tracker();
        t.record_successful_proposal(1, &vk(1)).unwrap();
        t.record_successful_proposal(1, &vk(2)).unwrap();
        t.record_successful_proposal(1, &vk(2)).unwrap();
        assert_eq!(t.get_score(1, &vk(1)).unwrap().successful_proposals, 1);
        assert_eq!(t.get_score(1, &vk(2)).unwrap().successful_proposals, 2);
    }

    #[test]
    fn validate_rejects_short_key() {
        let (t, _dir) = make_tracker();
        let result = t.record_successful_proposal(1, &[0u8; 16]);
        assert!(matches!(result, Err(ScoreError::BadValidatorKey(16))));
    }

    #[test]
    fn consecutive_misses_resets_on_success() {
        let (t, _dir) = make_tracker();
        // Three consecutive misses.
        for _ in 0..3 {
            t.record_missed_proposal(1, &vk(1)).unwrap();
        }
        assert_eq!(t.get_score(1, &vk(1)).unwrap().consecutive_misses, 3);

        // One success resets the counter.
        t.record_successful_proposal(1, &vk(1)).unwrap();
        assert_eq!(t.get_score(1, &vk(1)).unwrap().consecutive_misses, 0);
    }

    #[test]
    fn auto_deregister_triggers_at_threshold() {
        let (t, _dir) = make_tracker();
        for _ in 0..(AUTO_DEREGISTER_CONSECUTIVE_MISSES - 1) {
            t.record_missed_proposal(1, &vk(1)).unwrap();
        }
        // Just below threshold — should NOT trigger.
        assert!(!t.should_auto_deregister(1, &vk(1)).unwrap());

        // One more miss → at threshold.
        t.record_missed_proposal(1, &vk(1)).unwrap();
        assert!(t.should_auto_deregister(1, &vk(1)).unwrap());
    }

    #[test]
    fn auto_deregister_resets_on_recovery() {
        let (t, _dir) = make_tracker();
        for _ in 0..AUTO_DEREGISTER_CONSECUTIVE_MISSES {
            t.record_missed_proposal(1, &vk(1)).unwrap();
        }
        assert!(t.should_auto_deregister(1, &vk(1)).unwrap());

        // Validator recovers with one successful proposal.
        t.record_successful_proposal(1, &vk(1)).unwrap();
        assert!(!t.should_auto_deregister(1, &vk(1)).unwrap());
    }

    #[test]
    fn weights_are_configurable() {
        let dir = TempDir::new().unwrap();
        let db = RocksDB::new(dir.path().to_str().unwrap());
        db.open().unwrap();
        let custom = ScoreWeights {
            proposal: 10,
            participation: 5,
            miss_penalty: 20,
            invalid_penalty: 200,
        };
        let t = ValidatorScoreTracker::new(Arc::new(db), custom);
        t.record_successful_proposal(1, &vk(1)).unwrap();
        t.record_commit_signature(1, &vk(1)).unwrap();
        // 1 * 10 + 1 * 5 = 15
        assert_eq!(t.get_score(1, &vk(1)).unwrap().score, 15);
    }
}
