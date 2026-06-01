use informalsystems_malachitebft_core_types::{NilOrVal, ThresholdParams};
use libp2p::identity::ed25519::PublicKey;

use crate::consensus::validator::StoredValidatorSets;
use crate::core::error::HubError;
use crate::core::types::{CommitsExt, Vote, FARCASTER_EPOCH};
use crate::proto::{self};
use itertools::Itertools;
use tracing::error;

#[derive(Clone, Debug, PartialEq, PartialOrd, Eq, Ord)]
pub struct FarcasterTime {
    time: u64, // seconds since the farcaster epoch
}

impl FarcasterTime {
    pub fn current() -> Self {
        let time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - (FARCASTER_EPOCH / 1000);
        FarcasterTime { time }
    }

    pub fn new(time: u64) -> Self {
        FarcasterTime { time }
    }

    pub fn from_unix_seconds(time: u64) -> Self {
        let time = time - (FARCASTER_EPOCH / 1000);
        FarcasterTime { time }
    }

    pub fn to_unix_seconds(&self) -> u64 {
        self.time + (FARCASTER_EPOCH / 1000)
    }

    pub fn to_u64(&self) -> u64 {
        self.time
    }

    pub fn incr_by(&self, secs: u64) -> Self {
        FarcasterTime {
            time: self.time + secs,
        }
    }

    pub fn decr_by(&self, secs: u64) -> Self {
        FarcasterTime {
            time: self.time - secs,
        }
    }
}

impl Into<u64> for FarcasterTime {
    fn into(self) -> u64 {
        self.time
    }
}

#[allow(dead_code)]
pub fn to_farcaster_time(time_ms: u64) -> Result<u64, HubError> {
    if time_ms < FARCASTER_EPOCH {
        return Err(HubError {
            code: "bad_request.invalid_param".to_string(),
            message: format!("time_ms is before the farcaster epoch: {}", time_ms),
        });
    }

    let seconds_since_epoch = (time_ms - FARCASTER_EPOCH) / 1000;
    if seconds_since_epoch > u32::MAX as u64 {
        return Err(HubError {
            code: "bad_request.invalid_param".to_string(),
            message: format!("time too far in future: {}", time_ms),
        });
    }

    Ok(seconds_since_epoch as u64)
}

#[allow(dead_code)]
pub fn from_farcaster_time(time: u64) -> u64 {
    time * 1000 + FARCASTER_EPOCH
}

#[allow(dead_code)]
pub fn get_farcaster_time() -> Result<u64, HubError> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| HubError {
            code: "internal_error".to_string(),
            message: format!("failed to get time: {}", e),
        })?;
    Ok(to_farcaster_time(now.as_millis() as u64)?)
}

pub fn calculate_message_hash(data_bytes: &[u8]) -> Vec<u8> {
    blake3::hash(data_bytes).as_bytes()[0..20].to_vec()
}

pub fn verify_signatures(commits: &proto::Commits, validator_sets: &StoredValidatorSets) -> bool {
    // F185 (F151 residual): use the fallible decoder. `to_commit_certificate`
    // panics on peer-controlled inputs — missing `height`/`value`, or any
    // `CommitSignature.signer` whose length is not 32 → `Address::from_vec`
    // `copy_from_slice` abort. The decided-value path on read nodes
    // receives `proto::Commits` via raw `proto::GossipMessage::decode`
    // (`gossip.rs::map_gossip_bytes_to_system_message`) and the sync
    // value-response path re-decodes the embedded `Block`/`ShardChunk`
    // (`read_sync.rs` ValueResponse handler) — both bypass the codec
    // arm that F151 made fallible, so any peer can crash every
    // subscribed read-node pre-verify with a single gossip frame. Drop
    // the block on Err rather than panicking the actor.
    let certificate = match commits.try_to_commit_certificate() {
        Ok(c) => c,
        Err(e) => {
            error!(
                error = e,
                "Malformed Commits in verify_signatures; dropping"
            );
            return false;
        }
    };

    let validator_set = validator_sets.get_validator_set(certificate.height.as_u64());

    let mut expected_pubkeys = validator_set
        .validators
        .iter()
        .map(|validator| validator.public_key.to_bytes());

    if !ThresholdParams::default().quorum.is_met(
        certificate.aggregated_signature.signatures.len() as u64,
        expected_pubkeys.len() as u64,
    ) {
        error!(%certificate.height, "Block did not have quorum");
        return false;
    }

    for signature in certificate.aggregated_signature.signatures {
        let address_bytes = &signature.address.0;
        if !expected_pubkeys.contains(address_bytes) {
            error!(%certificate.height, "Block contained signatures from unexpected signers");
            return false;
        }

        let vote = Vote::new_precommit(
            certificate.height,
            certificate.round,
            NilOrVal::Val(certificate.value_id.clone()),
            signature.address.clone(),
        );

        let public_key = PublicKey::try_from_bytes(address_bytes).unwrap();
        if !public_key.verify(&vote.to_sign_bytes(), &signature.signature.0) {
            error!(%certificate.height, "Block contained invalid signatures");
            return false;
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_farcaster_time() {
        let time = get_farcaster_time().unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        assert!(time <= now);
        assert_eq!(time, now / 1000 - FARCASTER_EPOCH / 1000);
    }

    #[test]
    fn test_to_farcaster_time() {
        // It is an error to pass a time before the farcaster epoch
        let time = to_farcaster_time(0);
        assert!(time.is_err());

        let time = to_farcaster_time(FARCASTER_EPOCH - 1);
        assert!(time.is_err());

        let time = to_farcaster_time(FARCASTER_EPOCH).unwrap();
        assert_eq!(time, 0);

        let time = to_farcaster_time(FARCASTER_EPOCH + 1000).unwrap();
        assert_eq!(time, 1);
    }

    #[test]
    fn test_from_farcaster_time() {
        let time = from_farcaster_time(0);
        assert_eq!(time, FARCASTER_EPOCH);

        let time = from_farcaster_time(1);
        assert_eq!(time, FARCASTER_EPOCH + 1000);
    }

    /// F185 regression: peer-gossiped `Commits` with a malformed
    /// `CommitSignature.signer` (length ≠ 32) must NOT panic
    /// `verify_signatures` via `Address::from_vec`'s `copy_from_slice`.
    /// Before the fix, `to_commit_certificate()` was called as the
    /// function's first statement and triggered a remote-panic-DoS on
    /// every subscribed read-node from a single gossip frame. After
    /// the fix, the malformed Commits returns `false` (block dropped).
    #[test]
    fn verify_signatures_drops_commits_with_short_signer() {
        use crate::consensus::consensus::ValidatorSetConfig;
        use crate::consensus::validator::StoredValidatorSet;
        use crate::core::types::{ShardId, SnapchainShard};

        let cfg = ValidatorSetConfig {
            effective_at: 0,
            validator_public_keys: vec![],
            shard_ids: vec![0],
        };
        let stored = StoredValidatorSet::new(SnapchainShard::new(0), &cfg);
        let sets = StoredValidatorSets::new(0, vec![stored]);

        let commits = proto::Commits {
            height: Some(proto::Height {
                shard_index: 0,
                block_number: 1,
            }),
            round: 0,
            value: Some(proto::ShardHash {
                shard_index: 0,
                hash: vec![0u8; 32],
            }),
            signatures: vec![proto::CommitSignature {
                signer: vec![0u8; 16], // ≠ 32 bytes — would panic Address::from_vec
                signature: vec![0u8; 64],
            }],
        };
        assert!(!verify_signatures(&commits, &sets));
    }

    /// F185 regression: peer-gossiped `Commits` with missing `height`
    /// must NOT panic via `to_commit_certificate`'s `unwrap()`.
    #[test]
    fn verify_signatures_drops_commits_with_missing_height() {
        use crate::consensus::consensus::ValidatorSetConfig;
        use crate::consensus::validator::StoredValidatorSet;
        use crate::core::types::{ShardId, SnapchainShard};

        let cfg = ValidatorSetConfig {
            effective_at: 0,
            validator_public_keys: vec![],
            shard_ids: vec![0],
        };
        let stored = StoredValidatorSet::new(SnapchainShard::new(0), &cfg);
        let sets = StoredValidatorSets::new(0, vec![stored]);

        let commits = proto::Commits {
            height: None,
            round: 0,
            value: Some(proto::ShardHash {
                shard_index: 0,
                hash: vec![0u8; 32],
            }),
            signatures: vec![],
        };
        assert!(!verify_signatures(&commits, &sets));
    }

    /// F185 regression: missing `value` (ShardHash) must NOT panic.
    #[test]
    fn verify_signatures_drops_commits_with_missing_value() {
        use crate::consensus::consensus::ValidatorSetConfig;
        use crate::consensus::validator::StoredValidatorSet;
        use crate::core::types::{ShardId, SnapchainShard};

        let cfg = ValidatorSetConfig {
            effective_at: 0,
            validator_public_keys: vec![],
            shard_ids: vec![0],
        };
        let stored = StoredValidatorSet::new(SnapchainShard::new(0), &cfg);
        let sets = StoredValidatorSets::new(0, vec![stored]);

        let commits = proto::Commits {
            height: Some(proto::Height {
                shard_index: 0,
                block_number: 1,
            }),
            round: 0,
            value: None,
            signatures: vec![],
        };
        assert!(!verify_signatures(&commits, &sets));
    }
}
