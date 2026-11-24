use informalsystems_malachitebft_core_types::{NilOrVal, ThresholdParams};
use libp2p::identity::ed25519::PublicKey;

use crate::consensus::validator::StoredValidatorSets;
use crate::core::error::HubError;
use crate::core::types::{CommitsExt, Vote, FARCASTER_EPOCH};
use crate::proto::{self};
use crate::version::version::{EngineVersion, ProtocolFeature};
use itertools::Itertools;
use prost::Message;
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

/// Hash that commit certificates sign for a shard chunk: blake3 of the encoded header.
pub fn shard_chunk_hash(header: &proto::ShardHeader) -> Vec<u8> {
    blake3::hash(&header.encode_to_vec()).as_bytes().to_vec()
}

/// blake3 over a shard chunk's transactions in order, each length-delimited so that different
/// transaction lists cannot encode to the same bytes.
pub fn shard_transactions_hash(transactions: &[proto::Transaction]) -> Vec<u8> {
    let mut hasher = blake3::Hasher::new();
    for transaction in transactions {
        hasher.update(&transaction.encode_length_delimited_to_vec());
    }
    hasher.finalize().as_bytes().to_vec()
}

/// The `transactions_root` a shard or block header must carry for `transactions` under `version`:
/// their [`shard_transactions_hash`] once `HeaderTransactionsRoot` is enabled, empty before, so
/// headers from earlier versions hash exactly as they did.
pub fn expected_transactions_root(
    transactions: &[proto::Transaction],
    version: EngineVersion,
) -> Vec<u8> {
    if version.is_enabled(ProtocolFeature::HeaderTransactionsRoot) {
        // A node that does not know a field added after `version` decodes `data` without it.
        shard_transactions_hash(
            &crate::storage::store::account::transactions_without_unknown_fields(
                transactions,
                version,
            ),
        )
    } else {
        vec![]
    }
}

/// Hash that commit certificates sign for a block: blake3 of the encoded header.
pub fn block_hash(header: &proto::BlockHeader) -> Vec<u8> {
    blake3::hash(&header.encode_to_vec()).as_bytes().to_vec()
}

/// The `shard_witnesses_hash` committed to in a block header.
pub fn shard_witness_hash(witness: &proto::ShardWitness) -> Vec<u8> {
    blake3::hash(&witness.encode_to_vec()).as_bytes().to_vec()
}

/// The `events_hash` committed to in a block header. Empty when there are no events.
pub fn block_events_hash(events: &[proto::BlockEvent]) -> Vec<u8> {
    if events.is_empty() {
        return vec![];
    }
    let mut events_hasher = blake3::Hasher::new();
    for event in events {
        events_hasher.update(&event.hash);
    }
    events_hasher.finalize().as_bytes().to_vec()
}

/// True if each event's hash covers its data and the events together hash to `events_hash`.
pub fn block_events_match_hash(events: &[proto::BlockEvent], events_hash: &[u8]) -> bool {
    let events_self_consistent = events.iter().all(|event| match &event.data {
        Some(data) => event.hash == blake3::hash(&data.encode_to_vec()).as_bytes().to_vec(),
        None => false,
    });
    events_self_consistent && block_events_hash(events) == events_hash
}

/// Verifies that `commits` is a quorum of valid precommits from the validator set. This only
/// authenticates the certificate itself; callers must separately check that the certificate's
/// height and value match the value it is attached to.
pub fn verify_signatures(commits: &proto::Commits, validator_sets: &StoredValidatorSets) -> bool {
    let certificate = match commits.try_to_commit_certificate() {
        Ok(certificate) => certificate,
        Err(err) => {
            error!("Malformed commits: {}", err);
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

    #[test]
    fn test_expected_transactions_root_hashes_data_as_older_nodes_decode_it() {
        // A node without `Embed.emoji_label` decodes a chunk's `data` without it, and its root is
        // over that, so below InlineCustomEmoji every node hashes the label-less encoding.
        let transactions = |label: &str| {
            vec![proto::Transaction {
                fid: 1,
                user_messages: vec![proto::Message {
                    data: Some(proto::MessageData {
                        body: Some(proto::message_data::Body::CastAddBody(proto::CastAddBody {
                            text: ":check:".to_string(),
                            embeds: vec![proto::Embed {
                                embed: Some(proto::embed::Embed::Url(
                                    "https://example.com/check.webp".to_string(),
                                )),
                                emoji_label: label.to_string(),
                            }],
                            ..Default::default()
                        })),
                        ..Default::default()
                    }),
                    ..Default::default()
                }],
                ..Default::default()
            }]
        };
        let (labelled, as_decoded_by_older_nodes) = (transactions("check"), transactions(""));
        assert_ne!(
            shard_transactions_hash(&labelled),
            shard_transactions_hash(&as_decoded_by_older_nodes)
        );
        assert_eq!(
            expected_transactions_root(&labelled, EngineVersion::V24),
            shard_transactions_hash(&as_decoded_by_older_nodes)
        );
        assert_eq!(
            expected_transactions_root(&labelled, EngineVersion::V25),
            shard_transactions_hash(&labelled)
        );
    }

    #[test]
    fn test_expected_transactions_root_is_empty_before_v23() {
        let transactions = vec![proto::Transaction {
            fid: 1,
            ..Default::default()
        }];
        assert!(expected_transactions_root(&transactions, EngineVersion::V22).is_empty());
        assert_eq!(
            expected_transactions_root(&transactions, EngineVersion::V23),
            shard_transactions_hash(&transactions)
        );
    }
}
