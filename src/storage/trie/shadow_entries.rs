//! Key/value entries of the per-shard Keccak state trie on shards 1 and 2
//! (FIP-proof-of-work-tokenization §16.13, plan A5).
//!
//! The keys are the snapchain `TrieKey` bytes, so the Keccak trie holds
//! exactly the same set as the blake3 sync trie. The value of each key is the
//! canonical protobuf encoding of the object the key names:
//!
//! | Trie key                         | Value                         |
//! |----------------------------------|-------------------------------|
//! | `TrieKey::for_message(m)`        | `m.encode_to_vec()`           |
//! | `TrieKey::for_onchain_event(e)`  | `e.encode_to_vec()`           |
//! | `TrieKey::for_fname(fid, name)`  | `proof.encode_to_vec()`       |
//!
//! A storage-lend message has two keys (lender and borrower); both carry the
//! message bytes. Indexes and node-local data are not in the trie.
//!
//! No hub event carries the nonces and the last-use times of the gasless
//! keys (`is_gasless_state_key`). The content replay and the Hypersnap
//! blocks put their writes in the trie as their storage key and stored
//! bytes, as for the replica records (`ShardEngine::hypersnap_raw_ops`).
//! Their keys (6 and 38 bytes) are not `TrieKey` lengths (26 and 42 bytes).
//!
//! Before the pivot this trie is a shadow structure: the read node updates it
//! from the hub events of every committed chunk (§17.5 "Preparation in
//! epoch 0").

use super::merkle_trie::TrieKey;
use crate::proto;
use crate::storage::constants::{RootPrefix, UserPostfix};
use prost::Message as _;
use std::str;

/// The gasless-key records that no hub event carries: the user and app
/// nonces and the last-use times (`RootPrefix::GaslessKey`).
pub const GASLESS_STATE: [u8; 3] = [
    UserPostfix::GaslessKeyUserNonce as u8,
    UserPostfix::GaslessKeyAppNonce as u8,
    UserPostfix::GaslessKeyLastUsedAt as u8,
];

/// True for the storage key of a nonce or a last-use time of a gasless key.
pub fn is_gasless_state_key(key: &[u8]) -> bool {
    key.first() == Some(&(RootPrefix::GaslessKey as u8))
        && key.get(1).is_some_and(|p| GASLESS_STATE.contains(p))
}

/// Trie updates of one hub event: inserts with their values, then deletes.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ShadowEntries {
    pub inserts: Vec<(Vec<u8>, Vec<u8>)>,
    pub deletes: Vec<Vec<u8>>,
}

impl ShadowEntries {
    fn insert_message(&mut self, message: &proto::Message) {
        let value = message.encode_to_vec();
        for key in TrieKey::for_message(message) {
            self.inserts.push((key, value.clone()));
        }
    }

    fn delete_message(&mut self, message: &proto::Message) {
        self.deletes.extend(TrieKey::for_message(message));
    }

    /// Mirrors `TrieKey::for_hub_event`: the same keys, in the same insert and
    /// delete roles, with the values added.
    pub fn for_hub_event(event: &proto::HubEvent) -> ShadowEntries {
        let mut entries = ShadowEntries::default();
        match &event.body {
            Some(proto::hub_event::Body::MergeMessageBody(merge)) => {
                if let Some(msg) = &merge.message {
                    entries.insert_message(msg);
                }
                for deleted in &merge.deleted_messages {
                    entries.delete_message(deleted);
                }
            }
            Some(proto::hub_event::Body::MergeOnChainEventBody(merge)) => {
                if let Some(onchain_event) = &merge.on_chain_event {
                    entries.inserts.push((
                        TrieKey::for_onchain_event(onchain_event),
                        onchain_event.encode_to_vec(),
                    ));
                }
            }
            Some(proto::hub_event::Body::PruneMessageBody(prune)) => {
                if let Some(msg) = &prune.message {
                    entries.delete_message(msg);
                }
            }
            Some(proto::hub_event::Body::RevokeMessageBody(revoke)) => {
                if let Some(msg) = &revoke.message {
                    entries.delete_message(msg);
                }
            }
            Some(proto::hub_event::Body::MergeUsernameProofBody(merge)) => {
                if let Some(msg) = &merge.username_proof_message {
                    entries.insert_message(msg);
                }
                if let Some(msg) = &merge.deleted_username_proof_message {
                    entries.delete_message(msg);
                }
                if let Some(proof) = &merge.username_proof {
                    if proof.r#type == proto::UserNameType::UsernameTypeFname as i32
                        && proof.fid != 0
                    {
                        let name = str::from_utf8(&proof.name).unwrap().to_string();
                        entries
                            .inserts
                            .push((TrieKey::for_fname(proof.fid, &name), proof.encode_to_vec()));
                    }
                }
                if let Some(proof) = &merge.deleted_username_proof {
                    if proof.r#type == proto::UserNameType::UsernameTypeFname as i32 {
                        let name = str::from_utf8(&proof.name).unwrap().to_string();
                        entries.deletes.push(TrieKey::for_fname(proof.fid, &name));
                    }
                }
            }
            Some(proto::hub_event::Body::MergeFailure(_))
            | Some(proto::hub_event::Body::BlockConfirmedBody(_))
            | None => {}
        }
        entries
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::factory::{events_factory, hub_events_factory, messages_factory};

    fn keys_of(entries: &ShadowEntries) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
        (
            entries.inserts.iter().map(|(k, _)| k.clone()).collect(),
            entries.deletes.clone(),
        )
    }

    #[test]
    fn same_keys_as_the_blake3_trie() {
        let cast = messages_factory::casts::create_cast_add(42, "hello", None, None);
        let event = hub_events_factory::create_merge_event(&cast);
        let entries = ShadowEntries::for_hub_event(&event);
        assert_eq!(keys_of(&entries), TrieKey::for_hub_event(&event));
        assert_eq!(entries.inserts[0].1, cast.encode_to_vec());

        let onchain = events_factory::create_onchain_event(42);
        let event = proto::HubEvent {
            body: Some(proto::hub_event::Body::MergeOnChainEventBody(
                proto::MergeOnChainEventBody {
                    on_chain_event: Some(onchain.clone()),
                },
            )),
            ..Default::default()
        };
        let entries = ShadowEntries::for_hub_event(&event);
        assert_eq!(keys_of(&entries), TrieKey::for_hub_event(&event));
        assert_eq!(entries.inserts[0].1, onchain.encode_to_vec());
    }

    #[test]
    fn storage_lend_has_two_keys_with_the_same_value() {
        let lend = messages_factory::storage_lend::create_storage_lend(
            7,
            8,
            1,
            proto::StorageUnitType::UnitTypeLegacy,
            None,
            None,
        );
        let entries = ShadowEntries::for_hub_event(&hub_events_factory::create_merge_event(&lend));
        assert_eq!(entries.inserts.len(), 2);
        assert_ne!(entries.inserts[0].0, entries.inserts[1].0);
        assert_eq!(entries.inserts[0].1, entries.inserts[1].1);
    }
}
