//! The `KEY_REMOVE` messages of shards 1 and 2 that are leaves of the state
//! trie (FIP §16.13, §5.1).
//!
//! A `KEY_REMOVE` merge deletes the gasless key record, so no snapchain
//! store keeps the message. Before the pivot the block events of the shard
//! carry it. After the pivot shard 0 sends it in the outbox, which leaves no
//! block event. The content replay and the Hypersnap blocks keep a copy with
//! each trie update, so that a DA answer and a trie build find it.
//!
//! Storage layout:
//! ```text
//! [RootPrefix::HyperKeyRemoveMessage (1B)] [FID (8B, BE)] [hash]
//!     -> encoded Message
//! ```

use crate::core::error::HubError;
use crate::proto::{self, hub_event, MessageType};
use crate::storage::constants::RootPrefix;
use crate::storage::db::{RocksDB, RocksDbTransactionBatch};
use prost::Message as _;

pub fn make_key_remove_message_key(fid: u64, hash: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(1 + 8 + hash.len());
    key.push(RootPrefix::HyperKeyRemoveMessage as u8);
    key.extend_from_slice(&fid.to_be_bytes());
    key.extend_from_slice(hash);
    key
}

pub fn get_key_remove_message(
    db: &RocksDB,
    fid: u64,
    hash: &[u8],
) -> Result<Option<proto::Message>, HubError> {
    db.get(&make_key_remove_message_key(fid, hash))?
        .map(|v| {
            proto::Message::decode(v.as_slice())
                .map_err(|e| HubError::invalid_internal_state(&e.to_string()))
        })
        .transpose()
}

/// Mirror the `KEY_REMOVE` messages that `event` puts in the trie or takes
/// out of it (the keys of `TrieKey::for_hub_event`, inserts before deletes).
pub fn stage_key_remove_messages(txn: &mut RocksDbTransactionBatch, event: &proto::HubEvent) {
    let is_key_remove = |m: &proto::Message| m.msg_type() == MessageType::KeyRemove;
    let key = |m: &proto::Message| make_key_remove_message_key(m.fid(), &m.hash);
    let delete = |txn: &mut RocksDbTransactionBatch, m: &proto::Message| {
        if is_key_remove(m) {
            txn.delete(key(m));
        }
    };
    match &event.body {
        Some(hub_event::Body::MergeMessageBody(merge)) => {
            if let Some(m) = merge.message.as_ref().filter(|m| is_key_remove(m)) {
                txn.put(key(m), m.encode_to_vec());
            }
            for m in &merge.deleted_messages {
                delete(txn, m);
            }
        }
        Some(hub_event::Body::PruneMessageBody(prune)) => {
            if let Some(m) = &prune.message {
                delete(txn, m);
            }
        }
        Some(hub_event::Body::RevokeMessageBody(revoke)) => {
            if let Some(m) = &revoke.message {
                delete(txn, m);
            }
        }
        _ => {}
    }
}
