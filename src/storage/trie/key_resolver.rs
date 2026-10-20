//! Maps a blake3 sync-trie key back to the object it names, and to the value
//! bytes that the Keccak state trie stores for it (`shadow_entries`).
//!
//! The sync trie holds keys only. The shadow-trie backfill and the replicator
//! both need the message, on-chain event or fname proof behind each key. The
//! lookups go per (fid, type) and are cached, because trie keys come in FID
//! order.
//!
//! `KEY_REMOVE` is a special case: merging it deletes the gasless key record,
//! so no snapchain store keeps the message. The content replay and the
//! Hypersnap blocks keep it (`key_remove_store`). Otherwise it is found in
//! the shard's block events, which carry every `KEY_ADD`/`KEY_REMOVE`
//! replicated from shard 0 before the pivot.

use super::merkle_trie::{TrieKey, FNAME_MESSAGE_TYPE};
use crate::core::error::HubError;
use crate::proto::{self, MessageType, OnChainEventType};
use crate::storage::db::{PageOptions, RocksDbTransactionBatch};
use crate::storage::store::account::{
    get_key_remove_message, list_gasless_keys_by_fid, CastStore, LinkStore, StorageLendStore,
    UserDataStore, UsernameProofStore, VerificationStore, FID_BYTES,
};
use crate::storage::store::stores::Stores;
use prost::Message as _;
use std::collections::HashMap;

/// All messages of `message_type` for `fid` in the stores, or `None` if the
/// type is not kept in a message store. `LEND_STORAGE` includes the messages
/// in which `fid` is the borrower, because the sync trie has a key for both
/// sides.
pub fn messages_for_fid_and_type(
    stores: &Stores,
    fid: u64,
    message_type: MessageType,
) -> Result<Option<Vec<proto::Message>>, HubError> {
    let mut page_options = PageOptions::default();
    page_options.page_size = Some(usize::MAX);
    messages_of(
        stores,
        fid,
        message_type,
        &page_options,
        Option::<fn(&proto::Message) -> bool>::None,
    )
}

/// The message of `fid` and `message_type` with `hash`: from the hash index
/// for a cast, else from a scan of the FID's messages of the type that stops
/// at it.
pub fn message_by_hash(
    stores: &Stores,
    fid: u64,
    message_type: MessageType,
    hash: &[u8],
) -> Result<Option<proto::Message>, HubError> {
    if message_type == MessageType::CastAdd {
        return CastStore::get_cast_add(&stores.cast_store, fid, hash.to_vec());
    }
    let mut page_options = PageOptions::default();
    page_options.page_size = Some(1);
    Ok(messages_of(
        stores,
        fid,
        message_type,
        &page_options,
        Some(|m: &proto::Message| m.hash == hash),
    )?
    .and_then(|messages| messages.into_iter().find(|m| m.hash == hash)))
}

/// The messages of `fid` and `message_type` that pass `filter`, up to the
/// page size (some stores ignore both).
fn messages_of<F: Fn(&proto::Message) -> bool>(
    stores: &Stores,
    fid: u64,
    message_type: MessageType,
    page_options: &PageOptions,
    filter: Option<F>,
) -> Result<Option<Vec<proto::Message>>, HubError> {
    let page_options = page_options.clone();
    let messages = match message_type {
        MessageType::FrameAction
        | MessageType::None
        | MessageType::KeyAdd
        | MessageType::KeyRemove => return Ok(None),
        MessageType::CastAdd => {
            stores
                .cast_store
                .get_adds_by_fid(fid, &page_options, filter)?
                .messages
        }
        MessageType::CastRemove => {
            stores
                .cast_store
                .get_removes_by_fid(fid, &page_options, filter)?
                .messages
        }
        MessageType::ReactionAdd => {
            stores
                .reaction_store
                .get_adds_by_fid(fid, &page_options, filter)?
                .messages
        }
        MessageType::ReactionRemove => {
            stores
                .reaction_store
                .get_removes_by_fid(fid, &page_options, filter)?
                .messages
        }
        MessageType::LinkAdd => {
            stores
                .link_store
                .get_adds_by_fid(fid, &page_options, filter)?
                .messages
        }
        MessageType::LinkRemove => {
            stores
                .link_store
                .get_removes_by_fid(fid, &page_options, filter)?
                .messages
        }
        MessageType::LinkCompactState => {
            LinkStore::get_link_compact_state_message_by_fid(
                &stores.link_store,
                fid,
                &page_options,
            )?
            .messages
        }
        MessageType::UserDataAdd => {
            stores
                .user_data_store
                .get_adds_by_fid(fid, &page_options, filter)?
                .messages
        }
        MessageType::VerificationAddEthAddress => {
            VerificationStore::get_verification_adds_by_fid(
                &stores.verification_store,
                fid,
                &page_options,
            )?
            .messages
        }
        MessageType::VerificationRemove => {
            VerificationStore::get_verification_removes_by_fid(
                &stores.verification_store,
                fid,
                &page_options,
            )?
            .messages
        }
        MessageType::UsernameProof => {
            UsernameProofStore::get_username_proofs_by_fid(
                &stores.username_proof_store,
                fid,
                &page_options,
            )?
            .messages
        }
        MessageType::LendStorage => {
            let mut messages = stores
                .storage_lend_store
                .get_adds_by_fid(fid, &page_options, filter)?
                .messages;
            messages.extend(StorageLendStore::get_messages_by_borrower_fid(
                &stores.storage_lend_store,
                fid,
            )?);
            messages
        }
        MessageType::ChannelUpdate => {
            stores
                .channel_update_store
                .get_adds_by_fid(fid, &page_options, filter)?
                .messages
        }
        MessageType::ChannelMember => {
            stores
                .channel_member_store
                .get_adds_by_fid(fid, &page_options, filter)?
                .messages
        }
        MessageType::ChannelPin => {
            stores
                .channel_pin_store
                .get_adds_by_fid(fid, &page_options, filter)?
                .messages
        }
        MessageType::ChannelModerate => {
            stores
                .channel_moderate_store
                .get_adds_by_fid(fid, &page_options, filter)?
                .messages
        }
        // Hypersnap types (100–999) are shard-0 state, not in the shard-1/2
        // sync trie.
        _ => return Ok(None),
    };
    Ok(Some(messages))
}

/// The object behind a sync-trie key.
#[derive(Clone, Debug, PartialEq)]
pub enum TrieObject {
    Message(proto::Message),
    OnChainEvent(proto::OnChainEvent),
    Fname(proto::UserNameProof),
}

impl TrieObject {
    /// The value of the key in the Keccak state trie (FIP §16.13 table).
    pub fn state_value(&self) -> Vec<u8> {
        match self {
            TrieObject::Message(m) => m.encode_to_vec(),
            TrieObject::OnChainEvent(e) => e.encode_to_vec(),
            TrieObject::Fname(p) => p.encode_to_vec(),
        }
    }
}

/// Resolves sync-trie keys of one shard, with per-(fid, type) caches.
pub struct TrieKeyResolver<'a> {
    stores: &'a Stores,
    messages: HashMap<(u64, u8), HashMap<Vec<u8>, proto::Message>>,
    onchain: HashMap<(u64, u8), HashMap<Vec<u8>, proto::OnChainEvent>>,
    key_removes: Option<HashMap<Vec<u8>, proto::Message>>,
    /// Resolve each message key alone (`message_by_hash`), not through all
    /// the messages of its FID and type.
    one_leaf: bool,
}

impl<'a> TrieKeyResolver<'a> {
    pub fn new(stores: &'a Stores) -> Self {
        TrieKeyResolver {
            stores,
            messages: HashMap::new(),
            onchain: HashMap::new(),
            key_removes: None,
            one_leaf: false,
        }
    }

    /// A resolver for one key (a DA answer, FIP §5.1): a full scan caches
    /// all the messages of each FID and type, a single key does not need
    /// them.
    pub fn for_one_leaf(stores: &'a Stores) -> Self {
        TrieKeyResolver {
            one_leaf: true,
            ..Self::new(stores)
        }
    }

    /// Drop the caches of FIDs before `fid`. Trie keys come in FID order
    /// within a virtual shard, so this bounds memory during a full scan.
    pub fn evict_below(&mut self, fid: u64) {
        self.messages.retain(|(f, _), _| *f >= fid);
        self.onchain.retain(|(f, _), _| *f >= fid);
    }

    fn by_hash(messages: Vec<proto::Message>) -> HashMap<Vec<u8>, proto::Message> {
        messages.into_iter().map(|m| (m.hash.clone(), m)).collect()
    }

    fn key_add_messages(&self, fid: u64) -> Result<Vec<proto::Message>, HubError> {
        let mut page_options = PageOptions::default();
        page_options.page_size = Some(usize::MAX);
        let page = list_gasless_keys_by_fid(&self.stores.db, fid, &page_options)?;
        Ok(page
            .records
            .into_iter()
            .filter_map(|(_, record)| record.message)
            .collect())
    }

    /// Every `KEY_REMOVE` in the shard's block events, by message hash. Built
    /// once, on the first `KEY_REMOVE` key.
    fn key_removes(&mut self) -> Result<&HashMap<Vec<u8>, proto::Message>, HubError> {
        if self.key_removes.is_none() {
            let mut map = HashMap::new();
            let store = &self.stores.block_event_store;
            let max = store
                .max_seqnum()
                .map_err(|e| HubError::invalid_internal_state(&e.to_string()))?;
            for seqnum in 1..=max {
                let event = match store.get_block_event_by_seqnum(seqnum) {
                    Ok(Some(event)) => event,
                    _ => continue,
                };
                if let Some(proto::block_event_data::Body::MergeMessageEventBody(body)) =
                    event.data.and_then(|d| d.body)
                {
                    if let Some(message) = body.message {
                        if message.msg_type() == MessageType::KeyRemove {
                            map.insert(message.hash.clone(), message);
                        }
                    }
                }
            }
            self.key_removes = Some(map);
        }
        Ok(self.key_removes.as_ref().unwrap())
    }

    /// The object behind `trie_key`, or `None` if no store has it.
    pub fn resolve(&mut self, trie_key: &[u8]) -> Result<Option<TrieObject>, HubError> {
        let decoded = TrieKey::decode(trie_key)
            .map_err(|e| HubError::invalid_internal_state(&e.to_string()))?;
        let fid = decoded.fid;
        match (decoded.onchain_message_type, decoded.message_type) {
            (Some(FNAME_MESSAGE_TYPE), None) => {
                let name: Vec<u8> = decoded.rest.into_iter().take_while(|&b| b != 0).collect();
                let proof = UserDataStore::get_username_proof(
                    &self.stores.user_data_store,
                    &RocksDbTransactionBatch::new(),
                    &name,
                )?;
                Ok(proof.map(TrieObject::Fname))
            }
            (Some(event_type), None) => {
                let cache_key = (fid, event_type);
                if !self.onchain.contains_key(&cache_key) {
                    let event_type =
                        OnChainEventType::try_from(event_type as i32).map_err(|_| {
                            HubError::invalid_internal_state(&format!(
                                "trie key with unknown on-chain event type {}",
                                event_type
                            ))
                        })?;
                    let events = self
                        .stores
                        .onchain_event_store
                        .get_onchain_events(event_type, Some(fid))
                        .map_err(|e| HubError::invalid_internal_state(&e.to_string()))?;
                    let map = events
                        .into_iter()
                        .map(|e| {
                            let hash =
                                TrieKey::for_onchain_event(&e)[(1 + FID_BYTES + 1)..].to_vec();
                            (hash, e)
                        })
                        .collect();
                    self.onchain.insert(cache_key, map);
                }
                Ok(self.onchain[&cache_key]
                    .get(&decoded.rest)
                    .cloned()
                    .map(TrieObject::OnChainEvent))
            }
            (None, Some(message_type)) => {
                let hash = decoded.rest;
                let msg_type = MessageType::try_from(message_type as i32).map_err(|_| {
                    HubError::invalid_internal_state(&format!(
                        "trie key with unknown message type {}",
                        message_type
                    ))
                })?;
                if msg_type == MessageType::KeyRemove {
                    if let Some(m) = get_key_remove_message(&self.stores.db, fid, &hash)? {
                        return Ok(Some(TrieObject::Message(m)));
                    }
                    return Ok(self
                        .key_removes()?
                        .get(&hash)
                        .cloned()
                        .map(TrieObject::Message));
                }
                if self.one_leaf && msg_type != MessageType::KeyAdd {
                    return Ok(message_by_hash(self.stores, fid, msg_type, &hash)?
                        .map(TrieObject::Message));
                }
                let cache_key = (fid, message_type);
                if !self.messages.contains_key(&cache_key) {
                    let messages = if msg_type == MessageType::KeyAdd {
                        self.key_add_messages(fid)?
                    } else {
                        messages_for_fid_and_type(self.stores, fid, msg_type)?.unwrap_or_default()
                    };
                    self.messages.insert(cache_key, Self::by_hash(messages));
                }
                Ok(self.messages[&cache_key]
                    .get(&hash)
                    .cloned()
                    .map(TrieObject::Message))
            }
            _ => Err(HubError::invalid_internal_state("malformed trie key")),
        }
    }
}
