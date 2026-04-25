//! RocksDB storage for webhook records.
//!
//! Layout (prefix 0xE4):
//!
//!   <prefix> 0x01 <webhook_id:16>                  → JSON(Webhook)
//!   <prefix> 0x02 <fid:8 BE> <webhook_id:16>       → empty (owner index)
//!   <prefix> 0x03 <event_type:1> <webhook_id:16>   → empty (event-type index)
//!
//! All writes go through `RocksDbTransactionBatch` so create/update/delete
//! are atomic across the primary record and its indices.

use crate::api::webhooks::types::{EventTypeByte, Webhook, WebhookSubscription};
use crate::storage::db::{RocksDB, RocksDbTransactionBatch};
use std::sync::Arc;
use thiserror::Error;
use uuid::Uuid;

const PREFIX: u8 = 0xE4;
const SUB_PRIMARY: u8 = 0x01;
const SUB_OWNER_INDEX: u8 = 0x02;
const SUB_EVENT_INDEX: u8 = 0x03;

#[derive(Debug, Error)]
pub enum WebhookStoreError {
    #[error("rocksdb: {0}")]
    Storage(String),
    #[error("serialization: {0}")]
    Serde(String),
    #[error("not found")]
    NotFound,
}

/// Webhook record store.
pub struct WebhookStore {
    db: Arc<RocksDB>,
}

impl WebhookStore {
    pub fn new(db: Arc<RocksDB>) -> Self {
        Self { db }
    }

    /// Create a new webhook record. Caller is responsible for assigning
    /// `webhook_id`, secrets, timestamps, etc.
    pub fn create(&self, webhook: &Webhook) -> Result<(), WebhookStoreError> {
        let mut txn = RocksDbTransactionBatch::new();
        self.write_record(&mut txn, webhook)?;
        for byte in event_bytes_for_subscription(&webhook.subscription) {
            txn.put(make_event_index_key(byte, &webhook.webhook_id), Vec::new());
        }
        txn.put(
            make_owner_index_key(webhook.owner_fid, &webhook.webhook_id),
            Vec::new(),
        );
        self.db
            .commit(txn)
            .map_err(|e| WebhookStoreError::Storage(e.to_string()))
    }

    /// Update an existing webhook record. Re-derives the event-type index.
    pub fn update(&self, previous: &Webhook, next: &Webhook) -> Result<(), WebhookStoreError> {
        if previous.webhook_id != next.webhook_id || previous.owner_fid != next.owner_fid {
            return Err(WebhookStoreError::Serde(
                "webhook_id and owner_fid are immutable".into(),
            ));
        }

        let mut txn = RocksDbTransactionBatch::new();
        // Drop the old event-type index entries that are no longer needed.
        let prev_bytes: std::collections::HashSet<u8> =
            event_bytes_for_subscription(&previous.subscription)
                .into_iter()
                .collect();
        let next_bytes: std::collections::HashSet<u8> =
            event_bytes_for_subscription(&next.subscription)
                .into_iter()
                .collect();
        for byte in prev_bytes.difference(&next_bytes) {
            txn.delete(make_event_index_key(*byte, &next.webhook_id));
        }
        for byte in next_bytes.difference(&prev_bytes) {
            txn.put(make_event_index_key(*byte, &next.webhook_id), Vec::new());
        }
        self.write_record(&mut txn, next)?;
        self.db
            .commit(txn)
            .map_err(|e| WebhookStoreError::Storage(e.to_string()))
    }

    /// Hard-delete a webhook and its index entries.
    pub fn delete(&self, webhook: &Webhook) -> Result<(), WebhookStoreError> {
        let mut txn = RocksDbTransactionBatch::new();
        txn.delete(make_primary_key(&webhook.webhook_id));
        txn.delete(make_owner_index_key(webhook.owner_fid, &webhook.webhook_id));
        for byte in event_bytes_for_subscription(&webhook.subscription) {
            txn.delete(make_event_index_key(byte, &webhook.webhook_id));
        }
        self.db
            .commit(txn)
            .map_err(|e| WebhookStoreError::Storage(e.to_string()))
    }

    pub fn get(&self, webhook_id: &Uuid) -> Result<Option<Webhook>, WebhookStoreError> {
        let key = make_primary_key(webhook_id);
        match self
            .db
            .get(&key)
            .map_err(|e| WebhookStoreError::Storage(e.to_string()))?
        {
            Some(bytes) => {
                let webhook: Webhook = serde_json::from_slice(&bytes)
                    .map_err(|e| WebhookStoreError::Serde(e.to_string()))?;
                Ok(Some(webhook))
            }
            None => Ok(None),
        }
    }

    /// List all webhooks owned by `fid`. Bounded by `max` to keep the
    /// management API responsive even if a misconfigured caller hammers it.
    pub fn list_by_owner(&self, fid: u64, max: usize) -> Result<Vec<Webhook>, WebhookStoreError> {
        let prefix = make_owner_index_prefix(fid);
        let stop = increment_prefix(&prefix);
        let mut webhook_ids = Vec::new();
        self.db
            .for_each_iterator_by_prefix(
                Some(prefix.clone()),
                Some(stop),
                &crate::storage::db::PageOptions::default(),
                |key, _value| {
                    if webhook_ids.len() >= max {
                        return Ok(true); // stop
                    }
                    if key.len() < prefix.len() + 16 {
                        return Ok(false);
                    }
                    let id_bytes = &key[prefix.len()..prefix.len() + 16];
                    if let Ok(arr) = <[u8; 16]>::try_from(id_bytes) {
                        webhook_ids.push(Uuid::from_bytes(arr));
                    }
                    Ok(false)
                },
            )
            .map_err(|e| WebhookStoreError::Storage(e.to_string()))?;

        let mut out = Vec::with_capacity(webhook_ids.len());
        for id in webhook_ids {
            if let Some(w) = self.get(&id)? {
                out.push(w);
            }
        }
        Ok(out)
    }

    /// Count of webhooks owned by `fid`. Used to enforce per-owner caps.
    pub fn count_by_owner(&self, fid: u64) -> Result<usize, WebhookStoreError> {
        let prefix = make_owner_index_prefix(fid);
        let stop = increment_prefix(&prefix);
        let mut count = 0usize;
        self.db
            .for_each_iterator_by_prefix(
                Some(prefix),
                Some(stop),
                &crate::storage::db::PageOptions::default(),
                |_key, _value| {
                    count += 1;
                    Ok(false)
                },
            )
            .map_err(|e| WebhookStoreError::Storage(e.to_string()))?;
        Ok(count)
    }

    /// All webhook IDs subscribed to a given event byte. Used by the
    /// dispatcher to find candidate deliveries for an event.
    pub fn list_by_event_type(&self, event_byte: u8) -> Result<Vec<Uuid>, WebhookStoreError> {
        let prefix = make_event_index_prefix(event_byte);
        let stop = increment_prefix(&prefix);
        let mut ids = Vec::new();
        self.db
            .for_each_iterator_by_prefix(
                Some(prefix.clone()),
                Some(stop),
                &crate::storage::db::PageOptions::default(),
                |key, _value| {
                    if key.len() < prefix.len() + 16 {
                        return Ok(false);
                    }
                    let id_bytes = &key[prefix.len()..prefix.len() + 16];
                    if let Ok(arr) = <[u8; 16]>::try_from(id_bytes) {
                        ids.push(Uuid::from_bytes(arr));
                    }
                    Ok(false)
                },
            )
            .map_err(|e| WebhookStoreError::Storage(e.to_string()))?;
        Ok(ids)
    }

    /// List every registered webhook across every owner, up to `max`.
    /// Used by the admin override (`X-Admin-Api-Key`) for moderation
    /// and bulk inspection. Iterates the primary prefix.
    pub fn list_all(&self, max: usize) -> Result<Vec<Webhook>, WebhookStoreError> {
        let prefix = vec![PREFIX, SUB_PRIMARY];
        let stop = increment_prefix(&prefix);
        let mut out = Vec::new();
        self.db
            .for_each_iterator_by_prefix(
                Some(prefix),
                Some(stop),
                &crate::storage::db::PageOptions::default(),
                |_key, value| {
                    if out.len() >= max {
                        return Ok(true);
                    }
                    if let Ok(webhook) = serde_json::from_slice::<Webhook>(value) {
                        out.push(webhook);
                    }
                    Ok(false)
                },
            )
            .map_err(|e| WebhookStoreError::Storage(e.to_string()))?;
        Ok(out)
    }

    fn write_record(
        &self,
        txn: &mut RocksDbTransactionBatch,
        webhook: &Webhook,
    ) -> Result<(), WebhookStoreError> {
        let bytes =
            serde_json::to_vec(webhook).map_err(|e| WebhookStoreError::Serde(e.to_string()))?;
        txn.put(make_primary_key(&webhook.webhook_id), bytes);
        Ok(())
    }
}

fn make_primary_key(webhook_id: &Uuid) -> Vec<u8> {
    let mut key = Vec::with_capacity(2 + 16);
    key.push(PREFIX);
    key.push(SUB_PRIMARY);
    key.extend_from_slice(webhook_id.as_bytes());
    key
}

fn make_owner_index_prefix(fid: u64) -> Vec<u8> {
    let mut key = Vec::with_capacity(2 + 8);
    key.push(PREFIX);
    key.push(SUB_OWNER_INDEX);
    key.extend_from_slice(&fid.to_be_bytes());
    key
}

fn make_owner_index_key(fid: u64, webhook_id: &Uuid) -> Vec<u8> {
    let mut key = make_owner_index_prefix(fid);
    key.extend_from_slice(webhook_id.as_bytes());
    key
}

fn make_event_index_prefix(event_byte: u8) -> Vec<u8> {
    vec![PREFIX, SUB_EVENT_INDEX, event_byte]
}

fn make_event_index_key(event_byte: u8, webhook_id: &Uuid) -> Vec<u8> {
    let mut key = make_event_index_prefix(event_byte);
    key.extend_from_slice(webhook_id.as_bytes());
    key
}

/// Compute the smallest byte string strictly greater than `prefix` so it
/// can be used as an exclusive upper bound on a prefix scan. Mirrors the
/// helper used elsewhere in the api module.
fn increment_prefix(prefix: &[u8]) -> Vec<u8> {
    let mut out = prefix.to_vec();
    for byte in out.iter_mut().rev() {
        if *byte == 0xFF {
            *byte = 0x00;
            continue;
        }
        *byte += 1;
        return out;
    }
    // All bytes were 0xFF — append a sentinel byte.
    out.push(0x00);
    out
}

fn event_bytes_for_subscription(sub: &WebhookSubscription) -> Vec<u8> {
    let mut bytes = Vec::new();
    if sub.cast_created.is_some() {
        bytes.push(EventTypeByte::CastCreated.as_u8());
    }
    if sub.cast_deleted.is_some() {
        bytes.push(EventTypeByte::CastDeleted.as_u8());
    }
    if sub.user_created.is_some() {
        bytes.push(EventTypeByte::UserCreated.as_u8());
    }
    if sub.user_updated.is_some() {
        bytes.push(EventTypeByte::UserUpdated.as_u8());
    }
    if sub.follow_created.is_some() {
        bytes.push(EventTypeByte::FollowCreated.as_u8());
    }
    if sub.follow_deleted.is_some() {
        bytes.push(EventTypeByte::FollowDeleted.as_u8());
    }
    if sub.reaction_created.is_some() {
        bytes.push(EventTypeByte::ReactionCreated.as_u8());
    }
    if sub.reaction_deleted.is_some() {
        bytes.push(EventTypeByte::ReactionDeleted.as_u8());
    }
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::webhooks::types::{CastFilter, FollowFilter, UserCreatedFilter, WebhookSecret};
    use crate::storage::db::RocksDB;
    use tempfile::TempDir;

    fn fresh_store() -> (TempDir, WebhookStore) {
        let dir = TempDir::new().unwrap();
        let db = Arc::new(RocksDB::new(dir.path().to_str().unwrap()));
        db.open().unwrap();
        (dir, WebhookStore::new(db))
    }

    fn sample_webhook(fid: u64) -> Webhook {
        Webhook {
            webhook_id: Uuid::new_v4(),
            owner_fid: fid,
            target_url: "https://example.com/hook".into(),
            title: "test".into(),
            description: None,
            active: true,
            secrets: vec![WebhookSecret {
                uid: Uuid::new_v4(),
                value: "secret".into(),
                expires_at: None,
                created_at: 0,
            }],
            subscription: WebhookSubscription {
                cast_created: Some(CastFilter {
                    author_fids: vec![fid],
                    ..Default::default()
                }),
                user_created: Some(UserCreatedFilter::default()),
                ..Default::default()
            },
            http_timeout: 10,
            rate_limit: 1000,
            rate_limit_duration: 60,
            created_at: 0,
            updated_at: 0,
            deleted_at: None,
        }
    }

    #[test]
    fn create_then_get() {
        let (_dir, store) = fresh_store();
        let webhook = sample_webhook(42);
        store.create(&webhook).unwrap();

        let fetched = store.get(&webhook.webhook_id).unwrap().unwrap();
        assert_eq!(fetched.webhook_id, webhook.webhook_id);
        assert_eq!(fetched.owner_fid, 42);
        assert_eq!(fetched.target_url, "https://example.com/hook");
    }

    #[test]
    fn list_by_owner_returns_only_caller_webhooks() {
        let (_dir, store) = fresh_store();
        let mine_a = sample_webhook(1);
        let mine_b = sample_webhook(1);
        let theirs = sample_webhook(2);
        store.create(&mine_a).unwrap();
        store.create(&mine_b).unwrap();
        store.create(&theirs).unwrap();

        let mut listed = store.list_by_owner(1, 100).unwrap();
        listed.sort_by_key(|w| w.webhook_id);
        let mut expected = vec![mine_a.webhook_id, mine_b.webhook_id];
        expected.sort();
        let got: Vec<Uuid> = listed.iter().map(|w| w.webhook_id).collect();
        assert_eq!(got, expected);

        assert_eq!(store.count_by_owner(1).unwrap(), 2);
        assert_eq!(store.count_by_owner(2).unwrap(), 1);
    }

    #[test]
    fn list_by_event_type_finds_subscribers() {
        let (_dir, store) = fresh_store();
        let w = sample_webhook(7);
        store.create(&w).unwrap();

        let cast_subs = store
            .list_by_event_type(EventTypeByte::CastCreated.as_u8())
            .unwrap();
        assert_eq!(cast_subs, vec![w.webhook_id]);

        let user_subs = store
            .list_by_event_type(EventTypeByte::UserCreated.as_u8())
            .unwrap();
        assert_eq!(user_subs, vec![w.webhook_id]);

        // Not subscribed to follow events.
        let follow_subs = store
            .list_by_event_type(EventTypeByte::FollowCreated.as_u8())
            .unwrap();
        assert!(follow_subs.is_empty());
    }

    #[test]
    fn update_rewrites_event_type_index() {
        let (_dir, store) = fresh_store();
        let mut webhook = sample_webhook(9);
        store.create(&webhook).unwrap();

        // Replace cast_created with follow_created.
        let prev = webhook.clone();
        webhook.subscription = WebhookSubscription {
            follow_created: Some(FollowFilter::default()),
            ..Default::default()
        };
        store.update(&prev, &webhook).unwrap();

        let cast_subs = store
            .list_by_event_type(EventTypeByte::CastCreated.as_u8())
            .unwrap();
        assert!(cast_subs.is_empty(), "cast_created index should be cleared");

        let follow_subs = store
            .list_by_event_type(EventTypeByte::FollowCreated.as_u8())
            .unwrap();
        assert_eq!(follow_subs, vec![webhook.webhook_id]);
    }

    #[test]
    fn delete_removes_record_and_indices() {
        let (_dir, store) = fresh_store();
        let webhook = sample_webhook(11);
        store.create(&webhook).unwrap();
        store.delete(&webhook).unwrap();

        assert!(store.get(&webhook.webhook_id).unwrap().is_none());
        assert_eq!(store.count_by_owner(11).unwrap(), 0);
        let subs = store
            .list_by_event_type(EventTypeByte::CastCreated.as_u8())
            .unwrap();
        assert!(subs.is_empty());
    }
}
