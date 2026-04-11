//! RocksDB storage for mini app notification tokens.
//!
//! Layout (prefix 0xE5):
//!
//! - `<prefix> 0x01 <app_id_len:1> <app_id> <fid:8 BE>`
//!   → JSON(NotificationDetails)
//!   Primary record: per-(app, fid) the current `(url, token, enabled)`.
//!
//! - `<prefix> 0x02 <app_id_len:1> <app_id> <url_hash:8> <fid:8 BE>`
//!   → empty
//!   Recipient grouping: lets the fan-out sender batch tokens by their
//!   notification URL without scanning every `(app, fid)` record.
//!
//! All writes go through `RocksDbTransactionBatch` so updates to the
//! primary record and the URL-grouping index are atomic.
//!
//! `app_id` is variable-length but always ASCII (validated at config
//! parse time). The 1-byte length prefix lets a prefix scan be scoped to
//! a single app without confusing scans across apps.

use crate::api::notifications::types::NotificationDetails;
use crate::storage::db::{RocksDB, RocksDbTransactionBatch};
use blake3;
use std::sync::Arc;
use thiserror::Error;

const PREFIX: u8 = 0xE5;
const SUB_PRIMARY: u8 = 0x01;
const SUB_URL_INDEX: u8 = 0x02;

/// Maximum length we accept for an `app_id`. Keeps key sizes bounded.
///
/// Typed as `u8` rather than `usize` so the type system enforces the
/// "fits in a single length-prefix byte" invariant: every key
/// constructor in this module writes the length as a single byte, and
/// raising this past 255 would silently truncate. Pinning the type
/// prevents that footgun.
pub const MAX_APP_ID_LEN: u8 = 64;

#[derive(Debug, Error)]
pub enum NotificationStoreError {
    #[error("rocksdb: {0}")]
    Storage(String),
    #[error("serialization: {0}")]
    Serde(String),
    #[error("app_id too long (max {MAX_APP_ID_LEN} bytes)")]
    AppIdTooLong,
}

pub struct NotificationStore {
    db: Arc<RocksDB>,
}

impl NotificationStore {
    pub fn new(db: Arc<RocksDB>) -> Self {
        Self { db }
    }

    /// Insert or replace the `(app_id, fid)` record. Atomically updates
    /// the URL-grouping index if the URL changed (drops the old entry
    /// from the previous URL's grouping, adds it to the new URL's).
    pub fn upsert(
        &self,
        app_id: &str,
        fid: u64,
        details: &NotificationDetails,
    ) -> Result<(), NotificationStoreError> {
        validate_app_id(app_id)?;

        let primary_key = make_primary_key(app_id, fid);
        let mut txn = RocksDbTransactionBatch::new();

        // If a previous record exists, drop its URL-grouping entry first.
        if let Some(prev) = self.get(app_id, fid)? {
            if prev.url != details.url {
                txn.delete(make_url_index_key(app_id, &prev.url, fid));
            }
        }

        // Write the primary record.
        let bytes = serde_json::to_vec(details)
            .map_err(|e| NotificationStoreError::Serde(e.to_string()))?;
        txn.put(primary_key, bytes);

        // Only add the URL-grouping entry if notifications are
        // currently enabled — disabled tokens are skipped at fan-out
        // time so they don't belong in the index.
        if details.enabled {
            txn.put(make_url_index_key(app_id, &details.url, fid), Vec::new());
        }

        self.db
            .commit(txn)
            .map_err(|e| NotificationStoreError::Storage(e.to_string()))
    }

    /// Mark the existing record as `enabled = false` without dropping the
    /// `(url, token)` so a later `notifications_enabled` event can simply
    /// re-enable it. Removes the URL-grouping index entry so disabled
    /// tokens aren't picked up by the fan-out sender.
    pub fn set_enabled(
        &self,
        app_id: &str,
        fid: u64,
        enabled: bool,
        now: u64,
    ) -> Result<(), NotificationStoreError> {
        validate_app_id(app_id)?;
        let Some(mut prev) = self.get(app_id, fid)? else {
            // Nothing to update — gracefully no-op so a stray
            // `notifications_disabled` doesn't 404.
            return Ok(());
        };
        if prev.enabled == enabled {
            return Ok(());
        }
        prev.enabled = enabled;
        prev.updated_at = now;

        let bytes =
            serde_json::to_vec(&prev).map_err(|e| NotificationStoreError::Serde(e.to_string()))?;
        let mut txn = RocksDbTransactionBatch::new();
        txn.put(make_primary_key(app_id, fid), bytes);
        if enabled {
            txn.put(make_url_index_key(app_id, &prev.url, fid), Vec::new());
        } else {
            txn.delete(make_url_index_key(app_id, &prev.url, fid));
        }
        self.db
            .commit(txn)
            .map_err(|e| NotificationStoreError::Storage(e.to_string()))
    }

    /// Delete the `(app_id, fid)` record entirely (`miniapp_removed`).
    pub fn delete(&self, app_id: &str, fid: u64) -> Result<(), NotificationStoreError> {
        validate_app_id(app_id)?;
        let Some(prev) = self.get(app_id, fid)? else {
            return Ok(());
        };
        let mut txn = RocksDbTransactionBatch::new();
        txn.delete(make_primary_key(app_id, fid));
        txn.delete(make_url_index_key(app_id, &prev.url, fid));
        self.db
            .commit(txn)
            .map_err(|e| NotificationStoreError::Storage(e.to_string()))
    }

    pub fn get(
        &self,
        app_id: &str,
        fid: u64,
    ) -> Result<Option<NotificationDetails>, NotificationStoreError> {
        validate_app_id(app_id)?;
        let key = make_primary_key(app_id, fid);
        match self
            .db
            .get(&key)
            .map_err(|e| NotificationStoreError::Storage(e.to_string()))?
        {
            Some(bytes) => {
                let details: NotificationDetails = serde_json::from_slice(&bytes)
                    .map_err(|e| NotificationStoreError::Serde(e.to_string()))?;
                Ok(Some(details))
            }
            None => Ok(None),
        }
    }

    /// Return every FID that currently has notifications enabled for
    /// `app_id`, regardless of URL. Used by the send endpoint when the
    /// caller passes an empty `target_fids` (== send to all).
    ///
    /// Iterates the URL-grouping index (which only contains enabled
    /// records) and dedupes; each FID has at most one URL so this is a
    /// straight scan.
    pub fn list_all_enabled_fids(&self, app_id: &str) -> Result<Vec<u64>, NotificationStoreError> {
        validate_app_id(app_id)?;
        // The URL-grouping prefix is `<PREFIX> 0x02 <app_id_len> <app_id>`
        // followed by the 8-byte url hash and the 8-byte FID. We can
        // scan with the (prefix..increment(prefix)) range and pick off
        // the trailing 8 bytes as the FID.
        let mut prefix = Vec::with_capacity(3 + app_id.len());
        prefix.push(PREFIX);
        prefix.push(SUB_URL_INDEX);
        prefix.push(app_id_len_byte(app_id));
        prefix.extend_from_slice(app_id.as_bytes());
        let stop = increment_prefix(&prefix);

        let mut fids = std::collections::BTreeSet::new();
        self.db
            .for_each_iterator_by_prefix(
                Some(prefix),
                Some(stop),
                &crate::storage::db::PageOptions::default(),
                |key, _value| {
                    if key.len() < 8 {
                        return Ok(false);
                    }
                    let fid_bytes = &key[key.len() - 8..];
                    if let Ok(arr) = <[u8; 8]>::try_from(fid_bytes) {
                        fids.insert(u64::from_be_bytes(arr));
                    }
                    Ok(false)
                },
            )
            .map_err(|e| NotificationStoreError::Storage(e.to_string()))?;
        Ok(fids.into_iter().collect())
    }

    /// Return all FIDs that currently have notifications enabled and use
    /// the given URL for the given app. Used by the fan-out sender to
    /// build per-URL batches.
    pub fn enabled_fids_for_url(
        &self,
        app_id: &str,
        url: &str,
    ) -> Result<Vec<u64>, NotificationStoreError> {
        validate_app_id(app_id)?;
        let prefix = make_url_index_prefix(app_id, url);
        let stop = increment_prefix(&prefix);
        let mut fids = Vec::new();
        self.db
            .for_each_iterator_by_prefix(
                Some(prefix.clone()),
                Some(stop),
                &crate::storage::db::PageOptions::default(),
                |key, _value| {
                    if key.len() < prefix.len() + 8 {
                        return Ok(false);
                    }
                    let fid_bytes = &key[prefix.len()..prefix.len() + 8];
                    if let Ok(arr) = <[u8; 8]>::try_from(fid_bytes) {
                        fids.push(u64::from_be_bytes(arr));
                    }
                    Ok(false)
                },
            )
            .map_err(|e| NotificationStoreError::Storage(e.to_string()))?;
        Ok(fids)
    }
}

fn validate_app_id(app_id: &str) -> Result<(), NotificationStoreError> {
    if app_id.is_empty() || app_id.len() > MAX_APP_ID_LEN as usize {
        return Err(NotificationStoreError::AppIdTooLong);
    }
    Ok(())
}

/// Convert an already-validated `app_id` length to its single-byte
/// length prefix. Panics if the caller forgot to call `validate_app_id`
/// first — that's a programmer error inside this module, not user input.
fn app_id_len_byte(app_id: &str) -> u8 {
    debug_assert!(
        app_id.len() <= MAX_APP_ID_LEN as usize,
        "app_id length must have been validated before key construction"
    );
    u8::try_from(app_id.len()).expect("app_id length validated <= MAX_APP_ID_LEN (u8)")
}

fn make_primary_key(app_id: &str, fid: u64) -> Vec<u8> {
    let mut key = Vec::with_capacity(2 + 1 + app_id.len() + 8);
    key.push(PREFIX);
    key.push(SUB_PRIMARY);
    key.push(app_id_len_byte(app_id));
    key.extend_from_slice(app_id.as_bytes());
    key.extend_from_slice(&fid.to_be_bytes());
    key
}

fn make_url_index_prefix(app_id: &str, url: &str) -> Vec<u8> {
    let url_hash = url_hash_bytes(url);
    let mut key = Vec::with_capacity(2 + 1 + app_id.len() + 8);
    key.push(PREFIX);
    key.push(SUB_URL_INDEX);
    key.push(app_id_len_byte(app_id));
    key.extend_from_slice(app_id.as_bytes());
    key.extend_from_slice(&url_hash);
    key
}

fn make_url_index_key(app_id: &str, url: &str, fid: u64) -> Vec<u8> {
    let mut key = make_url_index_prefix(app_id, url);
    key.extend_from_slice(&fid.to_be_bytes());
    key
}

/// First 8 bytes of a blake3 hash of the URL. Collisions are vanishingly
/// unlikely for the few notification URLs an app sees in practice; the
/// fan-out path always re-checks the actual URL on the primary record so
/// a collision would just produce one extra primary lookup, never a wrong
/// delivery.
fn url_hash_bytes(url: &str) -> [u8; 8] {
    let hash = blake3::hash(url.as_bytes());
    let bytes = hash.as_bytes();
    let mut out = [0u8; 8];
    out.copy_from_slice(&bytes[..8]);
    out
}

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
    out.push(0x00);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn fresh_store() -> (TempDir, NotificationStore) {
        let dir = TempDir::new().unwrap();
        let db = Arc::new(RocksDB::new(dir.path().to_str().unwrap()));
        db.open().unwrap();
        (dir, NotificationStore::new(db))
    }

    fn details(url: &str, token: &str, enabled: bool) -> NotificationDetails {
        NotificationDetails {
            url: url.into(),
            token: token.into(),
            enabled,
            updated_at: 0,
        }
    }

    #[test]
    fn upsert_then_get_round_trips() {
        let (_d, store) = fresh_store();
        let d = details("https://x.com/n", "tok-1", true);
        store.upsert("app-a", 42, &d).unwrap();

        let got = store.get("app-a", 42).unwrap().unwrap();
        assert_eq!(got, d);
    }

    #[test]
    fn enabled_fids_for_url_groups_correctly() {
        let (_d, store) = fresh_store();
        let url_a = "https://a.example/n";
        let url_b = "https://b.example/n";

        store.upsert("app", 1, &details(url_a, "t1", true)).unwrap();
        store.upsert("app", 2, &details(url_a, "t2", true)).unwrap();
        store.upsert("app", 3, &details(url_b, "t3", true)).unwrap();
        store
            .upsert("other-app", 4, &details(url_a, "t4", true))
            .unwrap();

        let mut at_a = store.enabled_fids_for_url("app", url_a).unwrap();
        at_a.sort();
        assert_eq!(at_a, vec![1, 2]);

        let at_b = store.enabled_fids_for_url("app", url_b).unwrap();
        assert_eq!(at_b, vec![3]);

        // Cross-app isolation.
        let other = store.enabled_fids_for_url("other-app", url_a).unwrap();
        assert_eq!(other, vec![4]);
    }

    #[test]
    fn upsert_url_change_drops_old_grouping() {
        let (_d, store) = fresh_store();
        store
            .upsert("app", 1, &details("https://old", "t", true))
            .unwrap();
        store
            .upsert("app", 1, &details("https://new", "t", true))
            .unwrap();

        let old = store.enabled_fids_for_url("app", "https://old").unwrap();
        let new = store.enabled_fids_for_url("app", "https://new").unwrap();
        assert!(old.is_empty(), "old URL grouping must be dropped");
        assert_eq!(new, vec![1]);
    }

    #[test]
    fn set_enabled_false_drops_from_url_grouping() {
        let (_d, store) = fresh_store();
        store
            .upsert("app", 1, &details("https://x", "t", true))
            .unwrap();
        store.set_enabled("app", 1, false, 100).unwrap();

        // Primary still exists, marked disabled.
        let got = store.get("app", 1).unwrap().unwrap();
        assert!(!got.enabled);
        assert_eq!(got.updated_at, 100);

        // URL grouping cleared.
        let at_url = store.enabled_fids_for_url("app", "https://x").unwrap();
        assert!(at_url.is_empty());

        // Re-enabling restores the grouping.
        store.set_enabled("app", 1, true, 200).unwrap();
        let at_url = store.enabled_fids_for_url("app", "https://x").unwrap();
        assert_eq!(at_url, vec![1]);
    }

    #[test]
    fn delete_removes_record_and_grouping() {
        let (_d, store) = fresh_store();
        store
            .upsert("app", 1, &details("https://x", "t", true))
            .unwrap();
        store.delete("app", 1).unwrap();

        assert!(store.get("app", 1).unwrap().is_none());
        let at_url = store.enabled_fids_for_url("app", "https://x").unwrap();
        assert!(at_url.is_empty());
    }

    #[test]
    fn set_enabled_unknown_fid_is_a_noop() {
        let (_d, store) = fresh_store();
        // No record exists; this should silently succeed.
        store.set_enabled("app", 999, false, 0).unwrap();
    }

    #[test]
    fn list_all_enabled_fids_returns_only_enabled_for_app() {
        let (_d, store) = fresh_store();
        // Different URLs, all enabled.
        store
            .upsert("app", 1, &details("https://a", "t1", true))
            .unwrap();
        store
            .upsert("app", 2, &details("https://b", "t2", true))
            .unwrap();
        // Disabled — must NOT show up.
        store
            .upsert("app", 3, &details("https://c", "t3", false))
            .unwrap();
        // Different app — must NOT show up.
        store
            .upsert("other", 99, &details("https://x", "tx", true))
            .unwrap();

        let mut got = store.list_all_enabled_fids("app").unwrap();
        got.sort();
        assert_eq!(got, vec![1, 2]);
    }

    #[test]
    fn rejects_too_long_app_id() {
        let (_d, store) = fresh_store();
        let too_long = "x".repeat(MAX_APP_ID_LEN as usize + 1);
        let err = store.upsert(&too_long, 1, &details("https://x", "t", true));
        assert!(matches!(err, Err(NotificationStoreError::AppIdTooLong)));
    }
}
