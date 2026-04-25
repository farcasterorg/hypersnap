//! RocksDB-backed registry for mini apps.
//!
//! Apps are registered at runtime through the signed management API
//! (`/v2/farcaster/frame/app/`) rather than in config. Each app gets a
//! fresh random base58 `app_id` (16 characters, ~93 bits of entropy)
//! and is owned by the FID whose custody key signed the create request.
//!
//! # Storage layout (prefix `0xE7`)
//!
//! `app_id` is a fixed 16-character ASCII string, so keys have a
//! constant length and need no length prefix.
//!
//! ```text
//! <prefix> 0x01 <app_id:16 bytes>                      → JSON(RegisteredApp)
//! <prefix> 0x02 <owner_fid:8 BE> <app_id:16 bytes>     → empty (owner index)
//! ```
//!
//! Primary writes always go through a `RocksDbTransactionBatch` so the
//! primary record and owner index update atomically.

use crate::api::webhooks::types::WebhookSecret;
use crate::storage::db::{RocksDB, RocksDbTransactionBatch};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use thiserror::Error;

const PREFIX: u8 = 0xE7;
const SUB_PRIMARY: u8 = 0x01;
const SUB_OWNER_INDEX: u8 = 0x02;

/// Fixed length (in ASCII characters) of every `app_id`. Keys in
/// RocksDB assume this width so they sort cleanly by prefix.
pub const APP_ID_LEN: usize = 16;

/// Alphabet used for random `app_id` generation. Matches the Bitcoin
/// base58 alphabet (removes visually-confusable `0`, `O`, `I`, `l`).
const BASE58_ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

#[derive(Debug, Error)]
pub enum AppStoreError {
    #[error("rocksdb: {0}")]
    Storage(String),
    #[error("serialization: {0}")]
    Serde(String),
    #[error("app_id must be exactly {APP_ID_LEN} base58 characters")]
    BadAppId,
}

/// A registered mini app. Fields mutable by the owner are
/// `name` / `description` / `app_url` / `signer_fid_allowlist`.
/// `app_id`, `owner_fid`, and `created_at` are immutable.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegisteredApp {
    /// Server-assigned base58 identifier used in every URL path.
    pub app_id: String,
    /// FID that owns this app. Only the custody key for this FID may
    /// manage the record.
    pub owner_fid: u64,
    /// Human-readable name shown in management responses.
    pub name: String,
    /// Mini app's canonical URL. Informational — hypersnap never POSTs
    /// to it directly — but SSRF-checked at create/update time so a
    /// bad value surfaces immediately.
    pub app_url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Optional allowlist of signer FIDs whose JFS-signed token
    /// registration events will be accepted for this app. Empty = any
    /// active signer is accepted.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub signer_fid_allowlist: Vec<u64>,
    /// Bearer secrets the developer uses to authenticate calls to
    /// `/v2/farcaster/frame/notifications/<app_id>`. Multiple may be
    /// present during a rotation grace window; the most recently
    /// created unexpired entry is the canonical one to sign with.
    pub send_secrets: Vec<WebhookSecret>,
    pub created_at: u64,
    pub updated_at: u64,
}

/// Request body shape for `POST /v2/farcaster/frame/app/`.
#[derive(Debug, Clone, Deserialize)]
pub struct CreateAppRequest {
    pub name: String,
    pub app_url: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub signer_fid_allowlist: Vec<u64>,
}

/// Request body shape for `PUT /v2/farcaster/frame/app/`.
#[derive(Debug, Clone, Deserialize)]
pub struct UpdateAppRequest {
    pub app_id: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub app_url: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub signer_fid_allowlist: Option<Vec<u64>>,
}

/// Response wrapper around a single app record.
#[derive(Debug, Clone, Serialize)]
pub struct AppResponse {
    pub app: RegisteredApp,
}

#[derive(Debug, Clone, Serialize)]
pub struct AppListResponse {
    pub apps: Vec<RegisteredApp>,
}

/// Runtime store for mini-app registrations.
#[derive(Clone)]
pub struct NotificationAppStore {
    db: Arc<RocksDB>,
}

impl NotificationAppStore {
    pub fn new(db: Arc<RocksDB>) -> Self {
        Self { db }
    }

    /// Insert a newly-created app. Caller is responsible for assigning
    /// `app_id`, `created_at`, `updated_at`, and at least one entry in
    /// `send_secrets`.
    pub fn create(&self, app: &RegisteredApp) -> Result<(), AppStoreError> {
        validate_app_id(&app.app_id)?;
        let mut txn = RocksDbTransactionBatch::new();
        self.write_primary(&mut txn, app)?;
        txn.put(make_owner_index_key(app.owner_fid, &app.app_id), Vec::new());
        self.db
            .commit(txn)
            .map_err(|e| AppStoreError::Storage(e.to_string()))
    }

    /// Replace an existing app record. `app_id` and `owner_fid` are
    /// immutable — the caller must pass them back unchanged.
    pub fn update(
        &self,
        previous: &RegisteredApp,
        next: &RegisteredApp,
    ) -> Result<(), AppStoreError> {
        validate_app_id(&next.app_id)?;
        if previous.app_id != next.app_id || previous.owner_fid != next.owner_fid {
            return Err(AppStoreError::Serde(
                "app_id and owner_fid are immutable".into(),
            ));
        }
        let mut txn = RocksDbTransactionBatch::new();
        self.write_primary(&mut txn, next)?;
        self.db
            .commit(txn)
            .map_err(|e| AppStoreError::Storage(e.to_string()))
    }

    /// Hard-delete an app and its owner index entry.
    pub fn delete(&self, app: &RegisteredApp) -> Result<(), AppStoreError> {
        validate_app_id(&app.app_id)?;
        let mut txn = RocksDbTransactionBatch::new();
        txn.delete(make_primary_key(&app.app_id));
        txn.delete(make_owner_index_key(app.owner_fid, &app.app_id));
        self.db
            .commit(txn)
            .map_err(|e| AppStoreError::Storage(e.to_string()))
    }

    pub fn get(&self, app_id: &str) -> Result<Option<RegisteredApp>, AppStoreError> {
        if app_id.len() != APP_ID_LEN {
            // Malformed app_id from the URL path — return `None`
            // rather than an error so the caller can 404 cleanly.
            return Ok(None);
        }
        let key = make_primary_key(app_id);
        match self
            .db
            .get(&key)
            .map_err(|e| AppStoreError::Storage(e.to_string()))?
        {
            Some(bytes) => {
                let app: RegisteredApp = serde_json::from_slice(&bytes)
                    .map_err(|e| AppStoreError::Serde(e.to_string()))?;
                Ok(Some(app))
            }
            None => Ok(None),
        }
    }

    /// List all apps owned by `fid`, up to `max` entries.
    pub fn list_by_owner(&self, fid: u64, max: usize) -> Result<Vec<RegisteredApp>, AppStoreError> {
        let prefix = make_owner_index_prefix(fid);
        let stop = increment_prefix(&prefix);
        let mut app_ids: Vec<String> = Vec::new();
        self.db
            .for_each_iterator_by_prefix(
                Some(prefix.clone()),
                Some(stop),
                &crate::storage::db::PageOptions::default(),
                |key, _value| {
                    if app_ids.len() >= max {
                        return Ok(true);
                    }
                    if key.len() < prefix.len() + APP_ID_LEN {
                        return Ok(false);
                    }
                    let id_bytes = &key[prefix.len()..prefix.len() + APP_ID_LEN];
                    if let Ok(s) = std::str::from_utf8(id_bytes) {
                        app_ids.push(s.to_string());
                    }
                    Ok(false)
                },
            )
            .map_err(|e| AppStoreError::Storage(e.to_string()))?;

        let mut out = Vec::with_capacity(app_ids.len());
        for id in app_ids {
            if let Some(app) = self.get(&id)? {
                out.push(app);
            }
        }
        Ok(out)
    }

    /// List every registered app across every owner, up to `max`.
    /// Used by the admin override (`X-Admin-Api-Key`) for moderation
    /// and bulk inspection. Iterates the primary prefix so it returns
    /// apps in on-disk order (which is `app_id` sort order since the
    /// primary key is `<prefix> 0x01 <app_id>`).
    pub fn list_all(&self, max: usize) -> Result<Vec<RegisteredApp>, AppStoreError> {
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
                    if let Ok(app) = serde_json::from_slice::<RegisteredApp>(value) {
                        out.push(app);
                    }
                    Ok(false)
                },
            )
            .map_err(|e| AppStoreError::Storage(e.to_string()))?;
        Ok(out)
    }

    /// Count apps owned by `fid`. Used to enforce per-owner caps.
    pub fn count_by_owner(&self, fid: u64) -> Result<usize, AppStoreError> {
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
            .map_err(|e| AppStoreError::Storage(e.to_string()))?;
        Ok(count)
    }

    fn write_primary(
        &self,
        txn: &mut RocksDbTransactionBatch,
        app: &RegisteredApp,
    ) -> Result<(), AppStoreError> {
        let bytes = serde_json::to_vec(app).map_err(|e| AppStoreError::Serde(e.to_string()))?;
        txn.put(make_primary_key(&app.app_id), bytes);
        Ok(())
    }
}

// ----------------------------- helpers ---------------------------------

fn validate_app_id(app_id: &str) -> Result<(), AppStoreError> {
    if app_id.len() != APP_ID_LEN {
        return Err(AppStoreError::BadAppId);
    }
    if !app_id.bytes().all(|b| BASE58_ALPHABET.contains(&b)) {
        return Err(AppStoreError::BadAppId);
    }
    Ok(())
}

fn make_primary_key(app_id: &str) -> Vec<u8> {
    let mut key = Vec::with_capacity(2 + APP_ID_LEN);
    key.push(PREFIX);
    key.push(SUB_PRIMARY);
    key.extend_from_slice(app_id.as_bytes());
    key
}

fn make_owner_index_prefix(fid: u64) -> Vec<u8> {
    let mut key = Vec::with_capacity(2 + 8);
    key.push(PREFIX);
    key.push(SUB_OWNER_INDEX);
    key.extend_from_slice(&fid.to_be_bytes());
    key
}

fn make_owner_index_key(fid: u64, app_id: &str) -> Vec<u8> {
    let mut key = make_owner_index_prefix(fid);
    key.extend_from_slice(app_id.as_bytes());
    key
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

/// Generate a fresh random `app_id`. 16 characters of base58 → ~93
/// bits of entropy → collision probability is vanishing for any
/// realistic number of apps.
pub fn generate_app_id() -> String {
    let mut rng = rand::thread_rng();
    let mut buf = [0u8; APP_ID_LEN];
    rng.fill_bytes(&mut buf);
    buf.iter()
        .map(|b| BASE58_ALPHABET[(*b as usize) % BASE58_ALPHABET.len()] as char)
        .collect()
}

/// Generate a fresh 32-byte send secret, hex-encoded. Matches the
/// webhook secret format so the surrounding infrastructure can reuse
/// `pick_active_secret` without a second code path.
pub fn generate_send_secret(now: u64) -> WebhookSecret {
    let mut buf = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut buf);
    WebhookSecret {
        uid: uuid::Uuid::new_v4(),
        value: hex::encode(buf),
        expires_at: None,
        created_at: now,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn fresh_store() -> (TempDir, NotificationAppStore) {
        let dir = TempDir::new().unwrap();
        let db = Arc::new(RocksDB::new(dir.path().to_str().unwrap()));
        db.open().unwrap();
        (dir, NotificationAppStore::new(db))
    }

    fn sample_app(owner: u64) -> RegisteredApp {
        RegisteredApp {
            app_id: generate_app_id(),
            owner_fid: owner,
            name: "test app".into(),
            app_url: "https://app.example".into(),
            description: None,
            signer_fid_allowlist: vec![],
            send_secrets: vec![generate_send_secret(0)],
            created_at: 0,
            updated_at: 0,
        }
    }

    #[test]
    fn generate_app_id_is_fixed_length_base58() {
        for _ in 0..100 {
            let id = generate_app_id();
            assert_eq!(id.len(), APP_ID_LEN);
            assert!(id.bytes().all(|b| BASE58_ALPHABET.contains(&b)));
        }
    }

    #[test]
    fn generated_app_ids_are_distinct() {
        use std::collections::HashSet;
        let ids: HashSet<String> = (0..1000).map(|_| generate_app_id()).collect();
        assert_eq!(ids.len(), 1000, "expected 1000 distinct ids");
    }

    #[test]
    fn create_then_get() {
        let (_d, store) = fresh_store();
        let app = sample_app(42);
        store.create(&app).unwrap();

        let got = store.get(&app.app_id).unwrap().unwrap();
        assert_eq!(got, app);
    }

    #[test]
    fn get_unknown_returns_none() {
        let (_d, store) = fresh_store();
        // Valid-looking but never-created app_id.
        let fake = generate_app_id();
        assert!(store.get(&fake).unwrap().is_none());
    }

    #[test]
    fn get_malformed_app_id_returns_none() {
        let (_d, store) = fresh_store();
        // Too short, contains a forbidden character — either way, the
        // path parser could hand us rubbish and we must not panic.
        assert!(store.get("short").unwrap().is_none());
        assert!(store.get("0000000000000000").unwrap().is_none()); // '0' not in base58
    }

    #[test]
    fn list_by_owner_scopes_to_caller() {
        let (_d, store) = fresh_store();
        let mine_a = sample_app(1);
        let mine_b = sample_app(1);
        let theirs = sample_app(2);
        store.create(&mine_a).unwrap();
        store.create(&mine_b).unwrap();
        store.create(&theirs).unwrap();

        let mut listed = store.list_by_owner(1, 100).unwrap();
        listed.sort_by(|a, b| a.app_id.cmp(&b.app_id));
        let mut expected = vec![mine_a.app_id.clone(), mine_b.app_id.clone()];
        expected.sort();
        let got: Vec<String> = listed.into_iter().map(|a| a.app_id).collect();
        assert_eq!(got, expected);

        assert_eq!(store.count_by_owner(1).unwrap(), 2);
        assert_eq!(store.count_by_owner(2).unwrap(), 1);
    }

    #[test]
    fn update_rewrites_mutable_fields() {
        let (_d, store) = fresh_store();
        let mut app = sample_app(42);
        store.create(&app).unwrap();

        let prev = app.clone();
        app.name = "renamed".into();
        app.description = Some("now with description".into());
        app.updated_at = 100;
        store.update(&prev, &app).unwrap();

        let got = store.get(&app.app_id).unwrap().unwrap();
        assert_eq!(got.name, "renamed");
        assert_eq!(got.description.as_deref(), Some("now with description"));
        assert_eq!(got.updated_at, 100);
    }

    #[test]
    fn update_rejects_app_id_change() {
        let (_d, store) = fresh_store();
        let app = sample_app(42);
        store.create(&app).unwrap();

        let prev = app.clone();
        let mut next = app.clone();
        next.app_id = generate_app_id();
        assert!(store.update(&prev, &next).is_err());
    }

    #[test]
    fn update_rejects_owner_change() {
        let (_d, store) = fresh_store();
        let app = sample_app(42);
        store.create(&app).unwrap();

        let prev = app.clone();
        let mut next = app.clone();
        next.owner_fid = 99;
        assert!(store.update(&prev, &next).is_err());
    }

    #[test]
    fn list_all_returns_apps_across_owners() {
        let (_d, store) = fresh_store();
        let a = sample_app(1);
        let b = sample_app(2);
        let c = sample_app(3);
        store.create(&a).unwrap();
        store.create(&b).unwrap();
        store.create(&c).unwrap();

        let mut listed = store.list_all(100).unwrap();
        listed.sort_by(|x, y| x.app_id.cmp(&y.app_id));
        let mut expected = vec![a.app_id.clone(), b.app_id.clone(), c.app_id.clone()];
        expected.sort();
        let got: Vec<String> = listed.into_iter().map(|a| a.app_id).collect();
        assert_eq!(got, expected);
    }

    #[test]
    fn list_all_respects_max() {
        let (_d, store) = fresh_store();
        for owner in 1..=5 {
            store.create(&sample_app(owner)).unwrap();
        }
        let page = store.list_all(2).unwrap();
        assert_eq!(page.len(), 2);
    }

    #[test]
    fn delete_removes_record_and_owner_index() {
        let (_d, store) = fresh_store();
        let app = sample_app(42);
        store.create(&app).unwrap();
        store.delete(&app).unwrap();

        assert!(store.get(&app.app_id).unwrap().is_none());
        assert_eq!(store.count_by_owner(42).unwrap(), 0);
    }

    #[test]
    fn validate_app_id_rejects_bad_chars() {
        // Exact length but contains a '0' (not in base58).
        let bad = "0".repeat(APP_ID_LEN);
        assert!(matches!(
            validate_app_id(&bad),
            Err(AppStoreError::BadAppId)
        ));
    }

    #[test]
    fn validate_app_id_rejects_wrong_length() {
        assert!(matches!(
            validate_app_id("short"),
            Err(AppStoreError::BadAppId)
        ));
        let long = "a".repeat(APP_ID_LEN + 1);
        assert!(matches!(
            validate_app_id(&long),
            Err(AppStoreError::BadAppId)
        ));
    }
}
