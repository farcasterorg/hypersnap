//! User data reverse index.
//!
//! Indexes `UserDataAdd` messages by their value, enabling lookups like
//! "find the FID with Twitter username @foo" or "find users in location X"
//! without scanning all FIDs.
//!
//! Indexed data types:
//! - `UserDataType::Twitter` (8) — X/Twitter username → FID
//! - `UserDataType::Location` (7) — Location string → FID
//! - `UserDataType::Username` (6) — Farcaster username → FID (backup index)

use crate::api::config::FeatureConfig;
use crate::api::events::IndexEvent;
use crate::api::indexer::{Indexer, IndexerError, IndexerStats};
use crate::proto::message_data::Body;
use crate::proto::{Message, MessageType, UserDataType};
use crate::storage::db::{PageOptions, RocksDB, RocksDbTransactionBatch};
use crate::storage::util::increment_vec_u8;
use async_trait::async_trait;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Key prefix for the user data index (in the API RocksDB).
const USER_DATA_INDEX_PREFIX: u8 = 0xE9;

/// Sub-key for value→FID lookups: [prefix][0x01][data_type:1][value_lower:N] -> [fid:8_BE]
const VALUE_TO_FID: u8 = 0x01;

/// Sub-key for FID→value lookups: [prefix][0x02][data_type:1][fid:8_BE] -> [value:N]
/// Used to clean up old value when a user changes their twitter/location.
const FID_TO_VALUE: u8 = 0x02;

/// Checkpoint: [prefix][0xFF] -> event_id:8_BE
const CHECKPOINT: u8 = 0xFF;

/// Schema version key: [prefix][0xFE] -> version:4_BE
const SCHEMA_VERSION_KEY: u8 = 0xFE;

/// Current schema version. Bump to force re-backfill.
const SCHEMA_VERSION: u32 = 1;

/// User data types we index for reverse lookup.
const INDEXED_TYPES: &[i32] = &[
    UserDataType::Twitter as i32,  // 8
    UserDataType::Location as i32, // 7
];

pub struct UserDataIndexer {
    config: FeatureConfig,
    db: Arc<RocksDB>,
    checkpoint: AtomicU64,
    items_indexed: AtomicU64,
}

impl UserDataIndexer {
    pub fn new(config: FeatureConfig, db: Arc<RocksDB>) -> Self {
        // Check schema version — clear and re-backfill on upgrade
        let version_key = vec![USER_DATA_INDEX_PREFIX, SCHEMA_VERSION_KEY];
        let stored_version = match db.get(&version_key) {
            Ok(Some(v)) if v.len() == 4 => u32::from_be_bytes(v[..4].try_into().unwrap()),
            _ => 0,
        };
        if stored_version < SCHEMA_VERSION {
            if stored_version > 0 {
                tracing::info!(
                    "User data index schema upgraded (v{} -> v{}), clearing for re-backfill",
                    stored_version,
                    SCHEMA_VERSION
                );
            }
            Self::clear_all_data(&db);
            let mut txn = RocksDbTransactionBatch::new();
            txn.put(version_key, SCHEMA_VERSION.to_be_bytes().to_vec());
            let _ = db.commit(txn);
        }

        let checkpoint = Self::load_checkpoint(&db).unwrap_or(0);
        Self {
            config,
            db,
            checkpoint: AtomicU64::new(checkpoint),
            items_indexed: AtomicU64::new(0),
        }
    }

    /// Look up the FID for a user by a data type and value.
    /// For example, `get_fid_by_value(UserDataType::Twitter, "vitalik")`.
    pub fn get_fid_by_value(&self, data_type: i32, value: &str) -> Option<u64> {
        let key = Self::make_value_key(data_type, &value.to_lowercase());
        match self.db.get(&key) {
            Ok(Some(v)) if v.len() == 8 => Some(u64::from_be_bytes(v[..8].try_into().unwrap())),
            _ => None,
        }
    }

    /// Look up all FIDs matching a value prefix (for location search).
    pub fn get_fids_by_value_prefix(&self, data_type: i32, prefix: &str, limit: usize) -> Vec<u64> {
        let key_prefix = Self::make_value_key(data_type, &prefix.to_lowercase());
        let mut results = Vec::new();
        let _ = self.db.for_each_iterator_by_prefix(
            Some(key_prefix.clone()),
            Some(increment_vec_u8(&key_prefix)),
            &PageOptions {
                page_size: Some(limit),
                page_token: None,
                reverse: false,
            },
            |_key, value| {
                if value.len() == 8 {
                    results.push(u64::from_be_bytes(value[..8].try_into().unwrap()));
                }
                Ok(results.len() < limit)
            },
        );
        results
    }

    fn process_message(&self, message: &Message, txn: &mut RocksDbTransactionBatch) {
        let Some(data) = &message.data else { return };

        let msg_type = match MessageType::try_from(data.r#type) {
            Ok(mt) => mt,
            Err(_) => return,
        };

        if msg_type != MessageType::UserDataAdd {
            return;
        }

        let user_data = match &data.body {
            Some(Body::UserDataBody(body)) => body,
            _ => return,
        };

        let ud_type = user_data.r#type;
        if !INDEXED_TYPES.contains(&ud_type) {
            return;
        }

        let fid = data.fid;
        let value = user_data.value.to_lowercase();

        if value.is_empty() {
            return;
        }

        // Remove old value→FID mapping if the user changed their value
        let fid_key = Self::make_fid_key(ud_type, fid);
        if let Ok(Some(old_value)) = self.db.get(&fid_key) {
            let old_str = String::from_utf8_lossy(&old_value);
            if old_str.as_ref() != value {
                // Delete old reverse mapping
                let old_value_key = Self::make_value_key(ud_type, &old_str);
                txn.delete(old_value_key);
            }
        }

        // Write value→FID and FID→value
        let value_key = Self::make_value_key(ud_type, &value);
        txn.put(value_key, fid.to_be_bytes().to_vec());

        let fid_key = Self::make_fid_key(ud_type, fid);
        txn.put(fid_key, value.as_bytes().to_vec());

        self.items_indexed.fetch_add(1, Ordering::Relaxed);
    }

    fn make_value_key(data_type: i32, value_lower: &str) -> Vec<u8> {
        let mut key = Vec::with_capacity(3 + value_lower.len());
        key.push(USER_DATA_INDEX_PREFIX);
        key.push(VALUE_TO_FID);
        key.push(data_type as u8);
        key.extend_from_slice(value_lower.as_bytes());
        key
    }

    fn make_fid_key(data_type: i32, fid: u64) -> Vec<u8> {
        let mut key = Vec::with_capacity(3 + 8);
        key.push(USER_DATA_INDEX_PREFIX);
        key.push(FID_TO_VALUE);
        key.push(data_type as u8);
        key.extend_from_slice(&fid.to_be_bytes());
        key
    }

    fn make_checkpoint_key() -> Vec<u8> {
        vec![USER_DATA_INDEX_PREFIX, CHECKPOINT]
    }

    fn load_checkpoint(db: &RocksDB) -> Result<u64, IndexerError> {
        let key = Self::make_checkpoint_key();
        match db.get(&key) {
            Ok(Some(value)) if value.len() == 8 => {
                Ok(u64::from_be_bytes(value[..8].try_into().unwrap()))
            }
            Ok(_) => Ok(0),
            Err(e) => Err(IndexerError::Storage(e.to_string())),
        }
    }

    fn clear_all_data(db: &RocksDB) {
        let prefix = vec![USER_DATA_INDEX_PREFIX];
        let mut keys = Vec::new();
        let _ = db.for_each_iterator_by_prefix(
            Some(prefix.clone()),
            Some(increment_vec_u8(&prefix)),
            &PageOptions::default(),
            |key, _| {
                keys.push(key.to_vec());
                Ok(true)
            },
        );
        if !keys.is_empty() {
            let mut txn = RocksDbTransactionBatch::new();
            for key in keys {
                txn.delete(key);
            }
            let _ = db.commit(txn);
        }
    }
}

#[async_trait]
impl Indexer for UserDataIndexer {
    fn name(&self) -> &'static str {
        "user_data_index"
    }

    fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    async fn process_event(&self, event: &IndexEvent) -> Result<(), IndexerError> {
        match event {
            IndexEvent::MessageCommitted { message, .. } => {
                let mut txn = RocksDbTransactionBatch::new();
                self.process_message(message, &mut txn);
                if txn.len() > 0 {
                    self.db
                        .commit(txn)
                        .map_err(|e| IndexerError::Storage(e.to_string()))?;
                }
            }
            IndexEvent::MessagesCommitted { messages, .. } => {
                let mut txn = RocksDbTransactionBatch::new();
                for message in messages {
                    self.process_message(message, &mut txn);
                }
                if txn.len() > 0 {
                    self.db
                        .commit(txn)
                        .map_err(|e| IndexerError::Storage(e.to_string()))?;
                }
            }
            _ => {}
        }
        Ok(())
    }

    async fn process_batch(&self, events: &[IndexEvent]) -> Result<(), IndexerError> {
        let mut txn = RocksDbTransactionBatch::new();
        for event in events {
            match event {
                IndexEvent::MessageCommitted { message, .. } => {
                    self.process_message(message, &mut txn);
                }
                IndexEvent::MessagesCommitted { messages, .. } => {
                    for message in messages {
                        self.process_message(message, &mut txn);
                    }
                }
                _ => {}
            }
        }
        if txn.len() > 0 {
            self.db
                .commit(txn)
                .map_err(|e| IndexerError::Storage(e.to_string()))?;
        }
        Ok(())
    }

    fn last_checkpoint(&self) -> u64 {
        self.checkpoint.load(Ordering::SeqCst)
    }

    async fn save_checkpoint(&self, event_id: u64) -> Result<(), IndexerError> {
        let key = Self::make_checkpoint_key();
        let mut txn = RocksDbTransactionBatch::new();
        txn.put(key, event_id.to_be_bytes().to_vec());
        self.db
            .commit(txn)
            .map_err(|e| IndexerError::Storage(e.to_string()))?;
        self.checkpoint.store(event_id, Ordering::SeqCst);
        Ok(())
    }

    fn stats(&self) -> IndexerStats {
        IndexerStats {
            items_indexed: self.items_indexed.load(Ordering::Relaxed),
            last_event_id: self.checkpoint.load(Ordering::SeqCst),
            last_block_height: 0,
            backfill_complete: self.checkpoint.load(Ordering::SeqCst) > 0,
            size_bytes: 0,
        }
    }
}
