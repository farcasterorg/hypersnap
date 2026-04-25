//! Cast quotes reverse index.
//!
//! When a cast embeds another cast (via `Embed::CastId`), this is a "quote".
//! This indexer stores a reverse mapping from the *quoted* cast's hash to
//! the *quoting* cast, enabling `GET /v2/farcaster/cast/quotes/` lookups.

use crate::api::config::FeatureConfig;
use crate::api::events::IndexEvent;
use crate::api::indexer::{Indexer, IndexerError, IndexerStats};
use crate::proto::message_data::Body;
use crate::proto::{Message, MessageType};
use crate::storage::db::{PageOptions, RocksDB, RocksDbTransactionBatch};
use crate::storage::util::increment_vec_u8;
use async_trait::async_trait;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Key prefix for the cast quotes index (in the API RocksDB).
const QUOTES_PREFIX: u8 = 0xE8;

/// Sub-key for quote entries: [prefix][0x01][target_hash:20][quoting_fid:8][quoting_hash:20] -> [1]
const QUOTE_ENTRY: u8 = 0x01;

/// Checkpoint: [prefix][0xFF] -> event_id:8
const CHECKPOINT: u8 = 0xFF;

/// Schema version key: [prefix][0xFE] -> version:4
const SCHEMA_VERSION_KEY: u8 = 0xFE;

/// Current schema version. Bump this to force a re-backfill.
const SCHEMA_VERSION: u32 = 1;

pub struct CastQuotesIndexer {
    config: FeatureConfig,
    db: Arc<RocksDB>,
    checkpoint: AtomicU64,
    items_indexed: AtomicU64,
}

impl CastQuotesIndexer {
    pub fn new(config: FeatureConfig, db: Arc<RocksDB>) -> Self {
        // Check schema version — clear and re-backfill on upgrade
        let version_key = vec![QUOTES_PREFIX, SCHEMA_VERSION_KEY];
        let stored_version = match db.get(&version_key) {
            Ok(Some(v)) if v.len() == 4 => u32::from_be_bytes(v[..4].try_into().unwrap()),
            _ => 0,
        };
        if stored_version < SCHEMA_VERSION {
            if stored_version > 0 {
                tracing::info!(
                    "Cast quotes index schema upgraded (v{} -> v{}), clearing for re-backfill",
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

    /// Look up casts that quote a given cast (by its hash).
    ///
    /// Returns `(vec_of_(quoting_fid, quoting_hash), optional_next_cursor)`.
    pub fn get_quotes(
        &self,
        target_hash: &[u8],
        limit: usize,
    ) -> Result<Vec<(u64, Vec<u8>)>, IndexerError> {
        let prefix = Self::make_quote_prefix(target_hash);
        let mut results = Vec::new();

        self.db
            .for_each_iterator_by_prefix(
                Some(prefix.clone()),
                Some(increment_vec_u8(&prefix)),
                &PageOptions {
                    page_size: Some(limit),
                    page_token: None,
                    reverse: false,
                },
                |key, _value| {
                    // Key layout: [prefix:1][sub:1][target_hash:20][quoting_fid:8][quoting_hash:20]
                    let offset = 2 + target_hash.len(); // skip prefix + sub + target_hash
                    if key.len() >= offset + 8 + 20 {
                        let fid = u64::from_be_bytes(key[offset..offset + 8].try_into().unwrap());
                        let hash = key[offset + 8..offset + 28].to_vec();
                        results.push((fid, hash));
                    }
                    Ok(results.len() < limit)
                },
            )
            .map_err(|e| IndexerError::Storage(e.to_string()))?;

        Ok(results)
    }

    fn process_message(&self, message: &Message, txn: &mut RocksDbTransactionBatch) {
        let Some(data) = &message.data else { return };

        let msg_type = match MessageType::try_from(data.r#type) {
            Ok(mt) => mt,
            Err(_) => return,
        };

        if msg_type != MessageType::CastAdd {
            return;
        }

        let cast_body = match &data.body {
            Some(Body::CastAddBody(body)) => body,
            _ => return,
        };

        if message.hash.is_empty() {
            return;
        }

        // Index each embedded CastId as a quote relationship
        for embed in &cast_body.embeds {
            if let Some(crate::proto::embed::Embed::CastId(quoted)) = &embed.embed {
                if !quoted.hash.is_empty() {
                    let key = Self::make_quote_key(&quoted.hash, data.fid, &message.hash);
                    txn.put(key, vec![0x01]);
                    self.items_indexed.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }

    /// Build the prefix for scanning all quotes of a target cast.
    fn make_quote_prefix(target_hash: &[u8]) -> Vec<u8> {
        let mut key = Vec::with_capacity(2 + target_hash.len());
        key.push(QUOTES_PREFIX);
        key.push(QUOTE_ENTRY);
        key.extend_from_slice(target_hash);
        key
    }

    /// Build the full key for a single quote entry.
    fn make_quote_key(target_hash: &[u8], quoting_fid: u64, quoting_hash: &[u8]) -> Vec<u8> {
        let mut key = Vec::with_capacity(2 + target_hash.len() + 8 + quoting_hash.len());
        key.push(QUOTES_PREFIX);
        key.push(QUOTE_ENTRY);
        key.extend_from_slice(target_hash);
        key.extend_from_slice(&quoting_fid.to_be_bytes());
        key.extend_from_slice(quoting_hash);
        key
    }

    fn make_checkpoint_key() -> Vec<u8> {
        vec![QUOTES_PREFIX, CHECKPOINT]
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
        // Delete everything under our prefix by scanning and deleting keys
        let prefix = vec![QUOTES_PREFIX];
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
impl Indexer for CastQuotesIndexer {
    fn name(&self) -> &'static str {
        "cast_quotes"
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
