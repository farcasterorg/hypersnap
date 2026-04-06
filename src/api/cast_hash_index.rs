//! Lightweight cast hash → FID index.
//!
//! Stores a mapping from every cast's message hash to its author FID,
//! enabling O(1) cast-by-hash lookups without scanning all FIDs.

use crate::api::config::FeatureConfig;
use crate::api::events::IndexEvent;
use crate::api::indexer::{Indexer, IndexerError, IndexerStats};
use crate::proto::message_data::Body;
use crate::proto::{Message, MessageType};
use crate::storage::db::{RocksDB, RocksDbTransactionBatch};
use async_trait::async_trait;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Key prefix for the cast hash index (in the API RocksDB).
const CAST_HASH_PREFIX: u8 = 0xE4;

/// Sub-key: <prefix><hash:20> -> fid:8
const HASH_TO_FID: u8 = 0x01;

/// Checkpoint: <prefix><0xFF> -> event_id:8
const CHECKPOINT: u8 = 0xFF;

pub struct CastHashIndexer {
    config: FeatureConfig,
    db: Arc<RocksDB>,
    checkpoint: AtomicU64,
    items_indexed: AtomicU64,
}

impl CastHashIndexer {
    pub fn new(config: FeatureConfig, db: Arc<RocksDB>) -> Self {
        let checkpoint = Self::load_checkpoint(&db).unwrap_or(0);
        Self {
            config,
            db,
            checkpoint: AtomicU64::new(checkpoint),
            items_indexed: AtomicU64::new(0),
        }
    }

    /// Look up the FID for a cast by its message hash.
    pub fn get_fid_by_hash(&self, hash: &[u8]) -> Option<u64> {
        let key = Self::make_key(hash);
        match self.db.get(&key) {
            Ok(Some(value)) if value.len() == 8 => {
                Some(u64::from_be_bytes(value[..8].try_into().unwrap()))
            }
            _ => None,
        }
    }

    fn process_message(&self, message: &Message, txn: &mut RocksDbTransactionBatch) {
        let Some(data) = &message.data else { return };

        let msg_type = match MessageType::try_from(data.r#type) {
            Ok(mt) => mt,
            Err(_) => return,
        };

        // Index CastAdd messages only (CastRemove doesn't need a lookup)
        if msg_type != MessageType::CastAdd {
            return;
        }

        // Verify it's actually a cast body
        if !matches!(&data.body, Some(Body::CastAddBody(_))) {
            return;
        }

        if message.hash.is_empty() {
            return;
        }

        let key = Self::make_key(&message.hash);
        txn.put(key, data.fid.to_be_bytes().to_vec());
        self.items_indexed.fetch_add(1, Ordering::Relaxed);
    }

    fn make_key(hash: &[u8]) -> Vec<u8> {
        let mut key = Vec::with_capacity(2 + hash.len());
        key.push(CAST_HASH_PREFIX);
        key.push(HASH_TO_FID);
        key.extend_from_slice(hash);
        key
    }

    fn make_checkpoint_key() -> Vec<u8> {
        vec![CAST_HASH_PREFIX, CHECKPOINT]
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
}

#[async_trait]
impl Indexer for CastHashIndexer {
    fn name(&self) -> &'static str {
        "cast_hash"
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
