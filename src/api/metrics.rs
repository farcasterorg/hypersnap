//! Engagement metrics indexer for cast reactions and replies.
//!
//! This module tracks:
//! - Like counts per cast
//! - Recast counts per cast
//! - Reply counts per cast
//!
//! # Storage Schema
//!
//! Keys are prefixed with METRICS_PREFIX (0xE2):
//! - `[prefix][0x01][fid:8][hash:20]` -> CastMetrics (likes, recasts, replies)
//! - `[prefix][0x02][hour:4][fid:8][hash_len:1][hash]` -> i64 engagement score
//!   earned in that hour, from live events (trending windows)
//! - `[prefix][0x03]` -> farcaster time from which live events fill hour buckets
//! - `[prefix][0x04]` -> present once older hour buckets are backfilled
//! - `[prefix][0x05][hour:4][fid:8][hash_len:1][hash]` -> i64 score, backfilled
//!   from the stores for engagement before `[prefix][0x03]`
//! - `[prefix][0xFF]` -> checkpoint:8
//!
//! Subkeys 0x01/02/05/06/07 are also stored with bit 0x10 set for
//! the replacement generation. 0x06 records reaction membership and 0x07
//! records replies (including deletion tombstones); 0xF0..F3 track publication.
//! The old generation is retained until replacement replay completes.
//!
//! # Processing
//!
//! - ReactionAdd (type=Like): increment like count
//! - ReactionRemove (type=Like): decrement like count
//! - ReactionAdd (type=Recast): increment recast count
//! - ReactionRemove (type=Recast): decrement recast count
//! - CastAdd with parent_cast_id: increment reply count on parent
//!
//! Each of these also adds its weight (like 1, recast 2, reply 3) to the
//! target cast's bucket for the hour of the message timestamp, negated for
//! removals. Pruned messages are skipped: the hyper stores the API serves keep
//! them, and they were counted when they merged. Revoked messages are gone
//! from every store, so a revoked add counts as a removal.

use crate::api::config::MetricsConfig;
use crate::api::events::{IndexEvent, MessageEventKind};
use crate::api::indexer::{Indexer, IndexerError, IndexerStats};
use crate::proto::message_data::Body;
use crate::proto::{Message, MessageType, ReactionType};
use crate::storage::db::{PageOptions, RocksDB, RocksDbTransactionBatch};
use async_trait::async_trait;
use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::AtomicU8;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

mod replacement;

/// Key prefixes for metrics data.
mod keys {
    /// Prefix for all metrics index keys.
    pub const METRICS_PREFIX: u8 = 0xE2;

    /// Cast metrics: <prefix><0x01><fid:8><hash_len:1><hash:N> -> CastMetrics
    pub const CAST_METRICS: u8 = 0x01;

    /// Hourly engagement from live events: <prefix><0x02><hour:4><fid:8><hash_len:1><hash:N> -> i64
    pub const WINDOW_LIVE: u8 = 0x02;

    /// Farcaster time from which live events fill hour buckets: <prefix><0x03> -> u64
    pub const WINDOW_LIVE_SINCE: u8 = 0x03;

    /// Hourly engagement backfilled from the stores: same layout as WINDOW_LIVE
    pub const WINDOW_BACKFILL: u8 = 0x05;

    pub const MEMBERSHIP: u8 = 0x06;
    pub const REPLIES: u8 = 0x07;
    pub const ACTIVE: u8 = 0xF0;
    pub const BUILDING: u8 = 0xF1;
    pub const SCHEMA: u8 = 0xF2;
    pub const DELETING: u8 = 0xF3;

    /// Checkpoint: <prefix><0xFF> -> event_id:8
    pub const CHECKPOINT: u8 = 0xFF;
}

/// Engagement metrics for a single cast.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CastMetrics {
    pub likes: u64,
    pub recasts: u64,
    pub replies: u64,
}

/// Seconds of hourly engagement kept for trending windows (7 days and the
/// partial hour at the window's start).
pub const WINDOW_RETENTION_SECS: u64 = (7 * 24 + 1) * 3600;

const LIKE_WEIGHT: i64 = 1;
const RECAST_WEIGHT: i64 = 2;
const REPLY_WEIGHT: i64 = 3;

/// Metrics indexer for tracking engagement on casts.
pub struct MetricsIndexer {
    config: MetricsConfig,
    generation: AtomicU8,
    writer: Arc<Mutex<()>>,
    readers: Arc<RwLock<()>>,
    fixed_generation: bool,
    db: Arc<RocksDB>,
    checkpoint: AtomicU64,
    casts_tracked: AtomicU64,
    /// Legacy live-hour boundary. Replacement views replay all retained hours.
    window_live_since: u64,
    /// Last hour whose expired buckets were deleted.
    window_pruned_hour: Arc<[AtomicU64; 4]>,
}

impl MetricsIndexer {
    /// Create a new metrics indexer.
    pub fn new(config: MetricsConfig, db: Arc<RocksDB>) -> Self {
        let checkpoint = Self::load_checkpoint(&db).unwrap_or(0);
        let window_live_since = Self::load_or_init_window_live_since(&db);

        Self {
            config,
            generation: AtomicU8::new(
                Self::read_generation(&db, keys::ACTIVE)
                    .expect("Invalid metrics generation")
                    .unwrap_or(0),
            ),
            writer: Arc::new(Mutex::new(())),
            readers: Arc::new(RwLock::new(())),
            fixed_generation: false,
            db,
            checkpoint: AtomicU64::new(checkpoint),
            casts_tracked: AtomicU64::new(0),
            window_live_since,
            window_pruned_hour: Arc::new(std::array::from_fn(|_| AtomicU64::new(0))),
        }
    }

    /// The farcaster time live events start filling hour buckets from, set
    /// the first time an indexer opens this database.
    fn load_or_init_window_live_since(db: &RocksDB) -> u64 {
        let key = [keys::METRICS_PREFIX, keys::WINDOW_LIVE_SINCE];
        if let Ok(Some(value)) = db.get(&key) {
            if value.len() == 8 {
                return u64::from_be_bytes(value[..8].try_into().unwrap());
            }
        }
        let now = crate::core::util::get_farcaster_time().unwrap_or(0);
        if let Err(e) = db.put(&key, &now.to_be_bytes()) {
            tracing::warn!(error = %e, "Failed to persist trending window start");
        }
        now
    }

    /// Durable per-shard scan and tail positions, rather than the query
    /// handle's legacy event counter.
    pub fn backfill_progress(
        &self,
        shards: &[(u32, u64)],
    ) -> Result<serde_json::Value, IndexerError> {
        let _readers = self.readers.read();
        let building = self.building_generation()?;
        let generation = building.unwrap_or_else(|| self.generation());
        let mut progress = Vec::new();
        let mut scan_complete = true;
        let mut caught_up = true;
        for &(shard, tip) in shards {
            let mut row = super::metrics_scan::progress(&self.view(generation), &self.db, shard)?;
            let next = super::backfill::try_load_shard_checkpoint(
                &self.db,
                &super::metrics_worker::cursor(generation),
                shard,
            )?;
            scan_complete &= row["scan_complete"].as_bool().unwrap_or(false);
            caught_up &= next > tip;
            row["next_block"] = next.into();
            row["tip"] = tip.into();
            row["blocks_remaining"] = (tip + 1).saturating_sub(next).into();
            progress.push(row);
        }
        let phase = if building.is_some() {
            if scan_complete && !shards.is_empty() {
                "catching_up"
            } else {
                "scanning"
            }
        } else if self.stats().backfill_complete {
            if caught_up {
                "ready"
            } else {
                "catching_up"
            }
        } else {
            "initializing"
        };
        Ok(
            serde_json::json!({"phase":phase,"active_generation":self.generation(),"building_generation":building,"shards":progress}),
        )
    }

    /// Get metrics for a cast.
    pub fn get_cast_metrics(&self, fid: u64, hash: &[u8]) -> Result<CastMetrics, IndexerError> {
        let _guard = self.readers.read();
        let key = self.cast_key(fid, hash);
        match self.db.get(&key) {
            Ok(Some(data)) => {
                let metrics: CastMetrics = serde_json::from_slice(&data).map_err(|e| {
                    IndexerError::Storage(format!("Failed to deserialize metrics: {}", e))
                })?;
                Ok(metrics)
            }
            Ok(None) => Ok(CastMetrics::default()),
            Err(e) => Err(IndexerError::Storage(format!("DB read error: {:?}", e))),
        }
    }

    /// Casts by engagement score earned between `now - window_secs` and
    /// `now` (farcaster seconds, at hour granularity), highest first, as
    /// `(fid, hash, score)`. Casts whose net score is not positive are left out.
    pub fn get_trending_window(
        &self,
        window_secs: u64,
        now: u64,
    ) -> Result<Vec<(u64, Vec<u8>, f64)>, IndexerError> {
        let _guard = self.readers.read();
        let from_hour = (now.saturating_sub(window_secs) / 3600) as u32;
        let mut scores: HashMap<(u64, Vec<u8>), i64> = HashMap::new();
        for source in [
            keys::WINDOW_LIVE | self.generation(),
            keys::WINDOW_BACKFILL | self.generation(),
        ] {
            let start = [
                &[keys::METRICS_PREFIX, source][..],
                &from_hour.to_be_bytes(),
            ]
            .concat();
            let stop = vec![keys::METRICS_PREFIX, source + 1];
            self.db
                .for_each_iterator_by_prefix(
                    Some(start),
                    Some(stop),
                    &PageOptions::default(),
                    |key, value| {
                        if let (Some((fid, hash)), Ok(bytes)) =
                            (Self::parse_window_key(key), <[u8; 8]>::try_from(value))
                        {
                            *scores.entry((fid, hash.to_vec())).or_default() +=
                                i64::from_be_bytes(bytes);
                        }
                        Ok(false)
                    },
                )
                .map_err(|e| IndexerError::Storage(format!("Failed to iterate: {:?}", e)))?;
        }

        let mut ranked: Vec<(u64, Vec<u8>, f64)> = scores
            .into_iter()
            .filter(|(_, score)| *score > 0)
            .map(|((fid, hash), score)| (fid, hash, score as f64))
            .collect();
        ranked.sort_by(|a, b| {
            b.2.total_cmp(&a.2)
                .then_with(|| a.0.cmp(&b.0))
                .then_with(|| a.1.cmp(&b.1))
        });
        Ok(ranked)
    }

    /// Get number of casts being tracked.
    pub fn casts_tracked(&self) -> u64 {
        self.casts_tracked.load(Ordering::Relaxed)
    }

    /// Process a single message.
    fn process_message(
        &self,
        message: &Message,
        kind: MessageEventKind,
        txn: &mut RocksDbTransactionBatch,
    ) -> Result<(), IndexerError> {
        let data = match &message.data {
            Some(d) => d,
            None => return Ok(()),
        };

        if kind == MessageEventKind::Prune {
            return Ok(());
        }
        self.apply_engagement(message, data, kind, txn)
    }

    /// Add `delta` to the cast's live bucket for the hour of `timestamp`.
    /// Engagement older than live tracking is the backfill's, and engagement
    /// past retention would be deleted straight away.
    fn add_window_score(
        &self,
        fid: u64,
        hash: &[u8],
        timestamp: u32,
        delta: i64,
        txn: &mut RocksDbTransactionBatch,
    ) -> Result<(), IndexerError> {
        let timestamp = timestamp as u64;
        let now = crate::core::util::get_farcaster_time().unwrap_or(0);
        if timestamp
            < if self.generation() == 0 {
                self.window_live_since
            } else {
                0
            }
            || timestamp + WINDOW_RETENTION_SECS < now
            || delta == 0
        {
            return Ok(());
        }
        let key = Self::make_window_key(
            keys::WINDOW_LIVE | self.generation(),
            timestamp / 3600,
            fid,
            hash,
        );
        Self::add_to_window_key(&self.db, key, delta, txn)
    }

    /// Add `delta` to the i64 at `key`, reading pending writes in `txn` first.
    fn add_to_window_key(
        db: &RocksDB,
        key: Vec<u8>,
        delta: i64,
        txn: &mut RocksDbTransactionBatch,
    ) -> Result<(), IndexerError> {
        let current = match txn.batch.get(&key) {
            Some(pending) => pending.clone(),
            None => db
                .get(&key)
                .map_err(|e| IndexerError::Storage(e.to_string()))?,
        };
        let current = current
            .and_then(|bytes| <[u8; 8]>::try_from(bytes.as_slice()).ok())
            .map(i64::from_be_bytes)
            .unwrap_or(0);
        txn.put(key, (current + delta).to_be_bytes().to_vec());
        Ok(())
    }

    /// Delete hour buckets older than [`WINDOW_RETENTION_SECS`], at most once
    /// an hour.
    fn prune_window(&self, txn: &mut RocksDbTransactionBatch) -> Result<(), IndexerError> {
        let now = crate::core::util::get_farcaster_time().unwrap_or(0);
        let hour = now / 3600;
        if self.window_pruned_hour[(self.generation() / 0x10) as usize]
            .swap(hour, Ordering::Relaxed)
            == hour
        {
            return Ok(());
        }
        let cutoff = (now.saturating_sub(WINDOW_RETENTION_SECS) / 3600) as u32;
        for source in [
            keys::WINDOW_LIVE | self.generation(),
            keys::WINDOW_BACKFILL | self.generation(),
        ] {
            let start = vec![keys::METRICS_PREFIX, source];
            let stop = [&start[..], &cutoff.to_be_bytes()].concat();
            self.db
                .for_each_iterator_by_prefix(
                    Some(start),
                    Some(stop),
                    &PageOptions::default(),
                    |key, _| {
                        txn.delete(key.to_vec());
                        Ok(false)
                    },
                )
                .map_err(|e| IndexerError::Storage(format!("Failed to iterate: {:?}", e)))?;
        }
        Ok(())
    }

    fn make_window_key(source: u8, hour: u64, fid: u64, hash: &[u8]) -> Vec<u8> {
        let mut key = Vec::with_capacity(2 + 4 + 8 + 1 + hash.len());
        key.push(keys::METRICS_PREFIX);
        key.push(source);
        key.extend_from_slice(&(hour as u32).to_be_bytes());
        key.extend_from_slice(&fid.to_be_bytes());
        key.push(hash.len() as u8);
        key.extend_from_slice(hash);
        key
    }

    /// `(fid, hash)` from a window key.
    fn parse_window_key(key: &[u8]) -> Option<(u64, &[u8])> {
        let fid = u64::from_be_bytes(key.get(6..14)?.try_into().ok()?);
        let hash_len = *key.get(14)? as usize;
        Some((fid, key.get(15..15 + hash_len)?))
    }

    fn commit(&self, txn: RocksDbTransactionBatch) -> Result<(), IndexerError> {
        if txn.len() == 0 {
            return Ok(());
        }
        self.db
            .commit(txn)
            .map_err(|e| IndexerError::Storage(e.to_string()))
    }

    /// Get metrics from pending transaction or DB.
    fn get_metrics_from_txn(
        &self,
        key: &[u8],
        txn: &RocksDbTransactionBatch,
    ) -> Result<Option<CastMetrics>, IndexerError> {
        // Check pending writes first
        if let Some(Some(value)) = txn.batch.get(key) {
            let metrics: CastMetrics = serde_json::from_slice(value)
                .map_err(|e| IndexerError::Storage(format!("Failed to deserialize: {}", e)))?;
            return Ok(Some(metrics));
        }

        // Fall back to DB
        match self.db.get(key) {
            Ok(Some(data)) => {
                let metrics: CastMetrics = serde_json::from_slice(&data)
                    .map_err(|e| IndexerError::Storage(format!("Failed to deserialize: {}", e)))?;
                Ok(Some(metrics))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(IndexerError::Storage(format!("DB error: {:?}", e))),
        }
    }

    /// Update metrics for a cast based on a reaction.
    fn update_cast_metrics(
        &self,
        fid: u64,
        hash: &[u8],
        reaction_type: ReactionType,
        is_add: bool,
        txn: &mut RocksDbTransactionBatch,
    ) -> Result<(), IndexerError> {
        let key = self.cast_key(fid, hash);

        // Get existing metrics from txn or DB
        let mut metrics = match self.get_metrics_from_txn(&key, txn)? {
            Some(m) => m,
            None => {
                if is_add {
                    self.casts_tracked.fetch_add(1, Ordering::Relaxed);
                }
                CastMetrics::default()
            }
        };

        // Update the appropriate counter
        match reaction_type {
            ReactionType::Like => {
                if is_add {
                    metrics.likes = metrics.likes.saturating_add(1);
                } else {
                    metrics.likes = metrics.likes.saturating_sub(1);
                }
            }
            ReactionType::Recast => {
                if is_add {
                    metrics.recasts = metrics.recasts.saturating_add(1);
                } else {
                    metrics.recasts = metrics.recasts.saturating_sub(1);
                }
            }
            ReactionType::None => return Ok(()),
        }

        // Store updated metrics
        let value = serde_json::to_vec(&metrics)
            .map_err(|e| IndexerError::Storage(format!("Failed to serialize: {}", e)))?;
        txn.put(key, value);

        Ok(())
    }

    /// Add `delta` to the reply count for a cast.
    fn adjust_reply_count(
        &self,
        fid: u64,
        hash: &[u8],
        delta: i64,
        txn: &mut RocksDbTransactionBatch,
    ) -> Result<(), IndexerError> {
        let key = self.cast_key(fid, hash);

        // Get existing metrics from txn or DB
        let mut metrics = match self.get_metrics_from_txn(&key, txn)? {
            Some(m) => m,
            None => {
                self.casts_tracked.fetch_add(1, Ordering::Relaxed);
                CastMetrics::default()
            }
        };

        metrics.replies = metrics.replies.saturating_add_signed(delta);

        // Store updated metrics
        let value = serde_json::to_vec(&metrics)
            .map_err(|e| IndexerError::Storage(format!("Failed to serialize: {}", e)))?;
        txn.put(key, value);

        Ok(())
    }

    /// Create a key for cast metrics.
    fn make_cast_key(fid: u64, hash: &[u8]) -> Vec<u8> {
        let mut key = Vec::with_capacity(2 + 8 + 1 + hash.len());
        key.push(keys::METRICS_PREFIX);
        key.push(keys::CAST_METRICS);
        key.extend_from_slice(&fid.to_be_bytes());
        key.push(hash.len() as u8);
        key.extend_from_slice(hash);
        key
    }

    fn cast_key(&self, fid: u64, hash: &[u8]) -> Vec<u8> {
        let mut key = Self::make_cast_key(fid, hash);
        key[1] |= self.generation();
        key
    }

    fn write_events(&self, events: &[IndexEvent]) -> Result<(), IndexerError> {
        let mut txn = RocksDbTransactionBatch::new();
        for event in events {
            match event {
                IndexEvent::MessageCommitted { message, kind, .. } => {
                    self.process_message(message, *kind, &mut txn)?
                }
                IndexEvent::MessagesCommitted { messages, kind, .. } => {
                    for message in messages {
                        self.process_message(message, *kind, &mut txn)?;
                    }
                }
                _ => {}
            }
        }
        self.prune_window(&mut txn)?;
        self.commit(txn)
    }

    fn make_checkpoint_key() -> Vec<u8> {
        vec![keys::METRICS_PREFIX, keys::CHECKPOINT]
    }

    fn load_checkpoint(db: &RocksDB) -> Result<u64, IndexerError> {
        let key = Self::make_checkpoint_key();
        match db.get(&key) {
            Ok(Some(value)) if value.len() == 8 => {
                Ok(u64::from_be_bytes(value.try_into().unwrap()))
            }
            Ok(_) => Ok(0),
            Err(e) => Err(IndexerError::Storage(e.to_string())),
        }
    }
}

#[async_trait]
impl Indexer for MetricsIndexer {
    fn name(&self) -> &'static str {
        "metrics"
    }

    fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    async fn process_event(&self, event: &IndexEvent) -> Result<(), IndexerError> {
        match event {
            IndexEvent::MessageCommitted { .. } | IndexEvent::MessagesCommitted { .. } => {
                self.process_batch(std::slice::from_ref(event)).await?;
            }
            _ => {
                // Other event types not relevant for metrics
            }
        }
        Ok(())
    }

    async fn process_batch(&self, events: &[IndexEvent]) -> Result<(), IndexerError> {
        let _guard = self.writer.lock();
        self.write_events(events)?;
        // Live updates also reach the replacement; historical replay uses a
        // fixed view and never writes back into the generation being served.
        if !self.fixed_generation {
            if let Some(generation) = self.building_generation()? {
                self.view(generation).write_events(events)?;
            }
        }
        Ok(())
    }

    fn last_checkpoint(&self) -> u64 {
        self.checkpoint.load(Ordering::SeqCst)
    }

    async fn save_checkpoint(&self, event_id: u64) -> Result<(), IndexerError> {
        let key = Self::make_checkpoint_key();
        let value = event_id.to_be_bytes().to_vec();

        let mut txn = RocksDbTransactionBatch::new();
        txn.put(key, value);
        self.db
            .commit(txn)
            .map_err(|e| IndexerError::Storage(e.to_string()))?;

        self.checkpoint.store(event_id, Ordering::SeqCst);
        Ok(())
    }

    fn stats(&self) -> IndexerStats {
        IndexerStats {
            items_indexed: self.casts_tracked.load(Ordering::Relaxed),
            last_event_id: self.checkpoint.load(Ordering::SeqCst),
            last_block_height: 0,
            backfill_complete: matches!(self.building_generation(), Ok(None))
                && matches!(self.db.get(&[keys::METRICS_PREFIX, keys::SCHEMA]), Ok(Some(version)) if version == replacement::SCHEMA.to_be_bytes()),
            size_bytes: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::config::MetricsConfig;
    use crate::api::events::IndexEvent;
    use crate::proto::{CastAddBody, CastId, MessageData, ReactionBody};
    use crate::storage::db::RocksDB;

    fn make_test_db() -> Arc<RocksDB> {
        let tmp_path = tempfile::tempdir()
            .unwrap()
            .path()
            .as_os_str()
            .to_str()
            .unwrap()
            .to_string();
        let db = RocksDB::new(&tmp_path);
        db.open().unwrap();
        Arc::new(db)
    }

    fn create_indexer(db: Arc<RocksDB>) -> MetricsIndexer {
        let config = MetricsConfig {
            enabled: true,
            backfill_on_startup: false,
            backfill_batch_size: 100,
            ..Default::default()
        };
        MetricsIndexer::new(config, db)
    }

    fn create_reaction_message(
        fid: u64,
        target_fid: u64,
        target_hash: Vec<u8>,
        reaction_type: ReactionType,
        is_add: bool,
    ) -> Message {
        Message {
            data: Some(MessageData {
                fid,
                r#type: if is_add {
                    MessageType::ReactionAdd as i32
                } else {
                    MessageType::ReactionRemove as i32
                },
                timestamp: 1000,
                body: Some(crate::proto::message_data::Body::ReactionBody(
                    ReactionBody {
                        r#type: reaction_type as i32,
                        target: Some(crate::proto::reaction_body::Target::TargetCastId(CastId {
                            fid: target_fid,
                            hash: target_hash,
                        })),
                    },
                )),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    fn create_reply_message(fid: u64, parent_fid: u64, parent_hash: Vec<u8>) -> Message {
        Message {
            data: Some(MessageData {
                fid,
                r#type: MessageType::CastAdd as i32,
                timestamp: 1000,
                body: Some(crate::proto::message_data::Body::CastAddBody(CastAddBody {
                    parent: Some(crate::proto::cast_add_body::Parent::ParentCastId(CastId {
                        fid: parent_fid,
                        hash: parent_hash,
                    })),
                    text: "This is a reply".to_string(),
                    ..Default::default()
                })),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    fn at(mut message: Message, timestamp: u64) -> Message {
        message.data.as_mut().unwrap().timestamp = timestamp as u32;
        message
    }

    /// An indexer whose live hour buckets cover every timestamp.
    fn create_window_indexer() -> MetricsIndexer {
        let db = make_test_db();
        db.put(
            &[keys::METRICS_PREFIX, keys::WINDOW_LIVE_SINCE],
            &0u64.to_be_bytes(),
        )
        .unwrap();
        create_indexer(db)
    }

    #[tokio::test]
    async fn test_prune_does_not_recount_and_revoke_removes() {
        let indexer = create_indexer(make_test_db());
        let like = create_reaction_message(456, 123, vec![1; 20], ReactionType::Like, true);
        let reply = create_reply_message(789, 123, vec![1; 20]);
        for kind in [MessageEventKind::Merge, MessageEventKind::Prune] {
            indexer
                .process_event(&IndexEvent::message_of_kind(like.clone(), 1, 1, kind))
                .await
                .unwrap();
            indexer
                .process_event(&IndexEvent::message_of_kind(reply.clone(), 1, 1, kind))
                .await
                .unwrap();
        }
        let metrics = indexer.get_cast_metrics(123, &[1; 20]).unwrap();
        assert_eq!((metrics.likes, metrics.replies), (1, 1));

        for message in [like, reply] {
            indexer
                .process_event(&IndexEvent::message_of_kind(
                    message,
                    1,
                    1,
                    MessageEventKind::Revoke,
                ))
                .await
                .unwrap();
        }
        let metrics = indexer.get_cast_metrics(123, &[1; 20]).unwrap();
        assert_eq!((metrics.likes, metrics.replies), (0, 0));
    }

    #[tokio::test]
    async fn test_trending_window_ranks_engagement_inside_window() {
        let indexer = create_window_indexer();
        let now = crate::core::util::get_farcaster_time().unwrap();
        let (a, b, old) = (vec![0xa; 20], vec![0xb; 20], vec![0xc; 20]);
        let mut messages = vec![];
        for liker in 0..3 {
            messages.push(at(
                create_reaction_message(1000 + liker, 1, a.clone(), ReactionType::Like, true),
                now - 60,
            ));
        }
        // Recast (weight 2) and reply (weight 3) on B, three hours ago.
        messages.push(at(
            create_reaction_message(2000, 2, b.clone(), ReactionType::Recast, true),
            now - 3 * 3600,
        ));
        messages.push(at(create_reply_message(2001, 2, b.clone()), now - 3 * 3600));
        // Past retention: never bucketed.
        messages.push(at(
            create_reaction_message(3000, 3, old.clone(), ReactionType::Like, true),
            now - 8 * 24 * 3600,
        ));
        indexer
            .process_batch(&[IndexEvent::messages(messages, 1, 1)])
            .await
            .unwrap();

        let hour = indexer.get_trending_window(3600, now).unwrap();
        assert_eq!(hour, vec![(1, a.clone(), 3.0)]);
        let six_hours = indexer.get_trending_window(6 * 3600, now).unwrap();
        assert_eq!(six_hours, vec![(2, b.clone(), 5.0), (1, a.clone(), 3.0)]);
        let week = indexer.get_trending_window(7 * 24 * 3600, now).unwrap();
        assert!(week.iter().all(|(fid, _, _)| *fid != 3));

        // Unlikes inside the window come off the score; a cast at zero drops out.
        let unlikes: Vec<_> = (0..3)
            .map(|liker| {
                at(
                    create_reaction_message(1000 + liker, 1, a.clone(), ReactionType::Like, false),
                    now,
                )
            })
            .collect();
        indexer
            .process_batch(&[IndexEvent::messages(unlikes, 1, 1)])
            .await
            .unwrap();
        assert!(indexer.get_trending_window(3600, now).unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_window_buckets_skip_engagement_before_live_tracking() {
        // A fresh indexer starts live buckets now; older engagement is the
        // store backfill's to count.
        let indexer = create_indexer(make_test_db());
        let now = crate::core::util::get_farcaster_time().unwrap();
        let like = at(
            create_reaction_message(1, 9, vec![9; 20], ReactionType::Like, true),
            now - 3600,
        );
        indexer
            .process_event(&IndexEvent::message(like, 1, 1))
            .await
            .unwrap();
        assert!(indexer
            .get_trending_window(6 * 3600, now)
            .unwrap()
            .is_empty());
        assert_eq!(indexer.get_cast_metrics(9, &[9; 20]).unwrap().likes, 1);
    }

    #[tokio::test]
    async fn test_like_reaction() {
        let db = make_test_db();
        let indexer = create_indexer(db);

        let target_fid = 123u64;
        let target_hash = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];

        // Add a like
        let msg = create_reaction_message(
            456,
            target_fid,
            target_hash.clone(),
            ReactionType::Like,
            true,
        );
        let event = IndexEvent::message(msg, 1, 1);
        indexer.process_event(&event).await.unwrap();

        // Check metrics
        let metrics = indexer.get_cast_metrics(target_fid, &target_hash).unwrap();
        assert_eq!(metrics.likes, 1);
        assert_eq!(metrics.recasts, 0);
        assert_eq!(metrics.replies, 0);
    }

    #[tokio::test]
    async fn test_recast_reaction() {
        let db = make_test_db();
        let indexer = create_indexer(db);

        let target_fid = 123u64;
        let target_hash = vec![1, 2, 3, 4, 5, 6, 7, 8];

        // Add a recast
        let msg = create_reaction_message(
            456,
            target_fid,
            target_hash.clone(),
            ReactionType::Recast,
            true,
        );
        let event = IndexEvent::message(msg, 1, 1);
        indexer.process_event(&event).await.unwrap();

        // Check metrics
        let metrics = indexer.get_cast_metrics(target_fid, &target_hash).unwrap();
        assert_eq!(metrics.likes, 0);
        assert_eq!(metrics.recasts, 1);
        assert_eq!(metrics.replies, 0);
    }

    #[tokio::test]
    async fn test_reply_count() {
        let db = make_test_db();
        let indexer = create_indexer(db);

        let parent_fid = 123u64;
        let parent_hash = vec![1, 2, 3, 4, 5, 6, 7, 8];

        // Add a reply
        let msg = create_reply_message(456, parent_fid, parent_hash.clone());
        let event = IndexEvent::message(msg, 1, 1);
        indexer.process_event(&event).await.unwrap();

        // Check parent metrics
        let metrics = indexer.get_cast_metrics(parent_fid, &parent_hash).unwrap();
        assert_eq!(metrics.likes, 0);
        assert_eq!(metrics.recasts, 0);
        assert_eq!(metrics.replies, 1);
    }

    #[tokio::test]
    async fn test_multiple_reactions() {
        let db = make_test_db();
        let indexer = create_indexer(db);

        let target_fid = 123u64;
        let target_hash = vec![1, 2, 3, 4];

        // Add 3 likes from different users
        for user_fid in [100, 200, 300] {
            let msg = create_reaction_message(
                user_fid,
                target_fid,
                target_hash.clone(),
                ReactionType::Like,
                true,
            );
            let event = IndexEvent::message(msg, 1, 1);
            indexer.process_event(&event).await.unwrap();
        }

        // Add 2 recasts
        for user_fid in [400, 500] {
            let msg = create_reaction_message(
                user_fid,
                target_fid,
                target_hash.clone(),
                ReactionType::Recast,
                true,
            );
            let event = IndexEvent::message(msg, 1, 1);
            indexer.process_event(&event).await.unwrap();
        }

        // Check metrics
        let metrics = indexer.get_cast_metrics(target_fid, &target_hash).unwrap();
        assert_eq!(metrics.likes, 3);
        assert_eq!(metrics.recasts, 2);
        assert_eq!(metrics.replies, 0);
    }

    #[tokio::test]
    async fn test_reaction_remove() {
        let db = make_test_db();
        let indexer = create_indexer(db);

        let target_fid = 123u64;
        let target_hash = vec![1, 2, 3, 4];

        // Add 3 likes
        for user_fid in [100, 200, 300] {
            let msg = create_reaction_message(
                user_fid,
                target_fid,
                target_hash.clone(),
                ReactionType::Like,
                true,
            );
            let event = IndexEvent::message(msg, 1, 1);
            indexer.process_event(&event).await.unwrap();
        }

        // Remove 1 like
        let remove_msg = create_reaction_message(
            100,
            target_fid,
            target_hash.clone(),
            ReactionType::Like,
            false,
        );
        let event = IndexEvent::message(remove_msg, 1, 1);
        indexer.process_event(&event).await.unwrap();

        // Check metrics
        let metrics = indexer.get_cast_metrics(target_fid, &target_hash).unwrap();
        assert_eq!(metrics.likes, 2);
    }

    #[tokio::test]
    async fn test_combined_engagement() {
        let db = make_test_db();
        let indexer = create_indexer(db);

        let target_fid = 123u64;
        let target_hash = vec![1, 2, 3, 4, 5, 6, 7, 8];

        // Add likes
        for user_fid in [100, 200] {
            let msg = create_reaction_message(
                user_fid,
                target_fid,
                target_hash.clone(),
                ReactionType::Like,
                true,
            );
            let event = IndexEvent::message(msg, 1, 1);
            indexer.process_event(&event).await.unwrap();
        }

        // Add recasts
        for user_fid in [300, 400, 500] {
            let msg = create_reaction_message(
                user_fid,
                target_fid,
                target_hash.clone(),
                ReactionType::Recast,
                true,
            );
            let event = IndexEvent::message(msg, 1, 1);
            indexer.process_event(&event).await.unwrap();
        }

        // Add replies
        for user_fid in [600, 700, 800, 900] {
            let msg = create_reply_message(user_fid, target_fid, target_hash.clone());
            let event = IndexEvent::message(msg, 1, 1);
            indexer.process_event(&event).await.unwrap();
        }

        // Check final metrics
        let metrics = indexer.get_cast_metrics(target_fid, &target_hash).unwrap();
        assert_eq!(metrics.likes, 2);
        assert_eq!(metrics.recasts, 3);
        assert_eq!(metrics.replies, 4);
    }

    #[test]
    fn test_nonexistent_cast() {
        let db = make_test_db();
        let indexer = create_indexer(db);

        // Query metrics for a cast that doesn't exist
        let metrics = indexer.get_cast_metrics(999, &[1, 2, 3]).unwrap();
        assert_eq!(metrics.likes, 0);
        assert_eq!(metrics.recasts, 0);
        assert_eq!(metrics.replies, 0);
    }

    #[tokio::test]
    async fn test_batch_processing() {
        let db = make_test_db();
        let indexer = create_indexer(db);

        let target_fid = 123u64;
        let target_hash = vec![1, 2, 3, 4];

        // Create multiple messages
        let messages: Vec<Message> = (0..5)
            .map(|i| {
                create_reaction_message(
                    100 + i,
                    target_fid,
                    target_hash.clone(),
                    ReactionType::Like,
                    true,
                )
            })
            .collect();

        // Process as batch
        let event = IndexEvent::messages(messages, 1, 1);
        indexer.process_event(&event).await.unwrap();

        // Check metrics
        let metrics = indexer.get_cast_metrics(target_fid, &target_hash).unwrap();
        assert_eq!(metrics.likes, 5);
    }

    #[tokio::test]
    async fn test_checkpoint() {
        let db = make_test_db();
        let indexer = create_indexer(db.clone());

        assert_eq!(indexer.last_checkpoint(), 0);

        indexer.save_checkpoint(100).await.unwrap();
        assert_eq!(indexer.last_checkpoint(), 100);

        // Verify it persists
        let indexer2 = create_indexer(db);
        assert_eq!(indexer2.last_checkpoint(), 100);
    }

    #[test]
    fn test_indexer_name() {
        let db = make_test_db();
        let indexer = create_indexer(db);
        assert_eq!(indexer.name(), "metrics");
    }

    #[test]
    fn test_indexer_enabled() {
        let db = make_test_db();
        let indexer = create_indexer(db);
        assert!(indexer.is_enabled());
    }
    #[tokio::test]
    async fn duplicate_batches_and_restart_do_not_recount_engagement() {
        let db = make_test_db();
        let indexer = create_indexer(db.clone());
        let now = crate::core::util::get_farcaster_time().unwrap();
        let mut reply = at(create_reply_message(789, 123, vec![1; 20]), now);
        reply.hash = vec![3; 20];
        let messages = vec![
            at(
                create_reaction_message(456, 123, vec![1; 20], ReactionType::Like, true),
                now,
            ),
            at(
                create_reaction_message(456, 123, vec![1; 20], ReactionType::Recast, true),
                now,
            ),
            reply,
        ];
        let event = IndexEvent::messages(messages, 1, 1);
        indexer
            .process_batch(&[event.clone(), event.clone()])
            .await
            .unwrap();
        let score = indexer.get_trending_window(3600, now).unwrap();
        let restarted = create_indexer(db);
        restarted.process_event(&event).await.unwrap();
        let m = restarted.get_cast_metrics(123, &[1; 20]).unwrap();
        assert_eq!((m.likes, m.recasts, m.replies), (1, 1, 1));
        assert_eq!(restarted.get_trending_window(3600, now).unwrap(), score);
    }

    #[tokio::test]
    async fn reaction_membership_tracks_latest_state_and_ignores_stale_events() {
        let indexer = create_indexer(make_test_db());
        let like = at(
            create_reaction_message(456, 123, vec![1; 20], ReactionType::Like, true),
            100,
        );
        let unlike = at(
            create_reaction_message(456, 123, vec![1; 20], ReactionType::Like, false),
            200,
        );
        let relike = at(like.clone(), 300);
        for message in [unlike.clone(), like.clone(), unlike.clone()] {
            indexer
                .process_event(&IndexEvent::message(message, 1, 1))
                .await
                .unwrap();
        }
        assert_eq!(indexer.get_cast_metrics(123, &[1; 20]).unwrap().likes, 0);
        for message in [relike.clone(), relike, unlike, like] {
            indexer
                .process_event(&IndexEvent::message(message, 1, 1))
                .await
                .unwrap();
        }
        assert_eq!(indexer.get_cast_metrics(123, &[1; 20]).unwrap().likes, 1);
    }

    #[tokio::test]
    async fn deleted_and_revoked_replies_never_reappear_during_replay() {
        let indexer = create_indexer(make_test_db());
        let mut reply = create_reply_message(789, 123, vec![1; 20]);
        reply.hash = vec![3; 20];
        let remove = Message {
            hash: vec![4; 20],
            data: Some(MessageData {
                fid: 789,
                timestamp: 2000,
                r#type: MessageType::CastRemove as i32,
                body: Some(Body::CastRemoveBody(crate::proto::CastRemoveBody {
                    target_hash: reply.hash.clone(),
                })),
                ..Default::default()
            }),
            ..Default::default()
        };
        for message in [reply.clone(), remove.clone(), remove, reply.clone()] {
            indexer
                .process_event(&IndexEvent::message(message, 1, 1))
                .await
                .unwrap();
        }
        assert_eq!(indexer.get_cast_metrics(123, &[1; 20]).unwrap().replies, 0);
        // A delete delivered before the add also leaves a tombstone.
        let mut other = reply.clone();
        other.hash = vec![5; 20];
        indexer
            .process_event(&IndexEvent::message_of_kind(
                other.clone(),
                1,
                1,
                MessageEventKind::Revoke,
            ))
            .await
            .unwrap();
        indexer
            .process_event(&IndexEvent::message(other, 1, 1))
            .await
            .unwrap();
        assert_eq!(indexer.get_cast_metrics(123, &[1; 20]).unwrap().replies, 0);
    }

    #[tokio::test]
    async fn concurrent_duplicate_updates_are_serialized() {
        let indexer = Arc::new(create_indexer(make_test_db()));
        let event = IndexEvent::message(
            create_reaction_message(456, 123, vec![1; 20], ReactionType::Like, true),
            1,
            1,
        );
        let mut tasks = vec![];
        for _ in 0..20 {
            let indexer = indexer.clone();
            let event = event.clone();
            tasks.push(tokio::spawn(async move {
                indexer.process_event(&event).await.unwrap();
            }));
        }
        for task in tasks {
            task.await.unwrap();
        }
        assert_eq!(indexer.get_cast_metrics(123, &[1; 20]).unwrap().likes, 1);
    }

    #[tokio::test]
    async fn replacement_keeps_old_counts_until_publish_and_resumes_after_restart() {
        let db = make_test_db();
        let indexer = create_indexer(db.clone());
        let legacy_key = MetricsIndexer::make_cast_key(123, &[1; 20]);
        let legacy_value = serde_json::to_vec(&CastMetrics {
            likes: 7,
            recasts: 2,
            replies: 4,
        })
        .unwrap();
        db.put(&legacy_key, &legacy_value).unwrap();
        indexer.prepare().unwrap();
        let generation = indexer.building_generation().unwrap().unwrap();
        let replacement = indexer.view(generation);
        let old_like = create_reaction_message(456, 123, vec![1; 20], ReactionType::Like, true);
        replacement
            .process_event(&IndexEvent::message(old_like.clone(), 1, 1))
            .await
            .unwrap();
        assert_eq!(indexer.get_cast_metrics(123, &[1; 20]).unwrap().likes, 7);
        assert_eq!(db.get(&legacy_key).unwrap(), Some(legacy_value.clone()));
        assert!(indexer.delete_retired(1).unwrap()); // no retired generation yet
        assert_eq!(db.get(&legacy_key).unwrap(), Some(legacy_value.clone()));
        let restarted = create_indexer(db.clone());
        restarted.prepare().unwrap();
        assert_eq!(restarted.building_generation().unwrap(), Some(generation));
        assert_eq!(restarted.get_cast_metrics(123, &[1; 20]).unwrap().likes, 7);
        restarted
            .view(generation)
            .process_event(&IndexEvent::message(old_like, 1, 1))
            .await
            .unwrap();
        // Live activity updates both generations while the replacement builds.
        let live = create_reaction_message(999, 123, vec![1; 20], ReactionType::Like, true);
        restarted
            .process_event(&IndexEvent::message(live.clone(), 1, 2))
            .await
            .unwrap();
        assert_eq!(restarted.get_cast_metrics(123, &[1; 20]).unwrap().likes, 8);
        restarted
            .view(generation)
            .process_event(&IndexEvent::message(live, 1, 2))
            .await
            .unwrap();
        restarted.switch_to(generation).unwrap();
        assert_eq!(restarted.get_cast_metrics(123, &[1; 20]).unwrap().likes, 2);
        assert!(db.get(&legacy_key).unwrap().is_some()); // publish did not clear it
        let published = create_indexer(db.clone());
        published.prepare().unwrap();
        assert_eq!(published.building_generation().unwrap(), None);
        assert_eq!(published.get_cast_metrics(123, &[1; 20]).unwrap().likes, 2);
        while !published.delete_retired(1).unwrap() {}
        assert!(db.get(&legacy_key).unwrap().is_none());
        assert_eq!(published.get_cast_metrics(123, &[1; 20]).unwrap().likes, 2);
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn blocked_replacement_write_does_not_block_existing_metrics_reads() {
        let db = make_test_db();
        let reader = create_indexer(db.clone());
        db.put(
            &MetricsIndexer::make_cast_key(123, &[1; 20]),
            br#"{"likes":7,"recasts":0,"replies":0}"#,
        )
        .unwrap();
        reader.prepare().unwrap();
        let generation = reader.building_generation().unwrap().unwrap();
        let replacement = reader.view(generation);
        let replacement_key = replacement.cast_key(123, &[1; 20]);
        let db_guard = db.db();
        let crate::storage::db::DBProvider::Transaction(raw) = db_guard.as_ref().unwrap() else {
            panic!("expected TransactionDB");
        };
        let lock = raw.transaction();
        lock.get_for_update(&replacement_key, true).unwrap();
        let task = tokio::spawn(async move {
            replacement
                .process_event(&IndexEvent::message(
                    create_reaction_message(456, 123, vec![1; 20], ReactionType::Like, true),
                    1,
                    1,
                ))
                .await
        });
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while reader.writer.try_lock().is_some() {
                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            }
        })
        .await
        .unwrap();
        let started = std::time::Instant::now();
        assert_eq!(reader.get_cast_metrics(123, &[1; 20]).unwrap().likes, 7);
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
        drop(lock);
        task.await.unwrap().unwrap();
    }
}
