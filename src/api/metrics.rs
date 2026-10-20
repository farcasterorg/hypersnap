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
use crate::mempool::routing::{MessageRouter, ShardRouter};
use crate::proto::message_data::Body;
use crate::proto::{Message, MessageType, ReactionType};
use crate::storage::constants::{RootPrefix, UserPostfix};
use crate::storage::db::{PageOptions, RocksDB, RocksDbTransactionBatch};
use crate::storage::store::account::{make_user_key_with_prefix, message_decode};
use crate::storage::store::stores::Stores;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

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

    /// Present once the store backfill of hour buckets has finished: <prefix><0x04>
    pub const WINDOW_BACKFILL_DONE: u8 = 0x04;

    /// Hourly engagement backfilled from the stores: same layout as WINDOW_LIVE
    pub const WINDOW_BACKFILL: u8 = 0x05;

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
    db: Arc<RocksDB>,
    checkpoint: AtomicU64,
    casts_tracked: AtomicU64,
    /// Live events with a timestamp at or after this fill hour buckets;
    /// [`Self::backfill_window`] covers the engagement before it.
    window_live_since: u64,
    /// Last hour whose expired buckets were deleted.
    window_pruned_hour: AtomicU64,
}

impl MetricsIndexer {
    /// Create a new metrics indexer.
    pub fn new(config: MetricsConfig, db: Arc<RocksDB>) -> Self {
        let checkpoint = Self::load_checkpoint(&db).unwrap_or(0);
        let window_live_since = Self::load_or_init_window_live_since(&db);

        Self {
            config,
            db,
            checkpoint: AtomicU64::new(checkpoint),
            casts_tracked: AtomicU64::new(0),
            window_live_since,
            window_pruned_hour: AtomicU64::new(0),
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

    /// Get metrics for a cast.
    pub fn get_cast_metrics(&self, fid: u64, hash: &[u8]) -> Result<CastMetrics, IndexerError> {
        let key = Self::make_cast_key(fid, hash);
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
        let from_hour = (now.saturating_sub(window_secs) / 3600) as u32;
        let mut scores: HashMap<(u64, Vec<u8>), i64> = HashMap::new();
        for source in [keys::WINDOW_LIVE, keys::WINDOW_BACKFILL] {
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

    /// Fill hour buckets for the engagement that predates live bucket
    /// tracking, from every cast and reaction in `hyper_stores` timestamped
    /// within [`WINDOW_RETENTION_SECS`] before it. Runs once. Blocking.
    pub fn backfill_window(&self, hyper_stores: &HashMap<u32, Stores>) -> Result<(), IndexerError> {
        let done_key = [keys::METRICS_PREFIX, keys::WINDOW_BACKFILL_DONE];
        if matches!(self.db.get(&done_key), Ok(Some(_))) {
            return Ok(());
        }
        let until = self.window_live_since;
        let from = until.saturating_sub(WINDOW_RETENTION_SECS);
        let num_shards = hyper_stores.len() as u32;
        let router = ShardRouter {};

        for (&shard_id, stores) in hyper_stores {
            let Some(max_fid) = crate::storage::store::reconcile::max_registered_fid(stores) else {
                continue;
            };
            let mut txn = RocksDbTransactionBatch::new();
            for fid in 1..=max_fid {
                if router.route_fid(fid, num_shards) != shard_id {
                    continue;
                }
                let user = make_user_key_with_prefix(RootPrefix::HyperUser as u8, fid);
                for postfix in [UserPostfix::ReactionMessage, UserPostfix::CastMessage] {
                    let set = [&user[..], &[postfix as u8]].concat();
                    let start = [&set[..], &(from as u32).to_be_bytes()].concat();
                    let stop = [&set[..], &(until as u32).to_be_bytes()].concat();
                    stores
                        .db
                        .for_each_iterator_by_prefix(
                            Some(start),
                            Some(stop),
                            &PageOptions::default(),
                            |_key, value| {
                                if let Ok(message) = message_decode(value) {
                                    self.backfill_message(&message, &mut txn)?;
                                }
                                Ok(false)
                            },
                        )
                        .map_err(|e| IndexerError::Storage(format!("{:?}", e)))?;
                }
                if txn.len() >= 1000 {
                    self.commit(std::mem::replace(&mut txn, RocksDbTransactionBatch::new()))?;
                }
            }
            self.commit(txn)?;
        }

        self.db
            .put(&done_key, &[1])
            .map_err(|e| IndexerError::Storage(e.to_string()))
    }

    /// Add a stored message's engagement to the backfilled hour buckets.
    fn backfill_message(
        &self,
        message: &Message,
        txn: &mut RocksDbTransactionBatch,
    ) -> Result<(), crate::core::error::HubError> {
        let Some(data) = &message.data else {
            return Ok(());
        };
        let target = match (MessageType::try_from(data.r#type), &data.body) {
            (Ok(MessageType::ReactionAdd), Some(Body::ReactionBody(body))) => {
                match (&body.target, ReactionType::try_from(body.r#type)) {
                    (
                        Some(crate::proto::reaction_body::Target::TargetCastId(cast)),
                        Ok(ReactionType::Like),
                    ) => Some((cast, LIKE_WEIGHT)),
                    (
                        Some(crate::proto::reaction_body::Target::TargetCastId(cast)),
                        Ok(ReactionType::Recast),
                    ) => Some((cast, RECAST_WEIGHT)),
                    _ => None,
                }
            }
            (Ok(MessageType::CastAdd), Some(Body::CastAddBody(body))) => match &body.parent {
                Some(crate::proto::cast_add_body::Parent::ParentCastId(cast)) => {
                    Some((cast, REPLY_WEIGHT))
                }
                _ => None,
            },
            _ => None,
        };
        if let Some((cast, weight)) = target {
            let key = Self::make_window_key(
                keys::WINDOW_BACKFILL,
                data.timestamp as u64 / 3600,
                cast.fid,
                &cast.hash,
            );
            Self::add_to_window_key(&self.db, key, weight, txn).map_err(|e| {
                crate::core::error::HubError::invalid_internal_state(&e.to_string())
            })?;
        }
        Ok(())
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

        let msg_type = MessageType::try_from(data.r#type).unwrap_or(MessageType::None);
        // +1 counts the message, -1 takes it back.
        let delta = match (kind, msg_type) {
            (MessageEventKind::Prune, _) => return Ok(()),
            (MessageEventKind::Merge, MessageType::ReactionRemove) => -1,
            (MessageEventKind::Merge, _) => 1,
            (MessageEventKind::Revoke, MessageType::ReactionAdd | MessageType::CastAdd) => -1,
            (MessageEventKind::Revoke, _) => return Ok(()),
        };

        match msg_type {
            MessageType::ReactionAdd | MessageType::ReactionRemove => {
                self.process_reaction_message(data, delta, txn)?;
            }
            MessageType::CastAdd => {
                self.process_cast_add(data, delta, txn)?;
            }
            _ => {}
        }

        Ok(())
    }

    /// Process a reaction message (add or remove).
    fn process_reaction_message(
        &self,
        data: &crate::proto::MessageData,
        delta: i64,
        txn: &mut RocksDbTransactionBatch,
    ) -> Result<(), IndexerError> {
        let reaction_body = match &data.body {
            Some(Body::ReactionBody(body)) => body,
            _ => return Ok(()),
        };

        // Get the target cast
        let target_cast = match &reaction_body.target {
            Some(crate::proto::reaction_body::Target::TargetCastId(cast_id)) => cast_id,
            _ => return Ok(()), // URL reactions not tracked
        };

        let reaction_type =
            ReactionType::try_from(reaction_body.r#type).unwrap_or(ReactionType::None);
        if reaction_type == ReactionType::None {
            return Ok(());
        }

        let weight = if reaction_type == ReactionType::Recast {
            RECAST_WEIGHT
        } else {
            LIKE_WEIGHT
        };
        self.add_window_score(
            target_cast.fid,
            &target_cast.hash,
            data.timestamp,
            weight * delta,
            txn,
        )?;
        self.update_cast_metrics(
            target_cast.fid,
            &target_cast.hash,
            reaction_type,
            delta > 0,
            txn,
        )
    }

    /// Process a cast add message to track replies.
    fn process_cast_add(
        &self,
        data: &crate::proto::MessageData,
        delta: i64,
        txn: &mut RocksDbTransactionBatch,
    ) -> Result<(), IndexerError> {
        let cast_body = match &data.body {
            Some(Body::CastAddBody(body)) => body,
            _ => return Ok(()),
        };

        // Check if this is a reply (has a parent cast)
        let parent_cast = match &cast_body.parent {
            Some(crate::proto::cast_add_body::Parent::ParentCastId(cast_id)) => cast_id,
            _ => return Ok(()), // Not a reply
        };

        self.add_window_score(
            parent_cast.fid,
            &parent_cast.hash,
            data.timestamp,
            REPLY_WEIGHT * delta,
            txn,
        )?;
        self.adjust_reply_count(parent_cast.fid, &parent_cast.hash, delta, txn)
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
        if timestamp < self.window_live_since
            || timestamp + WINDOW_RETENTION_SECS < now
            || delta == 0
        {
            return Ok(());
        }
        let key = Self::make_window_key(keys::WINDOW_LIVE, timestamp / 3600, fid, hash);
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
        if self.window_pruned_hour.swap(hour, Ordering::Relaxed) == hour {
            return Ok(());
        }
        let cutoff = (now.saturating_sub(WINDOW_RETENTION_SECS) / 3600) as u32;
        for source in [keys::WINDOW_LIVE, keys::WINDOW_BACKFILL] {
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
        let key = Self::make_cast_key(fid, hash);

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
        let key = Self::make_cast_key(fid, hash);

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
        let mut txn = RocksDbTransactionBatch::new();

        for event in events {
            match event {
                IndexEvent::MessageCommitted { message, kind, .. } => {
                    self.process_message(message, *kind, &mut txn)?;
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
            backfill_complete: true,
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
    async fn test_backfill_window_counts_stored_engagement() {
        use crate::storage::store::test_helper;
        use crate::utils::factory::messages_factory;

        let (mut engine, _dir) = test_helper::new_engine().await;
        let fid = test_helper::FID_FOR_TEST;
        test_helper::register_user(
            fid,
            test_helper::default_signer(),
            test_helper::default_custody_address(),
            &mut engine,
        )
        .await;
        let cast = messages_factory::casts::create_cast_add(fid, "popular", None, None);
        let like = messages_factory::reactions::create_reaction_add(
            fid,
            ReactionType::Like,
            crate::proto::reaction_body::Target::TargetCastId(CastId {
                fid,
                hash: cast.hash.clone(),
            }),
            None,
            None,
        );
        test_helper::commit_message(&mut engine, &cast).await;
        test_helper::commit_message(&mut engine, &like).await;

        // Live tracking starts after the stored engagement.
        let now = crate::core::util::get_farcaster_time().unwrap();
        let db = make_test_db();
        db.put(
            &[keys::METRICS_PREFIX, keys::WINDOW_LIVE_SINCE],
            &(now + 60).to_be_bytes(),
        )
        .unwrap();
        let indexer = create_indexer(db);
        let hyper = HashMap::from([(1u32, engine.get_hyper_stores().unwrap())]);
        indexer.backfill_window(&hyper).unwrap();

        assert_eq!(
            indexer.get_trending_window(3600, now + 60).unwrap(),
            vec![(fid, cast.hash.clone(), 1.0)]
        );
        // Runs once.
        indexer.backfill_window(&hyper).unwrap();
        assert_eq!(
            indexer.get_trending_window(3600, now + 60).unwrap()[0].2,
            1.0
        );
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
}
