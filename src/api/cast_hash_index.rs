//! Lightweight cast hash → FID index.
//!
//! Stores a mapping from every cast's message hash to its author FID,
//! enabling O(1) cast-by-hash lookups without scanning all FIDs.

use crate::api::config::FeatureConfig;
use crate::api::events::IndexEvent;
use crate::api::indexer::{Indexer, IndexerError, IndexerStats};
use crate::proto::message_data::Body;
use crate::proto::{Message, MessageType};
use crate::storage::constants::{RootPrefix, UserPostfix};
use crate::storage::db::{DBProvider, RocksDB, RocksDbTransactionBatch};
use crate::storage::store::account::{encoded_fid_len, read_fid_key, HASH_LENGTH};
use crate::storage::store::stores::Stores;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use tokio::sync::broadcast;

/// Key prefix for the cast hash index (in the API RocksDB).
const CAST_HASH_PREFIX: u8 = 0xE4;

/// Sub-key: <prefix><hash:20> -> fid:8
const HASH_TO_FID: u8 = 0x01;

/// Checkpoint: <prefix><0xFF> -> event_id:8
const CHECKPOINT: u8 = 0xFF;
const STORE_BACKFILL: u8 = 0xFE;
const PAGE_CASTS: usize = 2000;
const PAGE_TIME: Duration = Duration::from_millis(100);

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct BackfillProgress {
    pub complete: bool,
    pub sources: Vec<SourceProgress>,
    pub error: Option<String>,
}

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct SourceProgress {
    pub shard_id: u32,
    pub source_prefix: u8,
    pub complete: bool,
    pub casts_indexed: u64,
    pub last_fid: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    page_token: Option<Vec<u8>>,
}

pub struct CastHashIndexer {
    config: FeatureConfig,
    db: Arc<RocksDB>,
    checkpoint: AtomicU64,
    items_indexed: AtomicU64,
    backfill: RwLock<BackfillProgress>,
}

impl CastHashIndexer {
    pub fn new(config: FeatureConfig, db: Arc<RocksDB>) -> Self {
        let checkpoint = Self::load_checkpoint(&db).unwrap_or(0);
        let backfill = db
            .get(&[CAST_HASH_PREFIX, STORE_BACKFILL])
            .ok()
            .flatten()
            .and_then(|v| serde_json::from_slice(&v).ok())
            .unwrap_or_default();
        Self {
            config,
            db,
            checkpoint: AtomicU64::new(checkpoint),
            items_indexed: AtomicU64::new(0),
            backfill: RwLock::new(backfill),
        }
    }

    /// Full retained-store coverage, independent of the pruned HubEvent cursor.
    pub fn is_complete(&self) -> bool {
        self.backfill.read().unwrap().complete
    }

    pub fn backfill_progress(&self) -> BackfillProgress {
        self.backfill.read().unwrap().clone()
    }

    /// Include both legacy and Hyper stores: either can contain casts absent
    /// from the other during reconciliation. Never clear existing mappings.
    pub fn prepare_backfill(&self, sources: &[(u32, Stores)]) -> Result<(), IndexerError> {
        let old = self.backfill_progress();
        let mut progress = BackfillProgress::default();
        for (shard_id, source) in sources {
            let source_prefix = source
                .cast_store
                .state_context()
                .root_prefix(RootPrefix::User);
            if progress
                .sources
                .iter()
                .any(|s| s.shard_id == *shard_id && s.source_prefix == source_prefix)
            {
                continue;
            }
            progress.sources.push(
                old.sources
                    .iter()
                    .find(|s| s.shard_id == *shard_id && s.source_prefix == source_prefix)
                    .cloned()
                    .unwrap_or(SourceProgress {
                        shard_id: *shard_id,
                        source_prefix,
                        ..Default::default()
                    }),
            );
        }
        progress
            .sources
            .sort_by_key(|s| (s.shard_id, s.source_prefix));
        progress.complete =
            !progress.sources.is_empty() && progress.sources.iter().all(|s| s.complete);
        // Invalidate in memory first, so a failed metadata write cannot leave
        // an old source plan advertised as complete.
        *self.backfill.write().unwrap() = progress.clone();
        self.db
            .put(
                &[CAST_HASH_PREFIX, STORE_BACKFILL],
                &serde_json::to_vec(&progress).map_err(storage_error)?,
            )
            .map_err(storage_error)
    }

    /// One bounded read/commit. Mappings and the exact resume key are committed
    /// atomically; an interrupted page is safe to retry alongside live writes.
    fn backfill_page(&self, shard_id: u32, source: &Stores) -> Result<(), IndexerError> {
        let mut progress = self.backfill_progress();
        let prefix = source
            .cast_store
            .state_context()
            .root_prefix(RootPrefix::User);
        let state = progress
            .sources
            .iter_mut()
            .find(|s| s.shard_id == shard_id && s.source_prefix == prefix)
            .ok_or_else(|| storage_error("Cast hash backfill source not initialized"))?;
        if state.complete {
            return Ok(());
        }
        let page = read_cast_page(&source.db, prefix, state.page_token.clone())?;
        let mut txn = RocksDbTransactionBatch::new();
        for (hash, fid) in &page.casts {
            txn.put(Self::make_key(hash), fid.to_be_bytes().to_vec());
        }
        state.casts_indexed += page.casts.len() as u64;
        if let Some(key) = &page.last_key {
            state.last_fid = read_fid_key(key, 1);
        }
        state.page_token = page.last_key.or(state.page_token.take());
        state.complete = page.complete;
        progress.complete = progress.sources.iter().all(|s| s.complete);
        progress.error = None;
        txn.put(
            vec![CAST_HASH_PREFIX, STORE_BACKFILL],
            serde_json::to_vec(&progress).map_err(storage_error)?,
        );
        self.db.commit(txn).map_err(storage_error)?;
        self.items_indexed
            .fetch_add(page.casts.len() as u64, Ordering::Relaxed);
        *self.backfill.write().unwrap() = progress;
        Ok(())
    }

    /// Runs independently of API startup, live indexing and the async runtime's
    /// workers. Cold reads bypass the block cache and yield between pages.
    pub fn spawn_backfill(
        self: &Arc<Self>,
        sources: Vec<(u32, Stores)>,
        mut shutdown: broadcast::Receiver<()>,
    ) -> tokio::task::JoinHandle<()> {
        let indexer = self.clone();
        tokio::spawn(async move {
            if sources.is_empty() {
                return;
            }
            let mut last_log = Instant::now();
            loop {
                for (shard_id, source) in &sources {
                    let index = indexer.clone();
                    let source = source.clone();
                    let shard_id = *shard_id;
                    let result = tokio::select! {
                        _ = shutdown.recv() => return,
                        result = tokio::task::spawn_blocking(move || index.backfill_page(shard_id, &source)) => result,
                    };
                    let error = match result {
                        Ok(Ok(())) => None,
                        Ok(Err(error)) => Some(error.to_string()),
                        Err(error) => Some(error.to_string()),
                    };
                    let delay = if let Some(error) = error {
                        tracing::warn!(shard_id, %error, "Cast hash store backfill failed; retrying");
                        indexer.backfill.write().unwrap().error = Some(error);
                        Duration::from_secs(5)
                    } else {
                        Duration::from_millis(10)
                    };
                    tokio::select! {
                        _ = shutdown.recv() => return,
                        _ = tokio::time::sleep(delay) => {}
                    }
                }
                if indexer.is_complete() {
                    tracing::info!("Cast hash store backfill complete");
                    return;
                }
                if last_log.elapsed() >= Duration::from_secs(30) {
                    for source in indexer.backfill_progress().sources {
                        tracing::info!(
                            shard_id = source.shard_id,
                            source_prefix = source.source_prefix,
                            casts_indexed = source.casts_indexed,
                            last_fid = source.last_fid,
                            complete = source.complete,
                            "Cast hash store backfill progress"
                        );
                    }
                    last_log = Instant::now();
                }
            }
        })
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

    /// Record a hash → FID mapping found outside the event stream, such as by
    /// a store probe for a cast older than the indexed event window.
    pub fn record(&self, hash: &[u8], fid: u64) {
        if let Err(e) = self.db.put(&Self::make_key(hash), &fid.to_be_bytes()) {
            tracing::warn!(error = %e, "Failed to record cast hash mapping");
        }
    }

    /// Record hash → FID mappings for casts authored by `fid`, writing only
    /// the hashes the index does not already hold.
    pub fn record_many(&self, fid: u64, hashes: &[Vec<u8>]) {
        if hashes.is_empty() {
            return;
        }
        let keys: Vec<Vec<u8>> = hashes.iter().map(|hash| Self::make_key(hash)).collect();
        let existing = match self.db.get_many(&keys) {
            Ok(values) => values,
            Err(e) => {
                tracing::warn!(error = %e, "Failed to check cast hash mappings");
                return;
            }
        };
        let mut txn = RocksDbTransactionBatch::new();
        for (key, value) in keys.into_iter().zip(existing) {
            if value.is_empty() {
                txn.put(key, fid.to_be_bytes().to_vec());
            }
        }
        if txn.len() > 0 {
            if let Err(e) = self.db.commit(txn) {
                tracing::warn!(error = %e, "Failed to record cast hash mappings");
            }
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

fn storage_error(error: impl std::fmt::Display) -> IndexerError {
    IndexerError::Storage(error.to_string())
}

struct CastPage {
    casts: Vec<(Vec<u8>, u64)>,
    last_key: Option<Vec<u8>>,
    complete: bool,
}

/// Walk only CastAdds secondary keys. They contain the hash and author already,
/// so this needs neither protobuf decoding nor a point read for every cast.
fn read_cast_page(
    db: &RocksDB,
    prefix: u8,
    token: Option<Vec<u8>>,
) -> Result<CastPage, IndexerError> {
    let start = token.map_or_else(
        || vec![prefix],
        |mut key| {
            key.push(0);
            key
        },
    );
    let mut opts = rocksdb::ReadOptions::default();
    opts.set_iterate_lower_bound(start.clone());
    opts.set_iterate_upper_bound(vec![prefix + 1]);
    opts.set_readahead_size(256 * 1024);
    opts.fill_cache(false);
    let guard = db.db();
    match guard.as_ref() {
        Some(DBProvider::Transaction(db)) => scan_casts(db.raw_iterator_opt(opts), &start),
        Some(DBProvider::ReadOnly(db)) => scan_casts(db.raw_iterator_opt(opts), &start),
        None => Err(storage_error("Cast hash source DB is not open")),
    }
}

fn scan_casts<D: rocksdb::DBAccess>(
    mut iter: rocksdb::DBRawIteratorWithThreadMode<'_, D>,
    start: &[u8],
) -> Result<CastPage, IndexerError> {
    let mut page = CastPage {
        casts: vec![],
        last_key: None,
        complete: false,
    };
    let started = Instant::now();
    iter.seek(start);
    while let Some((key, _)) = iter.item() {
        let fid_len =
            encoded_fid_len(key, 1).ok_or_else(|| storage_error("Invalid cast hash source FID"))?;
        let postfix = *key
            .get(1 + fid_len)
            .ok_or_else(|| storage_error("Missing cast hash source postfix"))?;
        page.last_key = Some(key.to_vec());
        if postfix == UserPostfix::CastAdds as u8 {
            if key.len() != 1 + fid_len + 1 + HASH_LENGTH {
                return Err(storage_error("Invalid cast-add index key"));
            }
            page.casts
                .push((key[2 + fid_len..].to_vec(), read_fid_key(key, 1)));
            iter.next();
        } else {
            let mut seek = key[..1 + fid_len].to_vec();
            if postfix < UserPostfix::CastAdds as u8 {
                seek.push(UserPostfix::CastAdds as u8);
            } else {
                // Advance the encoded prefix, rather than numeric FIDs: this
                // also visits sparse/native FIDs without iterating empty IDs.
                seek = crate::storage::util::increment_vec_u8(&seek);
            }
            iter.seek(seek);
        }
        if page.casts.len() >= PAGE_CASTS || started.elapsed() >= PAGE_TIME {
            break;
        }
    }
    iter.status().map_err(storage_error)?;
    page.complete = !iter.valid();
    Ok(page)
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
            backfill_complete: self.is_complete(),
            size_bytes: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hyper::StateContext;
    use crate::proto::FarcasterNetwork;
    use crate::storage::store::account::{CastStore, CastStoreDef};
    use crate::storage::store::stores::StoreLimits;
    use crate::storage::store::test_helper::default_merge_ctx;
    use crate::storage::trie::merkle_trie::MerkleTrie;
    use crate::utils::factory::messages_factory::casts;
    use crate::utils::statsd_wrapper::StatsdClientWrapper;

    fn new_index(db: Arc<RocksDB>) -> CastHashIndexer {
        CastHashIndexer::new(
            FeatureConfig {
                enabled: true,
                ..Default::default()
            },
            db,
        )
    }

    fn stores(path: &str) -> Stores {
        Stores::new(
            RocksDB::open_shard_db(path, 1),
            1,
            MerkleTrie::new().unwrap(),
            StoreLimits::default(),
            FarcasterNetwork::Devnet,
            StatsdClientWrapper::new(
                cadence::StatsdClient::builder("test", cadence::NopMetricSink).build(),
                false,
            ),
        )
    }

    fn merge(store: &Stores, message: &Message) {
        let mut txn = RocksDbTransactionBatch::new();
        store
            .cast_store
            .merge(message, &mut txn, &default_merge_ctx())
            .unwrap();
        store.db.commit(txn).unwrap();
    }

    #[tokio::test]
    async fn checkpoint_is_not_coverage_and_backfill_preserves_live_and_historical_mappings() {
        let dir = tempfile::tempdir().unwrap();
        let db = RocksDB::open_shard_db(dir.path().to_str().unwrap(), 0);
        let legacy = stores(dir.path().to_str().unwrap());
        let hyper = legacy.with_state_context(StateContext::Hyper);
        let old = casts::create_cast_add(42, "older than retained events", None, None);
        let retained = casts::create_cast_add(4_294_967_305, "hyper only, native FID", None, None);
        merge(&legacy, &old);
        merge(&hyper, &retained);
        let index = new_index(db.clone());
        index.save_checkpoint(123).await.unwrap();
        assert!(!index.stats().backfill_complete);
        index.record(&[9; 20], 99);
        let sources = vec![(1, legacy.clone()), (1, hyper.clone())];
        index.prepare_backfill(&sources).unwrap();
        index.backfill_page(1, &legacy).unwrap();
        assert!(!index.is_complete(), "Hyper history is still missing");
        assert_eq!(index.get_fid_by_hash(&old.hash), Some(42));
        assert_eq!(index.get_fid_by_hash(&[9; 20]), Some(99));
        // Live writes continue while the other source is still backfilling.
        let live = casts::create_cast_add(100, "live", None, None);
        index
            .process_event(&IndexEvent::message(live.clone(), 1, 456))
            .await
            .unwrap();
        index.backfill_page(1, &hyper).unwrap();
        assert!(index.is_complete());
        assert_eq!(index.get_fid_by_hash(&live.hash), Some(100));
        assert_eq!(index.get_fid_by_hash(&retained.hash), Some(4_294_967_305));
        assert!(
            CastStore::get_cast_add(&hyper.cast_store, 4_294_967_305, retained.hash.clone())
                .unwrap()
                .is_some()
        );
        drop(index);
        let reopened = new_index(db);
        reopened.prepare_backfill(&sources).unwrap();
        assert!(reopened.stats().backfill_complete);
        assert_eq!(
            reopened.get_fid_by_hash(&retained.hash),
            Some(4_294_967_305)
        );
    }

    #[test]
    fn store_walk_resumes_exact_pages_and_skips_unrelated_keys() {
        let dir = tempfile::tempdir().unwrap();
        let db = RocksDB::open_shard_db(dir.path().to_str().unwrap(), 0);
        let source = stores(dir.path().to_str().unwrap());
        let mut txn = RocksDbTransactionBatch::new();
        for n in 0..(PAGE_CASTS + 5) as u64 {
            let mut hash = vec![0; 20];
            hash[..8].copy_from_slice(&n.to_be_bytes());
            txn.put(CastStoreDef::make_cast_adds_key(42, &hash), vec![1]);
        }
        // Neither unrelated values nor primary protobufs need decoding.
        txn.put(
            vec![
                RootPrefix::User as u8,
                0,
                0,
                0,
                42,
                UserPostfix::CastMessage as u8,
            ],
            vec![255],
        );
        txn.put(
            vec![
                RootPrefix::User as u8,
                0,
                0,
                0,
                43,
                UserPostfix::ReactionMessage as u8,
            ],
            vec![255],
        );
        source.db.commit(txn).unwrap();
        let index = new_index(db.clone());
        let sources = vec![(1, source.clone())];
        index.prepare_backfill(&sources).unwrap();
        index.backfill_page(1, &source).unwrap();
        let first = index.backfill_progress();
        assert!(!first.complete);
        assert!(first.sources[0].casts_indexed > 0);
        assert!(first.sources[0].casts_indexed <= PAGE_CASTS as u64);
        drop(index);
        let resumed = new_index(db);
        resumed.prepare_backfill(&sources).unwrap();
        assert_eq!(
            resumed.backfill_progress().sources[0].page_token,
            first.sources[0].page_token
        );
        while !resumed.is_complete() {
            resumed.backfill_page(1, &source).unwrap();
        }
        assert_eq!(
            resumed.backfill_progress().sources[0].casts_indexed,
            (PAGE_CASTS + 5) as u64
        );
        for n in [0u64, PAGE_CASTS as u64 + 4] {
            let mut hash = vec![0; 20];
            hash[..8].copy_from_slice(&n.to_be_bytes());
            assert_eq!(resumed.get_fid_by_hash(&hash), Some(42));
        }
    }

    #[test]
    fn failed_source_read_does_not_mark_complete_and_new_sources_require_coverage() {
        let dir = tempfile::tempdir().unwrap();
        let db = RocksDB::open_shard_db(dir.path().to_str().unwrap(), 0);
        let source = stores(dir.path().to_str().unwrap());
        let index = new_index(db);
        index.prepare_backfill(&[(1, source.clone())]).unwrap();
        source.db.close();
        assert!(index.backfill_page(1, &source).is_err());
        assert!(!index.is_complete());
        assert!(index.backfill_progress().sources[0].page_token.is_none());
        source.db.open().unwrap();
        // A failed destination commit must not advance completion in memory.
        index.db.close();
        assert!(index.backfill_page(1, &source).is_err());
        assert!(!index.is_complete());
        assert!(index.backfill_progress().sources[0].page_token.is_none());
        index.db.open().unwrap();
        index.backfill_page(1, &source).unwrap();
        assert!(index.is_complete());
        let hyper = source.with_state_context(StateContext::Hyper);
        index
            .prepare_backfill(&[(1, source.clone()), (1, hyper.clone())])
            .unwrap();
        assert!(!index.is_complete());
        assert!(index.backfill_progress().sources[0].complete);
        index.backfill_page(1, &hyper).unwrap();
        assert!(index.is_complete());
    }
}
