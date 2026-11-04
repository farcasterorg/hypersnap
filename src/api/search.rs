//! Full-text search indexer using Tantivy.
//!
//! This module provides full-text search capabilities for:
//! - Casts (by text content, and by `#hashtag`)
//! - Users (by username, display name, bio)
//!
//! # Architecture
//!
//! The search index is stored on disk using Tantivy. The indexer processes
//! messages asynchronously and updates the index in batches for efficiency.
//!
//! # Schema upgrades
//!
//! An index built before hashtags (no `tags` field, timestamps that can't be
//! sorted on) is moved aside to `<index_path>.legacy` on startup and keeps
//! answering queries, and keeps receiving live casts, while a new index is
//! backfilled next to it. Once the backfill completes the legacy index is
//! deleted. Search never goes down or shrinks during the rebuild.
//!
//! # Usage
//!
//! ```ignore
//! let search = SearchIndexer::new(config, index_path)?;
//! search.process_event(&event).await?;
//! let results = search.search_casts("hello #farcaster", SearchSort::Newest, 0, 10)?;
//! ```

use crate::api::config::SearchConfig;
use crate::api::events::IndexEvent;
use crate::api::indexer::{Indexer, IndexerError, IndexerStats};
use crate::api::{backfill, backfill_checkpoint_name, SEARCH_BACKFILL_CHECKPOINT};
use crate::core::util::FarcasterTime;
use crate::proto::message_data::Body;
use crate::proto::{Message, MessageType};
use crate::storage::db::RocksDB;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;
use tantivy::collector::TopDocs;
use tantivy::query::QueryParser;
use tantivy::schema::{Field, Schema, Value, FAST, INDEXED, STORED, STRING, TEXT};
use tantivy::{
    doc, DocAddress, Index, IndexReader, IndexWriter, Order, ReloadPolicy, TantivyDocument,
};

/// Where the search backfill stops: casts from this Farcaster time on are
/// indexed live, so the walk (which runs alongside live indexing) skips them.
const SEARCH_BACKFILL_BEFORE: &str = "search_backfill_before";

/// A search result for a cast.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CastSearchResult {
    pub fid: u64,
    pub hash: String,
    pub text: String,
    pub timestamp: u32,
    pub score: f32,
}

/// A search result for a user.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserSearchResult {
    pub fid: u64,
    pub username: Option<String>,
    pub display_name: Option<String>,
    pub score: f32,
}

/// Order of cast search results, from Neynar's `sort_type`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SearchSort {
    /// Best text match first (`algorithmic`).
    #[default]
    Relevance,
    /// Newest first (`desc_chronological`).
    Newest,
    /// Oldest first (`chron`).
    Oldest,
}

impl SearchSort {
    pub fn parse(sort_type: &str) -> Self {
        match sort_type {
            "desc_chronological" => Self::Newest,
            "chron" => Self::Oldest,
            _ => Self::Relevance,
        }
    }
}

/// Hashtags in `text` as (byte range of `#tag`, lowercase tag). A hashtag is
/// `#`, a letter, then letters, digits or `_`, where the `#` doesn't follow a
/// word character or a URL's `/` or `&` (`a#b`, `x.com/#top`, `&#39;`).
fn hashtag_spans(text: &str) -> Vec<(std::ops::Range<usize>, String)> {
    let mut spans = Vec::new();
    for (start, _) in text.match_indices('#') {
        if let Some(prev) = text[..start].chars().next_back() {
            if prev.is_alphanumeric() || matches!(prev, '_' | '/' | '&' | '#') {
                continue;
            }
        }
        let rest = &text[start + 1..];
        if !rest.chars().next().is_some_and(char::is_alphabetic) {
            continue;
        }
        let len = rest
            .find(|c: char| !(c.is_alphanumeric() || c == '_'))
            .unwrap_or(rest.len());
        spans.push((start..start + 1 + len, rest[..len].to_lowercase()));
    }
    spans
}

/// The distinct hashtags of a cast, as indexed in `tags` (at most 32 of up to
/// 64 characters, so a hashtag wall can't bloat the index).
pub fn hashtags(text: &str) -> Vec<String> {
    let mut tags: Vec<String> = Vec::new();
    for (_, tag) in hashtag_spans(text) {
        if tag.chars().count() <= 64 && !tags.contains(&tag) {
            tags.push(tag);
            if tags.len() == 32 {
                break;
            }
        }
    }
    tags
}

/// A query with each `#tag` turned into an exact match on the `tags` field.
fn tag_query(query: &str) -> String {
    let mut out = String::with_capacity(query.len() + 8);
    let mut last = 0;
    for (range, tag) in hashtag_spans(query) {
        out.push_str(&query[last..range.start]);
        out.push_str("tags:");
        out.push_str(&tag);
        last = range.end;
    }
    out.push_str(&query[last..]);
    out
}

/// One Tantivy index directory with its writer and reader.
struct CastIndex {
    index: Index,
    writer: RwLock<IndexWriter>,
    reader: IndexReader,
    fid: Field,
    hash: Field,
    text: Field,
    timestamp: Field,
    /// None on a legacy index, which also can't sort by timestamp.
    tags: Option<Field>,
}

impl CastIndex {
    fn schema() -> Schema {
        // Same field order as the legacy schema, so older builds can still open it.
        let mut builder = Schema::builder();
        builder.add_u64_field("fid", STORED);
        builder.add_text_field("hash", STORED);
        builder.add_text_field("text", TEXT | STORED);
        builder.add_u64_field("timestamp", INDEXED | FAST | STORED);
        builder.add_text_field("tags", STRING);
        builder.build()
    }

    fn open(path: &Path, writer_bytes: usize) -> Result<Self, IndexerError> {
        std::fs::create_dir_all(path).map_err(|e| {
            IndexerError::Storage(format!("Failed to create index directory: {}", e))
        })?;
        let index = if SearchIndexer::exists(path)? {
            Index::open_in_dir(path)
        } else {
            Index::create_in_dir(path, Self::schema())
        }
        .map_err(|e| IndexerError::Storage(format!("Failed to open index: {}", e)))?;
        let writer = index
            .writer(writer_bytes)
            .map_err(|e| IndexerError::Storage(format!("Failed to create writer: {}", e)))?;
        let reader: IndexReader = index
            .reader_builder()
            .reload_policy(ReloadPolicy::OnCommitWithDelay)
            .try_into()
            .map_err(|e| IndexerError::Storage(format!("Failed to create reader: {}", e)))?;
        let schema = index.schema();
        let field = |name: &str| {
            schema
                .get_field(name)
                .map_err(|e| IndexerError::Storage(format!("Search index has no {name}: {e}")))
        };
        Ok(Self {
            fid: field("fid")?,
            hash: field("hash")?,
            text: field("text")?,
            timestamp: field("timestamp")?,
            tags: schema.get_field("tags").ok(),
            index,
            writer: RwLock::new(writer),
            reader,
        })
    }

    fn add(&self, fid: u64, hash: String, text: &str, timestamp: u32) -> Result<(), IndexerError> {
        let mut document = doc!(
            self.fid => fid,
            self.hash => hash,
            self.text => text,
            self.timestamp => timestamp as u64,
        );
        if let Some(tags) = self.tags {
            for tag in hashtags(text) {
                document.add_text(tags, tag);
            }
        }
        self.writer
            .read()
            .map_err(|_| IndexerError::Storage("Failed to acquire write lock".to_string()))?
            .add_document(document)
            .map_err(|e| IndexerError::Storage(format!("Failed to add document: {}", e)))?;
        Ok(())
    }

    fn commit(&self) -> Result<(), IndexerError> {
        self.writer
            .write()
            .map_err(|_| IndexerError::Storage("Failed to acquire write lock".to_string()))?
            .commit()
            .map_err(|e| IndexerError::Storage(format!("Failed to commit: {}", e)))?;
        Ok(())
    }

    fn search(
        &self,
        query: &str,
        sort: SearchSort,
        offset: usize,
        limit: usize,
    ) -> Result<Vec<CastSearchResult>, IndexerError> {
        let searcher = self.reader.searcher();
        let query = match self.tags {
            Some(_) => tag_query(query),
            None => query.to_string(),
        };
        let query = QueryParser::for_index(&self.index, vec![self.text])
            .parse_query(&query)
            .map_err(|e| IndexerError::Storage(format!("Failed to parse query: {}", e)))?;
        let top = TopDocs::with_limit(limit).and_offset(offset);
        let failed = |e| IndexerError::Storage(format!("Search failed: {:?}", e));
        let docs: Vec<(f32, DocAddress)> = match (sort, self.tags) {
            (SearchSort::Relevance, _) | (_, None) => {
                searcher.search(&query, &top).map_err(failed)?
            }
            (sort, Some(_)) => {
                let order = if sort == SearchSort::Newest {
                    Order::Desc
                } else {
                    Order::Asc
                };
                searcher
                    .search(&query, &top.order_by_fast_field::<u64>("timestamp", order))
                    .map_err(failed)?
                    .into_iter()
                    .map(|(_, address)| (0.0, address))
                    .collect()
            }
        };

        let mut results = Vec::with_capacity(docs.len());
        for (score, address) in docs {
            let doc: TantivyDocument = searcher
                .doc(address)
                .map_err(|e| IndexerError::Storage(format!("Failed to retrieve doc: {}", e)))?;
            let text = |field| {
                doc.get_first(field)
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string()
            };
            let number = |field| doc.get_first(field).and_then(|v| v.as_u64()).unwrap_or(0);
            results.push(CastSearchResult {
                fid: number(self.fid),
                hash: text(self.hash),
                text: text(self.text),
                timestamp: number(self.timestamp) as u32,
                score,
            });
        }
        Ok(results)
    }
}

/// Full-text search indexer using Tantivy.
pub struct SearchIndexer {
    config: SearchConfig,
    current: CastIndex,
    /// The pre-hashtag index and its directory, serving queries until the
    /// current index's backfill completes.
    legacy: RwLock<Option<(CastIndex, PathBuf)>>,
    /// The backfill indexes casts before this Farcaster time; live indexing owns the rest.
    backfill_before: AtomicU64,
    checkpoint: AtomicU64,
    docs_indexed: AtomicU64,
}

impl SearchIndexer {
    /// Open the index on persistent node storage and restore its backfill status.
    pub fn open(
        config: SearchConfig,
        db: &RocksDB,
        shard_ids: &[u32],
    ) -> Result<Self, IndexerError> {
        let db_path = std::path::PathBuf::from(db.location());
        let rocksdb_dir = db_path.parent().ok_or_else(|| {
            IndexerError::Storage("API database has no parent directory".to_string())
        })?;
        let index_path = config.resolved_index_path(rocksdb_dir);
        let legacy_path = PathBuf::from({
            let mut p = index_path.clone().into_os_string();
            p.push(".legacy");
            p
        });
        tracing::info!(path = %index_path.display(), "Opening persistent search index");
        if Self::exists(&index_path)? && !Self::has_tags(&index_path)? {
            // Keep serving from the old index while a new one is backfilled.
            tracing::info!(legacy = %legacy_path.display(), "Search index predates hashtags; rebuilding it alongside");
            if legacy_path.exists() {
                std::fs::remove_dir_all(&legacy_path).map_err(|e| {
                    IndexerError::Storage(format!("Failed to remove old legacy index: {}", e))
                })?;
            }
            std::fs::rename(&index_path, &legacy_path).map_err(|e| {
                IndexerError::Storage(format!("Failed to move legacy index aside: {}", e))
            })?;
        }
        if !Self::exists(&index_path)? {
            tracing::info!("Search index missing; resetting saved search backfill cursors");
            // The Tantivy directory may have been lost when an old container was
            // recreated, or moved aside above. Its RocksDB cursors survive, but no
            // longer describe this index. Reset both backfill paths BEFORE creating
            // the new index so a crash during initialization cannot leave a new
            // index with old cursors.
            for &shard_id in shard_ids {
                backfill::save_shard_checkpoint(db, SEARCH_BACKFILL_CHECKPOINT, shard_id, 0)?;
                backfill::save_shard_checkpoint(
                    db,
                    &backfill_checkpoint_name("search"),
                    shard_id,
                    0,
                )?;
            }
            // Live indexing starts now; the backfill takes everything older.
            backfill::save_shard_checkpoint(
                db,
                SEARCH_BACKFILL_BEFORE,
                0,
                FarcasterTime::current().to_u64(),
            )?;
        }
        let search = Self::new(config, &index_path)?;
        search.backfill_before.store(
            match backfill::load_shard_checkpoint(db, SEARCH_BACKFILL_BEFORE, 0) {
                // An index from before the boundary was recorded: no live/backfill overlap to avoid.
                0 => u64::MAX,
                before => before,
            },
            Ordering::SeqCst,
        );
        if legacy_path.exists() {
            match CastIndex::open(&legacy_path, 20 * 1024 * 1024) {
                Ok(legacy) => *search.legacy.write().unwrap() = Some((legacy, legacy_path)),
                Err(e) => {
                    tracing::warn!(error = ?e, "Failed to open legacy search index; searching the partial new one")
                }
            }
        }
        search.set_backfill_complete(
            !shard_ids.is_empty()
                && shard_ids.iter().all(|&shard_id| {
                    backfill::load_shard_checkpoint(db, SEARCH_BACKFILL_CHECKPOINT, shard_id)
                        == u64::MAX
                }),
        );
        Ok(search)
    }

    /// Create a new search indexer.
    ///
    /// # Arguments
    /// * `config` - Search configuration
    /// * `index_path` - Path to store the Tantivy index
    pub fn new<P: AsRef<Path>>(config: SearchConfig, index_path: P) -> Result<Self, IndexerError> {
        let current = CastIndex::open(index_path.as_ref(), config.memory_budget_mb * 1024 * 1024)?;
        let docs_indexed = current.reader.searcher().num_docs();
        Ok(Self {
            config,
            current,
            legacy: RwLock::new(None),
            backfill_before: AtomicU64::new(u64::MAX),
            checkpoint: AtomicU64::new(0),
            docs_indexed: AtomicU64::new(docs_indexed),
        })
    }

    pub(crate) fn exists(index_path: &Path) -> Result<bool, IndexerError> {
        if !index_path.try_exists().map_err(|e| {
            IndexerError::Storage(format!("Failed to inspect index directory: {}", e))
        })? {
            return Ok(false);
        }
        let directory = tantivy::directory::MmapDirectory::open(index_path)
            .map_err(|e| IndexerError::Storage(format!("Failed to open index directory: {}", e)))?;
        Index::exists(&directory)
            .map_err(|e| IndexerError::Storage(format!("Failed to inspect index: {}", e)))
    }

    fn has_tags(index_path: &Path) -> Result<bool, IndexerError> {
        let index = Index::open_in_dir(index_path)
            .map_err(|e| IndexerError::Storage(format!("Failed to open index: {}", e)))?;
        Ok(index.schema().get_field("tags").is_ok())
    }

    /// Record whether every shard's backfill is done. Done also retires the
    /// legacy index: queries move to the new one and its directory is deleted.
    pub(crate) fn set_backfill_complete(&self, complete: bool) {
        self.checkpoint
            .store(if complete { u64::MAX } else { 0 }, Ordering::SeqCst);
        if !complete {
            return;
        }
        let legacy = self.legacy.write().unwrap().take();
        if let Some((legacy, path)) = legacy {
            drop(legacy);
            match std::fs::remove_dir_all(&path) {
                Ok(()) => {
                    tracing::info!(path = %path.display(), "Search rebuild complete; removed legacy index")
                }
                Err(e) => {
                    tracing::warn!(error = %e, path = %path.display(), "Failed to remove legacy search index")
                }
            }
        }
    }

    /// The backfill indexes only casts before this Farcaster time.
    pub(crate) fn backfill_before(&self) -> u64 {
        self.backfill_before.load(Ordering::SeqCst)
    }

    /// Search casts by text and `#hashtags`, skipping `offset` results.
    /// While a legacy index serves, `#tag` matches the word and results are by relevance.
    pub fn search_casts(
        &self,
        query: &str,
        sort: SearchSort,
        offset: usize,
        limit: usize,
    ) -> Result<Vec<CastSearchResult>, IndexerError> {
        match self.legacy.read().unwrap().as_ref() {
            Some((legacy, _)) => legacy.search(query, sort, offset, limit),
            None => self.current.search(query, sort, offset, limit),
        }
    }

    /// Index a cast message without committing it. Returns whether it was a cast with text.
    pub(crate) fn index_cast(&self, message: &Message) -> Result<bool, IndexerError> {
        let data = match &message.data {
            Some(d) => d,
            None => return Ok(false),
        };

        let msg_type = MessageType::try_from(data.r#type).unwrap_or(MessageType::None);
        if msg_type != MessageType::CastAdd {
            return Ok(false);
        }

        let cast_body = match &data.body {
            Some(Body::CastAddBody(body)) => body,
            _ => return Ok(false),
        };

        // Skip empty text
        if cast_body.text.trim().is_empty() {
            return Ok(false);
        }

        let hash_hex = hex::encode(&message.hash);
        self.current
            .add(data.fid, hash_hex, &cast_body.text, data.timestamp)?;
        self.docs_indexed.fetch_add(1, Ordering::Relaxed);
        Ok(true)
    }

    /// Index a live cast: into the current index, and the legacy one while it serves.
    fn index_live(&self, message: &Message) -> Result<bool, IndexerError> {
        if !self.index_cast(message)? {
            return Ok(false);
        }
        if let Some((legacy, _)) = self.legacy.read().unwrap().as_ref() {
            let data = message.data.as_ref().unwrap();
            if let Some(Body::CastAddBody(body)) = &data.body {
                legacy.add(
                    data.fid,
                    hex::encode(&message.hash),
                    &body.text,
                    data.timestamp,
                )?;
            }
        }
        Ok(true)
    }

    /// Commit pending changes to the index (and the legacy one).
    pub(crate) fn commit(&self) -> Result<(), IndexerError> {
        self.current.commit()?;
        if let Some((legacy, _)) = self.legacy.read().unwrap().as_ref() {
            legacy.commit()?;
        }
        Ok(())
    }

    /// Get the number of documents in the index.
    pub fn num_docs(&self) -> u64 {
        self.current.reader.searcher().num_docs()
    }
}

#[async_trait]
impl Indexer for SearchIndexer {
    fn name(&self) -> &'static str {
        "search"
    }

    fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    async fn process_event(&self, event: &IndexEvent) -> Result<(), IndexerError> {
        match event {
            IndexEvent::MessageCommitted { message, .. } => {
                self.index_live(message)?;
                self.commit()?;
            }
            IndexEvent::MessagesCommitted { messages, .. } => {
                let mut indexed = 0;
                for message in messages {
                    if self.index_live(message)? {
                        indexed += 1;
                    }
                }
                if indexed > 0 {
                    self.commit()?;
                }
            }
            _ => {}
        }
        Ok(())
    }

    async fn process_batch(&self, events: &[IndexEvent]) -> Result<(), IndexerError> {
        let mut indexed = 0;

        for event in events {
            match event {
                IndexEvent::MessageCommitted { message, .. } => {
                    if self.index_live(message)? {
                        indexed += 1;
                    }
                }
                IndexEvent::MessagesCommitted { messages, .. } => {
                    for message in messages {
                        if self.index_live(message)? {
                            indexed += 1;
                        }
                    }
                }
                _ => {}
            }
        }

        if indexed > 0 {
            self.commit()?;
        }

        Ok(())
    }

    fn last_checkpoint(&self) -> u64 {
        self.checkpoint.load(Ordering::SeqCst)
    }

    async fn save_checkpoint(&self, event_id: u64) -> Result<(), IndexerError> {
        self.checkpoint.store(event_id, Ordering::SeqCst);
        Ok(())
    }

    fn stats(&self) -> IndexerStats {
        let cp = self.checkpoint.load(Ordering::SeqCst);
        IndexerStats {
            items_indexed: self.docs_indexed.load(Ordering::Relaxed),
            last_event_id: cp,
            last_block_height: 0,
            backfill_complete: cp > 0,
            size_bytes: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{CastAddBody, MessageData};

    fn create_cast_message(fid: u64, text: &str, hash: Vec<u8>) -> Message {
        Message {
            hash,
            data: Some(MessageData {
                fid,
                r#type: MessageType::CastAdd as i32,
                timestamp: 1000,
                body: Some(Body::CastAddBody(CastAddBody {
                    text: text.to_string(),
                    ..Default::default()
                })),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    fn create_test_indexer() -> (SearchIndexer, tempfile::TempDir) {
        let tmp_dir = tempfile::tempdir().unwrap();
        let config = SearchConfig {
            enabled: true,
            backfill_on_startup: false,
            backfill_batch_size: 100,
            memory_budget_mb: 50,
            ..Default::default()
        };
        let indexer = SearchIndexer::new(config, tmp_dir.path()).unwrap();
        (indexer, tmp_dir)
    }

    #[test]
    fn test_indexer_creation() {
        let (indexer, _tmp_dir) = create_test_indexer();
        assert!(indexer.is_enabled());
        assert_eq!(indexer.name(), "search");
    }

    #[tokio::test]
    async fn test_index_cast() {
        let (indexer, _tmp_dir) = create_test_indexer();

        let msg = create_cast_message(123, "Hello world from Farcaster!", vec![1, 2, 3, 4]);
        let event = IndexEvent::message(msg, 1, 1);

        indexer.process_event(&event).await.unwrap();

        // Need to reload the reader to see the new doc
        indexer.current.reader.reload().unwrap();

        let results = indexer
            .search_casts("hello", SearchSort::Relevance, 0, 10)
            .unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].fid, 123);
        assert!(results[0].text.contains("Hello"));
    }

    #[tokio::test]
    async fn test_search_multiple_casts() {
        let (indexer, _tmp_dir) = create_test_indexer();

        // Index multiple casts
        let messages = vec![
            create_cast_message(100, "The quick brown fox", vec![1, 0, 0, 0]),
            create_cast_message(200, "Hello world", vec![2, 0, 0, 0]),
            create_cast_message(300, "Farcaster is amazing", vec![3, 0, 0, 0]),
            create_cast_message(400, "Quick update on the project", vec![4, 0, 0, 0]),
        ];

        let event = IndexEvent::messages(messages, 1, 1);
        indexer.process_event(&event).await.unwrap();
        indexer.current.reader.reload().unwrap();

        // Search for "quick" - should find 2 results
        let results = indexer
            .search_casts("quick", SearchSort::Relevance, 0, 10)
            .unwrap();
        assert_eq!(results.len(), 2);

        // Search for "farcaster" - should find 1 result
        let results = indexer
            .search_casts("farcaster", SearchSort::Relevance, 0, 10)
            .unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].fid, 300);
    }

    #[tokio::test]
    async fn test_empty_text_not_indexed() {
        let (indexer, _tmp_dir) = create_test_indexer();

        let msg = create_cast_message(123, "   ", vec![1, 2, 3, 4]);
        let event = IndexEvent::message(msg, 1, 1);

        indexer.process_event(&event).await.unwrap();
        indexer.current.reader.reload().unwrap();

        assert_eq!(indexer.num_docs(), 0);
    }

    #[test]
    fn test_search_no_results() {
        let (indexer, _tmp_dir) = create_test_indexer();

        let results = indexer
            .search_casts("nonexistent", SearchSort::Relevance, 0, 10)
            .unwrap();
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn test_batch_processing() {
        let (indexer, _tmp_dir) = create_test_indexer();

        let events: Vec<IndexEvent> = (0..5)
            .map(|i| {
                let msg = create_cast_message(
                    100 + i,
                    &format!("Test message number {}", i),
                    vec![i as u8, 0, 0, 0],
                );
                IndexEvent::message(msg, 1, i)
            })
            .collect();

        indexer.process_batch(&events).await.unwrap();
        indexer.current.reader.reload().unwrap();

        let results = indexer
            .search_casts("message", SearchSort::Relevance, 0, 10)
            .unwrap();
        assert_eq!(results.len(), 5);
    }

    #[test]
    fn test_hashtags() {
        assert_eq!(
            hashtags("#Farcaster is #fun_2 (#gm) #gm"),
            vec!["farcaster", "fun_2", "gm"]
        );
        assert_eq!(hashtags("#日本 #café"), vec!["日本", "café"]);
        // not hashtags: numbers, mid-word, URL fragments, entities, ##
        assert!(hashtags("#1 a#b x.com/#top &#39; ## #").is_empty());
        assert_eq!(hashtags(&"#a ".repeat(40)), vec!["a"]);
        assert_eq!(tag_query("#Cats and dogs"), "tags:cats and dogs");
        assert_eq!(tag_query("no tags"), "no tags");
    }

    #[tokio::test]
    async fn test_hashtag_search_is_exact_and_pages_newest_first() {
        let (indexer, _tmp_dir) = create_test_indexer();
        let mut messages = Vec::new();
        for i in 0..5u8 {
            let mut m =
                create_cast_message(100 + i as u64, &format!("cast {i} #GM"), vec![i, 0, 0, 0]);
            m.data.as_mut().unwrap().timestamp = 1000 + i as u32;
            messages.push(m);
        }
        messages.push(create_cast_message(200, "just saying gm", vec![9, 0, 0, 0]));
        messages.push(create_cast_message(201, "#gmgm", vec![10, 0, 0, 0]));
        indexer
            .process_event(&IndexEvent::messages(messages, 1, 1))
            .await
            .unwrap();
        indexer.current.reader.reload().unwrap();

        let fids = |offset| {
            indexer
                .search_casts("#gm", SearchSort::Newest, offset, 2)
                .unwrap()
                .into_iter()
                .map(|r| r.fid)
                .collect::<Vec<_>>()
        };
        assert_eq!(fids(0), vec![104, 103]);
        assert_eq!(fids(2), vec![102, 101]);
        assert_eq!(fids(4), vec![100]);
        let oldest = indexer
            .search_casts("#gm", SearchSort::Oldest, 0, 1)
            .unwrap();
        assert_eq!(oldest[0].fid, 100);
        // the word still finds tags and plain mentions alike
        assert_eq!(
            indexer
                .search_casts("gm", SearchSort::Relevance, 0, 10)
                .unwrap()
                .len(),
            6
        );
        // a tag next to a word narrows it
        assert_eq!(
            indexer
                .search_casts("#gm cast", SearchSort::Newest, 0, 10)
                .unwrap()
                .len(),
            5
        );
    }

    #[tokio::test]
    async fn test_checkpoint() {
        let (indexer, _tmp_dir) = create_test_indexer();

        assert_eq!(indexer.last_checkpoint(), 0);
        indexer.save_checkpoint(100).await.unwrap();
        assert_eq!(indexer.last_checkpoint(), 100);
    }
}
