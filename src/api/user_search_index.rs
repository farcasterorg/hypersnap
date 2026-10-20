//! User search index: prefix lookup over usernames and display-name words.
//!
//! Each FID's current username and the words of its display name are stored
//! as sorted terms, so a prefix scan finds every user a partial query could
//! mean ("dw" finds "dwr"). Live `UserDataAdd` merges keep the terms current;
//! [`UserSearchIndexer::backfill`] fills them once from the stores, since the
//! event log only reaches back a few days.

use crate::api::config::FeatureConfig;
use crate::api::events::{IndexEvent, MessageEventKind};
use crate::api::indexer::{Indexer, IndexerError, IndexerStats};
use crate::mempool::routing::{MessageRouter, ShardRouter};
use crate::proto::message_data::Body;
use crate::proto::{Message, MessageType, UserDataType};
use crate::storage::db::{PageOptions, RocksDB, RocksDbTransactionBatch};
use crate::storage::store::account::UserDataStore;
use crate::storage::store::stores::Stores;
use crate::storage::util::increment_vec_u8;
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

/// Key prefix for the user search index (in the API RocksDB).
const SEARCH_PREFIX: u8 = 0xEC;
/// [prefix][0x01][field:1][term][0x00][fid:8] -> empty
const TERM: u8 = 0x01;
/// [prefix][0x02][field:1][fid:8] -> the FID's terms for the field, 0x00-separated
const FID_TERMS: u8 = 0x02;
/// [prefix][0xFD] -> present once the store backfill has finished.
const BACKFILL_DONE: u8 = 0xFD;
/// [prefix][0xFF] -> event_id:8
const CHECKPOINT: u8 = 0xFF;

/// Separates a term from the FID in term keys; stripped from terms.
const TERM_END: u8 = 0x00;
/// Longest term indexed, in bytes.
const MAX_TERM_BYTES: usize = 64;
/// Most display-name words indexed per user.
const MAX_DISPLAY_TERMS: usize = 8;

/// The profile field a term came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SearchField {
    Username = 0,
    DisplayName = 1,
}

/// A search hit: the FID and the term of it that matched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchHit {
    pub fid: u64,
    pub term: String,
}

pub struct UserSearchIndexer {
    config: FeatureConfig,
    db: Arc<RocksDB>,
    checkpoint: AtomicU64,
    items_indexed: AtomicU64,
    backfilled: AtomicBool,
}

impl UserSearchIndexer {
    pub fn new(config: FeatureConfig, db: Arc<RocksDB>) -> Self {
        let checkpoint = match db.get(&[SEARCH_PREFIX, CHECKPOINT]) {
            Ok(Some(v)) if v.len() == 8 => u64::from_be_bytes(v[..8].try_into().unwrap()),
            _ => 0,
        };
        let backfilled = matches!(db.get(&[SEARCH_PREFIX, BACKFILL_DONE]), Ok(Some(_)));
        Self {
            config,
            db,
            checkpoint: AtomicU64::new(checkpoint),
            items_indexed: AtomicU64::new(0),
            backfilled: AtomicBool::new(backfilled),
        }
    }

    /// Whether every user's terms are indexed, not only those seen live.
    pub fn is_complete(&self) -> bool {
        self.backfilled.load(Ordering::Acquire)
    }

    /// Up to `limit` hits whose `field` term starts with `prefix` (already
    /// normalized), in term order.
    pub fn search_prefix(&self, field: SearchField, prefix: &str, limit: usize) -> Vec<SearchHit> {
        let start = [&[SEARCH_PREFIX, TERM, field as u8][..], prefix.as_bytes()].concat();
        let stop = increment_vec_u8(&start);
        let term_offset = 3;
        let mut hits = Vec::new();
        let _ = self.db.for_each_iterator_by_prefix(
            Some(start),
            Some(stop),
            &PageOptions::default(),
            |key, _| {
                if key.len() < term_offset + 1 + 8 {
                    return Ok(false);
                }
                let (term, fid) = key[term_offset..].split_at(key.len() - term_offset - 9);
                if fid[0] == TERM_END {
                    hits.push(SearchHit {
                        fid: u64::from_be_bytes(fid[1..].try_into().unwrap()),
                        term: String::from_utf8_lossy(term).into_owned(),
                    });
                }
                Ok(hits.len() >= limit)
            },
        );
        hits
    }

    /// Normalize a search query or indexed value: trimmed, lowercased, with
    /// a leading `@` and the term separator removed.
    pub fn normalize(value: &str) -> String {
        let value = value.trim().trim_start_matches('@').to_lowercase();
        let mut normalized: String = value.chars().filter(|c| *c != '\0').collect();
        if normalized.len() > MAX_TERM_BYTES {
            let mut end = MAX_TERM_BYTES;
            while !normalized.is_char_boundary(end) {
                end -= 1;
            }
            normalized.truncate(end);
        }
        normalized
    }

    /// Terms a field value is found by: the whole value, and for display
    /// names each word too.
    fn terms_for(field: SearchField, value: &str) -> Vec<String> {
        let whole = Self::normalize(value);
        if whole.is_empty() {
            return vec![];
        }
        let mut terms = vec![whole.clone()];
        if field == SearchField::DisplayName {
            for word in whole
                .split(|c: char| c.is_whitespace())
                .map(|w| w.trim_matches(|c: char| !c.is_alphanumeric()))
                .filter(|w| !w.is_empty())
                .take(MAX_DISPLAY_TERMS)
            {
                if !terms.iter().any(|t| t == word) {
                    terms.push(word.to_string());
                }
            }
        }
        terms
    }

    /// Fill in the terms of every FID in `stores` that live events have not
    /// already written, from its current username and display name. Runs once.
    /// Blocking.
    pub fn backfill(&self, stores: &HashMap<u32, Stores>) -> Result<(), IndexerError> {
        if self.is_complete() {
            return Ok(());
        }
        let num_shards = stores.len() as u32;
        let router = ShardRouter {};
        for (&shard_id, shard) in stores {
            let Some(max_fid) = crate::storage::store::reconcile::max_registered_fid(shard) else {
                continue;
            };
            let mut txn = RocksDbTransactionBatch::new();
            for fid in 1..=max_fid {
                if router.route_fid(fid, num_shards) != shard_id {
                    continue;
                }
                let Ok(page) = UserDataStore::get_user_data_adds_by_fid(
                    &shard.user_data_store,
                    fid,
                    &PageOptions::default(),
                    None,
                    None,
                ) else {
                    continue;
                };
                for message in &page.messages {
                    if let Some((field, value)) = Self::field_value(message) {
                        if self.read_terms(field, fid, &txn)?.is_none() {
                            self.set_terms(field, fid, &Self::terms_for(field, &value), &mut txn)?;
                        }
                    }
                }
                if txn.len() >= 1000 {
                    self.commit(std::mem::replace(&mut txn, RocksDbTransactionBatch::new()))?;
                }
            }
            self.commit(txn)?;
        }
        self.db
            .put(&[SEARCH_PREFIX, BACKFILL_DONE], &[1])
            .map_err(|e| IndexerError::Storage(e.to_string()))?;
        self.backfilled.store(true, Ordering::Release);
        Ok(())
    }

    /// The searchable field and value of a username or display-name message.
    fn field_value(message: &Message) -> Option<(SearchField, String)> {
        let data = message.data.as_ref()?;
        if data.r#type != MessageType::UserDataAdd as i32 {
            return None;
        }
        let Some(Body::UserDataBody(body)) = &data.body else {
            return None;
        };
        let field = match UserDataType::try_from(body.r#type).ok()? {
            UserDataType::Username => SearchField::Username,
            UserDataType::Display => SearchField::DisplayName,
            _ => return None,
        };
        Some((field, body.value.clone()))
    }

    fn process_message(
        &self,
        message: &Message,
        kind: MessageEventKind,
        txn: &mut RocksDbTransactionBatch,
    ) -> Result<(), IndexerError> {
        let Some((field, value)) = Self::field_value(message) else {
            return Ok(());
        };
        let fid = message.data.as_ref().map(|d| d.fid).unwrap_or(0);
        let terms = Self::terms_for(field, &value);
        match kind {
            // A merge is the field's new current value.
            MessageEventKind::Merge => self.set_terms(field, fid, &terms, txn),
            // Pruning keeps the value in the hyper stores the API serves.
            MessageEventKind::Prune => Ok(()),
            // A revoked current value leaves the field empty.
            MessageEventKind::Revoke => {
                if self.read_terms(field, fid, txn)?.as_deref() == Some(terms.as_slice()) {
                    self.set_terms(field, fid, &[], txn)
                } else {
                    Ok(())
                }
            }
        }
    }

    fn read_terms(
        &self,
        field: SearchField,
        fid: u64,
        txn: &RocksDbTransactionBatch,
    ) -> Result<Option<Vec<String>>, IndexerError> {
        let key = Self::fid_terms_key(field, fid);
        let stored = match txn.batch.get(&key) {
            Some(pending) => pending.clone(),
            None => self
                .db
                .get(&key)
                .map_err(|e| IndexerError::Storage(e.to_string()))?,
        };
        Ok(stored.map(|bytes| {
            bytes
                .split(|b| *b == TERM_END)
                .filter(|t| !t.is_empty())
                .map(|t| String::from_utf8_lossy(t).into_owned())
                .collect()
        }))
    }

    /// Replace the FID's terms for `field` with `terms`.
    fn set_terms(
        &self,
        field: SearchField,
        fid: u64,
        terms: &[String],
        txn: &mut RocksDbTransactionBatch,
    ) -> Result<(), IndexerError> {
        for old in self.read_terms(field, fid, txn)?.unwrap_or_default() {
            if !terms.contains(&old) {
                txn.delete(Self::term_key(field, &old, fid));
            }
        }
        for term in terms {
            txn.put(Self::term_key(field, term, fid), vec![]);
        }
        txn.put(
            Self::fid_terms_key(field, fid),
            terms.join("\0").into_bytes(),
        );
        self.items_indexed.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    fn commit(&self, txn: RocksDbTransactionBatch) -> Result<(), IndexerError> {
        if txn.len() == 0 {
            return Ok(());
        }
        self.db
            .commit(txn)
            .map_err(|e| IndexerError::Storage(e.to_string()))
    }

    fn term_key(field: SearchField, term: &str, fid: u64) -> Vec<u8> {
        let mut key = Vec::with_capacity(3 + term.len() + 1 + 8);
        key.extend_from_slice(&[SEARCH_PREFIX, TERM, field as u8]);
        key.extend_from_slice(term.as_bytes());
        key.push(TERM_END);
        key.extend_from_slice(&fid.to_be_bytes());
        key
    }

    fn fid_terms_key(field: SearchField, fid: u64) -> Vec<u8> {
        [
            &[SEARCH_PREFIX, FID_TERMS, field as u8][..],
            &fid.to_be_bytes()[..],
        ]
        .concat()
    }
}

#[async_trait]
impl Indexer for UserSearchIndexer {
    fn name(&self) -> &'static str {
        "user_search"
    }

    fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    async fn process_event(&self, event: &IndexEvent) -> Result<(), IndexerError> {
        self.process_batch(std::slice::from_ref(event)).await
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
        self.commit(txn)
    }

    fn last_checkpoint(&self) -> u64 {
        self.checkpoint.load(Ordering::SeqCst)
    }

    async fn save_checkpoint(&self, event_id: u64) -> Result<(), IndexerError> {
        self.db
            .put(&[SEARCH_PREFIX, CHECKPOINT], &event_id.to_be_bytes())
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
    use crate::proto::{MessageData, UserDataBody};

    fn indexer() -> (tempfile::TempDir, UserSearchIndexer) {
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(RocksDB::new(dir.path().to_str().unwrap()));
        db.open().unwrap();
        let config = FeatureConfig {
            enabled: true,
            ..Default::default()
        };
        (dir, UserSearchIndexer::new(config, db))
    }

    fn user_data(fid: u64, kind: UserDataType, value: &str) -> Message {
        Message {
            data: Some(MessageData {
                fid,
                r#type: MessageType::UserDataAdd as i32,
                body: Some(Body::UserDataBody(UserDataBody {
                    r#type: kind as i32,
                    value: value.to_string(),
                })),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    fn fids(hits: Vec<SearchHit>) -> Vec<u64> {
        hits.into_iter().map(|h| h.fid).collect()
    }

    #[tokio::test]
    async fn test_prefix_finds_usernames_and_display_words() {
        let (_dir, idx) = indexer();
        idx.process_batch(&[IndexEvent::messages(
            vec![
                user_data(3, UserDataType::Username, "dwr"),
                user_data(3, UserDataType::Display, "Dan Romero"),
                user_data(4, UserDataType::Username, "dwrx.eth"),
                user_data(5, UserDataType::Username, "dan"),
            ],
            1,
            1,
        )])
        .await
        .unwrap();

        assert_eq!(
            fids(idx.search_prefix(SearchField::Username, "dw", 10)),
            vec![3, 4]
        );
        let exact = idx.search_prefix(SearchField::Username, "dwr", 10);
        assert_eq!(
            exact[0],
            SearchHit {
                fid: 3,
                term: "dwr".into()
            }
        );
        assert_eq!(
            fids(idx.search_prefix(SearchField::DisplayName, "rom", 10)),
            vec![3]
        );
        assert_eq!(
            fids(idx.search_prefix(SearchField::DisplayName, "dan r", 10)),
            vec![3]
        );
        assert_eq!(idx.search_prefix(SearchField::Username, "d", 1).len(), 1);
        assert!(idx.search_prefix(SearchField::Username, "x", 10).is_empty());
    }

    #[tokio::test]
    async fn test_rename_replaces_terms_and_prune_keeps_them() {
        let (_dir, idx) = indexer();
        idx.process_event(&IndexEvent::message(
            user_data(7, UserDataType::Username, "old"),
            1,
            1,
        ))
        .await
        .unwrap();
        idx.process_event(&IndexEvent::message(
            user_data(7, UserDataType::Username, "new"),
            1,
            1,
        ))
        .await
        .unwrap();
        assert!(idx
            .search_prefix(SearchField::Username, "old", 10)
            .is_empty());
        assert_eq!(
            fids(idx.search_prefix(SearchField::Username, "new", 10)),
            vec![7]
        );

        let current = user_data(7, UserDataType::Username, "new");
        idx.process_event(&IndexEvent::message_of_kind(
            current.clone(),
            1,
            1,
            MessageEventKind::Prune,
        ))
        .await
        .unwrap();
        assert_eq!(
            fids(idx.search_prefix(SearchField::Username, "new", 10)),
            vec![7]
        );

        idx.process_event(&IndexEvent::message_of_kind(
            current,
            1,
            1,
            MessageEventKind::Revoke,
        ))
        .await
        .unwrap();
        assert!(idx
            .search_prefix(SearchField::Username, "new", 10)
            .is_empty());
    }

    #[test]
    fn test_normalize() {
        assert_eq!(UserSearchIndexer::normalize("  @DWR "), "dwr");
        assert_eq!(UserSearchIndexer::normalize("a\0b"), "ab");
        assert_eq!(UserSearchIndexer::normalize(&"é".repeat(40)).len(), 64);
    }
}
