//! Sequential canonical-store rebuild. No historical block decode and no
//! per-message point lookup into the same source database.
use super::{backfill, IndexEvent, Indexer, IndexerError, MetricsIndexer};
use crate::proto::{message_data::Body, Message, MessageType};
use crate::storage::constants::{RootPrefix, UserPostfix};
use crate::storage::db::{DBProvider, RocksDB};
use crate::storage::store::account::{message_decode, read_fid_key, FID_BYTES, TS_HASH_LENGTH};
use crate::storage::store::stores::Stores;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

const PAGE_MESSAGES: usize = 2000;
const WRITE_MESSAGES: usize = 250;
const PAGE_TIME: Duration = Duration::from_millis(100);
const META: u8 = 0xF4;

#[derive(Default, Serialize, Deserialize)]
struct ScanState {
    boundary: u64,
    source_prefix: Option<u8>,
    page_token: Option<Vec<u8>>,
    complete: bool,
    rows_scanned: u64,
    messages_indexed: u64,
    last_fid: u64,
}

fn error(e: impl std::fmt::Display) -> IndexerError {
    IndexerError::Storage(e.to_string())
}
fn key(generation: u8, shard: u32) -> Vec<u8> {
    [vec![0xE2, META, generation], shard.to_be_bytes().to_vec()].concat()
}
fn load(db: &RocksDB, generation: u8, shard: u32) -> Result<Option<ScanState>, IndexerError> {
    db.get(&key(generation, shard))
        .map_err(error)?
        .map(|v| serde_json::from_slice(&v).map_err(error))
        .transpose()
}

/// Initializes scan boundaries durably before live block replay can advance.
/// A restart reuses them, including a completed walk awaiting publication.
pub(super) fn initialize(
    indexer: &MetricsIndexer,
    db: &RocksDB,
    tips: &HashMap<u32, u64>,
) -> Result<(), IndexerError> {
    for (&shard, &tip) in tips {
        let state = match load(db, indexer.generation(), shard)? {
            Some(state) => state,
            None => {
                let state = ScanState {
                    boundary: tip + 1,
                    ..Default::default()
                };
                db.put(
                    &key(indexer.generation(), shard),
                    &serde_json::to_vec(&state).map_err(error)?,
                )
                .map_err(error)?;
                state
            }
        };
        let name = super::metrics_worker::cursor(indexer.generation());
        if backfill::try_load_shard_checkpoint(db, &name, shard)? == 0 {
            backfill::save_shard_checkpoint(db, &name, shard, state.boundary).map_err(error)?;
        }
    }
    Ok(())
}

pub(super) async fn step(
    indexer: &MetricsIndexer,
    db: &RocksDB,
    canonical: &HashMap<u32, Stores>,
    tips: &HashMap<u32, u64>,
    stop: &AtomicBool,
) -> Result<bool, IndexerError> {
    if tips.keys().any(|id| !canonical.contains_key(id)) {
        return Err(error("Missing metrics source shard"));
    }
    initialize(indexer, db, tips)?;
    let mut complete = true;
    let mut shards: Vec<_> = tips.keys().copied().collect();
    shards.sort_unstable();
    for shard in shards {
        if stop.load(Ordering::Relaxed) {
            return Err(error("Metrics scan stopping"));
        }
        let source = canonical
            .get(&shard)
            .ok_or_else(|| error("Missing metrics source shard"))?;
        let mut state = load(db, indexer.generation(), shard)?
            .ok_or_else(|| error("Missing metrics scan state"))?;
        let prefix = source
            .cast_store
            .state_context()
            .root_prefix(RootPrefix::User);
        if state.source_prefix.is_some_and(|saved| saved != prefix) {
            return Err(error("Metrics scan source changed during rebuild"));
        }
        state.source_prefix = Some(prefix);
        if state.complete {
            continue;
        }
        let started = Instant::now();
        let page = read_page(source, state.page_token.clone(), stop)?;
        let read_ms = started.elapsed().as_millis() as u64;
        for messages in page.messages.chunks(WRITE_MESSAGES) {
            if stop.load(Ordering::Relaxed) {
                return Err(error("Metrics scan stopping"));
            }
            indexer
                .process_batch(&[IndexEvent::messages(
                    messages.to_vec(),
                    shard,
                    state.boundary.saturating_sub(1),
                )])
                .await?;
        }
        state.rows_scanned += page.rows;
        state.messages_indexed += page.messages.len() as u64;
        if let Some(token) = &page.last_key {
            state.last_fid = read_fid_key(token, 1);
        }
        state.page_token = page.last_key.or(state.page_token);
        state.complete = page.complete;
        // Data commits precede the scan cursor; retries are idempotent.
        db.put(
            &key(indexer.generation(), shard),
            &serde_json::to_vec(&state).map_err(error)?,
        )
        .map_err(error)?;
        tracing::debug!(
            generation = indexer.generation(),
            shard_id = shard,
            rows = page.rows,
            messages = page.messages.len(),
            read_ms,
            write_ms = started.elapsed().as_millis() as u64 - read_ms,
            "Metrics canonical scan batch"
        );
        complete &= state.complete;
    }
    Ok(complete)
}

struct Page {
    messages: Vec<Message>,
    rows: u64,
    last_key: Option<Vec<u8>>,
    complete: bool,
}
fn read_page(
    source: &Stores,
    token: Option<Vec<u8>>,
    stop: &AtomicBool,
) -> Result<Page, IndexerError> {
    let prefix = source
        .cast_store
        .state_context()
        .root_prefix(RootPrefix::User);
    let start = token.map_or_else(
        || vec![prefix],
        |mut token| {
            token.push(0);
            token
        },
    );
    let mut opts = rocksdb::ReadOptions::default();
    opts.set_iterate_lower_bound(start.clone());
    opts.set_iterate_upper_bound(vec![prefix + 1]);
    opts.set_readahead_size(256 * 1024);
    opts.fill_cache(false);
    let guard = source.db.db();
    match guard.as_ref() {
        Some(DBProvider::Transaction(db)) => scan(db.raw_iterator_opt(opts), &start, prefix, stop),
        Some(DBProvider::ReadOnly(db)) => scan(db.raw_iterator_opt(opts), &start, prefix, stop),
        None => Err(error("Metrics source DB is not open")),
    }
}

fn scan<D: rocksdb::DBAccess>(
    mut iter: rocksdb::DBRawIteratorWithThreadMode<'_, D>,
    start: &[u8],
    _prefix: u8,
    stop: &AtomicBool,
) -> Result<Page, IndexerError> {
    let mut page = Page {
        messages: vec![],
        rows: 0,
        last_key: None,
        complete: false,
    };
    let started = Instant::now();
    iter.seek(start);
    while let Some((key, value)) = iter.item() {
        if stop.load(Ordering::Relaxed) {
            return Err(error("Metrics scan stopping"));
        }
        if key.len() < 1 + FID_BYTES + 1 {
            return Err(error("Invalid metrics source key"));
        }
        let fid_len = crate::storage::store::account::encoded_fid_len(key, 1)
            .ok_or_else(|| error("Invalid metrics FID key"))?;
        let postfix = *key
            .get(1 + fid_len)
            .ok_or_else(|| error("Missing metrics postfix"))?;
        page.last_key = Some(key.to_vec());
        if postfix == UserPostfix::CastMessage as u8
            || postfix == UserPostfix::ReactionMessage as u8
        {
            if key.len() != 1 + fid_len + 1 + TS_HASH_LENGTH {
                return Err(error("Invalid metrics source message key"));
            }
            let message = message_decode(value).map_err(error)?;
            page.rows += 1;
            if relevant(&message) {
                page.messages.push(message);
            }
            iter.next();
        } else {
            // Skip entire unrelated message and secondary-index ranges. The
            // next seek starts at this fid's reactions or the next fid's casts.
            let mut seek = key[..1 + fid_len].to_vec();
            if postfix < UserPostfix::CastMessage as u8 {
                seek.push(UserPostfix::CastMessage as u8);
            } else if postfix < UserPostfix::ReactionMessage as u8 {
                seek.push(UserPostfix::ReactionMessage as u8);
            } else {
                seek = crate::storage::util::increment_vec_u8(&key[..1 + fid_len].to_vec());
            }
            iter.seek(seek);
        }
        if page.rows >= PAGE_MESSAGES as u64 || started.elapsed() >= PAGE_TIME {
            break;
        }
    }
    iter.status().map_err(error)?;
    page.complete = !iter.valid();
    Ok(page)
}
fn relevant(message: &Message) -> bool {
    let Some(data) = &message.data else {
        return false;
    };
    match (&data.body, MessageType::try_from(data.r#type)) {
        (Some(Body::CastAddBody(body)), Ok(MessageType::CastAdd)) => matches!(
            &body.parent,
            Some(crate::proto::cast_add_body::Parent::ParentCastId(_))
        ),
        (
            Some(Body::ReactionBody(body)),
            Ok(MessageType::ReactionAdd | MessageType::ReactionRemove),
        ) => matches!(
            &body.target,
            Some(crate::proto::reaction_body::Target::TargetCastId(_))
        ),
        (Some(Body::CastRemoveBody(_)), Ok(MessageType::CastRemove)) => true,
        _ => false,
    }
}

pub(super) fn progress(
    indexer: &MetricsIndexer,
    db: &RocksDB,
    shard: u32,
) -> Result<serde_json::Value, IndexerError> {
    let state = load(db, indexer.generation(), shard)?;
    Ok(match state {
        Some(state) => {
            serde_json::json!({"shard_id":shard,"scan_complete":state.complete,"rows_scanned":state.rows_scanned,"messages_indexed":state.messages_indexed,"last_fid":state.last_fid,"replay_from_block":state.boundary})
        }
        None => {
            serde_json::json!({"shard_id":shard,"scan_complete":indexer.stats().backfill_complete,"reused_existing_index":indexer.stats().backfill_complete,"rows_scanned":0,"messages_indexed":0,"last_fid":0})
        }
    })
}
