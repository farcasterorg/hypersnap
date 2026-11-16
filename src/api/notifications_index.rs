//! Notifications index: everything that notifies a user, newest first.
//!
//! One key per (notified user, message): likes and recasts of the user's
//! casts, replies to them, replies deeper in their threads, quotes, mentions
//! and follows. Keys sort by the message's timestamp and hash, so a page of
//! notifications is one reverse range scan from the cursor, however old the
//! cast that was liked. The value is empty: readers load the message itself
//! from the stores by its timestamp and hash, which also drops anything
//! removed since (an unlike, a deleted cast, an unfollow) without the index
//! having to track removes.
//!
//! Live merges keep it current; [`NotificationsIndexer::backfill`] walks the
//! stores once for history, since the event log only reaches back a few days.
//! Until that walk has finished, notifications keep using the bounded scan of
//! the user's newest casts.

use crate::api::backfill::{save_shard_checkpoint, try_load_shard_checkpoint};
use crate::api::config::FeatureConfig;
use crate::api::events::{IndexEvent, MessageEventKind};
use crate::api::indexer::{Indexer, IndexerError, IndexerStats};
use crate::mempool::routing::{MessageRouter, ShardRouter};
use crate::proto::message_data::Body;
use crate::proto::{cast_add_body, embed, link_body, reaction_body, CastId, Message, MessageType};
use crate::storage::db::{PageOptions, RocksDB, RocksDbTransactionBatch};
use crate::storage::store::account::{CastStore, LinkStore, ReactionStore};
use crate::storage::store::stores::Stores;
use crate::storage::util::increment_vec_u8;
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Key prefix for the notifications index (in the API RocksDB).
const PREFIX: u8 = 0xED;
/// [prefix][0x01][notified_fid:8][timestamp:4][hash:20][kind:1][actor_fid:8] -> empty
const ENTRY: u8 = 0x01;
/// [prefix][0xFD] -> present once the store walk has finished.
const BACKFILL_DONE: u8 = 0xFD;
/// Per-shard walk checkpoints (next fid to walk), in the shared checkpoint table.
const CHECKPOINT_NAME: &str = "notifications_index_v1";

/// Levels of a thread a reply notifies: its parent's author (a reply) and the
/// authors of the casts above that (deeper replies), the same reach as the
/// scan `include_quotes_and_deep_replies` used to do.
const THREAD_DEPTH: usize = 6;
/// Most stored replies a late cast picks up per thread level.
const REPLIES_PER_LEVEL: usize = 100;
/// [prefix][0xFC][shard_id:4] -> the highest block whose live events are indexed.
const INDEXED_HEIGHT: u8 = 0xFC;
/// Pending writes per commit, so a batch stays small in memory.
const COMMIT_EVERY: usize = 10_000;
/// FIDs walked between checkpoints.
const FIDS_PER_CHECKPOINT: u64 = 1_000;
/// Messages per store page during the walk.
const PAGE: usize = 1_000;
// ponytail: one fixed pace for the walk, so it never crowds out block commits
// on the shared DB; make it a config knob if operators need it faster or slower.
const WALK_MESSAGES_PER_SEC: f64 = 100_000.0;

const HASH_LEN: usize = 20;
/// Length of an entry key after [prefix][ENTRY][notified_fid].
const ENTRY_TAIL: usize = 4 + HASH_LEN + 1 + 8;

/// Why a message notifies a user.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Kind {
    /// A like or recast of one of the user's casts.
    Reaction = 1,
    /// A reply to one of the user's casts.
    Reply = 2,
    Mention = 3,
    Follow = 4,
    /// A cast embedding one of the user's casts.
    Quote = 5,
    /// A reply further down a thread under one of the user's casts.
    DeepReply = 6,
}

impl Kind {
    fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            1 => Kind::Reaction,
            2 => Kind::Reply,
            3 => Kind::Mention,
            4 => Kind::Follow,
            5 => Kind::Quote,
            6 => Kind::DeepReply,
            _ => return None,
        })
    }

    /// Kinds only sent with `include_quotes_and_deep_replies`.
    pub fn needs_flag(self) -> bool {
        matches!(self, Kind::Quote | Kind::DeepReply)
    }
}

/// One index entry: the message that notifies, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub timestamp: u32,
    pub hash: [u8; HASH_LEN],
    pub kind: Kind,
    pub actor: u64,
}

pub struct NotificationsIndexer {
    config: FeatureConfig,
    db: Arc<RocksDB>,
    /// Stores the API serves (hyper when available), for thread lookups and
    /// the walk.
    stores: HashMap<u32, Stores>,
    router: Box<dyn MessageRouter>,
    complete: AtomicBool,
    items_indexed: AtomicU64,
    /// Per shard, the highest block whose live events are indexed (as stored).
    heights: Mutex<HashMap<u32, u64>>,
}

impl NotificationsIndexer {
    pub fn new(config: FeatureConfig, db: Arc<RocksDB>, stores: HashMap<u32, Stores>) -> Self {
        let complete = matches!(db.get(&[PREFIX, BACKFILL_DONE]), Ok(Some(_)));
        let mut heights = HashMap::new();
        let start = vec![PREFIX, INDEXED_HEIGHT];
        let _ = db.for_each_iterator_by_prefix(
            Some(start.clone()),
            Some(increment_vec_u8(&start)),
            &PageOptions::default(),
            |key, value| {
                if let (Ok(shard), Ok(height)) = (key[2..].try_into(), value.try_into()) {
                    heights.insert(u32::from_be_bytes(shard), u64::from_be_bytes(height));
                }
                Ok(false)
            },
        );
        Self {
            config,
            db,
            stores,
            router: Box::new(ShardRouter {}),
            complete: AtomicBool::new(complete),
            items_indexed: AtomicU64::new(0),
            heights: Mutex::new(heights),
        }
    }

    /// Per shard, the highest block whose live events were indexed before this
    /// start. Events still queued when the node stopped were lost, so the
    /// blocks from there to the tip are replayed (`index_gaps`).
    pub fn indexed_heights(&self) -> HashMap<u32, u64> {
        self.heights.lock().unwrap().clone()
    }

    /// Record live events' block heights in `txn`, committed with their entries.
    fn note_height(&self, shard_id: u32, height: u64, txn: &mut RocksDbTransactionBatch) {
        let mut heights = self.heights.lock().unwrap();
        let known = heights.entry(shard_id).or_insert(0);
        if height > *known {
            *known = height;
            txn.put(
                [&[PREFIX, INDEXED_HEIGHT][..], &shard_id.to_be_bytes()[..]].concat(),
                height.to_be_bytes().to_vec(),
            );
        }
    }

    /// Route FIDs to shards with `router` instead of the mainnet one.
    pub fn with_router(mut self, router: Box<dyn MessageRouter>) -> Self {
        self.router = router;
        self
    }

    /// Whether the store walk has finished, so the index holds everything and
    /// not only what was merged since the node started indexing it.
    pub fn is_complete(&self) -> bool {
        self.complete.load(Ordering::Acquire)
    }

    /// Entries for `fid`, newest first, strictly before `before` (a message's
    /// timestamp and hash) when given. `f` returns `true` to stop.
    pub fn scan(
        &self,
        fid: u64,
        before: Option<(u32, &[u8])>,
        mut f: impl FnMut(Entry) -> bool,
    ) -> Result<(), IndexerError> {
        let start = Self::user_prefix(fid);
        let stop = match before {
            Some((ts, hash)) => [&start[..], &ts.to_be_bytes()[..], hash].concat(),
            None => increment_vec_u8(&start),
        };
        self.db
            .for_each_iterator_by_prefix(
                Some(start),
                Some(stop),
                &PageOptions {
                    reverse: true,
                    ..Default::default()
                },
                |key, _| {
                    let Some(entry) = Self::parse(key) else {
                        return Ok(false);
                    };
                    Ok(f(entry))
                },
            )
            .map(|_| ())
            .map_err(|e| IndexerError::Storage(e.to_string()))
    }

    /// Walk every FID's casts, reactions and links once, indexing what they
    /// notify. Resumes from per-shard checkpoints; marks the index complete
    /// only when every shard has been walked without a read error. Blocking.
    pub fn backfill(&self) -> Result<(), IndexerError> {
        if self.is_complete() {
            return Ok(());
        }
        let started = Instant::now();
        let mut pace = Pace::new();
        let mut shard_ids: Vec<_> = self.stores.keys().copied().collect();
        shard_ids.sort();
        for shard_id in shard_ids {
            let stores = &self.stores[&shard_id];
            let from = try_load_shard_checkpoint(&self.db, CHECKPOINT_NAME, shard_id)?;
            if from == u64::MAX {
                continue;
            }
            tracing::info!(shard_id, from, "Notifications index walk starting");
            let mut txn = RocksDbTransactionBatch::new();
            let mut token: Option<Vec<u8>> = None;
            let mut walked: u64 = 0;
            loop {
                let (fids, next) = stores
                    .onchain_event_store
                    .get_fids(&PageOptions {
                        page_size: Some(PAGE),
                        page_token: token.take(),
                        reverse: false,
                    })
                    .map_err(|e| IndexerError::Storage(e.to_string()))?;
                for fid in fids.into_iter().filter(|&fid| fid >= from) {
                    self.walk_fid(stores, fid, &mut txn, &mut pace)?;
                    walked += 1;
                    if walked % FIDS_PER_CHECKPOINT == 0 {
                        self.commit(std::mem::replace(&mut txn, RocksDbTransactionBatch::new()))?;
                        save_shard_checkpoint(&self.db, CHECKPOINT_NAME, shard_id, fid + 1)?;
                        if walked % (FIDS_PER_CHECKPOINT * 100) == 0 {
                            tracing::info!(
                                shard_id,
                                fid,
                                walked,
                                messages = pace.done,
                                elapsed_secs = started.elapsed().as_secs(),
                                "Notifications index walk progress"
                            );
                        }
                    }
                }
                match next {
                    Some(t) if !t.is_empty() => token = Some(t),
                    _ => break,
                }
            }
            self.commit(txn)?;
            save_shard_checkpoint(&self.db, CHECKPOINT_NAME, shard_id, u64::MAX)?;
            tracing::info!(shard_id, walked, "Notifications index walk done for shard");
        }
        self.db
            .put(&[PREFIX, BACKFILL_DONE], &[1])
            .map_err(|e| IndexerError::Storage(e.to_string()))?;
        self.complete.store(true, Ordering::Release);
        tracing::info!(
            messages = pace.done,
            elapsed_secs = started.elapsed().as_secs(),
            "Notifications index complete"
        );
        Ok(())
    }

    fn walk_fid(
        &self,
        stores: &Stores,
        fid: u64,
        txn: &mut RocksDbTransactionBatch,
        pace: &mut Pace,
    ) -> Result<(), IndexerError> {
        for set in 0..3 {
            let mut token: Option<Vec<u8>> = None;
            loop {
                let opts = PageOptions {
                    page_size: Some(PAGE),
                    page_token: token.take(),
                    reverse: false,
                };
                let page = match set {
                    0 => CastStore::get_cast_adds_by_fid(&stores.cast_store, fid, &opts),
                    1 => ReactionStore::get_reaction_adds_by_fid(
                        &stores.reaction_store,
                        fid,
                        0,
                        &opts,
                    ),
                    _ => LinkStore::get_link_adds_by_fid(
                        &stores.link_store,
                        fid,
                        String::new(),
                        &opts,
                    ),
                }
                .map_err(|e| IndexerError::Storage(e.to_string()))?;
                for message in &page.messages {
                    self.write(message, false, txn);
                    if txn.len() >= COMMIT_EVERY {
                        self.commit(std::mem::replace(txn, RocksDbTransactionBatch::new()))?;
                    }
                }
                pace.tick(page.messages.len());
                match page.next_page_token {
                    Some(t) if !t.is_empty() && !page.messages.is_empty() => token = Some(t),
                    _ => break,
                }
            }
        }
        Ok(())
    }

    /// The users `message` notifies, and why. Its author is never one of them.
    fn targets(&self, message: &Message) -> Vec<(u64, Kind)> {
        let Some(data) = &message.data else {
            return vec![];
        };
        let author = data.fid;
        let mut out: Vec<(u64, Kind)> = Vec::new();
        let mut add = |fid: u64, kind: Kind| {
            if fid != 0 && fid != author && !out.contains(&(fid, kind)) {
                out.push((fid, kind));
            }
        };
        match (MessageType::try_from(data.r#type), &data.body) {
            (Ok(MessageType::CastAdd), Some(Body::CastAddBody(body))) => {
                for &fid in &body.mentions {
                    add(fid, Kind::Mention);
                }
                for e in &body.embeds {
                    if let Some(embed::Embed::CastId(quoted)) = &e.embed {
                        add(quoted.fid, Kind::Quote);
                    }
                }
                if let Some(cast_add_body::Parent::ParentCastId(parent)) = &body.parent {
                    // The parent is checked when read; casts further up only
                    // notify once found in the stores, since a parent pointer
                    // can name any fid.
                    add(parent.fid, Kind::Reply);
                    let mut notified = vec![parent.fid];
                    let mut above = parent.clone();
                    for depth in 1..=THREAD_DEPTH {
                        let Some(up) = self.parent_of(&above) else {
                            break;
                        };
                        if depth > 1 && !notified.contains(&above.fid) {
                            notified.push(above.fid);
                            add(above.fid, Kind::DeepReply);
                        }
                        let Some(up) = up else { break };
                        above = up;
                    }
                }
            }
            (Ok(MessageType::ReactionAdd), Some(Body::ReactionBody(body))) => {
                if let Some(reaction_body::Target::TargetCastId(cast)) = &body.target {
                    add(cast.fid, Kind::Reaction);
                }
            }
            (Ok(MessageType::LinkAdd), Some(Body::LinkBody(body))) if body.r#type == "follow" => {
                if let Some(link_body::Target::TargetFid(fid)) = body.target {
                    add(fid, Kind::Follow);
                }
            }
            _ => {}
        }
        out
    }

    /// What `cast` replies to: `None` if the stores don't hold it (so it isn't
    /// really `cast.fid`'s), `Some(None)` if it's top-level.
    fn parent_of(&self, cast: &CastId) -> Option<Option<CastId>> {
        if self.stores.is_empty() {
            return None;
        }
        let shard = self.router.route_fid(cast.fid, self.stores.len() as u32);
        let stores = self.stores.get(&shard)?;
        let message = CastStore::get_cast_add(&stores.cast_store, cast.fid, cast.hash.clone())
            .ok()
            .flatten()?;
        Some(match message.data.and_then(|d| d.body) {
            Some(Body::CastAddBody(crate::proto::CastAddBody {
                parent: Some(cast_add_body::Parent::ParentCastId(parent)),
                ..
            })) => Some(parent),
            _ => None,
        })
    }

    /// A live (or replayed) message. A cast that's merged after replies to it
    /// (they reached their shard first) also completes those replies' thread
    /// notifications, which couldn't look past it when they were indexed. The
    /// walk doesn't need that: it reads stores that already hold every cast.
    fn process_message(
        &self,
        message: &Message,
        kind: MessageEventKind,
        txn: &mut RocksDbTransactionBatch,
    ) {
        match kind {
            // Pruning keeps the message in the hyper stores the API serves.
            MessageEventKind::Prune => {}
            MessageEventKind::Revoke => self.write(message, true, txn),
            MessageEventKind::Merge => {
                self.write(message, false, txn);
                if let Some(cast) = Self::cast_id(message) {
                    for reply in self.stored_replies(cast) {
                        self.write(&reply, false, txn);
                    }
                }
            }
        }
    }

    /// Put (or delete) the entries for everyone `message` notifies.
    fn write(&self, message: &Message, delete: bool, txn: &mut RocksDbTransactionBatch) {
        let Some(data) = &message.data else { return };
        if message.hash.len() != HASH_LEN {
            return;
        }
        for (fid, why) in self.targets(message) {
            let key = Self::key(fid, data.timestamp, &message.hash, why, data.fid);
            if delete {
                txn.delete(key);
            } else {
                txn.put(key, vec![]);
                self.items_indexed.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    fn cast_id(message: &Message) -> Option<CastId> {
        let data = message.data.as_ref()?;
        (data.r#type == MessageType::CastAdd as i32).then(|| CastId {
            fid: data.fid,
            hash: message.hash.clone(),
        })
    }

    /// Replies already in the stores under `cast`, down the levels a thread
    /// notifies, newest first and capped per level. Almost always none: a
    /// cast is usually merged before anyone can reply to it.
    fn stored_replies(&self, cast: CastId) -> Vec<Message> {
        let mut found = Vec::new();
        let mut level = vec![cast];
        for _ in 0..THREAD_DEPTH {
            let mut next: Vec<Message> = Vec::new();
            for parent in &level {
                let parent = cast_add_body::Parent::ParentCastId(parent.clone());
                for stores in self.stores.values() {
                    if let Ok(page) = CastStore::get_casts_by_parent(
                        &stores.cast_store,
                        &parent,
                        &PageOptions {
                            page_size: Some(REPLIES_PER_LEVEL),
                            page_token: None,
                            reverse: true,
                        },
                    ) {
                        next.extend(page.messages);
                    }
                }
                if next.len() >= REPLIES_PER_LEVEL {
                    break;
                }
            }
            if next.is_empty() {
                break;
            }
            next.truncate(REPLIES_PER_LEVEL);
            level = next.iter().filter_map(Self::cast_id).collect();
            found.extend(next);
        }
        found
    }

    fn commit(&self, txn: RocksDbTransactionBatch) -> Result<(), IndexerError> {
        if txn.len() == 0 {
            return Ok(());
        }
        self.db
            .commit(txn)
            .map_err(|e| IndexerError::Storage(e.to_string()))
    }

    fn user_prefix(fid: u64) -> Vec<u8> {
        [&[PREFIX, ENTRY][..], &fid.to_be_bytes()[..]].concat()
    }

    fn key(fid: u64, timestamp: u32, hash: &[u8], kind: Kind, actor: u64) -> Vec<u8> {
        let mut key = Self::user_prefix(fid);
        key.reserve(ENTRY_TAIL);
        key.extend_from_slice(&timestamp.to_be_bytes());
        key.extend_from_slice(hash);
        key.push(kind as u8);
        key.extend_from_slice(&actor.to_be_bytes());
        key
    }

    fn parse(key: &[u8]) -> Option<Entry> {
        let tail = key.get(10..).filter(|t| t.len() == ENTRY_TAIL)?;
        Some(Entry {
            timestamp: u32::from_be_bytes(tail[..4].try_into().ok()?),
            hash: tail[4..4 + HASH_LEN].try_into().ok()?,
            kind: Kind::from_u8(tail[4 + HASH_LEN])?,
            actor: u64::from_be_bytes(tail[5 + HASH_LEN..].try_into().ok()?),
        })
    }
}

/// Holds the walk to [`WALK_MESSAGES_PER_SEC`].
struct Pace {
    /// Messages walked in all.
    done: u64,
    since: Instant,
    since_done: u64,
}

impl Pace {
    fn new() -> Self {
        Self {
            done: 0,
            since: Instant::now(),
            since_done: 0,
        }
    }

    fn tick(&mut self, messages: usize) {
        self.done += messages as u64;
        self.since_done += messages as u64;
        let due = Duration::from_secs_f64(self.since_done as f64 / WALK_MESSAGES_PER_SEC);
        match due.checked_sub(self.since.elapsed()) {
            Some(wait) => std::thread::sleep(wait),
            // Behind (slow reads): no credit, so it never bursts to catch up.
            None => {
                self.since = Instant::now();
                self.since_done = 0;
            }
        }
    }
}

#[async_trait]
impl Indexer for NotificationsIndexer {
    fn name(&self) -> &'static str {
        "notifications_index"
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
            let messages = match event {
                IndexEvent::MessageCommitted { message, kind, .. } => {
                    self.process_message(message, *kind, &mut txn);
                    true
                }
                IndexEvent::MessagesCommitted { messages, kind, .. } => {
                    for message in messages {
                        self.process_message(message, *kind, &mut txn);
                    }
                    true
                }
                _ => false,
            };
            if let (true, Some(height)) = (messages, event.block_height()) {
                if height > 0 {
                    self.note_height(event.shard_id(), height, &mut txn);
                }
            }
        }
        self.commit(txn)
    }

    // Live writes are idempotent puts, and the replay after a restart goes by
    // block height (`indexed_heights`), so there's no event cursor to keep.
    fn last_checkpoint(&self) -> u64 {
        0
    }

    async fn save_checkpoint(&self, _event_id: u64) -> Result<(), IndexerError> {
        Ok(())
    }

    fn stats(&self) -> IndexerStats {
        IndexerStats {
            items_indexed: self.items_indexed.load(Ordering::Relaxed),
            backfill_complete: self.is_complete(),
            ..Default::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_round_trip_and_order() {
        let hash = [7u8; HASH_LEN];
        let key = NotificationsIndexer::key(1 << 33, 1234, &hash, Kind::DeepReply, 99);
        assert_eq!(
            NotificationsIndexer::parse(&key),
            Some(Entry {
                timestamp: 1234,
                hash,
                kind: Kind::DeepReply,
                actor: 99,
            })
        );
        // Newer sorts after older within a user, so a reverse scan is newest first.
        let older = NotificationsIndexer::key(5, 10, &[0xFF; HASH_LEN], Kind::Reaction, 1);
        let newer = NotificationsIndexer::key(5, 11, &[0x00; HASH_LEN], Kind::Reaction, 1);
        assert!(older < newer);
        assert!(NotificationsIndexer::user_prefix(5) < older);
        assert!(newer < increment_vec_u8(&NotificationsIndexer::user_prefix(5)));
    }

    /// The highest block indexed per shard survives a restart, so the blocks
    /// after it can be replayed.
    #[tokio::test]
    async fn test_indexed_heights_survive_a_restart() {
        use crate::utils::factory::messages_factory;
        let dir = tempfile::tempdir().unwrap();
        let open = || {
            let db = Arc::new(RocksDB::new(dir.path().to_str().unwrap()));
            db.open().unwrap();
            NotificationsIndexer::new(
                FeatureConfig {
                    enabled: true,
                    ..Default::default()
                },
                db,
                HashMap::new(),
            )
        };
        let index = open();
        let like = |fid| {
            messages_factory::reactions::create_reaction_add(
                fid,
                crate::proto::ReactionType::Like,
                reaction_body::Target::TargetCastId(CastId {
                    fid: 1,
                    hash: vec![9; HASH_LEN],
                }),
                None,
                None,
            )
        };
        for (shard, height) in [(2, 42), (2, 41), (1, 7)] {
            index
                .process_event(&IndexEvent::message(like(height), shard, height))
                .await
                .unwrap();
        }
        // Heights from the block backfill (0) don't count.
        index
            .process_event(&IndexEvent::message(like(3), 1, 0))
            .await
            .unwrap();
        drop(index);
        let reopened = open();
        assert_eq!(reopened.indexed_heights(), HashMap::from([(2, 42), (1, 7)]));
    }

    /// Bytes per entry on disk and write rate, for sizing the store walk.
    /// `cargo test --release --lib notifications_index_size -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn bench_notifications_index_size() {
        use rand::{Rng, SeedableRng};
        const ENTRIES: u64 = 2_000_000;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().to_str().unwrap().to_string();
        let db = RocksDB::new(&path);
        db.open().unwrap();
        let mut rng = rand::rngs::StdRng::seed_from_u64(1);
        let started = Instant::now();
        let mut txn = RocksDbTransactionBatch::new();
        for i in 0..ENTRIES {
            // Arriving in time order for random users, as a walk or live merges write them.
            let fid = rng.gen_range(1..200_000u64);
            let hash: [u8; HASH_LEN] = rng.gen();
            let kind = if rng.gen_bool(0.75) {
                Kind::Reaction
            } else {
                Kind::Reply
            };
            let actor = rng.gen_range(1..1_500_000u64);
            txn.put(
                NotificationsIndexer::key(fid, 1_000_000 + (i / 10) as u32, &hash, kind, actor),
                vec![],
            );
            if txn.len() >= COMMIT_EVERY {
                db.commit(std::mem::replace(&mut txn, RocksDbTransactionBatch::new()))
                    .unwrap();
            }
        }
        db.commit(txn).unwrap();
        let elapsed = started.elapsed();
        db.close();
        // Reopening flushes the write-ahead log into table files.
        let db = RocksDB::new(&path);
        db.open().unwrap();
        db.close();
        let sst: u64 = std::fs::read_dir(&path)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.path().extension().is_some_and(|x| x == "sst"))
            .map(|e| e.metadata().unwrap().len())
            .sum();
        eprintln!(
            "{ENTRIES} entries: {:.1} bytes/entry in table files, {:.0} entries/s written",
            sst as f64 / ENTRIES as f64,
            ENTRIES as f64 / elapsed.as_secs_f64()
        );
    }
}
