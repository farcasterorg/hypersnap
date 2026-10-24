//! The content replay (FIP §17.4). Snapchain prunes the messages over the
//! storage limits; Hypersnap keeps them. The genesis state of shard `s` is
//! the snapchain chunk history up to `H_s`, run again through the shard
//! engine with no pruning: each message is checked with the snapchain rules
//! of its chunk's version, revocations apply, and nothing is removed for
//! storage.
//!
//! The replay has its own DB, `<rocksdb_dir>/content-replay-<s>`. A read
//! node with `consensus.content_replay` runs it in the background behind the
//! committed chunks (`spawn_follower`). The genesis build completes it to
//! `H_s` (`pivot_boot::finish_content_replay`). It needs the chunks from the
//! first one.
//!
//! The Keccak trie of the replay is live from the first chunk, so the
//! genesis root is ready at `H_s`. `GetShadowRoots` reports it
//! (`replay_roots`), for the comparison before the pivot. The DB keeps only
//! its last chunk and prunes its hub events as it goes; the snapchain DB has
//! the chunk history.

use crate::proto::HubEvent;
use crate::proto::{FarcasterNetwork, ShardChunk};
use crate::storage::db::{PageOptions, RocksDB};
use crate::storage::store::account::HubEventStorageExt;
use crate::storage::store::engine::ShardEngine;
use crate::storage::store::shard::ShardStore;
use crate::storage::store::stores::StoreLimits;
use crate::storage::trie::merkle_trie::MerkleTrie;
use crate::utils::statsd_wrapper::StatsdClientWrapper;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tracing::{info, warn};

/// Chunks read from the snapchain DB at a time.
const BATCH: u64 = 100;
/// Chunks between two prunes of the replay DB's old chunks and events.
const PRUNE_INTERVAL: u64 = 1_000;

pub fn replay_db_path(rocksdb_dir: &Path, shard: u32) -> PathBuf {
    rocksdb_dir.join(format!("content-replay-{}", shard))
}

/// The replay DBs that this process has open, for `GetShadowRoots`.
pub type ReplayDbs = Arc<RwLock<BTreeMap<u32, Arc<RocksDB>>>>;

fn chunk_height(chunk: &ShardChunk) -> Option<u64> {
    Some(chunk.header.as_ref()?.height?.block_number)
}

pub struct ContentReplay {
    engine: ShardEngine,
    db: Arc<RocksDB>,
    shard: u32,
    last: Option<ShardChunk>,
}

impl ContentReplay {
    pub async fn open(
        rocksdb_dir: &Path,
        shard: u32,
        network: FarcasterNetwork,
        statsd: StatsdClientWrapper,
    ) -> Result<ContentReplay, String> {
        let path = replay_db_path(rocksdb_dir, shard);
        let db = Arc::new(RocksDB::new(path.to_str().ok_or("the path is not UTF-8")?));
        db.open()
            .map_err(|e| format!("{}: {}", path.display(), e))?;
        let mut engine = ShardEngine::new(
            db.clone(),
            network,
            MerkleTrie::new().map_err(|e| e.to_string())?,
            shard,
            StoreLimits::default(),
            statsd,
            0,
            None,
            None,
            None,
        )
        .await
        .map_err(|e| e.to_string())?;
        engine.enter_content_replay().map_err(|e| e.to_string())?;
        let last = engine.get_last_shard_chunk();
        Ok(ContentReplay {
            engine,
            db,
            shard,
            last,
        })
    }

    /// The height of the last replayed chunk (0: none yet).
    pub fn height(&self) -> u64 {
        self.last.as_ref().and_then(chunk_height).unwrap_or(0)
    }

    /// The hash of the last replayed chunk.
    pub fn last_hash(&self) -> Option<&[u8]> {
        self.last.as_ref().map(|c| c.hash.as_slice())
    }

    pub fn db(&self) -> Arc<RocksDB> {
        self.db.clone()
    }

    pub fn stores(&self) -> crate::storage::store::stores::Stores {
        self.engine.get_stores()
    }

    pub fn close(self) {
        let ContentReplay { engine, db, .. } = self;
        drop(engine);
        db.close();
    }

    /// Replay the chunks of `source` after `height()`, up to `to`, with no
    /// gap. The source chunks are the ones this node committed; the genesis
    /// build checks the hash of the chunk at `H_s`.
    pub async fn replay_to(&mut self, source: &ShardStore, to: u64) -> Result<(), String> {
        if self.height() == 0 && to > 0 {
            let first = source.min_block_number().map_err(|e| e.to_string())?;
            if first > 1 {
                return Err(format!(
                    "the snapchain DB of shard {} starts at chunk {}: the content replay needs \
                     the chunks from the first one",
                    self.shard, first
                ));
            }
        }
        while self.height() < to {
            let from = self.height() + 1;
            let end = (from + BATCH - 1).min(to);
            let chunks = source
                .get_shard_chunks(from, Some(end + 1))
                .map_err(|e| e.to_string())?;
            let mut applied = false;
            for chunk in chunks
                .iter()
                .filter(|c| chunk_height(c).is_some_and(|h| h <= end))
            {
                let height = chunk_height(chunk).unwrap_or(0);
                if height != self.height() + 1 {
                    return Err(format!(
                        "shard {}: chunk {} is missing from the snapchain DB",
                        self.shard,
                        self.height() + 1
                    ));
                }
                self.engine
                    .commit_replayed_chunk(chunk)
                    .await
                    .map_err(|e| format!("shard {} chunk {}: {}", self.shard, height, e))?;
                self.last = Some(chunk.clone());
                applied = true;
                if height % PRUNE_INTERVAL == 0 {
                    self.prune(height).await?;
                }
                tokio::task::yield_now().await;
            }
            if !applied {
                return Err(format!(
                    "shard {}: chunk {} is missing from the snapchain DB",
                    self.shard, from
                ));
            }
        }
        Ok(())
    }

    /// Remove the chunks and hub events below `height`.
    async fn prune(&self, height: u64) -> Result<(), String> {
        let page = PageOptions {
            page_size: Some(crate::storage::constants::PAGE_SIZE_MAX),
            ..Default::default()
        };
        ShardStore::new(self.db.clone(), self.shard)
            .prune_until(height, &page, Duration::ZERO)
            .await
            .map_err(|e| e.to_string())?;
        HubEvent::prune_events_util(self.db.clone(), height, &page, Duration::ZERO)
            .await
            .map_err(|e| e.to_string())?;
        Ok(())
    }
}

/// A read node with `consensus.content_replay`: replay each committed chunk
/// of `source` in the background. A failure stops the replay of this shard
/// for the run; the genesis build tries again.
pub fn spawn_follower(
    rocksdb_dir: PathBuf,
    shard: u32,
    network: FarcasterNetwork,
    source: ShardStore,
    statsd: StatsdClientWrapper,
    dbs: ReplayDbs,
) {
    tokio::spawn(async move {
        let mut replay = match ContentReplay::open(&rocksdb_dir, shard, network, statsd).await {
            Ok(r) => r,
            Err(e) => {
                warn!(shard, "Content replay not started: {}", e);
                return;
            }
        };
        dbs.write().unwrap().insert(shard, replay.db());
        info!(
            shard,
            height = replay.height(),
            "Content replay follows the snapchain chunks"
        );
        loop {
            let tip = source.max_block_number().unwrap_or(0);
            if tip > replay.height() {
                if let Err(e) = replay.replay_to(&source, tip).await {
                    warn!(shard, "Content replay stopped: {}", e);
                    return;
                }
            } else {
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        }
    });
}
