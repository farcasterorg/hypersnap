//! Shadow Keccak state trie of a shard (plan R0, FIP §17.5 "Preparation in
//! epoch 0").
//!
//! Before the pivot, a read node keeps one Keccak trie per shard beside the
//! blake3 sync trie. It holds the same keys as the sync trie, with the values
//! of `shadow_entries` (FIP §16.13 table). At the fork block, its root is the
//! genesis state root of the shard. Until then it is diagnostic only: nodes
//! compare their roots, and the update cost is measured at mainnet scale.
//!
//! The trie records live in the shard DB under `RootPrefix::KeccakTrieNode`.
//! A status record under `RootPrefix::KeccakTrieMeta` says whether the trie is
//! complete and up to which chunk height:
//!
//! * `Building { snapshot_height }`: a backfill is copying the state as of
//!   `snapshot_height` into the trie. The records are partial; after a restart
//!   they are cleared and the build starts again. Commits do not touch them.
//! * `Built { height }`: the records match the state after chunk `height`,
//!   and a catch-up (or the engine, when the gap is small) replays the hub
//!   events after it.
//! * `Live { height }`: the trie matches the shard state after chunk `height`.
//!   Every commit applies its hub events, in the same RocksDB batch as the
//!   chunk.

use super::shadow_entries::ShadowEntries;
use crate::proto;
use crate::storage::constants::RootPrefix;
use crate::storage::db::{RocksDB, RocksDbTransactionBatch};
use hypersnap_ktrie::{CommitBatch, KTrie, NodeKey, NodeStore, StoreError, TrieError};
use std::sync::Arc;

const META_KEY: [u8; 2] = [RootPrefix::KeccakTrieMeta as u8, 0];
/// `[141][1][height_be] -> root(32) || leaf_count(u64 BE)`, every
/// `HISTORY_INTERVAL` chunk heights, so nodes can compare roots at the same
/// height.
const HISTORY_TAG: u8 = 1;
pub const HISTORY_INTERVAL: u64 = 1_000;

fn history_key(height: u64) -> Vec<u8> {
    let mut k = vec![RootPrefix::KeccakTrieMeta as u8, HISTORY_TAG];
    k.extend_from_slice(&height.to_be_bytes());
    k
}

/// Root and leaf count recorded at `height`, if `height` is a multiple of
/// `HISTORY_INTERVAL` that the live trie passed.
pub fn root_at(db: &RocksDB, height: u64) -> Option<([u8; 32], u64)> {
    let bytes = db.get(&history_key(height)).ok()??;
    if bytes.len() != 40 {
        return None;
    }
    let mut root = [0u8; 32];
    root.copy_from_slice(&bytes[..32]);
    Some((root, u64::from_be_bytes(bytes[32..].try_into().ok()?)))
}

/// Root, leaf count and status of the trie of a shard, read from the DB
/// (no access to the engine needed).
pub fn report_from_db(db: Arc<RocksDB>) -> Result<ShadowRootReport, ShadowTrieError> {
    let status = ShadowStatus::read(&db);
    let trie = KTrie::open(RocksNodeStore::new(db))?;
    Ok(ShadowRootReport {
        status,
        root: trie.committed_root(),
        leaf_count: trie.len(),
    })
}

fn node_db_key(key: &NodeKey) -> Vec<u8> {
    let mut out = Vec::with_capacity(40);
    out.push(RootPrefix::KeccakTrieNode as u8);
    key.encode_into(&mut out);
    out
}

/// `NodeStore` over the shard RocksDB. Reads go to the DB; the trie serves
/// uncommitted and staged records itself. Writes normally reach the DB as
/// part of the chunk batch (`stage_into`), not through `put`/`delete`.
pub struct RocksNodeStore {
    db: Arc<RocksDB>,
}

impl RocksNodeStore {
    pub fn new(db: Arc<RocksDB>) -> Self {
        RocksNodeStore { db }
    }
}

impl NodeStore for RocksNodeStore {
    fn get(&self, key: &NodeKey) -> Result<Option<Vec<u8>>, StoreError> {
        self.db.get(&node_db_key(key)).map_err(StoreError::new)
    }

    fn put(&mut self, key: &NodeKey, value: &[u8]) -> Result<(), StoreError> {
        self.db
            .put(&node_db_key(key), value)
            .map_err(StoreError::new)
    }

    fn delete(&mut self, key: &NodeKey) -> Result<(), StoreError> {
        self.db.del(&node_db_key(key)).map_err(StoreError::new)
    }

    fn apply(&mut self, batch: &CommitBatch) -> Result<(), StoreError> {
        let mut txn = RocksDbTransactionBatch::new();
        stage_into(batch, &mut txn);
        self.db.commit(txn).map_err(StoreError::new)
    }
}

/// Copy the trie writes of `batch` into a RocksDB batch.
pub fn stage_into(batch: &CommitBatch, txn: &mut RocksDbTransactionBatch) {
    for (key, value) in &batch.writes {
        match value {
            Some(v) => txn.put(node_db_key(key), v.clone()),
            None => txn.delete(node_db_key(key)),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShadowStatus {
    /// No trie and no backfill yet.
    Absent,
    Building {
        snapshot_height: u64,
    },
    Built {
        height: u64,
    },
    Live {
        height: u64,
    },
}

impl ShadowStatus {
    fn encode(&self) -> Vec<u8> {
        match self {
            ShadowStatus::Absent => vec![0],
            ShadowStatus::Building { snapshot_height } => {
                let mut v = vec![1];
                v.extend_from_slice(&snapshot_height.to_be_bytes());
                v
            }
            ShadowStatus::Live { height } => {
                let mut v = vec![2];
                v.extend_from_slice(&height.to_be_bytes());
                v
            }
            ShadowStatus::Built { height } => {
                let mut v = vec![3];
                v.extend_from_slice(&height.to_be_bytes());
                v
            }
        }
    }

    fn decode(bytes: &[u8]) -> Option<ShadowStatus> {
        let height = |b: &[u8]| -> Option<u64> { Some(u64::from_be_bytes(b.try_into().ok()?)) };
        match bytes.first()? {
            0 => Some(ShadowStatus::Absent),
            1 => Some(ShadowStatus::Building {
                snapshot_height: height(&bytes[1..])?,
            }),
            2 => Some(ShadowStatus::Live {
                height: height(&bytes[1..])?,
            }),
            3 => Some(ShadowStatus::Built {
                height: height(&bytes[1..])?,
            }),
            _ => None,
        }
    }

    pub fn read(db: &RocksDB) -> ShadowStatus {
        match db.get(&META_KEY) {
            Ok(Some(bytes)) => ShadowStatus::decode(&bytes).unwrap_or(ShadowStatus::Absent),
            _ => ShadowStatus::Absent,
        }
    }

    pub fn stage(&self, txn: &mut RocksDbTransactionBatch) {
        txn.put(META_KEY.to_vec(), self.encode());
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ShadowTrieError {
    #[error("shadow trie: {0}")]
    Trie(String),
}

impl From<TrieError> for ShadowTrieError {
    fn from(e: TrieError) -> Self {
        ShadowTrieError::Trie(format!("{:?}", e))
    }
}

/// Root, size and status of a shadow trie, for the diagnostics endpoint.
#[derive(Clone, Debug)]
pub struct ShadowRootReport {
    pub status: ShadowStatus,
    pub root: [u8; 32],
    pub leaf_count: u64,
}

pub struct ShadowTrie {
    trie: KTrie<RocksNodeStore>,
    status: ShadowStatus,
}

impl ShadowTrie {
    pub fn open(db: Arc<RocksDB>) -> Result<ShadowTrie, ShadowTrieError> {
        let status = ShadowStatus::read(&db);
        let trie = KTrie::open(RocksNodeStore::new(db))?;
        Ok(ShadowTrie { trie, status })
    }

    pub fn status(&self) -> ShadowStatus {
        self.status
    }

    pub fn report(&self) -> ShadowRootReport {
        ShadowRootReport {
            status: self.status,
            root: self.trie.committed_root(),
            leaf_count: self.trie.len(),
        }
    }

    /// Re-read the trie and the status after a backfill finished or after
    /// a crash. Pending and staged records that were not persisted go away.
    pub fn reload(&mut self, db: &RocksDB) -> Result<(), ShadowTrieError> {
        self.trie.reload()?;
        self.status = ShadowStatus::read(db);
        Ok(())
    }

    /// Apply the trie updates of `events` without committing them.
    pub fn apply_events(&mut self, events: &[proto::HubEvent]) -> Result<(), ShadowTrieError> {
        self.apply_events_and_ops(events, &[])
    }

    /// Apply the trie updates of `events`, then the raw `(key, value)` ops
    /// (Hypersnap shards 1 and 2: replica records, fee charges, content
    /// fingerprints; FIP §16.13), without committing them.
    pub fn apply_events_and_ops(
        &mut self,
        events: &[proto::HubEvent],
        raw: &[(Vec<u8>, Option<Vec<u8>>)],
    ) -> Result<(), ShadowTrieError> {
        let mut ops: Vec<(Vec<u8>, Option<Vec<u8>>)> = Vec::new();
        for event in events {
            let entries = ShadowEntries::for_hub_event(event);
            for (key, value) in entries.inserts {
                ops.push((key, Some(value)));
            }
            for key in entries.deletes {
                ops.push((key, None));
            }
        }
        ops.extend(raw.iter().cloned());
        self.trie.apply(ops)?;
        Ok(())
    }

    /// Commit path of a live trie: apply the chunk's events and stage the
    /// trie writes and the new status into the chunk batch. Does nothing
    /// unless the trie is live. The caller commits `txn` before the next
    /// call (the trie serves the staged records until then).
    pub fn stage_chunk(
        &mut self,
        events: &[proto::HubEvent],
        height: u64,
        txn: &mut RocksDbTransactionBatch,
    ) -> Result<Option<[u8; 32]>, ShadowTrieError> {
        self.stage_chunk_with_ops(events, &[], height, txn)
    }

    pub fn stage_chunk_with_ops(
        &mut self,
        events: &[proto::HubEvent],
        raw: &[(Vec<u8>, Option<Vec<u8>>)],
        height: u64,
        txn: &mut RocksDbTransactionBatch,
    ) -> Result<Option<[u8; 32]>, ShadowTrieError> {
        match self.status {
            ShadowStatus::Live { height: last } if height > last => {}
            _ => return Ok(None),
        }
        self.apply_events_and_ops(events, raw)?;
        Ok(Some(self.commit_live(height, txn)))
    }

    fn commit_live(&mut self, height: u64, txn: &mut RocksDbTransactionBatch) -> [u8; 32] {
        let batch = self.trie.commit();
        stage_into(&batch, txn);
        self.status = ShadowStatus::Live { height };
        self.status.stage(txn);
        if height % HISTORY_INTERVAL == 0 {
            let mut v = batch.root.to_vec();
            v.extend_from_slice(&batch.len.to_be_bytes());
            txn.put(history_key(height), v);
        }
        batch.root
    }

    /// Hand-off from a finished backfill (`Built { height < chunk }`): apply
    /// the persisted events after the built height (`replay`), then this
    /// chunk's events, and go live at `height`.
    pub fn go_live(
        &mut self,
        replay: &[proto::HubEvent],
        events: &[proto::HubEvent],
        height: u64,
        txn: &mut RocksDbTransactionBatch,
    ) -> Result<Option<[u8; 32]>, ShadowTrieError> {
        match self.status {
            ShadowStatus::Built { height: built } if built < height => {}
            _ => return Ok(None),
        }
        self.apply_events(replay)?;
        self.apply_events(events)?;
        Ok(Some(self.commit_live(height, txn)))
    }

    /// Root after `events`, without keeping them: apply, read the root, roll
    /// back. Proposers and validators use it before the block commits.
    pub fn root_with(&mut self, events: &[proto::HubEvent]) -> Result<[u8; 32], ShadowTrieError> {
        self.root_with_ops(events, &[])
    }

    pub fn root_with_ops(
        &mut self,
        events: &[proto::HubEvent],
        raw: &[(Vec<u8>, Option<Vec<u8>>)],
    ) -> Result<[u8; 32], ShadowTrieError> {
        let result = self
            .apply_events_and_ops(events, raw)
            .map(|_| self.trie.root());
        self.trie.rollback();
        result
    }

    /// Mark an empty or fully built trie live at `height` (Hypersnap genesis).
    pub fn mark_live(&mut self, height: u64, txn: &mut RocksDbTransactionBatch) {
        self.status = ShadowStatus::Live { height };
        self.status.stage(txn);
    }

    /// Mutable access for the backfill.
    pub fn trie_mut(&mut self) -> &mut KTrie<RocksNodeStore> {
        &mut self.trie
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::factory::{hub_events_factory, messages_factory};

    fn open_db() -> (Arc<RocksDB>, tempfile::TempDir) {
        let dir = tempfile::TempDir::new().unwrap();
        let db = RocksDB::new(dir.path().join("shard").to_str().unwrap());
        db.open().unwrap();
        (Arc::new(db), dir)
    }

    #[test]
    fn status_round_trip() {
        for s in [
            ShadowStatus::Absent,
            ShadowStatus::Building { snapshot_height: 7 },
            ShadowStatus::Built { height: 9 },
            ShadowStatus::Live { height: u64::MAX },
        ] {
            assert_eq!(ShadowStatus::decode(&s.encode()), Some(s));
        }
    }

    #[test]
    fn live_trie_follows_commits_and_survives_reopen() {
        let (db, _dir) = open_db();
        // Mark the (empty) trie live at height 0, as a backfill of an empty
        // shard would.
        let mut txn = RocksDbTransactionBatch::new();
        ShadowStatus::Live { height: 0 }.stage(&mut txn);
        db.commit(txn).unwrap();

        let mut shadow = ShadowTrie::open(db.clone()).unwrap();
        let cast = messages_factory::casts::create_cast_add(9, "a", None, None);
        let remove = messages_factory::casts::create_cast_remove(9, &cast.hash, None, None);

        let mut txn = RocksDbTransactionBatch::new();
        let root1 = shadow
            .stage_chunk(
                &[hub_events_factory::create_merge_event(&cast)],
                1,
                &mut txn,
            )
            .unwrap()
            .unwrap();
        db.commit(txn).unwrap();
        assert_ne!(root1, [0u8; 32]);

        // A stale height is ignored.
        let mut txn = RocksDbTransactionBatch::new();
        assert!(shadow
            .stage_chunk(
                &[hub_events_factory::create_merge_event(&remove)],
                1,
                &mut txn
            )
            .unwrap()
            .is_none());

        // The remove replaces the add: the cast key is deleted, the remove
        // key is inserted.
        let event = proto::HubEvent {
            body: Some(proto::hub_event::Body::MergeMessageBody(
                proto::MergeMessageBody {
                    message: Some(remove.clone()),
                    deleted_messages: vec![cast.clone()],
                },
            )),
            ..Default::default()
        };
        let mut txn = RocksDbTransactionBatch::new();
        let root2 = shadow.stage_chunk(&[event], 2, &mut txn).unwrap().unwrap();
        db.commit(txn).unwrap();
        assert_ne!(root2, root1);

        // Same key set built from scratch gives the same root.
        let (db2, _dir2) = open_db();
        let mut fresh = ShadowTrie::open(db2).unwrap();
        fresh
            .apply_events(&[hub_events_factory::create_merge_event(&remove)])
            .unwrap();
        assert_eq!(fresh.trie_mut().root(), root2);

        // Reopen: same root and status from the DB.
        let reopened = ShadowTrie::open(db.clone()).unwrap();
        assert_eq!(reopened.report().root, root2);
        assert_eq!(reopened.status(), ShadowStatus::Live { height: 2 });
        assert_eq!(reopened.report().leaf_count, 1);
    }
}
