//! Epoch boundary checkpoints (FIP §17.7, plan A4).
//!
//! Shard `s` gives its epoch inputs from its state after its last block of
//! the previous epoch; shard 0 from its state after the boundary block. A
//! node takes a RocksDB checkpoint (hard-linked SST files) of each at that
//! point. PoQ (FIP §8) and the DA proofs (FIP §5.2) read the checkpoints, so
//! the inputs are the same on all nodes and survive a restart. A node deletes
//! a checkpoint after the scoring window and the DA window close.

use crate::chain::shard0::work::DaCheckpoints;
use crate::proto::FarcasterNetwork;
use crate::storage::db::{RocksDB, SnapchainDbOptimizationType};
use crate::storage::store::stores::{StoreLimits, Stores};
use crate::storage::trie::key_resolver::TrieKeyResolver;
use crate::storage::trie::merkle_trie::MerkleTrie;
use crate::storage::trie::shadow_trie::RocksNodeStore;
use hypersnap_ktrie::KTrie;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tracing::{error, info};

pub struct Checkpoints {
    root: PathBuf,
    network: FarcasterNetwork,
    /// The checkpoints opened so far, by (shard, epoch). A DA answer and its
    /// check read one checkpoint many times.
    opened: Mutex<HashMap<(u32, u64), Arc<RocksDB>>>,
    /// The block cache of the node. An open checkpoint keeps the index and
    /// filter blocks of its SST files in it: without it they stay in memory
    /// for as long as the checkpoint is open (about 0.3% of its size).
    block_cache: Option<rocksdb::Cache>,
}

impl Checkpoints {
    pub fn new(root: impl Into<PathBuf>, network: FarcasterNetwork) -> Self {
        Checkpoints {
            root: root.into(),
            network,
            opened: Mutex::new(HashMap::new()),
            block_cache: None,
        }
    }

    pub fn with_block_cache(mut self, cache: rocksdb::Cache) -> Self {
        self.block_cache = Some(cache);
        self
    }

    /// The checkpoint of `shard` for the boundary of `epoch`.
    pub fn path(&self, shard: u32, epoch: u64) -> PathBuf {
        self.root
            .join(format!("shard{}", shard))
            .join(format!("boundary{}", epoch))
    }

    pub fn exists(&self, shard: u32, epoch: u64) -> bool {
        self.path(shard, epoch).join("CURRENT").exists()
    }

    /// Take the checkpoint, if this node does not have it. RocksDB writes
    /// it to a temporary directory and renames it, so a crash leaves no
    /// partial checkpoint.
    pub fn take(&self, db: &RocksDB, shard: u32, epoch: u64) -> Result<(), String> {
        if self.exists(shard, epoch) {
            return Ok(());
        }
        let path = self.path(shard, epoch);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        // A directory without CURRENT is a partial copy from an older
        // release: start again.
        if path.exists() {
            std::fs::remove_dir_all(&path).map_err(|e| e.to_string())?;
        }
        db.create_checkpoint(path.to_str().unwrap())
            .map_err(|e| e.to_string())?;
        info!(shard, epoch, "Took epoch boundary checkpoint");
        Ok(())
    }

    /// The checkpoint as a read-only DB.
    pub fn open(&self, shard: u32, epoch: u64) -> Option<Arc<RocksDB>> {
        let mut opened = self.opened.lock().unwrap();
        if let Some(db) = opened.get(&(shard, epoch)) {
            return Some(db.clone());
        }
        if !self.exists(shard, epoch) {
            return None;
        }
        match RocksDB::new_with_cache(
            self.path(shard, epoch).to_str().unwrap(),
            SnapchainDbOptimizationType::Default,
            self.block_cache.clone(),
        )
        .open_read_only()
        {
            Ok(db) => {
                let db = Arc::new(db);
                opened.insert((shard, epoch), db.clone());
                Some(db)
            }
            Err(e) => {
                error!(shard, epoch, "Cannot open checkpoint: {}", e);
                None
            }
        }
    }

    /// Delete the checkpoints of boundaries before `epoch`.
    pub fn prune_before(&self, epoch: u64) {
        self.opened.lock().unwrap().retain(|(_, e), _| *e >= epoch);
        let Ok(shards) = std::fs::read_dir(&self.root) else {
            return;
        };
        for shard in shards.flatten() {
            let Ok(entries) = std::fs::read_dir(shard.path()) else {
                continue;
            };
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if let Some(e) = name
                    .strip_prefix("boundary")
                    .and_then(|n| n.parse::<u64>().ok())
                {
                    if e < epoch {
                        let _ = std::fs::remove_dir_all(entry.path());
                    }
                }
            }
        }
    }

    /// The leaf at or after `target_path` (FIP §5.1; the first leaf if there
    /// is none after it).
    fn first_leaf<S: hypersnap_ktrie::NodeStore>(
        trie: &KTrie<S>,
        target_path: &[u8; 32],
    ) -> Option<hypersnap_ktrie::LeafEntry> {
        match trie.first_at_or_after(target_path).ok()? {
            Some(l) => Some(l),
            None => trie.first_at_or_after(&[0u8; 32]).ok()?,
        }
    }

    /// The leaf at or after `target_path` in the state trie of the
    /// checkpoint (FIP §5.1; the first leaf if there is none after it), with
    /// its value, the encoded inclusion proof and the root.
    pub fn challenged_leaf(
        &self,
        epoch: u64,
        shard: u32,
        target_path: &[u8; 32],
    ) -> Option<ChallengedLeaf> {
        let db = self.open(shard, epoch)?;
        let trie = KTrie::open(RocksNodeStore::new(db.clone())).ok()?;
        let leaf = Self::first_leaf(&trie, target_path)?;
        // A `RootPrefix` record is in the trie as its storage key and stored
        // bytes. A snapchain trie key names an object in the stores. Its
        // first byte is a virtual shard, so it can look like a prefix, and
        // the leaf's value hash decides.
        let stored = db
            .get(&leaf.key)
            .ok()?
            .filter(|v| hypersnap_ktrie::value_hash(v) == leaf.value_hash);
        let value = if let Some(v) = stored {
            v
        } else if shard == 0 {
            return None;
        } else {
            let stores = Stores::new(
                db.clone(),
                shard,
                MerkleTrie::new().ok()?,
                StoreLimits::default(),
                self.network,
                crate::utils::statsd_wrapper::StatsdClientWrapper::new(
                    cadence::StatsdClient::builder("", cadence::NopMetricSink {}).build(),
                    false,
                ),
            );
            let mut resolver = TrieKeyResolver::for_one_leaf(&stores);
            let v = resolver.resolve(&leaf.key).ok()??.state_value();
            (hypersnap_ktrie::value_hash(&v) == leaf.value_hash).then_some(v)?
        };
        let proof = trie.prove(&leaf.key).ok()?.encode();
        Some(ChallengedLeaf {
            key: leaf.key,
            value,
            proof,
            root: trie.committed_root(),
        })
    }
}

pub struct ChallengedLeaf {
    pub key: Vec<u8>,
    pub value: Vec<u8>,
    pub proof: Vec<u8>,
    pub root: [u8; 32],
}

impl DaCheckpoints for Checkpoints {
    /// From the trie only: resolving the value of a snapchain leaf reads all
    /// the messages of its FID and type.
    fn expected_leaf(
        &self,
        epoch: u64,
        shard_id: u32,
        target_path: &[u8; 32],
    ) -> Option<(Vec<u8>, [u8; 32], [u8; 32])> {
        let db = self.open(shard_id, epoch)?;
        let trie = KTrie::open(RocksNodeStore::new(db)).ok()?;
        let leaf = Self::first_leaf(&trie, target_path)?;
        Some((leaf.key, leaf.value_hash, trie.committed_root()))
    }
}
