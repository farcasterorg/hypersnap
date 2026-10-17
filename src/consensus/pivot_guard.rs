//! Shard hold-back before the epoch-1 pivot (FIP-proof-of-work-tokenization
//! §17.2, plan A6a / WS8.2).
//!
//! The fork height `H_s` of shard `s` is the highest shard-`s` chunk that the
//! fork block (shard-0 height `PIVOT_HEIGHT − 1`) or an earlier shard-0 block
//! witnesses. A read node syncs each shard on its own, so without a guard a
//! shard can commit chunks above `H_s` before shard 0 reaches the fork block,
//! and there is no rollback for that.
//!
//! The guard: once a release sets `PIVOT_HEIGHT` for the network, a shard-1/2
//! chunk commits only after a committed shard-0 block witnesses it. Shard 0
//! stops at the fork block, so no chunk above `H_s` is ever witnessed and no
//! shard can overshoot.
//!
//! The guard is on for the whole run of such a release, not for a window
//! before the pivot: a node that catches up can have a shard far ahead of
//! shard 0, and a window keyed on the shard-0 height would open too late. In
//! normal operation the cost is the time until the next shard-0 block
//! witnesses the chunk.
//!
//! When shard 0 has applied the fork block and every shard is at its fork
//! height, the node persists the pivot marker and stops (FIP §17.5 steps
//! 1-4). A shard that is behind keeps syncing up to its fork height first.

use crate::proto::{PivotRecord, ShardForkPoint};
use crate::storage::constants::RootPrefix;
use crate::storage::db::RocksDB;
use crate::storage::store::block::BlockStore;
use crate::storage::store::node_local_state::DataType;
use prost::Message as _;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use tracing::warn;

fn marker_key() -> Vec<u8> {
    vec![
        RootPrefix::NodeLocalState as u8,
        DataType::PivotMarker as u8,
    ]
}

/// The pivot marker (FIP §17.5 step 4): the fork block and the fork point of
/// each shard, as a partial `PivotRecord`. A node that finds it at start-up
/// starts as a Hypersnap node.
pub fn write_marker(db: &RocksDB, marker: &PivotRecord) -> Result<(), String> {
    db.put(&marker_key(), &marker.encode_to_vec())
        .map_err(|e| e.to_string())
}

pub fn read_marker(db: &RocksDB) -> Option<PivotRecord> {
    let bytes = db.get(&marker_key()).ok()??;
    PivotRecord::decode(bytes.as_slice()).ok()
}

/// Remove a marker of an abandoned pivot (FIP §17.8).
pub fn delete_marker(db: &RocksDB) -> Result<(), String> {
    db.del(&marker_key()).map_err(|e| e.to_string())
}

/// Per-network pivot parameters that are fixed in a release.
pub mod params {
    use crate::proto::FarcasterNetwork;

    /// Snapchain shard-0 height of the shard-0 pivot block (§17.2). `None`
    /// until a release fixes it for the network.
    pub fn pivot_height(network: FarcasterNetwork) -> Option<u64> {
        match network {
            FarcasterNetwork::Mainnet => None,
            FarcasterNetwork::Testnet => None,
            FarcasterNetwork::Devnet => None,
            FarcasterNetwork::None => None,
        }
    }

    /// `GENESIS_VALIDATORS_HASH` (§17.3): keccak256 of the encoded genesis
    /// validator file. `None` until a release fixes it for the network.
    pub fn genesis_validators_hash(network: FarcasterNetwork) -> Option<[u8; 32]> {
        match network {
            FarcasterNetwork::Mainnet => None,
            FarcasterNetwork::Testnet => None,
            FarcasterNetwork::Devnet => None,
            FarcasterNetwork::None => None,
        }
    }

    /// The pivot height in effect: `override_height` if it is not 0
    /// (rehearsals and devnets), else the release value.
    pub fn effective_pivot_height(network: FarcasterNetwork, override_height: u64) -> Option<u64> {
        if override_height > 0 {
            Some(override_height)
        } else {
            pivot_height(network)
        }
    }
}

#[derive(Clone)]
pub struct PivotGuard {
    pivot_height: u64,
    blocks: BlockStore,
    /// The shards other than 0 that this node syncs.
    shards: Vec<u32>,
    /// The committed height of each shard, as its read validator reports it.
    heights: Arc<Mutex<BTreeMap<u32, u64>>>,
}

impl PivotGuard {
    pub fn new(pivot_height: u64, blocks: BlockStore, shards: Vec<u32>) -> Self {
        PivotGuard {
            pivot_height,
            blocks,
            shards,
            heights: Default::default(),
        }
    }

    /// The shard-0 DB, where the marker goes.
    pub fn db(&self) -> &RocksDB {
        &self.blocks.db
    }

    pub fn pivot_height(&self) -> u64 {
        self.pivot_height
    }

    /// Height of the highest shard-`shard_id` chunk that a committed shard-0
    /// block witnesses. Each block witnesses the latest chunk of every shard,
    /// so the last committed block gives the maximum.
    pub fn witnessed_height(&self, shard_id: u32) -> Option<u64> {
        let block = match self.blocks.get_last_block() {
            Ok(Some(block)) => block,
            Ok(None) => return None,
            Err(e) => {
                warn!(
                    shard_id,
                    "pivot guard: cannot read the last shard-0 block: {}", e
                );
                return None;
            }
        };
        block
            .shard_witness
            .as_ref()?
            .shard_chunk_witnesses
            .iter()
            .filter_map(|w| w.height)
            .filter(|h| h.shard_index == shard_id)
            .map(|h| h.block_number)
            .max()
    }

    /// The fork block is shard-0 height `PIVOT_HEIGHT − 1` (FIP §17.2).
    pub fn fork_height(&self) -> u64 {
        self.pivot_height.saturating_sub(1)
    }

    /// The fork points from the last committed shard-0 block (the fork
    /// block, after it commits).
    pub fn fork_points(&self, shards: &[u32]) -> Vec<ShardForkPoint> {
        let Ok(Some(block)) = self.blocks.get_last_block() else {
            return vec![];
        };
        let witnesses = block
            .shard_witness
            .map(|w| w.shard_chunk_witnesses)
            .unwrap_or_default();
        shards
            .iter()
            .filter_map(|&s| {
                witnesses
                    .iter()
                    .filter(|w| w.height.is_some_and(|h| h.shard_index == s))
                    .max_by_key(|w| w.height.unwrap().block_number)
                    .map(|w| ShardForkPoint {
                        shard_id: s,
                        fork_height: w.height.unwrap().block_number,
                        chunk_hash: w.shard_hash.clone(),
                    })
            })
            .collect()
    }

    /// Record that shard `shard_id` is at `height`. Returns the marker when
    /// the pivot is ready: shard 0 has applied the fork block and every shard
    /// is at its fork height.
    pub fn record_height(&self, shard_id: u32, height: u64) -> Option<PivotRecord> {
        let heights = {
            let mut heights = self.heights.lock().unwrap();
            heights.insert(shard_id, height);
            heights.clone()
        };
        let fork = match self.blocks.get_last_block() {
            Ok(Some(b)) if b.header.as_ref()?.height?.block_number == self.fork_height() => b,
            _ => return None,
        };
        let points = self.fork_points(&self.shards);
        if points.len() != self.shards.len() {
            return None;
        }
        if points
            .iter()
            .any(|p| heights.get(&p.shard_id).copied() != Some(p.fork_height))
        {
            return None;
        }
        Some(PivotRecord {
            pivot_height: self.pivot_height,
            fork_block_hash: fork.hash,
            shard_forks: points,
            ..Default::default()
        })
    }

    /// True if shard `shard_id` may commit its chunk at `chunk_height` now.
    /// Shard 0 applies no block after the fork block (FIP §17.5 step 1).
    pub fn allows(&self, shard_id: u32, chunk_height: u64) -> bool {
        if shard_id == 0 {
            return chunk_height <= self.fork_height();
        }
        match self.witnessed_height(shard_id) {
            Some(witnessed) => chunk_height <= witnessed,
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{self, Height};
    use crate::storage::db::RocksDB;
    use std::sync::Arc;

    fn block(height: u64, witnesses: &[(u32, u64)]) -> proto::Block {
        proto::Block {
            header: Some(proto::BlockHeader {
                height: Some(Height::new(0, height)),
                ..Default::default()
            }),
            hash: vec![height as u8; 32],
            shard_witness: Some(proto::ShardWitness {
                shard_chunk_witnesses: witnesses
                    .iter()
                    .map(|&(shard, h)| proto::ShardChunkWitness {
                        height: Some(Height::new(shard, h)),
                        shard_root: vec![],
                        shard_hash: vec![],
                    })
                    .collect(),
            }),
            ..Default::default()
        }
    }

    fn store() -> (BlockStore, tempfile::TempDir) {
        let dir = tempfile::TempDir::new().unwrap();
        let db = RocksDB::new(dir.path().join("blocks").to_str().unwrap());
        db.open().unwrap();
        (BlockStore::new(Arc::new(db)), dir)
    }

    #[test]
    fn holds_chunks_until_witnessed() {
        let (blocks, _dir) = store();
        let guard = PivotGuard::new(1_000, blocks.clone(), vec![1, 2]);

        // No shard-0 block yet: nothing is witnessed.
        assert!(!guard.allows(1, 1));
        assert!(guard.allows(0, 1));

        blocks.put_block(&block(10, &[(1, 50), (2, 40)])).unwrap();
        assert!(guard.allows(1, 50));
        assert!(!guard.allows(1, 51));
        assert!(guard.allows(2, 40));
        assert!(!guard.allows(2, 41));

        blocks.put_block(&block(11, &[(1, 52), (2, 41)])).unwrap();
        assert!(guard.allows(1, 52));
        assert!(!guard.allows(1, 53));
        assert!(guard.allows(2, 41));
    }

    #[test]
    fn shard_0_stops_at_the_fork_block_and_records_the_fork_points() {
        let (blocks, _dir) = store();
        let guard = PivotGuard::new(1_000, blocks.clone(), vec![1, 2]);
        assert_eq!(guard.fork_height(), 999);
        assert!(guard.allows(0, 999));
        assert!(!guard.allows(0, 1_000));

        let mut fork = block(999, &[(1, 70), (2, 80)]);
        if let Some(w) = fork.shard_witness.as_mut() {
            for x in &mut w.shard_chunk_witnesses {
                x.shard_hash = vec![x.height.unwrap().shard_index as u8; 32];
            }
        }
        blocks.put_block(&fork).unwrap();
        let points = guard.fork_points(&[1, 2]);
        assert_eq!(points.len(), 2);
        assert_eq!((points[0].shard_id, points[0].fork_height), (1, 70));
        assert_eq!((points[1].shard_id, points[1].fork_height), (2, 80));
        assert_eq!(points[1].chunk_hash, vec![2u8; 32]);

        let dir = tempfile::TempDir::new().unwrap();
        let db = RocksDB::new(dir.path().join("m").to_str().unwrap());
        db.open().unwrap();
        assert!(read_marker(&db).is_none());
        let marker = PivotRecord {
            pivot_height: 1_000,
            fork_block_hash: vec![9u8; 32],
            shard_forks: points,
            ..Default::default()
        };
        write_marker(&db, &marker).unwrap();
        assert_eq!(read_marker(&db), Some(marker));
        delete_marker(&db).unwrap();
        assert!(read_marker(&db).is_none());
    }

    #[test]
    fn the_pivot_is_ready_when_every_shard_is_at_its_fork_height() {
        let (blocks, _dir) = store();
        let guard = PivotGuard::new(1_000, blocks.clone(), vec![1, 2]);
        let shard2 = guard.clone();
        assert!(guard.record_height(1, 70).is_none(), "no fork block yet");
        blocks.put_block(&block(998, &[(1, 69), (2, 79)])).unwrap();
        assert!(guard.record_height(1, 69).is_none());

        blocks.put_block(&block(999, &[(1, 70), (2, 80)])).unwrap();
        assert!(guard.record_height(1, 70).is_none(), "shard 2 is behind");
        assert!(shard2.record_height(2, 79).is_none());
        let marker = shard2.record_height(2, 80).expect("ready");
        assert_eq!(marker.pivot_height, 1_000);
        assert_eq!(marker.fork_block_hash, vec![231u8; 32]);
        assert_eq!(
            marker
                .shard_forks
                .iter()
                .map(|p| (p.shard_id, p.fork_height))
                .collect::<Vec<_>>(),
            vec![(1, 70), (2, 80)]
        );
        // Shard 0 reports too; the answer is the same.
        assert_eq!(guard.record_height(0, 999), Some(marker));
    }
}
