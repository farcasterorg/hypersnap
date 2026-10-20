//! The undecided proposed values of a Hypersnap shard. The proposer keeps
//! them in the shard DB as well as in memory, so that a validator that
//! restarts can commit a value that its consensus WAL decides: the WAL has
//! the proposal and the votes, not the value. Without the value, the node
//! starts the height again, and its peers, which have moved on, do not send
//! that height again. In a small set they need its vote for the next height,
//! so the chain stops. Node-local data: not in the state trie.

use crate::consensus::proposer::ProposedValues;
use crate::proto::{FullProposal, Height, ShardHash};
use crate::storage::constants::RootPrefix;
use crate::storage::db::{PageOptions, RocksDB, RocksDbTransactionBatch};
use crate::storage::store::node_local_state::DataType;
use prost::Message as _;
use std::sync::Arc;
use tracing::{error, info};

pub struct UndecidedValues {
    db: Arc<RocksDB>,
    memory: ProposedValues,
}

fn prefix() -> Vec<u8> {
    vec![
        RootPrefix::NodeLocalState as u8,
        DataType::HypersnapUndecidedValue as u8,
    ]
}

/// `[NodeLocalState][HypersnapUndecidedValue][height u64][value hash]`.
fn key(height: u64, hash: &[u8]) -> Vec<u8> {
    let mut k = prefix();
    k.extend_from_slice(&height.to_be_bytes());
    k.extend_from_slice(hash);
    k
}

fn height_of(key: &[u8]) -> u64 {
    let start = prefix().len();
    key.get(start..start + 8)
        .and_then(|b| <[u8; 8]>::try_from(b).ok())
        .map(u64::from_be_bytes)
        .unwrap_or(0)
}

fn shard_hash_height(value: &Option<FullProposal>) -> u64 {
    value.as_ref().map_or(0, |v| v.height().block_number)
}

impl UndecidedValues {
    pub fn new(db: Arc<RocksDB>) -> Self {
        UndecidedValues {
            db,
            memory: ProposedValues::new(),
        }
    }

    pub fn add(&mut self, value: FullProposal) {
        let k = key(value.height().block_number, &value.shard_hash().hash);
        if let Err(e) = self.db.put(&k, &value.encode_to_vec()) {
            error!("Could not store an undecided value: {}", e);
        }
        self.memory.add_proposed_value(value);
    }

    /// The value with `shard_hash`, from memory or, after a restart, from
    /// the DB.
    pub fn get(&self, shard_hash: &ShardHash) -> Option<FullProposal> {
        if let Some(v) = self.memory.get_by_shard_hash(shard_hash) {
            return Some(v.clone());
        }
        let p = prefix();
        let mut found = None;
        let _ = self.db.for_each_iterator_by_prefix(
            Some(p.clone()),
            Some(crate::storage::util::increment_vec_u8(&p)),
            &PageOptions::default(),
            |k, v| {
                if k.ends_with(&shard_hash.hash) {
                    if let Ok(value) = FullProposal::decode(v) {
                        if value.shard_hash() == *shard_hash {
                            found = Some(value);
                            return Ok(true);
                        }
                    }
                }
                Ok(false)
            },
        );
        if found.is_some() {
            info!(
                height = shard_hash_height(&found),
                "Found an undecided value of the WAL in the DB"
            );
        }
        found
    }

    /// Drop the values of `height` and below.
    pub fn decide(&mut self, height: Height) {
        self.memory.decide(height);
        let p = prefix();
        let mut txn = RocksDbTransactionBatch::new();
        let _ = self.db.for_each_iterator_by_prefix(
            Some(p.clone()),
            Some(crate::storage::util::increment_vec_u8(&p)),
            &PageOptions::default(),
            |k, _| {
                if height_of(k) > height.block_number {
                    return Ok(true);
                }
                txn.delete(k.to_vec());
                Ok(false)
            },
        );
        if txn.len() > 0 {
            if let Err(e) = self.db.commit(txn) {
                error!("Could not drop the decided values: {}", e);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::full_proposal::ProposedValue;

    fn value(height: u64, n: u8) -> FullProposal {
        let mut block = crate::proto::HypersnapBlock {
            header: Some(crate::proto::HypersnapBlockHeader {
                shard_id: 1,
                height,
                timestamp: n as u64,
                ..Default::default()
            }),
            ..Default::default()
        };
        crate::chain::block::seal(&mut block);
        FullProposal {
            height: Some(Height::new(1, height)),
            round: 0,
            proposer: vec![n],
            proposed_value: Some(ProposedValue::HypersnapBlock(block.encode_to_vec())),
        }
    }

    #[test]
    fn a_value_survives_a_restart_until_its_height_is_decided() {
        let dir = tempfile::TempDir::new().unwrap();
        let db = Arc::new(RocksDB::new(dir.path().to_str().unwrap()));
        db.open().unwrap();
        let (a, b, c) = (value(7, 1), value(7, 2), value(8, 3));
        let mut values = UndecidedValues::new(db.clone());
        for v in [&a, &b, &c] {
            values.add(v.clone());
        }

        // A restart: a new cache over the same DB.
        let mut values = UndecidedValues::new(db.clone());
        assert_eq!(values.get(&b.shard_hash()), Some(b.clone()));
        assert_eq!(values.get(&c.shard_hash()), Some(c.clone()));
        values.decide(Height::new(1, 7));
        assert_eq!(values.get(&a.shard_hash()), None);
        assert_eq!(values.get(&b.shard_hash()), None);
        assert_eq!(values.get(&c.shard_hash()), Some(c));
    }
}
