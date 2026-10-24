//! Read access to the committed shard-0 state: the epoch sets and the tip,
//! for the consensus of all three shards, and the outbox for shards 1 and 2.

use super::keys;
use super::state::BlockState;
use super::validators;
use super::{Shard0Error, Shard0Params};
use crate::chain::block::{block_hash, ParentInfo};
use crate::chain::proposer::{EpochSetSource, Shard0Tip};
use crate::chain::shard_blocks::HypersnapBlockStore;
use crate::chain::validator_sets::EpochSet;
use crate::proto::OutboxEntry;
use crate::storage::db::RocksDB;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub struct Shard0Reader {
    db: Arc<RocksDB>,
    params: Shard0Params,
    genesis_parent: ParentInfo,
    store: HypersnapBlockStore,
    sets: Arc<Mutex<BTreeMap<u64, EpochSet>>>,
}

impl Shard0Reader {
    pub fn new(db: Arc<RocksDB>, params: Shard0Params, genesis_parent: ParentInfo) -> Self {
        Shard0Reader {
            store: HypersnapBlockStore::new(db.clone()),
            db,
            params,
            genesis_parent,
            sets: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    /// The set of `epoch` (FIP §4.9). The seed of an epoch needs the last
    /// block of the previous epoch, so it is known before the boundary block
    /// commits; the set record is known one epoch earlier.
    pub fn epoch_set(&self, epoch: u64) -> Result<Option<EpochSet>, Shard0Error> {
        if let Some(set) = self.sets.lock().unwrap().get(&epoch) {
            return Ok(Some(set.clone()));
        }
        let set = read_epoch_set(
            &self.db,
            &self.params,
            &self.genesis_parent,
            &self.store,
            epoch,
        )?;
        if let Some(set) = &set {
            let mut cache = self.sets.lock().unwrap();
            cache.insert(epoch, set.clone());
            // Keep the last few epochs.
            while cache.len() > 4 {
                let first = *cache.keys().next().unwrap();
                cache.remove(&first);
            }
        }
        Ok(set)
    }

    /// The height of the last committed (so certified) shard-0 block.
    pub fn tip_height(&self) -> u64 {
        self.store
            .last()
            .and_then(|b| b.header)
            .map(|h| h.height)
            .unwrap_or(self.genesis_parent.height)
    }

    /// The outbox entries of the shard-0 block at `height`, in order.
    pub fn outbox(&self, height: u64) -> Result<Vec<OutboxEntry>, Shard0Error> {
        let state = BlockState::new(self.db.clone());
        state
            .txn()
            .scan(&keys::outbox_of_height(height))?
            .values()
            .map(|v| {
                <OutboxEntry as prost::Message>::decode(v.as_slice())
                    .map_err(|e| Shard0Error::Internal(e.to_string()))
            })
            .collect()
    }
}

pub(crate) fn read_epoch_set(
    db: &Arc<RocksDB>,
    params: &Shard0Params,
    genesis_parent: &ParentInfo,
    store: &HypersnapBlockStore,
    epoch: u64,
) -> Result<Option<EpochSet>, Shard0Error> {
    if epoch == 0 {
        return Ok(None);
    }
    let state = BlockState::new(db.clone());
    let mut txn = state.txn();
    if validators::epoch_seed(&txn, epoch)?.is_none() {
        let last = params.epochs.boundary_height(epoch) - 1;
        let hash = if last == genesis_parent.height {
            Some(genesis_parent.hash)
        } else {
            store
                .get(last)
                .and_then(|b| b.header)
                .map(|h| block_hash(&h))
        };
        match hash {
            Some(h) => txn.put(
                keys::epoch_seed(epoch),
                crate::chain::epoch::epoch_seed(epoch, &h).to_vec(),
            ),
            None => return Ok(None),
        }
    }
    validators::epoch_set(&txn, epoch)
}

impl EpochSetSource for Shard0Reader {
    fn set(&self, epoch: u64) -> Option<EpochSet> {
        self.epoch_set(epoch).ok().flatten()
    }
}

impl Shard0Tip for Shard0Reader {
    fn highest_certified(&self) -> u64 {
        self.tip_height()
    }
}
