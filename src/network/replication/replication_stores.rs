use crate::{
    network::replication::{error::ReplicationError, replicator::ShardMetadata},
    proto,
    storage::{
        db::RocksDB,
        store::stores::{StoreLimits, Stores},
        trie::merkle_trie,
    },
    utils::statsd_wrapper::StatsdClientWrapper,
};
use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};
use tracing::{debug, error};

type TimestampedStore = (u64, Stores); // (farcaster timestamp, Stores)

pub struct ReplicationStores {
    shard_stores: HashMap<u32, Stores>,
    // Shard -> Height -> TimestampedStore
    read_only_stores: RwLock<HashMap<u32, HashMap<u64, TimestampedStore>>>,
    statsd_client: StatsdClientWrapper,
    network: proto::FarcasterNetwork,
}

impl ReplicationStores {
    const SNAPSHOT_METRIC_NAME: &'static str = "replication.snapshot.count";

    pub fn new(
        shard_stores: HashMap<u32, Stores>,
        statsd_client: StatsdClientWrapper,
        network: proto::FarcasterNetwork,
    ) -> Self {
        ReplicationStores {
            shard_stores,
            statsd_client: statsd_client,
            read_only_stores: RwLock::new(HashMap::new()),
            network,
        }
    }

    pub fn network(&self) -> proto::FarcasterNetwork {
        self.network.clone()
    }

    pub fn get(&self, shard: u32, height: u64) -> Option<Stores> {
        match self.read_only_stores.read() {
            Ok(stores) => match stores.get(&shard) {
                Some(stores) => stores.get(&height).map(|(_, store)| store.clone()),
                None => None,
            },
            Err(_) => {
                error!("Failed to acquire read lock on read_only_stores");
                None
            }
        }
    }

    pub fn get_timestamp(&self, shard: u32, height: u64) -> Result<u64, ReplicationError> {
        // Distinguish a poisoned lock (a bug worth surfacing as an internal error, mirroring
        // `get_metadata`) from a genuinely absent snapshot. Collapsing both to `None` here made a
        // lock-poisoning panic look like a missing snapshot to the caller.
        let stores = self.read_only_stores.read().map_err(|_| {
            ReplicationError::InternalError(
                "Failed to acquire read lock on read_only_stores".to_string(),
            )
        })?;
        stores
            .get(&shard)
            .and_then(|snapshots| snapshots.get(&height))
            .map(|(timestamp, _)| *timestamp)
            .ok_or_else(|| {
                ReplicationError::StoreNotFound(
                    shard,
                    height,
                    "No timestamp found for the snapshot".to_string(),
                )
            })
    }

    // Returns a list of (height, farcaster timestamp) pairs for the given shard.
    pub fn get_metadata(&self, shard: u32) -> Result<Vec<ShardMetadata>, ReplicationError> {
        let results = match self.read_only_stores.read() {
            Ok(stores) => stores.get(&shard).map(|snapshots| {
                snapshots
                    .iter()
                    .map(|(&height, (timestamp, stores))| ShardMetadata {
                        shard_id: shard,
                        height,
                        timestamp: *timestamp,
                        num_items: stores.trie.items().unwrap_or(0),
                    })
                    .collect()
            }),
            Err(_) => {
                return Err(ReplicationError::InternalError(
                    "Failed to acquire read lock on read_only_stores".to_string(),
                ));
            }
        };

        match results {
            Some(metadata) => Ok(metadata),
            None => Err(ReplicationError::ShardStoreNotFound(shard)),
        }
    }

    pub fn max_height_for_shard(&self, shard_id: u32) -> Option<u64> {
        match self.read_only_stores.read() {
            Ok(stores) => stores
                .get(&shard_id)
                .and_then(|shard_stores| shard_stores.keys().max().cloned()),
            Err(_) => {
                error!("Failed to acquire read lock on read_only_stores");
                None
            }
        }
    }

    fn new_timestamped_store(
        &self,
        shard: u32,
        timestamp: u64,
        read_only_db: RocksDB,
    ) -> TimestampedStore {
        let trie = merkle_trie::MerkleTrie::new().unwrap();
        let store = Stores::new(
            Arc::new(read_only_db),
            shard,
            trie,
            StoreLimits::default(),
            self.network.clone(),
            self.statsd_client.clone(),
        );
        (timestamp, store)
    }

    fn insert_snapshot(
        &self,
        shard: u32,
        height: u64,
        timestamped_store: TimestampedStore,
    ) -> Result<(), ReplicationError> {
        let stores = self.read_only_stores.write();
        if stores.is_err() {
            return Err(ReplicationError::InternalError(
                "Failed to acquire write lock on read_only_stores".to_string(),
            ));
        }
        let mut stores = stores.unwrap();

        if !stores.contains_key(&shard) {
            stores.insert(shard, HashMap::new());
        }

        if stores[&shard].contains_key(&height) {
            return Ok(());
        }

        stores
            .get_mut(&shard)
            .unwrap()
            .insert(height, timestamped_store);

        self.capture_snapshot_metrics(&stores);

        Ok(())
    }

    pub fn open_snapshot(
        &self,
        shard: u32,
        height: u64,
        timestamp: u64,
    ) -> Result<(), ReplicationError> {
        let stores = self.shard_stores.get(&shard);
        if stores.is_none() {
            return Err(ReplicationError::ShardStoreNotFound(shard));
        }

        let read_only_db = stores.unwrap().db.open_read_only().map_err(|e| {
            ReplicationError::InternalError(format!(
                "Failed to open read-only database for shard {}: {}",
                shard, e
            ))
        })?;
        let timestamped_store = self.new_timestamped_store(shard, timestamp, read_only_db);

        // Opening the read-only handle does not stop writers, so the next block can commit
        // while it opens. A block commits its chunk and its state in one transaction, so the
        // opened height shows whether this view is exactly `height`. Do not keep a view that
        // is at a different height.
        let opened_height = timestamped_store
            .1
            .shard_store
            .max_block_number()
            .map_err(|e| {
                ReplicationError::InternalError(format!(
                    "Failed to read the height of the read-only view of shard {}: {}",
                    shard, e
                ))
            })?;
        if opened_height != height {
            return Err(ReplicationError::InternalError(format!(
                "Read-only view of shard {} opened at height {}, not {}; snapshot not taken",
                shard, opened_height, height
            )));
        }

        self.insert_snapshot(shard, height, timestamped_store)
    }

    pub fn close_aged_snapshots(&self, shard: u32, min_timestamp: u64) {
        let stores = self.read_only_stores.write();
        if stores.is_err() {
            error!("Failed to acquire write lock on read_only_stores");
            return;
        }
        let mut stores = stores.unwrap();

        match stores.get_mut(&shard) {
            Some(shard_stores) => {
                shard_stores.retain(|&_, &mut (timestamp, _)| timestamp >= min_timestamp)
            }
            None => debug!("Shard {} has no snapshots in read_only_stores", shard),
        }

        self.capture_snapshot_metrics(&stores);
    }

    fn close_all_snapshots(&mut self) {
        let stores = self.read_only_stores.write();
        if stores.is_err() {
            error!("Failed to acquire write lock on read_only_stores");
            return;
        }
        let mut stores = stores.unwrap();
        stores.clear();
    }

    fn capture_snapshot_metrics(&self, stores: &HashMap<u32, HashMap<u64, TimestampedStore>>) {
        for (shard, heights) in stores.iter() {
            self.statsd_client.gauge_with_shard(
                shard.clone(),
                Self::SNAPSHOT_METRIC_NAME,
                heights.len() as u64,
            );
        }
    }
}

impl Drop for ReplicationStores {
    fn drop(&mut self) {
        self.close_all_snapshots();
    }
}
