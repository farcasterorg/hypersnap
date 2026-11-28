use crate::{
    network::replication::{error::ReplicationError, replicator::ShardMetadata},
    proto,
    storage::{
        db::{DBProvider, RocksDB},
        store::stores::{StoreLimits, Stores},
        trie::merkle_trie,
    },
    utils::statsd_wrapper::StatsdClientWrapper,
};
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
};
use tracing::{debug, error, warn};

type SstFiles = Arc<[(PathBuf, u64)]>;

struct TimestampedStore {
    timestamp: u64,
    stores: Stores,
    ssts: SstFiles,
}

struct SnapshotFiles {
    shard: u32,
    height: u64,
    timestamp: u64,
    ssts: SstFiles,
}

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
                Some(stores) => stores.get(&height).map(|snapshot| snapshot.stores.clone()),
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
            .map(|snapshot| snapshot.timestamp)
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
                    .map(|(&height, snapshot)| ShardMetadata {
                        shard_id: shard,
                        height,
                        timestamp: snapshot.timestamp,
                        num_items: snapshot.stores.trie.items().unwrap_or(0),
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
    ) -> Result<TimestampedStore, ReplicationError> {
        // These are the SSTs in the read-only view, which can keep their file
        // descriptors open even after compaction unlinks them in the live DB.
        let directory = PathBuf::from(read_only_db.location());
        let ssts = {
            let guard = read_only_db.db();
            let Some(DBProvider::ReadOnly(db)) = guard.as_ref() else {
                return Err(ReplicationError::InternalError(
                    "Missing read-only snapshot DB".into(),
                ));
            };
            db.live_files()
                .map_err(|error| ReplicationError::InternalError(error.to_string()))?
                .into_iter()
                .map(|file| {
                    (
                        directory.join(file.name.trim_start_matches('/')),
                        file.size as u64,
                    )
                })
                .collect()
        };
        let trie = merkle_trie::MerkleTrie::new().unwrap();
        let store = Stores::new(
            Arc::new(read_only_db),
            shard,
            trie,
            StoreLimits::default(),
            self.network.clone(),
            self.statsd_client.clone(),
        );
        Ok(TimestampedStore {
            timestamp,
            stores: store,
            ssts,
        })
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
        let timestamped_store = self.new_timestamped_store(shard, timestamp, read_only_db)?;

        // Opening the read-only handle does not stop writers, so the next block can commit
        // while it opens. A block commits its chunk and its state in one transaction, so the
        // opened height shows whether this view is exactly `height`. Do not keep a view that
        // is at a different height.
        let opened_height = timestamped_store
            .stores
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
                shard_stores.retain(|_, snapshot| snapshot.timestamp >= min_timestamp)
            }
            None => debug!("Shard {} has no snapshots in read_only_stores", shard),
        }

        self.capture_snapshot_metrics(&stores);
    }

    pub(super) fn enforce_obsolete_sst_budget(&self, budget: u64) -> Result<(), ReplicationError> {
        let mut snapshots: Vec<_> = {
            let stores = self.read_only_stores.read()?;
            stores
                .iter()
                .flat_map(|(&shard, entries)| {
                    entries.iter().map(move |(&height, entry)| SnapshotFiles {
                        shard,
                        height,
                        timestamp: entry.timestamp,
                        ssts: Arc::clone(&entry.ssts),
                    })
                })
                .collect()
        };

        // Check unique files outside the registry lock. A shared SST only
        // becomes reclaimable after every retained view that references it goes.
        snapshots
            .sort_unstable_by_key(|snapshot| (snapshot.timestamp, snapshot.shard, snapshot.height));
        let mut files = HashMap::<&Path, (u64, usize)>::new();
        let mut obsolete_bytes = 0u64;
        for snapshot in &snapshots {
            for (path, size) in snapshot.ssts.iter() {
                match files.entry(path.as_path()) {
                    std::collections::hash_map::Entry::Occupied(mut entry) => {
                        entry.get_mut().1 += 1
                    }
                    std::collections::hash_map::Entry::Vacant(entry) => {
                        let exists = path.try_exists().map_err(|error| {
                            ReplicationError::InternalError(format!(
                                "Checking {}: {error}",
                                path.display()
                            ))
                        })?;
                        let obsolete_size = if exists { 0 } else { *size };
                        obsolete_bytes = obsolete_bytes.saturating_add(obsolete_size);
                        entry.insert((obsolete_size, 1));
                    }
                }
            }
        }
        self.statsd_client.gauge(
            "replication.snapshot.obsolete_sst_bytes",
            obsolete_bytes,
            vec![],
        );
        if obsolete_bytes <= budget {
            return Ok(());
        }

        let mut evict = Vec::new();
        for snapshot in &snapshots {
            if !snapshot
                .ssts
                .iter()
                .any(|(path, _)| files[path.as_path()].0 > 0)
            {
                continue;
            }
            evict.push((snapshot.shard, snapshot.height));
            for (path, _) in snapshot.ssts.iter() {
                let (size, refs) = files.get_mut(path.as_path()).unwrap();
                *refs -= 1;
                if *refs == 0 {
                    obsolete_bytes = obsolete_bytes.saturating_sub(*size);
                }
            }
            if obsolete_bytes <= budget {
                break;
            }
        }

        // Stop advertising these heights before dropping handles. Requests
        // already holding a Stores clone retain a consistent view until done.
        let retired: Vec<_> = {
            let mut stores = self.read_only_stores.write()?;
            let retired = evict
                .into_iter()
                .filter_map(|(shard, height)| {
                    stores
                        .get_mut(&shard)?
                        .remove(&height)
                        .map(|snapshot| (shard, height, snapshot))
                })
                .collect();
            self.capture_snapshot_metrics(&stores);
            retired
        };
        for (shard, height, _) in retired {
            self.statsd_client
                .incr("replication.snapshot.evicted_for_disk_budget");
            warn!(
                shard,
                height,
                budget_bytes = budget,
                "Retiring replication snapshot to release obsolete SSTs"
            );
        }
        Ok(())
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

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use crate::storage::{constants::RootPrefix, store::test_helper};
    use prost::Message;
    use rocksdb::{Options, WriteBatch, DB};
    use std::fs;

    fn deleted_sst_handles(directory: &Path) -> usize {
        fs::read_dir("/proc/self/fd")
            .unwrap()
            .filter_map(Result::ok)
            .filter_map(|entry| fs::read_link(entry.path()).ok())
            .filter(|target| {
                target.starts_with(directory)
                    && target.to_string_lossy().ends_with(".sst (deleted)")
            })
            .count()
    }

    #[tokio::test]
    async fn disk_budget_retires_old_views_and_releases_deleted_ssts() {
        let (engine, _temp_dir) = test_helper::new_engine().await;
        let source = engine.get_stores();
        let directory = PathBuf::from(source.db.location());
        source.db.close();

        // Use a plain RocksDB writer to force flush and compaction on demand.
        // The production replication code still opens the read-only views.
        let writer = DB::open(&Options::default(), &directory).unwrap();
        let write_generation = |generation| {
            let mut batch = WriteBatch::default();
            for key in 0..1000u32 {
                batch.put(
                    [&[255], key.to_be_bytes().as_slice()].concat(),
                    [generation; 512],
                );
            }
            writer.write(batch).unwrap();
            writer.flush().unwrap();
        };
        write_generation(0);

        let shard = engine.shard_id();
        let write_height = |height: u64| {
            let mut key = vec![RootPrefix::Shard as u8];
            key.extend_from_slice(&height.to_be_bytes());
            let chunk = proto::ShardChunk {
                header: Some(proto::ShardHeader {
                    height: Some(proto::Height {
                        shard_index: shard,
                        block_number: height,
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            };
            writer.put(key, chunk.encode_to_vec()).unwrap();
            writer.flush().unwrap();
        };
        let stores = ReplicationStores::new(
            HashMap::from([(shard, source)]),
            test_helper::statsd_client(),
            engine.network,
        );
        write_height(1);
        stores.open_snapshot(shard, 1, 1).unwrap();
        write_height(2);
        stores.open_snapshot(shard, 2, 2).unwrap();
        let reader = stores.get(shard, 1).unwrap();
        let (first_files, second_files) = {
            let snapshots = stores.read_only_stores.read().unwrap();
            let snapshots = &snapshots[&shard];
            (
                Arc::clone(&snapshots[&1].ssts),
                Arc::clone(&snapshots[&2].ssts),
            )
        };

        write_generation(1);
        write_height(3);
        writer.compact_range(None::<&[u8]>, None::<&[u8]>);
        stores.open_snapshot(shard, 3, 3).unwrap();

        let obsolete_files: HashMap<_, _> = first_files
            .iter()
            .chain(second_files.iter())
            .filter(|(path, _)| !path.exists())
            .map(|(path, size)| (path, *size))
            .collect();
        assert!(first_files.iter().any(|(path, _)| {
            obsolete_files.contains_key(path) && second_files.iter().any(|(other, _)| other == path)
        }));
        let obsolete_bytes = obsolete_files.values().sum();
        assert!(deleted_sst_handles(&directory) > 0);

        // Two snapshots share the same obsolete SST bytes.
        stores.enforce_obsolete_sst_budget(obsolete_bytes).unwrap();
        assert_eq!(stores.get_metadata(shard).unwrap().len(), 3);

        stores.enforce_obsolete_sst_budget(0).unwrap();
        assert!(stores.get(shard, 1).is_none());
        assert!(stores.get(shard, 2).is_none());
        assert!(stores.get(shard, 3).is_some());

        // A request that already acquired the old view can still finish.
        let key = [255, 0, 0, 0, 0];
        assert_eq!(reader.db.get(&key).unwrap().unwrap(), vec![0; 512]);
        assert!(deleted_sst_handles(&directory) > 0);
        drop(reader);
        assert_eq!(deleted_sst_handles(&directory), 0);
    }
}
