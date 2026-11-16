use crate::proto::FarcasterNetwork;
use crate::storage::db::snapshot::{
    clear_old_snapshots, upload_streaming_snapshot, Config, SnapshotError,
};
use crate::storage::store::block_engine::BlockStores;
use crate::storage::store::stores::Stores;
use crate::utils::statsd_wrapper::StatsdClientWrapper;
use std::collections::{HashMap, HashSet};
use tokio_cron_scheduler::{Job, JobSchedulerError};
use tracing::{error, info};

// Keep one publisher active through export, uploads, and remote cleanup. A long
// upload remains protected regardless of directory timestamps or elapsed time.
static UPLOAD_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

pub async fn upload_snapshot(
    snapshot_config: Config,
    fc_network: FarcasterNetwork,
    block_stores: BlockStores,
    shard_stores: HashMap<u32, Stores>,
    statsd_client: StatsdClientWrapper,
    only_for_shard_ids: Option<HashSet<u32>>,
) -> Result<(), SnapshotError> {
    let _upload_guard = UPLOAD_LOCK
        .try_lock()
        .map_err(|_| SnapshotError::UploadAlreadyInProgress)?;
    let mut databases: Vec<_> = shard_stores
        .iter()
        .map(|(shard, stores)| (*shard, stores.db.clone()))
        .collect();
    databases.push((0, block_stores.db));
    databases.sort_by_key(|(shard, _)| *shard);
    let mut failures = Vec::new();
    for (shard, db) in databases {
        if only_for_shard_ids
            .as_ref()
            .is_some_and(|ids| !ids.contains(&shard))
        {
            continue;
        }
        info!(shard, "Starting streaming snapshot upload");
        statsd_client.emit_jemalloc_stats();
        if let Err(error) =
            upload_streaming_snapshot(fc_network, db, &snapshot_config, shard, &statsd_client).await
        {
            error!(shard, %error, "Snapshot upload failed; continuing with remaining shards");
            failures.push(format!("shard {shard} upload: {error}"));
            statsd_client.emit_jemalloc_stats();
            continue;
        }
        if let Err(error) = clear_old_snapshots(fc_network, &snapshot_config, shard).await {
            error!(shard, %error, "Snapshot published, but cleanup failed; continuing with remaining shards");
            failures.push(format!("shard {shard} cleanup: {error}"));
        } else {
            info!(shard, "Streaming snapshot upload complete");
        }
        statsd_client.emit_jemalloc_stats();
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(SnapshotError::UploadFailures(failures.join("; ")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::store::test_helper;
    use crate::storage::{db::RocksDB, trie::merkle_trie::MerkleTrie};
    use std::sync::Arc;
    use tempfile::TempDir;

    fn block_stores(dir: &TempDir) -> BlockStores {
        let db = Arc::new(RocksDB::new(dir.path().join("db").to_str().unwrap()));
        db.open().unwrap();
        BlockStores::new(db, MerkleTrie::new().unwrap(), FarcasterNetwork::Devnet)
    }
    fn config(dir: &TempDir) -> Config {
        Config {
            backup_dir: dir.path().join("backup").to_string_lossy().into_owned(),
            ..Default::default()
        }
    }
    #[tokio::test]
    #[serial_test::serial(snapshot_upload)]
    async fn empty_filter_creates_no_staging_directory() {
        let dir = TempDir::new().unwrap();
        let config = config(&dir);
        upload_snapshot(
            config.clone(),
            FarcasterNetwork::Devnet,
            block_stores(&dir),
            HashMap::new(),
            test_helper::statsd_client(),
            Some(HashSet::new()),
        )
        .await
        .unwrap();
        assert!(!std::path::Path::new(&config.backup_dir).exists());
    }
    #[tokio::test]
    #[serial_test::serial(snapshot_upload)]
    async fn interrupted_legacy_backup_does_not_block_upload_or_get_deleted() {
        let dir = TempDir::new().unwrap();
        let config = config(&dir);
        std::fs::create_dir_all(&config.backup_dir).unwrap();
        let backup = std::path::Path::new(&config.backup_dir).join("old.tar.gz");
        std::fs::write(&backup, b"previous backup").unwrap();
        upload_snapshot(
            config,
            FarcasterNetwork::Devnet,
            block_stores(&dir),
            HashMap::new(),
            test_helper::statsd_client(),
            Some(HashSet::new()),
        )
        .await
        .unwrap();
        assert_eq!(std::fs::read(backup).unwrap(), b"previous backup");
    }
    #[tokio::test]
    #[serial_test::serial(snapshot_upload)]
    async fn running_upload_blocks_a_second_publisher() {
        let guard = UPLOAD_LOCK.lock().await;
        let dir = TempDir::new().unwrap();
        let result = upload_snapshot(
            config(&dir),
            FarcasterNetwork::Devnet,
            block_stores(&dir),
            HashMap::new(),
            test_helper::statsd_client(),
            Some(HashSet::new()),
        )
        .await;
        assert!(matches!(
            result,
            Err(SnapshotError::UploadAlreadyInProgress)
        ));
        drop(guard);
    }
    #[tokio::test]
    #[serial_test::serial(snapshot_upload)]
    async fn upload_failure_is_reported_and_guard_is_released() {
        let dir = TempDir::new().unwrap();
        let mut config = config(&dir);
        config.min_free_disk_bytes = u64::MAX;
        config.endpoint_url = "http://127.0.0.1:9".into();
        config.aws_access_key_id = "test".into();
        config.aws_secret_access_key = "test".into();
        let result = upload_snapshot(
            config,
            FarcasterNetwork::Devnet,
            block_stores(&dir),
            HashMap::new(),
            test_helper::statsd_client(),
            Some([0].into()),
        )
        .await;
        assert!(result.unwrap_err().to_string().contains("reserve"));
        assert!(UPLOAD_LOCK.try_lock().is_ok());
    }
}

pub fn snapshot_upload_job(
    schedule: &str,
    snapshot_config: Config,
    fc_network: FarcasterNetwork,
    block_stores: BlockStores,
    shard_stores: HashMap<u32, Stores>,
    statsd_client: StatsdClientWrapper,
) -> Result<Job, JobSchedulerError> {
    Job::new_async(schedule, move |_, _| {
        let snapshot_config = snapshot_config.clone();
        let block_stores = block_stores.clone();
        let shard_stores = shard_stores.clone();
        let statsd_client = statsd_client.clone();
        Box::pin(async move {
            if let Err(err) = upload_snapshot(
                snapshot_config,
                fc_network,
                block_stores,
                shard_stores,
                statsd_client,
                None,
            )
            .await
            {
                error!("Error uploading snapshots {}", err);
            }
        })
    })
}
