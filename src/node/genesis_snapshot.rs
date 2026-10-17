//! The genesis state snapshot (FIP §17.4, §17.5). The content replay needs
//! the snapchain chunks of shards 1 and 2 from the first one. A node that
//! synced from a snapchain snapshot does not have them, so it uses the
//! replay DBs at `H_s` of the bootstrap validators:
//!
//! 1. A bootstrap validator exports its replay DBs (`export`,
//!    `hypersnap_pivot export-genesis`) to `<network>/genesis-<P>/<s>` of a
//!    snapshot bucket.
//! 2. The node gets the certified `PivotRecord` (`fetch_certified_record`):
//!    the shard-0 pivot block with its certificate, and the record that the
//!    block names, from a Hypersnap node. It checks the certificate with
//!    `set(1)` of the genesis validator file. Thus the node starts only after
//!    the shard-0 pivot block is certified.
//! 3. It downloads the snapshot (`download`) and installs it (`install`): it
//!    builds the Keccak trie of each shard again from the state, and it
//!    accepts the state only if the root is `genesis_state_roots[s]` of the
//!    certified record and the store walk passes (`state_walk`). It deletes
//!    the hub events and the chunks before `H_s`, which the root does not
//!    prove. The DB becomes the replay DB of the shard.
//! 4. The genesis build continues as after a content replay. The record that
//!    it builds must be the certified record (`BootSource::certified`).

use crate::chain::block::block_hash;
use crate::chain::certificate;
use crate::chain::genesis_file;
use crate::chain::pivot::genesis_validators_hash;
use crate::node::content_replay;
use crate::node::pivot_boot::{
    check_fork_chunk, offline_stores, open, rebuild_shard_root, snapchain_db_path,
};
use crate::proto::hub_service_client::HubServiceClient;
use crate::proto::{
    CertifiedBlocksRequest, FarcasterNetwork, GenesisValidatorFile, GetPivotRecordRequest,
    HypersnapBlock, PivotRecord,
};
use crate::storage::constants::RootPrefix;
use crate::storage::db::backup::backup_db;
use crate::storage::db::snapshot::{self, genesis_snapshot_directory};
use crate::storage::store::shard::ShardStore;
use crate::storage::trie::{shadow_trie, state_walk};
use prost::Message as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, warn};

/// The download of the snapshot unpacks here, in the RocksDB directory.
pub const STAGING_DIR: &str = "genesis-snapshot.staging";
const DOWNLOAD_DIR: &str = "genesis-snapshot.download";
const FETCH_TIMEOUT: Duration = Duration::from_secs(60);

/// The DB of shard `shard` in an unpacked snapshot (`backup_db` names it).
pub fn staged_db_path(staging: &Path, shard: u32) -> PathBuf {
    staging.join(format!("shard-{}", shard))
}

fn last_height(db: &std::sync::Arc<crate::storage::db::RocksDB>, shard: u32) -> u64 {
    ShardStore::new(db.clone(), shard)
        .get_last_shard_chunk()
        .ok()
        .flatten()
        .and_then(|c| c.header?.height)
        .map(|h| h.block_number)
        .unwrap_or(0)
}

/// The shards whose content replay cannot reach `H_s` with the snapchain
/// chunks of this node.
pub fn shards_without_history(
    rocksdb_dir: &Path,
    marker: &PivotRecord,
) -> Result<Vec<u32>, String> {
    let mut out = Vec::new();
    for point in &marker.shard_forks {
        let s = point.shard_id;
        let replay_path = content_replay::replay_db_path(rocksdb_dir, s);
        let replayed = if replay_path.exists() {
            let db = open(&replay_path)?;
            let h = last_height(&db, s);
            db.close();
            h
        } else {
            0
        };
        if replayed >= point.fork_height {
            continue;
        }
        let db = open(&snapchain_db_path(rocksdb_dir, s))?;
        let first = ShardStore::new(db.clone(), s)
            .min_block_number()
            .unwrap_or(u64::MAX);
        db.close();
        if first > replayed + 1 {
            out.push(s);
        }
    }
    Ok(out)
}

/// The checks of a `PivotRecord` and the shard-0 pivot block that names it:
/// the fork point of the marker, the genesis validator file, the record hash
/// in the header, and the certificate against `set(1)` of the file.
pub fn verify_certified_pivot(
    record: &PivotRecord,
    block: &HypersnapBlock,
    marker: &PivotRecord,
    file: &GenesisValidatorFile,
    network: FarcasterNetwork,
) -> Result<(), String> {
    if record.pivot_height != marker.pivot_height
        || record.fork_block_hash != marker.fork_block_hash
        || record.shard_forks != marker.shard_forks
    {
        return Err("the PivotRecord is for another fork point than the marker".into());
    }
    if record.genesis_validators_hash.as_slice() != genesis_validators_hash(file).as_slice() {
        return Err("the PivotRecord is for another genesis validator file".into());
    }
    let header = block
        .header
        .as_ref()
        .ok_or("the pivot block has no header")?;
    if header.shard_id != 0 || header.height != record.pivot_height {
        return Err("the block is not the shard-0 pivot block".into());
    }
    let hash = block_hash(header);
    if block.hash.as_slice() != hash.as_slice() {
        return Err("the hash of the pivot block is not the hash of its header".into());
    }
    if header.pivot_record_hash.as_slice()
        != alloy_primitives::keccak256(record.encode_to_vec()).as_slice()
    {
        return Err("the pivot block names another PivotRecord".into());
    }
    let cert = block
        .certificate
        .as_ref()
        .ok_or("the pivot block has no certificate")?;
    if cert.shard_id != 0 || cert.height != header.height || cert.block_hash.as_slice() != hash {
        return Err("the certificate is not for the pivot block".into());
    }
    let fork: [u8; 32] = record
        .fork_block_hash
        .as_slice()
        .try_into()
        .map_err(|_| "the fork block hash is not 32 bytes")?;
    let set = genesis_file::epoch1_set(file, network, &fork)?;
    if set.record.set_root != record.set_root_epoch1 {
        return Err("set(1) of the genesis validator file is not set_root_epoch1".into());
    }
    certificate::verify(&set, cert)
        .map_err(|e| format!("the certificate of the pivot block: {}", e))
}

async fn fetch_from(url: &str, pivot_height: u64) -> Result<(PivotRecord, HypersnapBlock), String> {
    let mut client = HubServiceClient::connect(url.to_string())
        .await
        .map_err(|e| e.to_string())?;
    let record = client
        .get_pivot_record(GetPivotRecordRequest {})
        .await
        .map_err(|e| e.message().to_string())?
        .into_inner();
    let mut blocks = client
        .get_certified_blocks(CertifiedBlocksRequest {
            shard_id: 0,
            start_height: pivot_height,
            stop_height: Some(pivot_height + 1),
        })
        .await
        .map_err(|e| e.message().to_string())?
        .into_inner();
    let block = blocks
        .message()
        .await
        .map_err(|e| e.message().to_string())?
        .ok_or("no shard-0 pivot block")?;
    Ok((record, block))
}

/// The certified `PivotRecord`, from the first node in `urls` (gRPC) that
/// has the certified shard-0 pivot block. `expected_genesis_hash`:
/// `GENESIS_VALIDATORS_HASH` of the release, if it has one.
pub async fn fetch_certified_record(
    urls: &[String],
    marker: &PivotRecord,
    file: &GenesisValidatorFile,
    expected_genesis_hash: Option<[u8; 32]>,
    network: FarcasterNetwork,
) -> Result<PivotRecord, String> {
    if let Some(expected) = expected_genesis_hash {
        if genesis_validators_hash(file) != expected {
            return Err("the genesis validator file is not GENESIS_VALIDATORS_HASH".into());
        }
    }
    if urls.is_empty() {
        return Err(
            "hypersnap.genesis_snapshot_rpc is empty: a node without the chunk history needs \
             the certified shard-0 pivot block from a Hypersnap node"
                .into(),
        );
    }
    let mut errors = Vec::new();
    for url in urls {
        let fetched = tokio::time::timeout(FETCH_TIMEOUT, fetch_from(url, marker.pivot_height))
            .await
            .map_err(|_| "no answer".to_string())
            .and_then(|r| r)
            .and_then(|(record, block)| {
                verify_certified_pivot(&record, &block, marker, file, network).map(|_| record)
            });
        match fetched {
            Ok(record) => {
                info!(
                    url = url.as_str(),
                    record_hash = hex::encode(alloy_primitives::keccak256(record.encode_to_vec())),
                    "Got the certified PivotRecord"
                );
                return Ok(record);
            }
            Err(e) => errors.push(format!("{}: {}", url, e)),
        }
    }
    Err(format!(
        "no certified shard-0 pivot block ({}). A node without the chunk history starts after \
         the shard-0 pivot block is certified",
        errors.join("; ")
    ))
}

/// Make the snapshot of each replay DB at `H_s` in `backup_dir`. Returns the
/// directory of the chunks of each shard. If this node built the genesis,
/// the root of each DB must be its `genesis_state_roots[s]`. The store walk
/// runs on each DB first, so that a DB that an importing node would reject
/// is not published.
pub fn export(
    rocksdb_dir: &Path,
    marker: &PivotRecord,
    own_record: Option<&PivotRecord>,
    backup_dir: &Path,
    network: FarcasterNetwork,
) -> Result<Vec<(u32, String)>, String> {
    std::fs::create_dir_all(backup_dir).map_err(|e| e.to_string())?;
    let backup_dir = backup_dir.to_str().ok_or("the path is not UTF-8")?;
    let mut out = Vec::new();
    for point in &marker.shard_forks {
        let s = point.shard_id;
        let db = open(&content_replay::replay_db_path(rocksdb_dir, s))?;
        let checked = check_fork_chunk(&db, s, point, "content replay").and_then(|_| {
            let root = shadow_trie::report_from_db(db.clone())
                .map_err(|e| e.to_string())?
                .root;
            match own_record.and_then(|r| r.genesis_state_roots.get(s as usize)) {
                Some(expected) if expected.as_slice() != root.as_slice() => Err(format!(
                    "the replay DB of shard {} has the root {}, the PivotRecord has {}",
                    s,
                    hex::encode(root),
                    hex::encode(expected)
                )),
                Some(_) => Ok(()),
                None => {
                    warn!(
                        shard = s,
                        "No PivotRecord: the root of the export is not checked"
                    );
                    Ok(())
                }
            }
        });
        let checked = checked.and_then(|_| {
            walk_stores(
                &db,
                &rocksdb_dir.join(format!("genesis-walk-{}", s)),
                s,
                network,
            )
        });
        let chunks = checked.and_then(|_| {
            backup_db(
                db.clone(),
                backup_dir,
                s,
                chrono::Utc::now().timestamp_millis(),
            )
            .map_err(|e| e.to_string())
        });
        db.close();
        out.push((s, chunks?));
    }
    Ok(out)
}

/// Download the snapshots of `shards` from `url` into `<rocksdb_dir>/STAGING_DIR`.
pub async fn download(
    snapshot_config: &snapshot::Config,
    url: &str,
    rocksdb_dir: &Path,
    marker: &PivotRecord,
    network: FarcasterNetwork,
    shards: &[u32],
) -> Result<PathBuf, String> {
    if url.is_empty() {
        return Err("hypersnap.genesis_snapshot_url is empty".into());
    }
    let staging = rocksdb_dir.join(STAGING_DIR);
    if staging.exists() {
        std::fs::remove_dir_all(&staging).map_err(|e| e.to_string())?;
    }
    let mut config = snapshot_config.clone();
    config.snapshot_download_url = url.trim_end_matches('/').to_string();
    config.snapshot_download_dir = rocksdb_dir
        .join(DOWNLOAD_DIR)
        .to_string_lossy()
        .into_owned();
    let directories = shards
        .iter()
        .map(|&s| {
            (
                s,
                genesis_snapshot_directory(network, marker.pivot_height, s),
            )
        })
        .collect();
    snapshot::download_snapshot_dirs(&config, staging.to_string_lossy().into_owned(), directories)
        .await
        .map_err(|e| e.to_string())?;
    Ok(staging)
}

/// Check the snapshots of `shards` in `staging` against the certified
/// record, and make them the replay DBs. Nothing is installed if a shard
/// fails, and the staging directory is removed.
pub fn install(
    staging: &Path,
    rocksdb_dir: &Path,
    marker: &PivotRecord,
    certified: &PivotRecord,
    network: FarcasterNetwork,
    shards: &[u32],
) -> Result<(), String> {
    let checked = shards
        .iter()
        .try_for_each(|&s| check_staged(staging, marker, certified, network, s));
    if let Err(e) = checked {
        let _ = std::fs::remove_dir_all(staging);
        return Err(e);
    }
    for &s in shards {
        let target = content_replay::replay_db_path(rocksdb_dir, s);
        if target.exists() {
            std::fs::remove_dir_all(&target).map_err(|e| e.to_string())?;
        }
        std::fs::rename(staged_db_path(staging, s), &target).map_err(|e| e.to_string())?;
    }
    let _ = std::fs::remove_dir_all(staging);
    Ok(())
}

fn check_staged(
    staging: &Path,
    marker: &PivotRecord,
    certified: &PivotRecord,
    network: FarcasterNetwork,
    s: u32,
) -> Result<(), String> {
    let point = marker
        .shard_forks
        .iter()
        .find(|p| p.shard_id == s)
        .ok_or_else(|| format!("no fork point for shard {}", s))?;
    let expected = certified
        .genesis_state_roots
        .get(s as usize)
        .ok_or_else(|| format!("the certified PivotRecord has no root for shard {}", s))?;
    let path = staged_db_path(staging, s);
    if !path.exists() {
        return Err(format!("the snapshot has no DB for shard {}", s));
    }
    let db = open(&path)?;
    info!(
        shard = s,
        "Building the Keccak trie of the genesis state snapshot"
    );
    let checked = check_fork_chunk(&db, s, point, "genesis snapshot")
        .and_then(|_| rebuild_shard_root(&db, s, point.fork_height, network))
        .and_then(|root| {
            if root.as_slice() != expected.as_slice() {
                return Err(format!(
                    "the genesis state snapshot of shard {} has the Keccak root {}; the \
                     certified PivotRecord has {}",
                    s,
                    hex::encode(root),
                    hex::encode(expected)
                ));
            }
            info!(
                shard = s,
                root = hex::encode(root),
                "The genesis state snapshot has the certified root"
            );
            walk_stores(&db, &staging.join(format!("walk-{}", s)), s, network)
        })
        .and_then(|_| drop_history(&db, point.fork_height));
    db.close();
    checked
}

/// The store walk of `db` (FIP §17.5): each object in the stores is in the
/// Keccak trie, and the store records are the records that the objects
/// derive. `scratch` gets the derived records, and it is removed after.
pub(crate) fn walk_stores(
    db: &Arc<crate::storage::db::RocksDB>,
    scratch: &Path,
    shard: u32,
    network: FarcasterNetwork,
) -> Result<(), String> {
    if scratch.exists() {
        std::fs::remove_dir_all(scratch).map_err(|e| e.to_string())?;
    }
    let derived = open(scratch)?;
    let result = offline_stores(&derived, shard, network)
        .and_then(|stores| state_walk::check(db, &stores))
        .map_err(|e| format!("store walk of shard {}: {}", shard, e));
    derived.close();
    let _ = std::fs::remove_dir_all(scratch);
    result.map(|_| ())
}

/// Delete the history that the snapshot does not prove: the hub events, and
/// the chunks before `fork_height`.
fn drop_history(db: &crate::storage::db::RocksDB, fork_height: u64) -> Result<(), String> {
    let events = RootPrefix::HubEvents as u8;
    state_walk::delete_range(db, &[events], &[events + 1])?;
    let mut stop = vec![RootPrefix::Shard as u8];
    stop.extend_from_slice(&fork_height.to_be_bytes());
    state_walk::delete_range(db, &[RootPrefix::Shard as u8], &stop)?;
    Ok(())
}
