//! The first start of a Hypersnap validator after the pivot marker (FIP
//! §17.5 steps 5-12, §17.8; plan WS8).
//!
//! A snapchain read node stops when shard 0 has applied the fork block and
//! every shard is at its fork height, with the marker in its shard-0 DB
//! (`consensus::pivot_guard`). At the next start, `prepare` builds the
//! genesis state:
//!
//! 0. `finish_content_replay` (before `prepare`) runs the content replay of
//!    each shard to `H_s` (`node::content_replay`).
//! 1. It checks the fork block, and the chunk at `H_s` of each shard in the
//!    snapchain DB and in the replay DB.
//! 2. It makes RocksDB checkpoints (hard links) of the snapchain shard-0 DB
//!    and of the replay DBs in a build directory. These DBs do not change,
//!    so a rollback can continue the snapchain sync and the replay (§17.8).
//! 3. It checks the genesis validator file against `GENESIS_VALIDATORS_HASH`.
//! 4. It takes the Keccak root of each shard at `H_s` from the replay's
//!    trie, which is live at `H_s`.
//! 5. It builds the shard-0 genesis and the `PivotRecord` (`chain::pivot`).
//! 6. It renames the build directory to the Hypersnap data directory. A
//!    crash before this step leaves no partial state.
//!
//! Layout of the data directory: `node::hypersnap_node`, plus
//! `pivot_record.pb`.
//!
//! `prune_pre_pivot_history` (an operator option, §17.7) removes the
//! snapchain history after the shard-0 pivot block is certified.

use crate::chain::block::ParentInfo;
use crate::chain::genesis_file;
use crate::chain::pivot::{build_genesis, genesis_validators_hash, PivotInputs};
use crate::chain::shard0::Shard0Params;
use crate::consensus::pivot_guard;
use crate::node::content_replay::{self, ContentReplay};
use crate::node::hypersnap_node::ShardGenesis;
use crate::proto::{
    FarcasterNetwork, GenesisValidatorFile, HyperRecoveryEvent, PivotRecord, ShardLink,
};
use crate::storage::db::{RocksDB, RocksDbTransactionBatch};
use crate::storage::store::block::BlockStore;
use crate::storage::store::shard::ShardStore;
use crate::storage::store::stores::{StoreLimits, Stores};
use crate::storage::trie::merkle_trie::MerkleTrie;
use crate::storage::trie::shadow_backfill;
use crate::storage::trie::shadow_trie::{self, ShadowStatus, ShadowTrie};
use crate::utils::statsd_wrapper::StatsdClientWrapper;
use prost::Message as _;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::{info, warn};

pub const PIVOT_RECORD_FILE: &str = "pivot_record.pb";

/// The DB of shard `shard` in the snapchain read-node layout.
pub fn snapchain_db_path(rocksdb_dir: &Path, shard: u32) -> PathBuf {
    rocksdb_dir.join(format!("shard-{}", shard))
}

fn build_dir(data_dir: &Path) -> PathBuf {
    let mut name = data_dir.file_name().unwrap_or_default().to_os_string();
    name.push(".pivot-build");
    data_dir.with_file_name(name)
}

pub(crate) fn open(path: &Path) -> Result<Arc<RocksDB>, String> {
    let db = RocksDB::new(path.to_str().ok_or("the path is not UTF-8")?);
    db.open()
        .map_err(|e| format!("{}: {}", path.display(), e))?;
    Ok(Arc::new(db))
}

fn hash32(bytes: &[u8], what: &str) -> Result<[u8; 32], String> {
    bytes
        .try_into()
        .map_err(|_| format!("{} is not 32 bytes", what))
}

/// The marker in the snapchain shard-0 DB, if there is one.
pub fn read_marker(rocksdb_dir: &Path) -> Option<PivotRecord> {
    finish_marker_swap(rocksdb_dir);
    let path = snapchain_db_path(rocksdb_dir, 0);
    if !path.exists() {
        return None;
    }
    let db = open(&path).ok()?;
    let marker = pivot_guard::read_marker(&db);
    db.close();
    marker
}

#[derive(Debug, PartialEq)]
pub enum MarkerState {
    /// No marker: a snapchain read node.
    None,
    /// The fork block is applied: start as a Hypersnap node.
    Pivot(PivotRecord),
    /// The marker was for another `PIVOT_HEIGHT` and is removed: continue
    /// the snapchain sync.
    RolledBack(PivotRecord),
}

/// Compare the marker with the `PIVOT_HEIGHT` of this release (FIP §17.8).
/// A marker of another height is from a pivot that did not get a
/// certificate: remove it, move the Hypersnap data directory aside, and
/// continue the snapchain sync from the old fork block.
pub fn check_marker(
    rocksdb_dir: &Path,
    data_dir: &Path,
    pivot_height: Option<u64>,
) -> Result<MarkerState, String> {
    finish_marker_swap(rocksdb_dir);
    let path = snapchain_db_path(rocksdb_dir, 0);
    if !path.exists() {
        return Ok(MarkerState::None);
    }
    let db = open(&path)?;
    let Some(marker) = pivot_guard::read_marker(&db) else {
        db.close();
        return Ok(MarkerState::None);
    };
    if pivot_height == Some(marker.pivot_height) {
        db.close();
        return Ok(MarkerState::Pivot(marker));
    }
    if let Some(new) = pivot_height {
        if new < marker.pivot_height {
            db.close();
            return Err(format!(
                "the release moves PIVOT_HEIGHT from {} to {}; the node is already past the \
                 new fork block",
                marker.pivot_height, new
            ));
        }
    }
    pivot_guard::delete_marker(&db)?;
    db.close();
    let _ = std::fs::remove_dir_all(build_dir(data_dir));
    if data_dir.exists() {
        let mut aside = data_dir.as_os_str().to_os_string();
        aside.push(format!(".abandoned-{}", marker.pivot_height));
        let aside = PathBuf::from(aside);
        let _ = std::fs::remove_dir_all(&aside);
        std::fs::rename(data_dir, &aside).map_err(|e| e.to_string())?;
        warn!(moved_to = %aside.display(), "Moved the data of the abandoned pivot aside");
    }
    warn!(
        old = marker.pivot_height,
        new = ?pivot_height,
        "Rollback: the pivot marker is removed; the snapchain sync continues"
    );
    Ok(MarkerState::RolledBack(marker))
}

/// Compare `EXEMPT_RECOVERIES` of the release with the `Recover` logs of
/// this node's watcher. The genesis uses the release list; a difference
/// is only a warning.
pub fn check_exempt_recoveries(params: &Shard0Params, recoveries: &[HyperRecoveryEvent]) {
    use crate::chain::exempt_recoveries::{differences, from_watcher};
    let (missing, extra) = differences(&params.exempt_recoveries, &from_watcher(recoveries));
    if missing.is_empty() && extra.is_empty() {
        info!(
            count = params.exempt_recoveries.len(),
            "The recovery watcher agrees with EXEMPT_RECOVERIES"
        );
        return;
    }
    let show = |l: &[(u64, [u8; 32])]| {
        l.iter()
            .take(5)
            .map(|(fid, h)| format!("{} 0x{}", fid, hex::encode(h)))
            .collect::<Vec<_>>()
            .join(", ")
    };
    warn!(
        not_in_watcher = missing.len(),
        not_in_release = extra.len(),
        first_not_in_watcher = show(&missing),
        first_not_in_release = show(&extra),
        "The recovery watcher differs from EXEMPT_RECOVERIES; the genesis uses the release list"
    );
}

/// The DB of the recovery watcher (`hypersnap.recovery_watcher_rpc_url`).
pub fn recoveries_dir(rocksdb_dir: &Path) -> std::path::PathBuf {
    rocksdb_dir.join("recoveries")
}

/// The `Recover` logs that the recovery watcher of this node recorded
/// (`<rocksdb_dir>/recoveries`), to check `EXEMPT_RECOVERIES` (FIP §2) and to
/// make the list (`hypersnap_pivot recovery-list`). A node without them
/// has nothing to check.
pub fn read_recoveries(
    rocksdb_dir: &Path,
    network: FarcasterNetwork,
) -> Result<Vec<HyperRecoveryEvent>, String> {
    let path = recoveries_dir(rocksdb_dir);
    if !path.exists() {
        if network != FarcasterNetwork::Devnet {
            warn!(
                path = %path.display(),
                "No recovery watcher records to check EXEMPT_RECOVERIES"
            );
        }
        return Ok(vec![]);
    }
    let db = open(&path)?;
    let events = crate::chain::recovery_store::RecoveryEventStore::new(db.clone())
        .iter_all()
        .map_err(|e| e.to_string());
    db.close();
    events
}

/// FIP §17.4: run the content replay of each shard to `H_s` from the
/// snapchain DB. A read node with `consensus.content_replay` has done most
/// of it before the fork block.
pub async fn finish_content_replay(
    rocksdb_dir: &Path,
    marker: &PivotRecord,
    network: FarcasterNetwork,
    statsd: StatsdClientWrapper,
) -> Result<(), String> {
    for point in &marker.shard_forks {
        let s = point.shard_id;
        let snap = open(&snapchain_db_path(rocksdb_dir, s))?;
        let mut replay = ContentReplay::open(rocksdb_dir, s, network, statsd.clone()).await?;
        let from = replay.height();
        if from > point.fork_height {
            replay.close();
            snap.close();
            return Err(format!(
                "the content replay of shard {} is at {}, above its fork height {}",
                s, from, point.fork_height
            ));
        }
        if from < point.fork_height {
            info!(
                shard = s,
                from,
                to = point.fork_height,
                "Running the content replay to the fork height"
            );
        }
        let result = replay
            .replay_to(&ShardStore::new(snap.clone(), s), point.fork_height)
            .await;
        let hash = replay.last_hash().map(|h| h.to_vec());
        replay.close();
        snap.close();
        result?;
        if hash.as_deref() != Some(point.chunk_hash.as_slice()) {
            return Err(format!(
                "the content replay of shard {} has another chunk at {}",
                s, point.fork_height
            ));
        }
    }
    Ok(())
}

pub struct BootSource<'a> {
    /// The snapchain DBs (`shard-0`, `shard-1`, ...).
    pub rocksdb_dir: &'a Path,
    pub data_dir: &'a Path,
    pub params: &'a Shard0Params,
    pub genesis_file: &'a GenesisValidatorFile,
    /// `GENESIS_VALIDATORS_HASH` of the release. `None`: no check (devnets).
    pub expected_genesis_hash: Option<[u8; 32]>,
    /// The `Recover` logs of this node's recovery watcher. They only check
    /// `EXEMPT_RECOVERIES` of the release (FIP §2).
    pub recoveries: &'a [HyperRecoveryEvent],
    /// The certified `PivotRecord`, for a node that installed a genesis
    /// state snapshot (`node::genesis_snapshot`). The built record must be
    /// equal to it.
    pub certified: Option<&'a PivotRecord>,
}

/// The genesis of each shard and the `PivotRecord` of this node.
#[derive(Clone, Debug)]
pub struct PivotBoot {
    pub record: PivotRecord,
    /// The parent of the shard-0 pivot block (the fork block).
    pub shard0_parent: ParentInfo,
    pub shards: BTreeMap<u32, ShardGenesis>,
}

/// FIP §17.5 steps 5-12. A data directory that already has a `PivotRecord`
/// is used again.
pub fn prepare(src: &BootSource, marker: &PivotRecord) -> Result<PivotBoot, String> {
    let record_path = src.data_dir.join(PIVOT_RECORD_FILE);
    if record_path.exists() {
        let bytes = std::fs::read(&record_path).map_err(|e| e.to_string())?;
        let record = PivotRecord::decode(bytes.as_slice()).map_err(|e| e.to_string())?;
        if record.pivot_height != marker.pivot_height
            || record.fork_block_hash != marker.fork_block_hash
        {
            return Err(format!(
                "{} is for another pivot than the marker",
                record_path.display()
            ));
        }
        return genesis_points(src.data_dir, record);
    }
    if src.data_dir.exists()
        && std::fs::read_dir(src.data_dir)
            .map_err(|e| e.to_string())?
            .next()
            .is_some()
    {
        return Err(format!(
            "{} has data but no {}; move it away first",
            src.data_dir.display(),
            PIVOT_RECORD_FILE
        ));
    }
    let build = build_dir(src.data_dir);
    if build.exists() {
        warn!(dir = %build.display(), "Removing an interrupted pivot build");
        std::fs::remove_dir_all(&build).map_err(|e| e.to_string())?;
    }
    std::fs::create_dir_all(&build).map_err(|e| e.to_string())?;
    let record = build_in(src, marker, &build)?;
    if let Some(certified) = src.certified {
        let differ = record_differences(&record, certified);
        if !differ.is_empty() {
            return Err(format!(
                "the genesis that this node built is not the certified PivotRecord ({})",
                differ.join(", ")
            ));
        }
    }
    std::fs::write(build.join(PIVOT_RECORD_FILE), record.encode_to_vec())
        .map_err(|e| e.to_string())?;
    if src.data_dir.exists() {
        std::fs::remove_dir(src.data_dir).map_err(|e| e.to_string())?;
    }
    std::fs::rename(&build, src.data_dir).map_err(|e| e.to_string())?;
    info!(
        record_hash = hex::encode(alloy_primitives::keccak256(record.encode_to_vec())),
        "Built the genesis state and the PivotRecord"
    );
    genesis_points(src.data_dir, record)
}

fn build_in(src: &BootSource, marker: &PivotRecord, build: &Path) -> Result<PivotRecord, String> {
    let params = src.params;
    let pivot = marker.pivot_height;
    let network = params.network;

    // Steps 4-5: the fork block and the chunk at H_s of each shard.
    let snap0 = open(&snapchain_db_path(src.rocksdb_dir, 0))?;
    let fork = BlockStore::new(snap0.clone())
        .get_block_by_height(pivot - 1)
        .map_err(|e| e.to_string())?
        .ok_or("the snapchain shard-0 DB has no fork block")?;
    if fork.hash != marker.fork_block_hash {
        return Err("the fork block is not the one in the marker".into());
    }
    let fork_timestamp = fork.header.as_ref().map(|h| h.timestamp).unwrap_or(0);
    snap0
        .create_checkpoint(build.join("shard0").to_str().unwrap())
        .map_err(|e| e.to_string())?;
    snap0.close();
    let mut fname = Some(0u64);
    for point in &marker.shard_forks {
        let s = point.shard_id;
        let snap = open(&snapchain_db_path(src.rocksdb_dir, s))?;
        check_fork_chunk(&snap, s, point, "snapchain")?;
        // The replay DB keeps only its last chunks.
        fname = match (fname, fname_cursor(&snap, s, point.fork_height)) {
            (Some(a), Some(b)) => Some(a.max(b)),
            _ => None,
        };
        snap.close();
        let db = open(&content_replay::replay_db_path(src.rocksdb_dir, s))?;
        let checked = check_fork_chunk(&db, s, point, "content replay");
        if checked.is_ok() {
            db.create_checkpoint(build.join(format!("shard{}", s)).to_str().unwrap())
                .map_err(|e| e.to_string())?;
        }
        db.close();
        checked?;
    }

    // A node without the chunk history may not find the last fname transfer;
    // the certified record has it.
    let fname = match (fname, src.certified) {
        (Some(f), _) => f,
        (None, Some(c)) => c.fname_cursor,
        (None, None) => {
            return Err(
                "the snapchain chunks of a shard have no fname transfer, and they do \
                        not start at the first chunk"
                    .into(),
            )
        }
    };

    // Steps 6-8 (the stateful checks of each entry are in the builder).
    let hash = genesis_validators_hash(src.genesis_file);
    match src.expected_genesis_hash {
        Some(expected) if expected != hash => {
            return Err(format!(
                "the genesis validator file hash {} is not GENESIS_VALIDATORS_HASH {}",
                hex::encode(hash),
                hex::encode(expected)
            ))
        }
        Some(_) => {}
        None => warn!(
            hash = hex::encode(hash),
            "No GENESIS_VALIDATORS_HASH in this release; the file is not checked"
        ),
    }
    for entry in &src.genesis_file.validators {
        genesis_file::check_entry(entry, network)?;
    }

    // Steps 9-12.
    let mut social = BTreeMap::new();
    let mut shard_roots = BTreeMap::new();
    for point in &marker.shard_forks {
        let s = point.shard_id;
        let db = open(&build.join(format!("shard{}", s)))?;
        shard_roots.insert(s, shard_root(&db, s, point.fork_height, network)?);
        social.insert(s, db);
    }
    check_exempt_recoveries(params, src.recoveries);
    let shard0 = open(&build.join("shard0"))?;
    let inputs = PivotInputs {
        params,
        pivot_height: pivot,
        fork_block_hash: hash32(&marker.fork_block_hash, "the fork block hash")?,
        fork_timestamp,
        shard_forks: marker.shard_forks.clone(),
        shard_roots,
        genesis_file: src.genesis_file,
        fname_cursor: fname,
        social: social.clone(),
    };
    let record = build_genesis(&shard0, &inputs).map_err(|e| e.to_string());
    shard0.close();
    for db in social.values() {
        db.close();
    }
    record
}

/// The chunk at `H_s` must be the last chunk of `db`.
pub(crate) fn check_fork_chunk(
    db: &Arc<RocksDB>,
    shard: u32,
    point: &crate::proto::ShardForkPoint,
    what: &str,
) -> Result<(), String> {
    let last = ShardStore::new(db.clone(), shard)
        .get_last_shard_chunk()
        .map_err(|e| e.to_string())?;
    let at = last
        .as_ref()
        .and_then(|c| c.header.as_ref()?.height)
        .map(|h| h.block_number);
    if at != Some(point.fork_height) || last.map(|c| c.hash) != Some(point.chunk_hash.clone()) {
        return Err(format!(
            "the {} DB of shard {} is at {:?}, not at its fork height {}",
            what, shard, at, point.fork_height
        ));
    }
    Ok(())
}

/// The Keccak root of shard `shard` at `height` (FIP §17.4): the trie if it
/// is live at `height`, else a build from the shard state.
fn shard_root(
    db: &Arc<RocksDB>,
    shard: u32,
    height: u64,
    network: FarcasterNetwork,
) -> Result<[u8; 32], String> {
    let status = ShadowStatus::read(db);
    if status == (ShadowStatus::Live { height }) {
        return shadow_trie::report_from_db(db.clone())
            .map(|r| r.root)
            .map_err(|e| e.to_string());
    }
    info!(
        shard,
        height,
        ?status,
        "No live shadow trie at the fork height; building the Keccak trie"
    );
    rebuild_shard_root(db, shard, height, network)
}

/// The stores of a shard DB that no engine runs.
pub(crate) fn offline_stores(
    db: &Arc<RocksDB>,
    shard: u32,
    network: FarcasterNetwork,
) -> Result<Stores, String> {
    Ok(Stores::new(
        db.clone(),
        shard,
        MerkleTrie::new().map_err(|e| e.to_string())?,
        StoreLimits::default(),
        network,
        StatsdClientWrapper::new(
            cadence::StatsdClient::builder("", cadence::NopMetricSink).build(),
            false,
        ),
    ))
}

/// Build the Keccak trie of `db` again from its state at `height`, and mark
/// it live at `height`.
pub(crate) fn rebuild_shard_root(
    db: &Arc<RocksDB>,
    shard: u32,
    height: u64,
    network: FarcasterNetwork,
) -> Result<[u8; 32], String> {
    shadow_backfill::clear_trie_records(db).map_err(|e| e.to_string())?;
    let stores = offline_stores(db, shard, network)?;
    let outcome = shadow_backfill::build_from_snapshot(&stores, db.clone(), height)
        .map_err(|e| e.to_string())?;
    if outcome.unresolved_keys > 0 {
        warn!(
            shard,
            unresolved = outcome.unresolved_keys,
            "Sync-trie keys with no object"
        );
    }
    let root = shadow_backfill::add_gasless_state(db.clone()).map_err(|e| e.to_string())?;
    let mut trie = ShadowTrie::open(db.clone()).map_err(|e| e.to_string())?;
    let mut txn = RocksDbTransactionBatch::new();
    trie.mark_live(height, &mut txn);
    db.commit(txn).map_err(|e| e.to_string())?;
    Ok(root)
}

/// `fname_cursor` (FIP §17.4): the highest fname transfer ID in the shard
/// chunks at or below `height`. Validators include transfers in ID order, so
/// the last chunk with a transfer has the highest one. `None`: no chunk has
/// a transfer, and the DB does not start at the first chunk.
pub fn fname_cursor(db: &Arc<RocksDB>, shard: u32, height: u64) -> Option<u64> {
    let store = ShardStore::new(db.clone(), shard);
    let first = store.min_block_number().unwrap_or(0);
    let mut h = height;
    loop {
        let Ok(Some(chunk)) = store.get_chunk_by_height(h) else {
            return (first <= 1 || h < 1).then_some(0);
        };
        let highest = chunk
            .transactions
            .iter()
            .flat_map(|t| &t.system_messages)
            .filter_map(|m| m.fname_transfer.as_ref())
            .map(|f| f.id)
            .max();
        if let Some(id) = highest {
            return Some(id);
        }
        if h == 0 {
            return Some(0);
        }
        h -= 1;
    }
}

/// The fields in which two records differ.
pub fn record_differences(a: &PivotRecord, b: &PivotRecord) -> Vec<String> {
    let mut out = Vec::new();
    let mut check = |name: &str, same: bool| {
        if !same {
            out.push(name.to_string());
        }
    };
    check("pivot_height", a.pivot_height == b.pivot_height);
    check("fork_block_hash", a.fork_block_hash == b.fork_block_hash);
    check("shard_forks", a.shard_forks == b.shard_forks);
    check(
        "genesis_state_roots",
        a.genesis_state_roots == b.genesis_state_roots,
    );
    check(
        "trust_snapshot_root",
        a.trust_snapshot_root == b.trust_snapshot_root,
    );
    check(
        "genesis_validators_hash",
        a.genesis_validators_hash == b.genesis_validators_hash,
    );
    check("set_root_epoch1", a.set_root_epoch1 == b.set_root_epoch1);
    check("onchain_cursor", a.onchain_cursor == b.onchain_cursor);
    check("fname_cursor", a.fname_cursor == b.fname_cursor);
    check("params_hash", a.params_hash == b.params_hash);
    if out.is_empty() && a != b {
        out.push("other fields".into());
    }
    out
}

/// FIP §17.7 "Pre-pivot history": remove the snapchain history that the node
/// does not use. It removes the shard-0 blocks below the fork block and the
/// chunks below `H_s` of each shard from the data directory (a restart reads
/// the fork block and the chunks at `H_s`), and it replaces the snapchain
/// DBs and the replay DBs with a shard-0 DB that has only the marker. Run it
/// only after the shard-0 pivot block is certified: a rollback needs the
/// history (§17.8).
pub async fn prune_pre_pivot_history(
    rocksdb_dir: &Path,
    record: &PivotRecord,
    shard0: &Arc<RocksDB>,
    shards: &BTreeMap<u32, Arc<RocksDB>>,
) -> Result<(), String> {
    let page = crate::storage::db::PageOptions {
        page_size: Some(crate::storage::constants::PAGE_SIZE_MAX),
        ..Default::default()
    };
    let throttle = std::time::Duration::from_millis(10);
    let blocks = BlockStore::new(shard0.clone())
        .prune_until(record.pivot_height - 1, &page, throttle)
        .await
        .map_err(|e| e.to_string())?;
    let mut chunks = 0;
    for point in &record.shard_forks {
        if let Some(db) = shards.get(&point.shard_id) {
            chunks += ShardStore::new(db.clone(), point.shard_id)
                .prune_until(point.fork_height, &page, throttle)
                .await
                .map_err(|e| e.to_string())?;
        }
    }
    replace_snapchain_dbs(rocksdb_dir, record)?;
    info!(blocks, chunks, "Pruned the pre-pivot history");
    Ok(())
}

fn swap_path(rocksdb_dir: &Path, suffix: &str) -> PathBuf {
    let mut name = snapchain_db_path(rocksdb_dir, 0).into_os_string();
    name.push(".");
    name.push(suffix);
    PathBuf::from(name)
}

/// Keep only the marker of the snapchain DBs, and remove the replay DBs.
/// The new shard-0 DB is written first and then swapped in;
/// `finish_marker_swap` completes a swap that a crash interrupted, so the
/// node does not start without its marker.
fn replace_snapchain_dbs(rocksdb_dir: &Path, record: &PivotRecord) -> Result<(), String> {
    let marker = read_marker(rocksdb_dir).ok_or("no pivot marker in the snapchain shard-0 DB")?;
    if marker.pivot_height != record.pivot_height {
        return Err("the pivot marker is for another pivot".into());
    }
    let fresh = swap_path(rocksdb_dir, "pruned");
    let old = swap_path(rocksdb_dir, "old");
    for dir in [&fresh, &old] {
        if dir.exists() {
            std::fs::remove_dir_all(dir).map_err(|e| e.to_string())?;
        }
    }
    let db = open(&fresh)?;
    pivot_guard::write_marker(&db, &marker).map_err(|e| e.to_string())?;
    db.close();
    let current = snapchain_db_path(rocksdb_dir, 0);
    std::fs::rename(&current, &old).map_err(|e| e.to_string())?;
    std::fs::rename(&fresh, &current).map_err(|e| e.to_string())?;
    std::fs::remove_dir_all(&old).map_err(|e| e.to_string())?;
    for point in &record.shard_forks {
        for path in [
            snapchain_db_path(rocksdb_dir, point.shard_id),
            content_replay::replay_db_path(rocksdb_dir, point.shard_id),
        ] {
            if path.exists() {
                std::fs::remove_dir_all(&path).map_err(|e| e.to_string())?;
            }
        }
    }
    Ok(())
}

/// Complete an interrupted `replace_snapchain_dbs`.
fn finish_marker_swap(rocksdb_dir: &Path) {
    let current = snapchain_db_path(rocksdb_dir, 0);
    let fresh = swap_path(rocksdb_dir, "pruned");
    if !current.exists() && fresh.exists() {
        if let Err(e) = std::fs::rename(&fresh, &current) {
            warn!("Cannot complete the snapchain DB swap: {}", e);
        }
    }
    let old = swap_path(rocksdb_dir, "old");
    if current.exists() && old.exists() {
        let _ = std::fs::remove_dir_all(&old);
    }
}

/// The parents and the genesis links of the pivot blocks, from the data
/// directory and the record.
fn genesis_points(data_dir: &Path, record: PivotRecord) -> Result<PivotBoot, String> {
    let shard0 = open(&data_dir.join("shard0"))?;
    let fork = BlockStore::new(shard0.clone())
        .get_block_by_height(record.pivot_height - 1)
        .map_err(|e| e.to_string())?
        .ok_or("no fork block in the shard-0 DB")?;
    shard0.close();
    let shard0_parent = ParentInfo {
        height: record.pivot_height - 1,
        hash: hash32(&record.fork_block_hash, "the fork block hash")?,
        timestamp: fork.header.as_ref().map(|h| h.timestamp).unwrap_or(0),
        epoch_ref_height: None,
        shard_links: vec![],
    };
    let mut shards = BTreeMap::new();
    for point in &record.shard_forks {
        let s = point.shard_id;
        let db = open(&data_dir.join(format!("shard{}", s)))?;
        let chunk = ShardStore::new(db.clone(), s)
            .get_chunk_by_height(point.fork_height)
            .map_err(|e| e.to_string())?
            .ok_or_else(|| format!("no chunk at the fork height of shard {}", s))?;
        db.close();
        let root = record
            .genesis_state_roots
            .get(s as usize)
            .ok_or_else(|| format!("no genesis root for shard {}", s))?;
        shards.insert(
            s,
            ShardGenesis {
                parent: ParentInfo {
                    height: point.fork_height,
                    hash: hash32(&point.chunk_hash, "a chunk hash")?,
                    timestamp: chunk.header.as_ref().map(|h| h.timestamp).unwrap_or(0),
                    epoch_ref_height: None,
                    shard_links: vec![],
                },
                link: ShardLink {
                    shard_id: s,
                    height: point.fork_height,
                    block_hash: point.chunk_hash.clone(),
                    state_root: root.clone(),
                },
            },
        );
    }
    Ok(PivotBoot {
        record,
        shard0_parent,
        shards,
    })
}
