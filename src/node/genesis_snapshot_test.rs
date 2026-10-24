//! The genesis state snapshot (FIP §17.4): a node whose snapchain DBs do not
//! start at the first chunk installs the replay DBs of a node that has the
//! history, and only with the roots of the certified `PivotRecord`.

use super::pivot_boot_test::{boot, fixture, open, Fixture, PIVOT};
use crate::chain::certificate;
use crate::chain::genesis_file;
use crate::chain::shard0::engine::{Shard0Engine, Shard0Proposal};
use crate::chain::shard0::test_support::{params, TestInputs};
use crate::core::consensus_keys::ConsensusDomain;
use crate::node::content_replay::replay_db_path;
use crate::node::genesis_snapshot::{
    export, install, shards_without_history, staged_db_path, verify_certified_pivot,
};
use crate::node::pivot_boot::{
    check_marker, finish_content_replay, prepare, snapchain_db_path, BootSource, MarkerState,
    PivotBoot,
};
use crate::proto::{self, FarcasterNetwork, HypersnapBlock, PivotRecord};
use crate::storage::constants::RootPrefix;
use crate::storage::db::{snapshot, PageOptions};
use crate::storage::store::shard::ShardStore;
use crate::storage::store::test_helper;
use prost::Message as _;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// The marker, the boot of a node with the history, and its shard-0 pivot
/// block with the certificate of the bootstrap set.
async fn certified_pivot(
    f: &Fixture,
    dir: &Path,
    p: &crate::chain::shard0::Shard0Params,
) -> (PivotRecord, PivotBoot, HypersnapBlock) {
    let MarkerState::Pivot(marker) = check_marker(&f.rocks, dir, Some(PIVOT)).unwrap() else {
        panic!("no marker");
    };
    let a = boot(f, dir, p).await;
    let mut engine = Shard0Engine::new(
        open(&dir.join("shard0")),
        p.clone(),
        a.shard0_parent.clone(),
    )
    .unwrap();
    let inputs = TestInputs {
        pivot: Some(a.record.clone()),
        ..Default::default()
    };
    let mut block = engine
        .propose(
            &inputs,
            Shard0Proposal {
                timestamp: f.fork_ts + 12,
                shard_links: a.shards.values().map(|g| g.link.clone()).collect(),
                ..Default::default()
            },
        )
        .unwrap();
    let set = engine.epoch_set(1).unwrap().unwrap();
    // `set(1)` of the file alone is the set of the genesis state.
    let fork: [u8; 32] = a.record.fork_block_hash.as_slice().try_into().unwrap();
    assert_eq!(
        genesis_file::epoch1_set(&f.file, FarcasterNetwork::Devnet, &fork)
            .unwrap()
            .record,
        set.record
    );
    let height = block.header.as_ref().unwrap().height;
    let signatures: BTreeMap<_, _> = f
        .consensus
        .iter()
        .map(|k| {
            let address = k.public_key().address();
            let bytes = certificate::precommit_sign_bytes(0, height, 0, &block.hash, &address);
            (address, k.sign(ConsensusDomain::Vote, &bytes))
        })
        .collect();
    block.certificate =
        Some(certificate::build(&set, 0, height, 0, &block.hash, &signatures).unwrap());
    drop(engine);
    (marker, a, block)
}

/// The snapshot of the replay DBs of `f`, unpacked into `staging`, as a
/// download makes it.
async fn exported(f: &Fixture, marker: &PivotRecord, record: &PivotRecord, work: &Path) -> PathBuf {
    let staging = work.join("staging");
    for (shard, dir) in export(
        &f.rocks,
        marker,
        Some(record),
        &work.join("backup"),
        FarcasterNetwork::Devnet,
    )
    .unwrap()
    {
        let mut chunks: Vec<String> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().path().to_string_lossy().into_owned())
            .collect();
        chunks.sort();
        snapshot::unpack_chunks(
            &chunks,
            work.join(format!("shard_{}.tar", shard)).to_str().unwrap(),
            staging.to_str().unwrap(),
            shard,
        )
        .await
        .unwrap();
    }
    staging
}

/// The RocksDB directory of a node that synced from a snapchain snapshot:
/// the shard-0 DB with the marker, and shard DBs that start at `H_s`.
async fn node_without_history(f: &Fixture, marker: &PivotRecord, rocks: &Path) {
    std::fs::create_dir_all(rocks).unwrap();
    for s in [0u32, 1, 2] {
        let db = open(&snapchain_db_path(&f.rocks, s));
        db.create_checkpoint(snapchain_db_path(rocks, s).to_str().unwrap())
            .unwrap();
        db.close();
    }
    for point in &marker.shard_forks {
        let db = open(&snapchain_db_path(rocks, point.shard_id));
        ShardStore::new(db.clone(), point.shard_id)
            .prune_until(
                point.fork_height,
                &PageOptions::default(),
                std::time::Duration::ZERO,
            )
            .await
            .unwrap();
        assert_eq!(
            ShardStore::new(db.clone(), point.shard_id)
                .min_block_number()
                .unwrap(),
            point.fork_height
        );
        db.close();
    }
}

#[tokio::test]
async fn a_node_without_the_history_installs_the_certified_genesis_snapshot() {
    let f = fixture().await;
    let mut p = params();
    p.epochs.pivot_height_0 = PIVOT;
    let work = tempfile::TempDir::new().unwrap();
    let (marker, a, block) = certified_pivot(&f, &work.path().join("a"), &p).await;
    let record = a.record.clone();

    // The certified record: the pivot block names it, and set(1) signed it.
    verify_certified_pivot(&record, &block, &marker, &f.file, FarcasterNetwork::Devnet).unwrap();
    let mut other = record.clone();
    other.fname_cursor += 1;
    let err = verify_certified_pivot(&other, &block, &marker, &f.file, FarcasterNetwork::Devnet)
        .unwrap_err();
    assert!(err.contains("names another PivotRecord"), "{}", err);
    let mut uncertified = block.clone();
    uncertified.certificate = None;
    assert!(verify_certified_pivot(
        &record,
        &uncertified,
        &marker,
        &f.file,
        FarcasterNetwork::Devnet
    )
    .is_err());
    // Two of the four signers: no quorum.
    let mut weak = block.clone();
    let cert = weak.certificate.as_mut().unwrap();
    cert.signer_bitmap[0] &= 0x3f;
    if let Some(proto::commit_certificate::Form::Bundled(b)) = cert.form.as_mut() {
        b.signatures.drain(..2);
    }
    assert!(
        verify_certified_pivot(&record, &weak, &marker, &f.file, FarcasterNetwork::Devnet).is_err()
    );

    let staging = exported(&f, &marker, &record, work.path()).await;
    let rocks = work.path().join("rocks-b");
    node_without_history(&f, &marker, &rocks).await;
    assert_eq!(shards_without_history(&rocks, &marker).unwrap(), vec![1, 2]);
    // The node with the history needs no snapshot.
    assert!(shards_without_history(&f.rocks, &marker)
        .unwrap()
        .is_empty());

    install(
        &staging,
        &rocks,
        &marker,
        &record,
        FarcasterNetwork::Devnet,
        &[1, 2],
    )
    .unwrap();
    assert!(!staging.exists());
    assert!(shards_without_history(&rocks, &marker).unwrap().is_empty());
    // The history that the snapshot does not prove is gone: no hub events,
    // and no chunk before H_s.
    for point in &marker.shard_forks {
        let db = open(&replay_db_path(&rocks, point.shard_id));
        let events = RootPrefix::HubEvents as u8;
        let mut any_event = false;
        db.for_each_iterator_by_prefix_paged(
            Some(vec![events]),
            Some(vec![events + 1]),
            &PageOptions::default(),
            |_, _| {
                any_event = true;
                Ok(true)
            },
        )
        .unwrap();
        assert!(!any_event, "shard {} keeps hub events", point.shard_id);
        assert_eq!(
            ShardStore::new(db.clone(), point.shard_id)
                .min_block_number()
                .unwrap(),
            point.fork_height
        );
        db.close();
    }
    finish_content_replay(
        &rocks,
        &marker,
        FarcasterNetwork::Devnet,
        test_helper::statsd_client(),
    )
    .await
    .unwrap();
    let data = work.path().join("b");
    let b = prepare(
        &BootSource {
            rocksdb_dir: &rocks,
            data_dir: &data,
            params: &p,
            genesis_file: &f.file,
            expected_genesis_hash: Some(crate::chain::pivot::genesis_validators_hash(&f.file)),
            recoveries: &[],
            certified: Some(&record),
        },
        &marker,
    )
    .unwrap();
    assert_eq!(b.record, record);
}

/// Change the text of the cast of the fixture in a staged DB.
fn forge_cast(db_path: &Path) {
    let db = open(db_path);
    let mut forged = None;
    db.for_each_iterator_by_prefix_paged(
        Some(vec![RootPrefix::User as u8]),
        Some(vec![RootPrefix::User as u8 + 1]),
        &PageOptions::default(),
        |key, value| {
            if let Ok(mut m) = proto::Message::decode(value) {
                if let Some(proto::message_data::Body::CastAddBody(body)) =
                    m.data.as_mut().and_then(|d| d.body.as_mut())
                {
                    if body.text == "before the pivot" {
                        body.text = "forged".into();
                        forged = Some((key.to_vec(), m.encode_to_vec()));
                        return Ok(true);
                    }
                }
            }
            Ok(false)
        },
    )
    .unwrap();
    let (key, value) = forged.expect("the cast is in the snapshot");
    db.put(&key, &value).unwrap();
    db.close();
}

#[tokio::test]
async fn a_genesis_snapshot_with_another_state_is_rejected() {
    let f = fixture().await;
    let mut p = params();
    p.epochs.pivot_height_0 = PIVOT;
    let work = tempfile::TempDir::new().unwrap();
    let (marker, a, _) = certified_pivot(&f, &work.path().join("a"), &p).await;
    let record = a.record.clone();
    let rocks = work.path().join("rocks-b");
    node_without_history(&f, &marker, &rocks).await;

    // One changed message.
    let staging = exported(&f, &marker, &record, work.path()).await;
    forge_cast(&staged_db_path(&staging, 1));
    let err = install(
        &staging,
        &rocks,
        &marker,
        &record,
        FarcasterNetwork::Devnet,
        &[1, 2],
    )
    .unwrap_err();
    assert!(err.contains("Keccak root"), "{}", err);
    assert!(!staging.exists());
    for s in [1u32, 2] {
        assert!(!replay_db_path(&rocks, s).exists());
    }

    // A record with another root.
    let staging = exported(&f, &marker, &record, &work.path().join("again")).await;
    let mut other = record.clone();
    other.genesis_state_roots[2] = vec![7u8; 32];
    let err = install(
        &staging,
        &rocks,
        &marker,
        &other,
        FarcasterNetwork::Devnet,
        &[1, 2],
    )
    .unwrap_err();
    assert!(err.contains("shard 2"), "{}", err);
    assert!(!replay_db_path(&rocks, 1).exists());
}
