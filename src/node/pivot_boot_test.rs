//! WS8 end to end in one process: a read node's snapchain DBs at the fork
//! block, two independent boots from the marker, the shard-0 pivot block,
//! the pivot block of a shard with the genesis replica, and a rollback.

use crate::chain::block::seal;
use crate::chain::certificate;
use crate::chain::genesis_file;
use crate::chain::shard0::engine::{Shard0Engine, Shard0Proposal};
use crate::chain::shard0::keys;
use crate::chain::shard0::test_support::{params, TestInputs};
use crate::chain::shard_blocks::{ProposalInputs, ShardBlockProducer, ValidationInputs};
use crate::consensus::pivot_guard;
use crate::core::consensus_keys::{ConsensusDomain, ConsensusPrivateKey};
use crate::node::pivot_boot::{
    check_marker, finish_content_replay, prepare, prune_pre_pivot_history, snapchain_db_path,
    BootSource, MarkerState, PivotBoot,
};
use crate::proto::{
    self, FarcasterNetwork, GenesisValidatorFile, Height, IdRegisterEventType, PivotRecord,
    ShardForkPoint,
};
use crate::storage::db::RocksDB;
use crate::storage::store::account::{OnchainEventStore, StoreEventHandler, StoreOptions};
use crate::storage::store::block::BlockStore;
use crate::storage::store::engine::ShardEngine;
use crate::storage::store::stores::StoreLimits;
use crate::storage::store::test_helper::{self, EngineOptions};
use crate::storage::trie::merkle_trie::MerkleTrie;
use crate::storage::trie::shadow_trie::ShadowStatus;
use crate::utils::factory::{events_factory, messages_factory};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use prost::Message as _;
use rand::SeedableRng;
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

pub(super) const PIVOT: u64 = 100;

pub(super) fn open(path: &Path) -> Arc<RocksDB> {
    let db = Arc::new(RocksDB::new(path.to_str().unwrap()));
    db.open().unwrap();
    db
}

pub(super) struct Fixture {
    _dir: tempfile::TempDir,
    pub(super) rocks: std::path::PathBuf,
    pub(super) file: GenesisValidatorFile,
    pub(super) consensus: Vec<ConsensusPrivateKey>,
    pub(super) fork_ts: u64,
}

/// A user with a cast on one shard, in the snapchain layout.
async fn snapchain_shard(rocks: &Path, shard: u32, fid: u64) -> (u64, Vec<u8>) {
    let db = open(&snapchain_db_path(rocks, shard));
    let (mut engine, _tmp) = test_helper::new_engine_with_options(EngineOptions {
        db: Some(db.clone()),
        shard_id: shard,
        ..Default::default()
    })
    .await;
    let signer = test_helper::default_signer();
    for event in [
        test_helper::default_storage_event(fid),
        events_factory::create_id_register_event(
            fid,
            IdRegisterEventType::Register,
            test_helper::default_custody_address(),
            None,
        ),
        events_factory::create_signer_event(
            fid,
            signer.clone(),
            proto::SignerEventType::Add,
            None,
            None,
        ),
    ] {
        test_helper::commit_event(&mut engine, &event).await;
    }
    let cast =
        messages_factory::casts::create_cast_add(fid, "before the pivot", None, Some(&signer));
    test_helper::commit_message(&mut engine, &cast).await;
    let chunk = engine.get_last_shard_chunk().unwrap();
    let height = chunk.header.as_ref().unwrap().height.unwrap().block_number;
    drop(engine);
    db.close();
    (height, chunk.hash)
}

/// Snapchain DBs of a read node that stopped at the fork block of `PIVOT`.
pub(super) async fn fixture() -> Fixture {
    let dir = tempfile::TempDir::new().unwrap();
    let rocks = dir.path().join("rocks");
    std::fs::create_dir_all(&rocks).unwrap();
    let fork_ts = messages_factory::farcaster_time() as u64;

    let (h1, c1) = snapchain_shard(&rocks, 1, test_helper::FID_FOR_TEST).await;
    let (h2, c2) = snapchain_shard(&rocks, 2, 4_321).await;

    let eths: Vec<PrivateKeySigner> = (1..=4u8)
        .map(|i| PrivateKeySigner::from_bytes(&[i + 10; 32].into()).unwrap())
        .collect();
    let shard0 = open(&snapchain_db_path(&rocks, 0));
    let store = OnchainEventStore::new(shard0.clone(), StoreEventHandler::new());
    let mut txn = crate::storage::db::RocksDbTransactionBatch::new();
    for (i, eth) in eths.iter().enumerate() {
        let fid = i as u64 + 1;
        let mut e = events_factory::create_id_register_event(
            fid,
            IdRegisterEventType::Register,
            eth.address().to_vec(),
            None,
        );
        e.block_timestamp = 1_600_000_000;
        store.merge_onchain_event(e, &mut txn).unwrap();
    }
    shard0.commit(txn).unwrap();
    let blocks = BlockStore::new(shard0.clone());
    for (height, ts) in [(PIVOT - 2, fork_ts - 1), (PIVOT - 1, fork_ts)] {
        blocks
            .put_block(&proto::Block {
                header: Some(proto::BlockHeader {
                    height: Some(Height::new(0, height)),
                    timestamp: ts,
                    ..Default::default()
                }),
                hash: vec![height as u8; 32],
                shard_witness: Some(proto::ShardWitness {
                    shard_chunk_witnesses: vec![
                        proto::ShardChunkWitness {
                            height: Some(Height::new(1, h1)),
                            shard_root: vec![],
                            shard_hash: c1.clone(),
                        },
                        proto::ShardChunkWitness {
                            height: Some(Height::new(2, h2)),
                            shard_root: vec![],
                            shard_hash: c2.clone(),
                        },
                    ],
                }),
                ..Default::default()
            })
            .unwrap();
    }
    // What the read node's guard writes after the fork block.
    let guard = pivot_guard::PivotGuard::new(PIVOT, blocks, vec![1, 2]);
    guard.record_height(1, h1);
    let marker = guard.record_height(2, h2).expect("the pivot is ready");
    pivot_guard::write_marker(&shard0, &marker).unwrap();
    shard0.close();

    let mut consensus = Vec::new();
    let mut entries = Vec::new();
    for (i, eth) in eths.iter().enumerate() {
        let fid = i as u64 + 1;
        let custody = hypersnap_falcon::keygen_from_seed([fid as u8 + 40; 32]);
        let node = hypersnap_falcon::keygen_from_seed([fid as u8 + 60; 32]);
        let consensus_key = hypersnap_falcon::keygen_from_seed([fid as u8 + 80; 32]);
        let keys = genesis_file::EntryKeys {
            fid,
            network: FarcasterNetwork::Devnet,
            timestamp: fork_ts as u32,
            deadline: (fork_ts + 3_600) as u32,
            custody: &custody,
            node: &node,
            consensus: &consensus_key,
        };
        let sig = eth
            .sign_hash_sync(&genesis_file::custody_migration_hash(&keys).into())
            .unwrap()
            .as_bytes()
            .to_vec();
        let mut rng = rand_chacha::ChaCha20Rng::from_seed([fid as u8; 32]);
        entries.push(genesis_file::entry(&keys, sig, &mut rng).unwrap());
        consensus.push(ConsensusPrivateKey::falcon(consensus_key));
    }
    Fixture {
        _dir: dir,
        rocks,
        file: genesis_file::assemble(entries, FarcasterNetwork::Devnet).unwrap(),
        consensus,
        fork_ts,
    }
}

pub(super) async fn boot(
    f: &Fixture,
    data_dir: &Path,
    p: &crate::chain::shard0::Shard0Params,
) -> PivotBoot {
    let MarkerState::Pivot(marker) = check_marker(&f.rocks, data_dir, Some(PIVOT)).unwrap() else {
        panic!("no marker");
    };
    if !data_dir
        .join(crate::node::pivot_boot::PIVOT_RECORD_FILE)
        .exists()
    {
        finish_content_replay(
            &f.rocks,
            &marker,
            FarcasterNetwork::Devnet,
            test_helper::statsd_client(),
        )
        .await
        .unwrap();
    }
    prepare(
        &BootSource {
            rocksdb_dir: &f.rocks,
            data_dir,
            params: p,
            genesis_file: &f.file,
            expected_genesis_hash: Some(crate::chain::pivot::genesis_validators_hash(&f.file)),
            recoveries: &[],
            certified: None,
        },
        &marker,
    )
    .unwrap()
}

async fn shard_engine(db: Arc<RocksDB>, shard: u32, fork_height: u64) -> ShardEngine {
    let mut engine = ShardEngine::new_with_opts(
        db,
        FarcasterNetwork::Devnet,
        MerkleTrie::new().unwrap(),
        shard,
        StoreLimits::default(),
        test_helper::statsd_client(),
        1_000,
        None,
        None,
        None,
        StoreOptions::default(),
    )
    .await
    .unwrap();
    engine
        .enter_hypersnap_mode(
            Some(fork_height),
            crate::version::version::EngineVersion::latest(),
        )
        .unwrap();
    engine
}

#[tokio::test]
async fn two_nodes_boot_from_the_marker_and_agree_on_the_pivot_blocks() {
    let f = fixture().await;
    let mut p = params();
    p.epochs.pivot_height_0 = PIVOT;
    let work = tempfile::TempDir::new().unwrap();
    let (dir_a, dir_b) = (work.path().join("a"), work.path().join("b"));

    let a = boot(&f, &dir_a, &p).await;
    let b = boot(&f, &dir_b, &p).await;
    assert_eq!(a.record, b.record, "independent boots agree");
    let record = a.record.clone();
    assert_eq!(record.pivot_height, PIVOT);
    assert_eq!(record.genesis_state_roots.len(), 3);
    for (s, g) in &a.shards {
        assert_eq!(g.link.state_root, record.genesis_state_roots[*s as usize]);
        assert_eq!(g.parent.epoch_ref_height, None);
    }
    // A boot again uses the built directory.
    assert_eq!(boot(&f, &dir_a, &p).await.record, record);

    // The snapchain DBs are unchanged: no Keccak trie, the marker kept.
    for s in [1u32, 2] {
        let db = open(&snapchain_db_path(&f.rocks, s));
        assert_eq!(ShadowStatus::read(&db), ShadowStatus::Absent);
        db.close();
    }
    let db = open(&snapchain_db_path(&f.rocks, 0));
    assert!(pivot_guard::read_marker(&db).is_some());
    db.close();

    // The shard-0 pivot block: proposed on node A, valid on node B, certified
    // by the bootstrap set.
    let mut engines: Vec<Shard0Engine> = [&dir_a, &dir_b]
        .iter()
        .map(|d| {
            Shard0Engine::new(open(&d.join("shard0")), p.clone(), a.shard0_parent.clone()).unwrap()
        })
        .collect();
    let inputs = TestInputs {
        pivot: Some(record.clone()),
        ..Default::default()
    };
    let links: Vec<proto::ShardLink> = a.shards.values().map(|g| g.link.clone()).collect();
    let mut block0 = engines[0]
        .propose(
            &inputs,
            Shard0Proposal {
                timestamp: f.fork_ts + 12,
                shard_links: links,
                ..Default::default()
            },
        )
        .unwrap();
    engines[1]
        .validate(&block0, &inputs, None, u64::MAX)
        .unwrap();
    let set = engines[0].epoch_set(1).unwrap().unwrap();
    let h0 = block0.header.as_ref().unwrap().height;
    let sign = |shard: u32, height: u64, hash: &[u8]| {
        f.consensus
            .iter()
            .map(|k| {
                let address = k.public_key().address();
                let bytes = certificate::precommit_sign_bytes(shard, height, 0, hash, &address);
                (address, k.sign(ConsensusDomain::Vote, &bytes))
            })
            .collect::<BTreeMap<_, _>>()
    };
    block0.certificate =
        Some(certificate::build(&set, 0, h0, 0, &block0.hash, &sign(0, h0, &block0.hash)).unwrap());
    assert_eq!(
        engines[0].commit(&block0).unwrap(),
        engines[1].commit(&block0).unwrap()
    );

    // The pivot block of the shard of a bootstrap FID applies the genesis
    // outbox (PIVOT − 1): the custody record reaches the replica.
    let fid = (1..=4u64)
        .find(|&fid| p.shard_of(fid) == 1)
        .expect("a FID on shard 1");
    let g1 = a.shards[&1].clone();
    let mut producers = Vec::new();
    for (dir, engine0) in [&dir_a, &dir_b].iter().zip(&engines) {
        let db = open(&dir.join("shard1"));
        let engine = shard_engine(db, 1, g1.parent.height).await;
        producers.push(
            ShardBlockProducer::new(engine, p.epochs, g1.parent.clone())
                .with_outbox(Arc::new(engine0.reader()))
                .with_pivot_record(&record),
        );
    }
    let validation = ValidationInputs {
        highest_certified_shard0: PIVOT,
        max_timestamp: u64::MAX,
        parent_set: None,
    };
    let early = producers[0].propose(ProposalInputs {
        timestamp: messages_factory::farcaster_time() as u64 + 1,
        epoch_ref_height: PIVOT - 1,
        messages: vec![],
    });
    let err = producers[1]
        .validate(&early.unwrap(), &validation)
        .unwrap_err()
        .to_string();
    assert!(err.contains("below PIVOT_HEIGHT_0"), "{}", err);
    let block1 = producers[0]
        .propose(ProposalInputs {
            timestamp: messages_factory::farcaster_time() as u64 + 2,
            epoch_ref_height: PIVOT,
            messages: vec![],
        })
        .unwrap();
    let header = block1.header.clone().unwrap();
    assert_eq!(header.height, g1.parent.height + 1);
    assert_eq!(
        header.pivot_record_hash,
        alloy_primitives::keccak256(record.encode_to_vec()).to_vec()
    );
    let mut tampered = block1.clone();
    tampered.header.as_mut().unwrap().pivot_record_hash = vec![0u8; 32];
    seal(&mut tampered);
    let err = producers[1]
        .validate(&tampered, &validation)
        .unwrap_err()
        .to_string();
    assert!(err.contains("pivot_record_hash"), "{}", err);
    producers[1].validate(&block1, &validation).unwrap();

    let h1 = header.height;
    let mut decided = block1.clone();
    decided.certificate =
        Some(certificate::build(&set, 1, h1, 0, &block1.hash, &sign(1, h1, &block1.hash)).unwrap());
    let mut roots = Vec::new();
    for producer in producers.iter_mut() {
        assert!(producer
            .engine
            .db
            .get(&keys::custody(fid))
            .unwrap()
            .is_none());
        roots.push(producer.commit(decided.clone()).await.unwrap());
        assert!(
            producer
                .engine
                .db
                .get(&keys::custody(fid))
                .unwrap()
                .is_some(),
            "the replica has the custody of bootstrap FID {}",
            fid
        );
    }
    assert_eq!(roots[0], roots[1]);
}

#[tokio::test]
async fn a_new_pivot_height_rolls_the_marker_back() {
    let f = fixture().await;
    let mut p = params();
    p.epochs.pivot_height_0 = PIVOT;
    let work = tempfile::TempDir::new().unwrap();
    let data = work.path().join("hypersnap");
    let built = boot(&f, &data, &p).await;

    // The release moves PIVOT_HEIGHT up: the marker goes, the built genesis
    // moves aside, the snapchain DBs stay at the old fork point.
    let state = check_marker(&f.rocks, &data, Some(PIVOT + 50)).unwrap();
    assert!(matches!(state, MarkerState::RolledBack(m) if m.pivot_height == PIVOT));
    assert!(!data.exists());
    assert!(work
        .path()
        .join(format!("hypersnap.abandoned-{}", PIVOT))
        .exists());
    assert_eq!(
        check_marker(&f.rocks, &data, Some(PIVOT + 50)).unwrap(),
        MarkerState::None
    );
    for (s, g) in &built.shards {
        let db = open(&snapchain_db_path(&f.rocks, *s));
        let last = crate::storage::store::shard::ShardStore::new(db.clone(), *s)
            .get_last_shard_chunk()
            .unwrap()
            .unwrap();
        assert_eq!(
            last.header.unwrap().height.unwrap().block_number,
            g.parent.height
        );
        db.close();
    }

    // A release cannot move PIVOT_HEIGHT below a fork block that the node
    // applied.
    let db = open(&snapchain_db_path(&f.rocks, 0));
    pivot_guard::write_marker(
        &db,
        &PivotRecord {
            pivot_height: PIVOT,
            shard_forks: vec![ShardForkPoint::default()],
            ..Default::default()
        },
    )
    .unwrap();
    db.close();
    assert!(check_marker(&f.rocks, &data, Some(PIVOT - 10)).is_err());
}

#[tokio::test]
async fn pruning_keeps_the_marker_the_fork_block_and_the_chunks_at_h_s() {
    let f = fixture().await;
    let mut p = params();
    p.epochs.pivot_height_0 = PIVOT;
    let work = tempfile::TempDir::new().unwrap();
    let data = work.path().join("hypersnap");
    let built = boot(&f, &data, &p).await;
    let record = built.record.clone();

    let shard0 = open(&data.join("shard0"));
    let shards: BTreeMap<u32, Arc<RocksDB>> = built
        .shards
        .keys()
        .map(|s| (*s, open(&data.join(format!("shard{}", s)))))
        .collect();
    let blocks = BlockStore::new(shard0.clone());
    assert!(blocks.get_block_by_height(PIVOT - 2).unwrap().is_some());
    prune_pre_pivot_history(&f.rocks, &record, &shard0, &shards)
        .await
        .unwrap();

    // The data directory keeps the fork block and the chunks at `H_s`.
    assert!(blocks.get_block_by_height(PIVOT - 2).unwrap().is_none());
    assert!(blocks.get_block_by_height(PIVOT - 1).unwrap().is_some());
    for (s, g) in &built.shards {
        let store = crate::storage::store::shard::ShardStore::new(shards[s].clone(), *s);
        assert!(store
            .get_chunk_by_height(g.parent.height)
            .unwrap()
            .is_some());
        assert!(store.get_chunk_by_height(1).unwrap().is_none() || g.parent.height == 1);
    }
    shard0.close();
    for db in shards.values() {
        db.close();
    }

    // The snapchain DBs: only shard 0, with only the marker.
    for s in [1u32, 2] {
        assert!(!snapchain_db_path(&f.rocks, s).exists());
        assert!(!crate::node::content_replay::replay_db_path(&f.rocks, s).exists());
    }
    let db = open(&snapchain_db_path(&f.rocks, 0));
    assert!(BlockStore::new(db.clone())
        .get_block_by_height(PIVOT - 1)
        .unwrap()
        .is_none());
    db.close();
    // The node still starts as a Hypersnap node with the same genesis.
    assert_eq!(boot(&f, &data, &p).await.record, record);

    // A swap that a crash interrupted is completed at the next start.
    std::fs::rename(
        snapchain_db_path(&f.rocks, 0),
        f.rocks.join("shard-0.pruned"),
    )
    .unwrap();
    assert!(matches!(
        check_marker(&f.rocks, &data, Some(PIVOT)).unwrap(),
        MarkerState::Pivot(_)
    ));
}
