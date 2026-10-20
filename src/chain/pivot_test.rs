//! WS8 rehearsal in one process: two nodes build the genesis from the same
//! epoch-0 state and get the same `PivotRecord`; the pivot block made on one
//! is valid on the other.

use crate::chain::block::{block_hash, ParentInfo};
use crate::chain::certificate;
use crate::chain::genesis_file;
use crate::chain::pivot::{build_genesis, genesis_validators_hash, PivotInputs};
use crate::chain::shard0::auth::test_keys::*;
use crate::chain::shard0::engine::{Shard0Engine, Shard0Proposal};
use crate::chain::shard0::keys::{self, FidClock};
use crate::chain::shard0::state::BlockState;
use crate::chain::shard0::test_support::{params, TestInputs};
use crate::core::consensus_keys::{ConsensusDomain, ConsensusPrivateKey};
use crate::proto::{
    self, FarcasterNetwork, GenesisValidator, IdRegisterEventType, OnChainEvent, ShardForkPoint,
    ShardLink,
};
use crate::storage::db::RocksDB;
use crate::storage::store::account::{OnchainEventStore, StoreEventHandler};
use alloy_signer_local::PrivateKeySigner;
use prost::Message as _;
use rand::SeedableRng;
use std::collections::BTreeMap;
use std::sync::Arc;

const PIVOT: u64 = 100;
const FORK_HASH: [u8; 32] = [9u8; 32];
/// Farcaster time of the fork block.
const FORK_TS: u64 = 160_000_000;

fn id_event(
    fid: u64,
    custody: &[u8],
    kind: IdRegisterEventType,
    ts: u64,
    tx: u8,
    log: u32,
) -> OnChainEvent {
    OnChainEvent {
        r#type: proto::OnChainEventType::EventTypeIdRegister as i32,
        chain_id: 10,
        block_number: (ts / 2) as u32,
        block_timestamp: ts,
        transaction_hash: vec![tx; 32],
        log_index: log,
        fid,
        version: 1,
        body: Some(proto::on_chain_event::Body::IdRegisterEventBody(
            proto::IdRegisterEventBody {
                to: custody.to_vec(),
                event_type: kind as i32,
                ..Default::default()
            },
        )),
        ..Default::default()
    }
}

struct Validator {
    consensus: ConsensusPrivateKey,
    entry: GenesisValidator,
}

/// A genesis entry: migration, attestation, registration (FIP §17.3).
fn validator(fid: u64, eth: &PrivateKeySigner) -> Validator {
    let custody = falcon(fid as u8 + 40);
    let node = falcon(fid as u8 + 60);
    let consensus = falcon(fid as u8 + 80);
    let keys = genesis_file::EntryKeys {
        fid,
        network: FarcasterNetwork::Devnet,
        timestamp: FORK_TS as u32,
        deadline: (FORK_TS + 3_600) as u32,
        custody: &custody,
        node: &node,
        consensus: &consensus,
    };
    let signature = {
        use alloy_signer::SignerSync;
        eth.sign_hash_sync(&genesis_file::custody_migration_hash(&keys).into())
            .unwrap()
            .as_bytes()
            .to_vec()
    };
    let mut rng = rand_chacha::ChaCha20Rng::from_seed([fid as u8; 32]);
    let entry = genesis_file::entry(&keys, signature, &mut rng).unwrap();
    Validator {
        consensus: ConsensusPrivateKey::falcon(consensus),
        entry,
    }
}

fn open(dir: &tempfile::TempDir, name: &str) -> Arc<RocksDB> {
    let db = Arc::new(RocksDB::new(dir.path().join(name).to_str().unwrap()));
    db.open().unwrap();
    db
}

/// The epoch-0 shard-0 state: registrations long ago, one exempt recovery
/// transfer, one normal transfer.
fn epoch0(db: &Arc<RocksDB>, eths: &[PrivateKeySigner]) {
    let store = OnchainEventStore::new(db.clone(), StoreEventHandler::new());
    let mut txn = crate::storage::db::RocksDbTransactionBatch::new();
    for (i, eth) in eths.iter().enumerate() {
        let fid = i as u64 + 1;
        store
            .merge_onchain_event(
                id_event(
                    fid,
                    eth.address().as_slice(),
                    IdRegisterEventType::Register,
                    1_600_000_000,
                    fid as u8,
                    0,
                ),
                &mut txn,
            )
            .unwrap();
    }
    let other = PrivateKeySigner::from_bytes(&[90u8; 32].into()).unwrap();
    for (fid, tx) in [(1000u64, 50u8), (1001, 60)] {
        store
            .merge_onchain_event(
                id_event(
                    fid,
                    other.address().as_slice(),
                    IdRegisterEventType::Register,
                    1_600_000_000,
                    tx,
                    0,
                ),
                &mut txn,
            )
            .unwrap();
        store
            .merge_onchain_event(
                id_event(
                    fid,
                    other.address().as_slice(),
                    IdRegisterEventType::Transfer,
                    1_700_000_000,
                    tx + 1,
                    3,
                ),
                &mut txn,
            )
            .unwrap();
    }
    db.commit(txn).unwrap();
}

#[test]
fn two_nodes_build_the_same_genesis_and_accept_the_pivot_block() {
    let eths: Vec<PrivateKeySigner> = (1..=4u8)
        .map(|i| PrivateKeySigner::from_bytes(&[i + 10; 32].into()).unwrap())
        .collect();
    let validators: Vec<Validator> = eths
        .iter()
        .enumerate()
        .map(|(i, e)| validator(i as u64 + 1, e))
        .collect();
    let file = genesis_file::assemble(
        validators.iter().rev().map(|v| v.entry.clone()).collect(),
        FarcasterNetwork::Devnet,
    )
    .unwrap();
    assert_eq!(
        file.validators
            .iter()
            .map(|e| e.custody_migration.as_ref().unwrap().fid())
            .collect::<Vec<_>>(),
        vec![1, 2, 3, 4],
        "sorted by FID"
    );
    // EXEMPT_RECOVERIES has FID 1000's transfer; FID 1001's is not a
    // recovery before the cutoff.
    let mut params = params();
    params.epochs.pivot_height_0 = PIVOT;
    params.min_validator_fid_age_secs = 90 * 24 * 3600;
    params.exempt_recoveries = vec![(1000, [51u8; 32])];
    let mut without = params.clone();
    without.exempt_recoveries.clear();
    assert_ne!(
        without.params_hash(),
        params.params_hash(),
        "params_hash covers the list"
    );
    let shard_forks = vec![
        ShardForkPoint {
            shard_id: 1,
            fork_height: 50,
            chunk_hash: vec![1u8; 32],
        },
        ShardForkPoint {
            shard_id: 2,
            fork_height: 60,
            chunk_hash: vec![2u8; 32],
        },
    ];

    let mut nodes = Vec::new();
    let mut records = Vec::new();
    for _ in 0..2 {
        let dir = tempfile::TempDir::new().unwrap();
        let shard0 = open(&dir, "shard0");
        epoch0(&shard0, &eths);
        let social: BTreeMap<u32, Arc<RocksDB>> =
            [(1u32, open(&dir, "s1")), (2u32, open(&dir, "s2"))]
                .into_iter()
                .collect();
        let inputs = PivotInputs {
            params: &params,
            pivot_height: PIVOT,
            fork_block_hash: FORK_HASH,
            fork_timestamp: FORK_TS,
            shard_forks: shard_forks.clone(),
            shard_roots: [(1u32, [1u8; 32]), (2u32, [2u8; 32])].into_iter().collect(),
            genesis_file: &file,
            fname_cursor: 0,
            social,
        };
        let record = build_genesis(&shard0, &inputs).unwrap();
        records.push(record);
        nodes.push((dir, shard0));
    }
    assert_eq!(records[0], records[1], "independent builds agree");
    let record = records[0].clone();
    assert_eq!(
        record.genesis_validators_hash,
        genesis_validators_hash(&file).to_vec()
    );

    // The clocks: the exempt recovery keeps the registration time.
    let state = BlockState::new(nodes[0].1.clone());
    let clock =
        |fid| FidClock::decode(&state.txn().get(&keys::fid_clock(fid)).unwrap().unwrap()).unwrap();
    assert_eq!(clock(1000).last_custody_change, 0);
    assert_eq!(clock(1001).last_custody_change, 1_700_000_000);
    assert!(
        state.txn().exists(&keys::custody(3)).unwrap(),
        "bootstrap custody migrated"
    );
    // The replica of each bootstrap custody goes to the FID's shard through
    // the outbox at PIVOT_HEIGHT − 1.
    let outbox: Vec<proto::OutboxEntry> = state
        .txn()
        .scan(&keys::outbox_of_height(PIVOT - 1))
        .unwrap()
        .values()
        .map(|v| proto::OutboxEntry::decode(v.as_slice()).unwrap())
        .collect();
    for fid in 1..=4u64 {
        let entry = outbox
            .iter()
            .find(|e| e.fid == fid)
            .unwrap_or_else(|| panic!("no outbox entry for FID {}", fid));
        assert_eq!(entry.shard_id, params.shard_of(fid));
        assert!(entry.writes.iter().any(|w| w.key == keys::custody(fid)));
    }

    // The pivot block: proposed on node 0, valid on node 1.
    let parent = ParentInfo {
        height: PIVOT - 1,
        hash: FORK_HASH,
        timestamp: FORK_TS,
        epoch_ref_height: None,
        shard_links: vec![],
    };
    let mut engines: Vec<Shard0Engine> = nodes
        .iter()
        .map(|(_, db)| Shard0Engine::new(db.clone(), params.clone(), parent.clone()).unwrap())
        .collect();
    let inputs = TestInputs {
        pivot: Some(record.clone()),
        ..Default::default()
    };
    let links = vec![
        ShardLink {
            shard_id: 1,
            height: 50,
            block_hash: vec![1u8; 32],
            state_root: vec![1u8; 32],
        },
        ShardLink {
            shard_id: 2,
            height: 60,
            block_hash: vec![2u8; 32],
            state_root: vec![2u8; 32],
        },
    ];
    let mut block = engines[0]
        .propose(
            &inputs,
            Shard0Proposal {
                timestamp: FORK_TS + 12,
                shard_links: links,
                ..Default::default()
            },
        )
        .unwrap();
    let header = block.header.clone().unwrap();
    assert_eq!(
        header.pivot_record_hash,
        alloy_primitives::keccak256(record.encode_to_vec()).to_vec()
    );
    engines[1]
        .validate(&block, &inputs, None, u64::MAX)
        .unwrap();
    // A node with another PivotRecord prevotes nil.
    let mut other = record.clone();
    other.fname_cursor += 1;
    let wrong = TestInputs {
        pivot: Some(other),
        ..Default::default()
    };
    assert!(engines[1].validate(&block, &wrong, None, u64::MAX).is_err());
    engines[1]
        .validate(&block, &inputs, None, u64::MAX)
        .unwrap();

    // The bootstrap validators certify it.
    let set = engines[0].epoch_set(1).unwrap().unwrap();
    assert_eq!(set.record.members.len(), 4);
    let sigs: BTreeMap<_, _> = validators
        .iter()
        .map(|v| {
            let address = v.consensus.public_key().address();
            let bytes =
                certificate::precommit_sign_bytes(0, header.height, 0, &block.hash, &address);
            (address, v.consensus.sign(ConsensusDomain::Vote, &bytes))
        })
        .collect();
    block.certificate =
        Some(certificate::build(&set, 0, header.height, 0, &block.hash, &sigs).unwrap());
    let r0 = engines[0].commit(&block).unwrap();
    let r1 = engines[1].commit(&block).unwrap();
    assert_eq!(r0, r1);
    assert_eq!(block_hash(&header).to_vec(), block.hash);
}

/// Each consensus parameter is in `params_hash` (FIP §17.4), also the ones
/// that a devnet sets in its config.
#[test]
fn params_hash_covers_every_consensus_parameter() {
    let base = params();
    let changes: Vec<(&str, Box<dyn Fn(&mut crate::chain::shard0::Shard0Params)>)> = vec![
        (
            "network",
            Box::new(|p| p.network = FarcasterNetwork::Testnet),
        ),
        ("retro_minted", Box::new(|p| p.retro_minted += 1)),
        (
            "min_difficulty_bits",
            Box::new(|p| p.min_difficulty_bits += 1),
        ),
        ("max_memo_bytes", Box::new(|p| p.max_memo_bytes += 1)),
        ("protocol_chain_id", Box::new(|p| p.protocol_chain_id += 1)),
        (
            "onboard_anchor_window",
            Box::new(|p| p.onboard_anchor_window += 1),
        ),
        (
            "onboarding_stake_gate",
            Box::new(|p| p.onboarding_stake_gate ^= true),
        ),
        (
            "min_onboarding_stake",
            Box::new(|p| p.min_onboarding_stake += 1),
        ),
        (
            "min_onboarding_stake_duration",
            Box::new(|p| p.min_onboarding_stake_duration += 1),
        ),
        ("scoring_delay", Box::new(|p| p.scoring_delay += 1)),
        (
            "pause_duration_secs",
            Box::new(|p| p.pause_duration_secs += 1),
        ),
        (
            "seed_reveal_margin",
            Box::new(|p| p.seed_reveal_margin += 1),
        ),
    ];
    for (name, change) in changes {
        let mut p = base.clone();
        change(&mut p);
        assert_ne!(p.params_hash(), base.params_hash(), "{name}");
    }
}

/// The consensus constants that the release compiles in are in `params_hash`
/// through `release_constants_hash`. The pinned value fails when one of them
/// changes: a new value is a new release, so update the pin on purpose.
#[test]
fn release_constants_hash_is_pinned() {
    let hash = crate::chain::pivot::release_constants_hash();
    assert_eq!(hash, crate::chain::pivot::release_constants_hash());
    assert_eq!(hex::encode(hash), PINNED_RELEASE_CONSTANTS_HASH);
}

const PINNED_RELEASE_CONSTANTS_HASH: &str =
    "260c1a7c6172ac086d5da3fd197fb8642ff3b56eb0bcd13ffd9be991f11f60b3";
