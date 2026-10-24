//! Test harness for the shard-0 engine: a genesis state with a bootstrap
//! set, node inputs that accept everything, and a helper that runs a block
//! through propose, validate, certificate and commit on several nodes.

use super::engine::{Shard0Engine, Shard0Inputs, Shard0Proposal};
use super::work::DaCheckpoints;
use super::Shard0Params;
use crate::chain::block::ParentInfo;
use crate::chain::certificate::{self, test_support::TestValidators};
use crate::core::consensus_keys::{ConsensusDomain, ConsensusPrivateKey};
use crate::proto::{
    self, FarcasterNetwork, FeeSettlement, HyperInboundBurn, HypersnapBlock, OnChainEvent,
    PivotRecord, ScoringResult, ShardLink, ValidatorRecord,
};
use crate::storage::db::RocksDB;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

pub const PIVOT: u64 = 100;
pub const EPOCH_LEN: u64 = 20;
pub const FORK_HASH: [u8; 32] = [9u8; 32];
/// Farcaster time of the fork block.
pub const T0: u64 = 150_000_000;

pub fn params() -> Shard0Params {
    let mut p = Shard0Params::new(FarcasterNetwork::Devnet, PIVOT);
    p.epochs.epoch_length = EPOCH_LEN;
    p.min_validator_fid_age_secs = 0;
    p.bridge_outbound_activation_epoch = 1;
    p.vouch_grace_epochs = 2;
    p.unstaking_period_epochs = 1;
    p.scoring_delay = 5;
    p.min_difficulty_bits = 8;
    p.onboarding_stake_gate = true;
    p.min_onboarding_stake_duration = 2;
    p.seed_reveal_margin = 5;
    p
}

pub fn genesis_parent() -> ParentInfo {
    ParentInfo {
        height: PIVOT - 1,
        hash: FORK_HASH,
        timestamp: T0,
        epoch_ref_height: None,
        shard_links: vec![],
    }
}

/// Node inputs: every watcher item is final, every link is certified.
#[derive(Default)]
pub struct TestInputs {
    pub settlements: Mutex<BTreeMap<(u32, u64), FeeSettlement>>,
    pub scoring: Mutex<BTreeMap<u64, ScoringResult>>,
    pub pivot: Option<PivotRecord>,
    pub checkpoints: TestCheckpoints,
    pub tips: Mutex<Vec<ShardLink>>,
}

#[derive(Default)]
pub struct TestCheckpoints {
    pub leaves: Mutex<BTreeMap<(u64, u32), (Vec<u8>, Vec<u8>, [u8; 32])>>,
}

impl DaCheckpoints for TestCheckpoints {
    fn expected_leaf(
        &self,
        epoch: u64,
        shard: u32,
        _: &[u8; 32],
    ) -> Option<(Vec<u8>, [u8; 32], [u8; 32])> {
        self.leaves
            .lock()
            .unwrap()
            .get(&(epoch, shard))
            .map(|(key, value, root)| (key.clone(), hypersnap_ktrie::value_hash(value), *root))
    }
}

impl Shard0Inputs for TestInputs {
    fn onchain_event_ok(&self, _: &OnChainEvent) -> bool {
        true
    }
    fn inbound_burn_ok(&self, _: &HyperInboundBurn) -> bool {
        true
    }
    fn shard_link_ok(&self, _: &ShardLink) -> bool {
        true
    }
    fn fee_settlements(&self, shard: u32, after: u64, upto: u64) -> Option<Vec<FeeSettlement>> {
        Some(
            self.settlements
                .lock()
                .unwrap()
                .range((shard, after + 1)..=(shard, upto))
                .map(|(_, s)| s.clone())
                .collect(),
        )
    }
    fn scoring_result(&self, epoch: u64) -> Option<ScoringResult> {
        // An epoch that a test does not score has an empty result.
        Some(
            self.scoring
                .lock()
                .unwrap()
                .get(&epoch)
                .cloned()
                .unwrap_or(ScoringResult {
                    epoch,
                    ..Default::default()
                }),
        )
    }
    fn pivot_record(&self) -> Option<PivotRecord> {
        self.pivot.clone()
    }
    fn da_checkpoints(&self) -> &dyn DaCheckpoints {
        &self.checkpoints
    }
    fn shard_tips(&self) -> Vec<ShardLink> {
        self.tips.lock().unwrap().clone()
    }
}

pub fn pivot_record() -> PivotRecord {
    PivotRecord {
        pivot_height: PIVOT,
        fork_block_hash: FORK_HASH.to_vec(),
        snapchain_engine_version: crate::version::version::EngineVersion::latest() as u32,
        ..Default::default()
    }
}

pub fn link(shard: u32, height: u64) -> ShardLink {
    ShardLink {
        shard_id: shard,
        height,
        block_hash: vec![height as u8; 32],
        state_root: vec![shard as u8; 32],
    }
}

/// The bootstrap set of the genesis state.
pub struct Genesis {
    pub validators: TestValidators,
    /// The node keys of the bootstrap validators, if the genesis attests
    /// them (their FIDs are then migrated, with the custody keys
    /// `falcon(140 + s)`). Empty: placeholder node key hashes.
    pub node_keys: Vec<FalconSecretKey>,
}

impl Genesis {
    pub fn new(n: u8) -> Self {
        Genesis {
            validators: crate::chain::certificate::test_support::test_validators(n, 1),
            node_keys: vec![],
        }
    }

    /// Bootstrap validators with node keys `falcon(120 + s)` that the genesis
    /// attests, so that they sign node-key messages (FIP §3).
    pub fn with_node_keys(n: u8) -> Self {
        Genesis {
            validators: crate::chain::certificate::test_support::test_validators(n, 1),
            node_keys: (1..=n).map(|s| falcon(120 + s)).collect(),
        }
    }

    fn records(&self) -> Vec<ValidatorRecord> {
        self.validators
            .keys
            .iter()
            .zip(&self.validators.set.record.members)
            .enumerate()
            .map(|(i, (k, _))| {
                let ConsensusPrivateKey::Falcon { public, .. } = k else {
                    unreachable!()
                };
                let hash = public.key_id();
                let member = self
                    .validators
                    .set
                    .record
                    .members
                    .iter()
                    .find(|m| m.consensus_key_hash == hash)
                    .unwrap();
                let node_key_hash = match self.node_keys.get(i) {
                    Some(nk) => super::auth::falcon_key_hash(&falcon_public(nk)).to_vec(),
                    None => member.node_key_hash.clone(),
                };
                ValidatorRecord {
                    fid: member.fid,
                    consensus_key_hash: hash.to_vec(),
                    consensus_key: public.as_bytes().to_vec(),
                    node_key_hash,
                    registration_epoch: 1,
                    join_epoch: 1,
                    ..Default::default()
                }
            })
            .collect()
    }

    /// Write the genesis state (the bootstrap set, `set(1)`, the epoch-1
    /// seed) through the trie, as the genesis builder does.
    pub fn write(&self, db: &Arc<RocksDB>, params: &Shard0Params) {
        let validators: Vec<crate::chain::genesis::BootstrapValidator> = self
            .records()
            .into_iter()
            .enumerate()
            .map(|(i, r)| crate::chain::genesis::BootstrapValidator {
                fid: r.fid,
                consensus_key: r.consensus_key,
                node_key_hash: r.node_key_hash.as_slice().try_into().unwrap(),
                node_public_key: self.node_keys.get(i).map(falcon_public).unwrap_or_default(),
                custody_key: self
                    .node_keys
                    .get(i)
                    .map(|_| falcon_public(&falcon(140 + i as u8 + 1)))
                    .unwrap_or_default(),
            })
            .collect();
        crate::chain::genesis::write_bootstrap_set(db, &validators, &FORK_HASH, params).unwrap();
    }
}

pub struct Node {
    pub engine: Shard0Engine,
    _dir: tempfile::TempDir,
}

pub fn node(genesis: &Genesis) -> Node {
    node_with(genesis, params())
}

pub fn node_with(genesis: &Genesis, params: Shard0Params) -> Node {
    let dir = tempfile::TempDir::new().unwrap();
    let db = Arc::new(RocksDB::new(dir.path().join("shard0").to_str().unwrap()));
    db.open().unwrap();
    genesis.write(&db, &params);
    Node {
        engine: Shard0Engine::new(db, params, genesis_parent()).unwrap(),
        _dir: dir,
    }
}

/// A network of `n` nodes over the same genesis.
pub struct Net {
    pub genesis: Genesis,
    pub nodes: Vec<Node>,
    pub inputs: TestInputs,
}

impl Net {
    pub fn new(n: usize) -> Self {
        Self::with_params(n, params())
    }

    pub fn with_params(n: usize, params: Shard0Params) -> Self {
        Self::with_genesis(n, params, Genesis::new(4))
    }

    pub fn with_genesis(n: usize, params: Shard0Params, genesis: Genesis) -> Self {
        let nodes = (0..n)
            .map(|_| node_with(&genesis, params.clone()))
            .collect();
        Net {
            genesis,
            nodes,
            inputs: TestInputs {
                pivot: Some(pivot_record()),
                ..Default::default()
            },
        }
    }

    pub fn next_height(&self) -> u64 {
        self.nodes[0].engine.next_height()
    }

    /// The default proposal of the next height: links that advance by one.
    pub fn proposal(&self, messages: Vec<proto::Message>) -> Shard0Proposal {
        let h = self.next_height();
        Shard0Proposal {
            timestamp: T0 + 12 * (h - PIVOT + 1),
            shard_links: vec![link(1, h - PIVOT), link(2, h - PIVOT)],
            messages,
            ..Default::default()
        }
    }

    /// Propose on node 0, validate on the others, certify, commit on all.
    pub fn run(&mut self, proposal: Shard0Proposal) -> HypersnapBlock {
        self.run_at_round(proposal, 0)
    }

    /// As `run`, with a certificate of `round`: the proposers of the rounds
    /// before it missed their proposals (§4.7).
    pub fn run_at_round(&mut self, proposal: Shard0Proposal, round: u32) -> HypersnapBlock {
        let mut block = self.nodes[0]
            .engine
            .propose(&self.inputs, proposal)
            .unwrap();
        self.validate_on_others(&block);
        self.commit_certified_at(&mut block, round);
        block
    }

    pub fn certify_and_commit(&mut self, block: &mut HypersnapBlock) {
        self.validate_on_others(block);
        self.commit_certified(block);
    }

    fn validate_on_others(&mut self, block: &HypersnapBlock) {
        let header = block.header.clone().unwrap();
        let parent_set = block.parent_certificate.as_ref().map(|c| {
            self.nodes[0]
                .engine
                .epoch_set(c.epoch)
                .unwrap()
                .expect("set of the parent epoch")
        });
        for n in self.nodes.iter_mut().skip(1) {
            n.engine
                .validate(block, &self.inputs, parent_set.as_ref(), u64::MAX)
                .unwrap_or_else(|e| panic!("validation at {}: {}", header.height, e));
        }
    }

    /// Certify `block` with the genesis keys and commit it on every node.
    /// The nodes other than the proposer run it as a decided block from
    /// sync, without their views.
    pub fn commit_certified(&mut self, block: &mut HypersnapBlock) {
        self.commit_certified_at(block, 0)
    }

    /// Certify `block` at `round` with the genesis keys that are in the set
    /// of its epoch, and commit it on every node.
    pub fn commit_certified_at(&mut self, block: &mut HypersnapBlock, round: u32) {
        let header = block.header.clone().unwrap();
        let set = self.nodes[0]
            .engine
            .epoch_set(header.epoch)
            .unwrap()
            .unwrap();
        let sigs: BTreeMap<_, _> = self
            .genesis
            .validators
            .keys
            .iter()
            .filter(|k| {
                let address = k.public_key().address();
                set.record
                    .members
                    .iter()
                    .any(|m| m.consensus_key_hash == address.to_vec())
            })
            .map(|k| {
                let address = k.public_key().address();
                let bytes = certificate::precommit_sign_bytes(
                    0,
                    header.height,
                    round,
                    &block.hash,
                    &address,
                );
                (address, k.sign(ConsensusDomain::Vote, &bytes))
            })
            .collect();
        block.certificate =
            Some(certificate::build(&set, 0, header.height, round, &block.hash, &sigs).unwrap());
        let mut roots = Vec::new();
        for n in self.nodes.iter_mut() {
            roots.push(n.engine.commit(block).unwrap());
        }
        assert!(
            roots.windows(2).all(|w| w[0] == w[1]),
            "roots differ: {:?}",
            roots
        );
        assert_eq!(roots[0].as_slice(), header.state_root.as_slice());
    }

    pub fn run_empty(&mut self) -> HypersnapBlock {
        let p = self.proposal(vec![]);
        self.run(p)
    }
}

// ---- A funded network (FIDs 1000 and 2000), for the engine tests and the
// fuzz targets ----

use super::auth::test_keys::{eip712_sign, falcon, falcon_message, falcon_public};
use super::keys;
use super::state::BlockState;
use crate::proto::{
    message_data::Body, CustodyMigrationBody, IdRegisterEventType, MessageData, MessageType,
    TokenTransferBody,
};
use alloy_signer_local::PrivateKeySigner;
use hypersnap_falcon::FalconSecretKey;
use prost::Message as _;

pub fn data(fid: u64, t: MessageType, body: Body, timestamp: u64) -> MessageData {
    MessageData {
        r#type: t as i32,
        fid,
        timestamp: timestamp as u32,
        network: FarcasterNetwork::Devnet as i32,
        body: Some(body),
    }
}

pub fn id_register(fid: u64, custody: &[u8], n: u8) -> OnChainEvent {
    OnChainEvent {
        r#type: proto::OnChainEventType::EventTypeIdRegister as i32,
        chain_id: 10,
        block_number: 1_000 + n as u32,
        block_timestamp: 1_700_000_000,
        transaction_hash: vec![n; 32],
        log_index: 0,
        fid,
        version: 1,
        body: Some(proto::on_chain_event::Body::IdRegisterEventBody(
            proto::IdRegisterEventBody {
                to: custody.to_vec(),
                event_type: IdRegisterEventType::Register as i32,
                ..Default::default()
            },
        )),
        ..Default::default()
    }
}

pub fn burn(fid: u64, amount: u64, n: u8) -> HyperInboundBurn {
    HyperInboundBurn {
        source_chain_id: 1,
        burn_id: vec![n; 32],
        recipient_fid: fid,
        amount,
        ..Default::default()
    }
}

pub fn eth(seed: u8) -> PrivateKeySigner {
    PrivateKeySigner::from_bytes(&[seed; 32].into()).unwrap()
}

pub fn balance(net: &Net, fid: u64) -> u64 {
    let state = BlockState::new(net.nodes[0].engine.db().clone());
    let txn = state.txn();
    txn.get_u64(&keys::balance(fid)).unwrap()
}

pub fn read<T: prost::Message + Default>(net: &Net, key: &[u8]) -> Option<T> {
    let state = BlockState::new(net.nodes[0].engine.db().clone());
    let txn = state.txn();
    txn.get_proto(key).unwrap()
}

pub fn block_time(net: &Net) -> u64 {
    net.proposal(vec![]).timestamp
}

pub fn migration(
    net: &Net,
    fid: u64,
    custody: &FalconSecretKey,
    eth_signer: &PrivateKeySigner,
) -> proto::Message {
    let mut body = CustodyMigrationBody {
        falcon_custody_key: falcon_public(custody),
        nonce: 0,
        deadline: (block_time(net) + 3_600) as u32,
        ..Default::default()
    };
    let unsigned = data(
        fid,
        MessageType::CustodyMigration,
        Body::CustodyMigrationBody(body.clone()),
        block_time(net),
    );
    body.eip712_signature = eip712_sign(
        eth_signer,
        super::auth::EIP712_CUSTODY_MIGRATION,
        &unsigned.encode_to_vec(),
    );
    falcon_message(
        custody,
        data(
            fid,
            MessageType::CustodyMigration,
            Body::CustodyMigrationBody(body),
            block_time(net),
        ),
    )
}

pub fn transfer(
    net: &Net,
    fid: u64,
    key: &FalconSecretKey,
    to: u64,
    amount: u64,
    nonce: u64,
) -> proto::Message {
    falcon_message(
        key,
        data(
            fid,
            MessageType::TokenTransfer,
            Body::TokenTransferBody(TokenTransferBody {
                recipient_fid: to,
                amount,
                nonce,
                memo: vec![],
            }),
            block_time(net),
        ),
    )
}

/// Pivot block, then FIDs 1000 (migrated, funded) and 2000.
pub fn funded_net() -> (Net, FalconSecretKey, PrivateKeySigner) {
    funded_net_with(params())
}

pub fn funded_net_with(params: Shard0Params) -> (Net, FalconSecretKey, PrivateKeySigner) {
    funded(Net::with_params(3, params))
}

/// `net` after its pivot block, then FIDs 1000 (migrated, funded) and 2000.
pub fn funded(mut net: Net) -> (Net, FalconSecretKey, PrivateKeySigner) {
    net.run_empty();
    let owner = eth(5);
    let other = eth(6);
    let mut p = net.proposal(vec![]);
    p.onchain_events = vec![
        id_register(1000, owner.address().as_slice(), 1),
        id_register(2000, other.address().as_slice(), 2),
    ];
    p.inbound_burns = vec![burn(1000, 100_000_000, 1)];
    let b = net.run(p);
    assert_eq!(b.system_messages.len(), 3);
    assert_eq!(balance(&net, 1000), 100_000_000);

    let custody = falcon(11);
    let m = migration(&net, 1000, &custody, &owner);
    let b = net.run(net.proposal(vec![m]));
    assert_eq!(b.messages.len(), 1, "migration accepted");
    (net, custody, owner)
}
