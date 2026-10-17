//! Test harness for the shard-0 engine: a genesis state with a bootstrap
//! set, node inputs that accept everything, and a helper that runs a block
//! through propose, validate, certificate and commit on several nodes.

use super::engine::{Shard0Engine, Shard0Inputs, Shard0Proposal};
use super::keys;
use super::state::{BlockState, Shard0Trie};
use super::work::DaCheckpoints;
use super::Shard0Params;
use crate::chain::block::ParentInfo;
use crate::chain::certificate::{self, test_support::TestValidators};
use crate::chain::epoch::epoch_seed;
use crate::chain::validator_sets::build_record;
use crate::core::consensus_keys::{ConsensusDomain, ConsensusPrivateKey};
use crate::proto::{
    self, FarcasterNetwork, FeeSettlement, HyperInboundBurn, HyperValidatorSetMember,
    HypersnapBlock, OnChainEvent, PivotRecord, ScoringResult, ShardLink, ValidatorRecord,
};
use crate::storage::db::{RocksDB, RocksDbTransactionBatch};
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
    ) -> Option<(Vec<u8>, Vec<u8>, [u8; 32])> {
        self.leaves.lock().unwrap().get(&(epoch, shard)).cloned()
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
}

impl Genesis {
    pub fn new(n: u8) -> Self {
        Genesis {
            validators: crate::chain::certificate::test_support::test_validators(n, 1),
        }
    }

    fn records(&self) -> Vec<ValidatorRecord> {
        self.validators
            .keys
            .iter()
            .zip(&self.validators.set.record.members)
            .map(|(k, _)| {
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
                ValidatorRecord {
                    fid: member.fid,
                    consensus_key_hash: hash.to_vec(),
                    consensus_key: public.as_bytes().to_vec(),
                    node_key_hash: member.node_key_hash.clone(),
                    registration_epoch: 1,
                    join_epoch: 1,
                    ..Default::default()
                }
            })
            .collect()
    }

    /// Write the genesis state (the bootstrap set, `set(1)`, the epoch-1
    /// seed) through the trie, as the genesis builder does.
    pub fn write(&self, db: &Arc<RocksDB>) {
        let validators: Vec<crate::chain::genesis::BootstrapValidator> = self
            .records()
            .into_iter()
            .map(|r| crate::chain::genesis::BootstrapValidator {
                fid: r.fid,
                consensus_key: r.consensus_key,
                node_key_hash: r.node_key_hash.as_slice().try_into().unwrap(),
                node_public_key: vec![],
            })
            .collect();
        crate::chain::genesis::write_bootstrap_set(db, &validators, &FORK_HASH).unwrap();
    }
}

pub struct Node {
    pub engine: Shard0Engine,
    _dir: tempfile::TempDir,
}

pub fn node(genesis: &Genesis) -> Node {
    let dir = tempfile::TempDir::new().unwrap();
    let db = Arc::new(RocksDB::new(dir.path().join("shard0").to_str().unwrap()));
    db.open().unwrap();
    genesis.write(&db);
    Node {
        engine: Shard0Engine::new(db, params(), genesis_parent()).unwrap(),
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
        let genesis = Genesis::new(4);
        let nodes = (0..n).map(|_| node(&genesis)).collect();
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
        let mut block = self.nodes[0]
            .engine
            .propose(&self.inputs, proposal)
            .unwrap();
        self.certify_and_commit(&mut block);
        block
    }

    pub fn certify_and_commit(&mut self, block: &mut HypersnapBlock) {
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
        self.commit_certified(block);
    }

    /// Certify `block` with the genesis keys and commit it on every node.
    /// The nodes other than the proposer run it as a decided block from
    /// sync, without their views.
    pub fn commit_certified(&mut self, block: &mut HypersnapBlock) {
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
            .map(|k| {
                let address = k.public_key().address();
                let bytes =
                    certificate::precommit_sign_bytes(0, header.height, 0, &block.hash, &address);
                (address, k.sign(ConsensusDomain::Vote, &bytes))
            })
            .collect();
        block.certificate =
            Some(certificate::build(&set, 0, header.height, 0, &block.hash, &sigs).unwrap());
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
