//! Shard 0 and shard 1 together (FIP §12, §16.8, §17.7): the outbox moves
//! custody, signers, fee balances and on-chain events to the replica of
//! shard 1; shard 1 checks a migrated FID's signers against it and charges
//! fees; shard 0 settles the charges through its link.

use crate::chain::block::{block_hash, ParentInfo};
use crate::chain::certificate;
use crate::chain::shard0::auth::test_keys::*;
use crate::chain::shard0::engine::Shard0Proposal;
use crate::chain::shard0::keys;
use crate::chain::shard0::state::BlockState;
use crate::chain::shard0::test_support::{self as s0, Net};
use crate::chain::shard0::views::{LocalShard, NodeViews, ScoringSource, Watchers};
use crate::chain::shard_blocks::{ProposalInputs, ShardBlockProducer};
use crate::core::consensus_keys::ConsensusDomain;
use crate::core::util::FarcasterTime;
use crate::proto::{
    self, message_data::Body, CastAddBody, CustodyMigrationBody, FarcasterNetwork, FeeDepositBody,
    HyperInboundBurn, KeyAddBody, MessageData, MessageType, OnChainEvent, ScoringResult, ShardLink,
};
use crate::storage::db::RocksDB;
use crate::storage::store::account::StoreOptions;
use crate::storage::store::engine::ShardEngine;
use crate::storage::store::mempool_poller::MempoolMessage;
use crate::storage::store::stores::StoreLimits;
use crate::storage::trie::merkle_trie::MerkleTrie;
use crate::utils::factory::events_factory;
use crate::utils::statsd_wrapper::StatsdClientWrapper;
use alloy_signer_local::PrivateKeySigner;
use hypersnap_falcon::domains;
use prost::Message as _;
use std::collections::BTreeMap;
use std::sync::Arc;

struct AllFinal;
impl Watchers for AllFinal {
    fn onchain_event_ok(&self, _: &OnChainEvent) -> bool {
        true
    }
    fn inbound_burn_ok(&self, _: &HyperInboundBurn) -> bool {
        true
    }
    fn pending_inbound_burns(&self) -> Vec<HyperInboundBurn> {
        vec![]
    }
}
struct NoScoring;
impl ScoringSource for NoScoring {
    fn scoring_result(&self, _: u64) -> Option<ScoringResult> {
        None
    }
}

fn statsd() -> StatsdClientWrapper {
    StatsdClientWrapper::new(
        cadence::StatsdClient::builder("", cadence::NopMetricSink {}).build(),
        true,
    )
}

fn data(fid: u64, t: MessageType, body: Body, timestamp: u64) -> MessageData {
    MessageData {
        r#type: t as i32,
        fid,
        timestamp: timestamp as u32,
        network: FarcasterNetwork::Devnet as i32,
        body: Some(body),
    }
}

fn cast(fid: u64, text: &str, ts: u64) -> MessageData {
    data(
        fid,
        MessageType::CastAdd,
        Body::CastAddBody(CastAddBody {
            text: text.to_string(),
            ..Default::default()
        }),
        ts,
    )
}

/// A shard-1 node over the outbox of node 0 of a shard-0 [`Net`].
pub(crate) struct Shard1 {
    pub(crate) producer: ShardBlockProducer,
    pub(crate) db: Arc<RocksDB>,
    _dir: tempfile::TempDir,
}

impl Shard1 {
    pub(crate) async fn new(net: &Net) -> Self {
        let dir = tempfile::TempDir::new().unwrap();
        let db = Arc::new(RocksDB::new(dir.path().join("shard1").to_str().unwrap()));
        db.open().unwrap();
        let mut engine = ShardEngine::new_with_opts(
            db.clone(),
            FarcasterNetwork::Devnet,
            MerkleTrie::new().unwrap(),
            1,
            StoreLimits::default(),
            statsd(),
            256,
            None,
            None,
            None,
            StoreOptions::default(),
        )
        .await
        .unwrap();
        engine
            .enter_hypersnap_mode(Some(0), crate::version::version::EngineVersion::latest())
            .unwrap();
        let reader = net.nodes[0].engine.reader();
        let producer = ShardBlockProducer::new(
            engine,
            net.nodes[0].engine.params().epochs,
            ParentInfo {
                height: 0,
                hash: [0u8; 32],
                timestamp: 0,
                epoch_ref_height: None,
                shard_links: vec![],
            },
        )
        .with_outbox(Arc::new(reader));
        Shard1 {
            producer,
            db,
            _dir: dir,
        }
    }

    /// The time of the next shard-1 block: the time of the shard-0 tip, so
    /// that the two shards have one clock.
    pub(crate) fn time(net: &Net) -> u64 {
        net.nodes[0].engine.tip().unwrap().header.unwrap().timestamp
    }

    /// Propose, certify and commit one shard-1 block.
    pub(crate) async fn run(
        &mut self,
        net: &Net,
        messages: Vec<MempoolMessage>,
    ) -> proto::HypersnapBlock {
        let tip0 = net.nodes[0].engine.tip().unwrap().header.unwrap().height;
        let mut block = self
            .producer
            .propose(ProposalInputs {
                timestamp: Self::time(net),
                epoch_ref_height: tip0,
                messages,
            })
            .unwrap();
        certify(net, &mut block);
        self.producer.commit(block.clone()).await.unwrap();
        block
    }

    fn link(&self) -> ShardLink {
        let h = self.producer.tip().unwrap().header.unwrap();
        ShardLink {
            shard_id: 1,
            height: h.height,
            block_hash: block_hash(&h).to_vec(),
            state_root: h.state_root,
        }
    }
}

/// A round-0 certificate of three genesis validators for a shard-1 block.
pub(crate) fn certify(net: &Net, block: &mut proto::HypersnapBlock) {
    let header = block.header.clone().unwrap();
    let set = net.nodes[0]
        .engine
        .epoch_set(header.epoch)
        .unwrap()
        .unwrap();
    let sigs: BTreeMap<_, _> = net
        .genesis
        .validators
        .keys
        .iter()
        .take(3)
        .map(|k| {
            let address = k.public_key().address();
            let bytes =
                certificate::precommit_sign_bytes(1, header.height, 0, &block.hash, &address);
            (address, k.sign(ConsensusDomain::Vote, &bytes))
        })
        .collect();
    block.certificate =
        Some(certificate::build(&set, 1, header.height, 0, &block.hash, &sigs).unwrap());
}

pub(crate) fn genesis_link(shard: u32) -> ShardLink {
    ShardLink {
        shard_id: shard,
        height: 0,
        block_hash: vec![0u8; 32],
        state_root: vec![0u8; 32],
    }
}

fn shard0_balance(net: &Net, key: &[u8]) -> u64 {
    let state = BlockState::new(net.nodes[0].engine.db().clone());
    let txn = state.txn();
    txn.get_u64(key).unwrap()
}

fn p0(net: &Net, messages: Vec<proto::Message>) -> Shard0Proposal {
    Shard0Proposal {
        shard_links: vec![genesis_link(1), genesis_link(2)],
        ..net.proposal(messages)
    }
}

/// Shard 0: the pivot, then FID 1000 registers, gets 10 tokens, migrates,
/// adds a Falcon-512 cast signer with `ttl`, and deposits 5 tokens of fees.
fn migrated_fid(net: &mut Net, ttl: u32) -> hypersnap_falcon::FalconSecretKey {
    let ts = |net: &Net| net.proposal(vec![]).timestamp;

    // Shard 0: pivot; FID 1000 registers and gets 10 tokens.
    net.run(p0(net, vec![]));
    let owner = PrivateKeySigner::from_bytes(&[5u8; 32].into()).unwrap();
    let mut p = p0(net, vec![]);
    p.onchain_events = vec![events_factory::create_id_register_event(
        1000,
        proto::IdRegisterEventType::Register,
        owner.address().to_vec(),
        Some(1_700_000_000),
    )];
    p.inbound_burns = vec![HyperInboundBurn {
        source_chain_id: 1,
        burn_id: vec![1u8; 32],
        recipient_fid: 1000,
        amount: 10_000_000,
        ..Default::default()
    }];
    net.run(p);

    // Migration, a Falcon-512 signer for casts, and a fee deposit.
    let custody = falcon(41);
    let mut body = CustodyMigrationBody {
        falcon_custody_key: falcon_public(&custody),
        deadline: (ts(net) + 3_600) as u32,
        ..Default::default()
    };
    let unsigned = data(
        1000,
        MessageType::CustodyMigration,
        Body::CustodyMigrationBody(body.clone()),
        ts(net),
    );
    body.eip712_signature = eip712_sign(
        &owner,
        crate::chain::shard0::auth::EIP712_CUSTODY_MIGRATION,
        &unsigned.encode_to_vec(),
    );
    let migration = falcon_message(
        &custody,
        data(
            1000,
            MessageType::CustodyMigration,
            Body::CustodyMigrationBody(body),
            ts(net),
        ),
    );
    let signer = falcon(42);
    let mut body = KeyAddBody {
        key: falcon_public(&signer),
        key_type: crate::chain::shard0::registry::KEY_TYPE_FALCON512,
        deadline: (FarcasterTime::current().to_u64() + 3_600) as u32,
        nonce: 1,
        scopes: vec![MessageType::CastAdd as i32],
        ttl,
        ..Default::default()
    };
    let unsigned = data(
        1000,
        MessageType::KeyAdd,
        Body::KeyAddBody(body.clone()),
        ts(net),
    );
    body.custody_signature =
        falcon_sign(&custody, domains::KEY_ADD_FALCON, &unsigned.encode_to_vec());
    let key_add = falcon_message(
        &signer,
        data(1000, MessageType::KeyAdd, Body::KeyAddBody(body), ts(net)),
    );
    let deposit = falcon_message(
        &custody,
        data(
            1000,
            MessageType::FeeDeposit,
            Body::FeeDepositBody(FeeDepositBody {
                amount: 5_000_000,
                nonce: 1,
            }),
            ts(net),
        ),
    );
    let b = net.run(p0(net, vec![migration, key_add, deposit]));
    assert_eq!(
        b.messages.len(),
        3,
        "migration, signer and deposit accepted"
    );
    signer
}

#[tokio::test]
async fn migrated_fid_casts_on_shard_1_and_fees_settle_on_shard_0() {
    let mut net = Net::new(1);
    let mut shard1 = Shard1::new(&net).await;
    let signer = migrated_fid(&mut net, 3_600);

    // Shard 1 applies the outbox; the FID gets storage on its own shard.
    let now = Shard1::time(&net);
    let rent = events_factory::create_rent_event_with_timestamp(
        1000,
        10,
        crate::utils::factory::time::current_timestamp(),
    );
    shard1
        .run(&net, vec![MempoolMessage::OnchainEvent(rent)])
        .await;
    let state = BlockState::new(shard1.db.clone());
    assert!(
        state.txn().exists(&keys::custody(1000)).unwrap(),
        "custody replica"
    );
    assert_eq!(
        state.txn().get_u64(&keys::fee_balance(1000)).unwrap(),
        5_000_000
    );

    // A Falcon-signed cast is accepted, an Ed25519-only one is not, and a
    // near-duplicate pays a fee.
    let ok = falcon_message(&signer, cast(1000, "hello hypersnap", now));
    let ed = ed25519_dalek::SigningKey::from_bytes(&[8u8; 32]);
    let ed_only = ed25519_message(&ed, cast(1000, "classical", now));
    let dup = falcon_message(&signer, cast(1000, "hello hypersnap", now + 1));
    let b1 = shard1
        .run(
            &net,
            vec![
                MempoolMessage::UserMessage(ok),
                MempoolMessage::UserMessage(ed_only),
            ],
        )
        .await;
    let h = b1.header.as_ref().unwrap().height;
    assert!(crate::chain::replica::charges_of_block(&shard1.db, h)
        .unwrap()
        .is_empty());
    // The fingerprints of earlier blocks make the copy a near-duplicate.
    let b1 = shard1
        .run(&net, vec![MempoolMessage::UserMessage(dup)])
        .await;
    let h1 = b1.header.as_ref().unwrap().height;
    let charges = crate::chain::replica::charges_of_block(&shard1.db, h1).unwrap();
    assert_eq!(charges.len(), 1, "one charge for FID 1000");
    let fee = charges[0].amount;
    assert_eq!(fee, 125_000, "1 token × (1 − 0.875)");

    // Shard 0 links the next shard-1 block, which has the certificate round
    // of the charged block, and settles every block below it (§12).
    shard1.run(&net, vec![]).await;
    let views = NodeViews {
        shards: [(1u32, LocalShard::new(shard1.db.clone(), genesis_link(1)))]
            .into_iter()
            .collect(),
        reader: net.nodes[0].engine.reader(),
        watchers: Arc::new(AllFinal),
        scoring: Arc::new(NoScoring),
        pivot: None,
        checkpoints: Arc::new(s0::TestCheckpoints::default()),
        link_lag: 0,
    };
    let mut p = p0(&net, vec![]);
    p.shard_links = vec![shard1.link(), genesis_link(2)];
    let mut block = net.nodes[0].engine.propose(&views, p).unwrap();
    let settlements: Vec<_> = block
        .system_messages
        .iter()
        .filter_map(|m| match &m.message {
            Some(proto::hypersnap_system_message::Message::FeeSettlement(s)) => Some(s.clone()),
            _ => None,
        })
        .collect();
    let first = settlements[0].height;
    assert_eq!(
        settlements.iter().map(|s| s.height).collect::<Vec<_>>(),
        (first..=h1).collect::<Vec<_>>(),
        "one settlement for each block"
    );
    let settlements: Vec<_> = settlements
        .into_iter()
        .filter(|s| !s.charges.is_empty())
        .collect();
    assert_eq!(settlements.len(), 1);
    assert_eq!(settlements[0].height, h1);
    net.certify_and_commit(&mut block);
    assert_eq!(
        shard0_balance(&net, &keys::fee_balance(1000)),
        5_000_000 - fee
    );
    let burned = fee * 60 / 100;
    assert_eq!(
        shard0_balance(&net, &keys::meta(keys::Meta::Burned)),
        burned
    );
    assert_eq!(
        shard0_balance(&net, &keys::balance(settlements[0].proposer_fid)),
        fee - burned
    );

    // Shard 1 gets the new balance and the settlement point.
    shard1.run(&net, vec![]).await;
    let state = BlockState::new(shard1.db.clone());
    assert_eq!(
        state.txn().get_u64(&keys::fee_balance(1000)).unwrap(),
        5_000_000 - fee
    );
    assert_eq!(
        state
            .txn()
            .get_u64(&crate::chain::replica::unsettled_key(1000))
            .unwrap(),
        0
    );

    // A node that has a certificate of another round for the block computes
    // the same settlements: the round comes from the next block (§12).
    use crate::chain::shard0::engine::Shard0Inputs as _;
    let ours = views.fee_settlements(1, 0, h1).unwrap();
    let store = crate::chain::shard_blocks::HypersnapBlockStore::new(shard1.db.clone());
    let mut other = store.get(h1).unwrap();
    other.certificate.as_mut().unwrap().round += 1;
    let mut txn = crate::storage::db::RocksDbTransactionBatch::new();
    store.stage(&other, &mut txn);
    shard1.db.commit(txn).unwrap();
    assert_eq!(views.fee_settlements(1, 0, h1).unwrap(), ours);
}

#[tokio::test]
async fn native_fid_casts_on_its_shard() {
    use crate::chain::shard0::onboarding::*;
    use alloy_signer::SignerSync;
    let mut net = Net::new(1);
    let mut shard1 = Shard1::new(&net).await;
    let ts = |net: &Net| net.proposal(vec![]).timestamp;
    let p0 = |net: &Net, messages: Vec<proto::Message>| Shard0Proposal {
        shard_links: vec![genesis_link(1), genesis_link(2)],
        ..net.proposal(messages)
    };
    net.run(p0(&net, vec![]));

    // Onboard a native FID with a Falcon-512 custody key (PoW gate).
    let user = PrivateKeySigner::from_bytes(&[61u8; 32].into()).unwrap();
    let custody: [u8; 20] = user.address().0 .0;
    let custody_key = falcon(62);
    let tip = net.nodes[0].engine.tip().unwrap().header.unwrap();
    let anchor = block_hash(&tip);
    let mut nonce = 0u64;
    let pow = loop {
        let n = nonce.to_be_bytes().to_vec();
        if pow_target_met(&pow_hash(&custody, &anchor, &n), 8) {
            break proto::PowSolution {
                nonce: n,
                difficulty_bits: 8,
            };
        }
        nonce += 1;
    };
    let commitment = pow_gate_commitment(&pow.nonce, 8);
    let hash = typed_hash(onboard_typed_data(
        10,
        &custody,
        tip.height,
        &anchor,
        &commitment,
    ))
    .unwrap();
    let body = proto::HyperNativeOnboardBody {
        custody_address: custody.to_vec(),
        custody_signature: user
            .sign_hash_sync(&hash.into())
            .unwrap()
            .as_bytes()
            .to_vec(),
        anchor_block_height: tip.height,
        anchor_block_hash: anchor.to_vec(),
        gate_proof: Some(proto::hyper_native_onboard_body::GateProof::Pow(pow)),
        falcon_custody_key: falcon_public(&custody_key),
        ..Default::default()
    };
    let onboard = falcon_message(
        &custody_key,
        data(
            0,
            MessageType::NativeOnboard,
            Body::NativeOnboardBody(body),
            ts(&net),
        ),
    );
    assert_eq!(net.run(p0(&net, vec![onboard])).messages.len(), 1);
    let fid = FIRST_NATIVE_FID;
    assert_eq!(net.nodes[0].engine.params().shard_of(fid), 1);

    // A Falcon-512 signer for casts.
    let signer = falcon(63);
    let mut body = KeyAddBody {
        key: falcon_public(&signer),
        key_type: crate::chain::shard0::registry::KEY_TYPE_FALCON512,
        deadline: (FarcasterTime::current().to_u64() + 3_600) as u32,
        nonce: 1,
        scopes: vec![MessageType::CastAdd as i32],
        ttl: 3_600,
        ..Default::default()
    };
    let unsigned = data(
        fid,
        MessageType::KeyAdd,
        Body::KeyAddBody(body.clone()),
        ts(&net),
    );
    body.custody_signature = falcon_sign(
        &custody_key,
        domains::KEY_ADD_FALCON,
        &unsigned.encode_to_vec(),
    );
    let key_add = falcon_message(
        &signer,
        data(fid, MessageType::KeyAdd, Body::KeyAddBody(body), ts(&net)),
    );
    assert_eq!(net.run(p0(&net, vec![key_add])).messages.len(), 1);

    // Shard 1 gets the native registry, the custody and the signer; a cast
    // merges with no storage units.
    shard1.run(&net, vec![]).await;
    let now = Shard1::time(&net);
    let cast_msg = falcon_message(&signer, cast(fid, "native hello", now));
    let v = shard1.producer.engine.version_for(&FarcasterTime::new(now));
    shard1
        .producer
        .engine
        .validate_user_message(
            &cast_msg,
            &FarcasterTime::new(now),
            v,
            &mut crate::storage::db::RocksDbTransactionBatch::new(),
        )
        .unwrap();
    let b = shard1
        .run(&net, vec![MempoolMessage::UserMessage(cast_msg)])
        .await;
    assert_eq!(
        b.transactions
            .iter()
            .map(|t| t.user_messages.len())
            .sum::<usize>(),
        1
    );
    let stored = shard1
        .producer
        .engine
        .get_casts_by_fid(fid)
        .map(|page| page.messages.len())
        .unwrap_or(0);
    assert_eq!(stored, 1, "the cast is in the store");
}

/// An FID that is not migrated: shard 0 sends its snapchain `KEY_ADD` and
/// `KEY_REMOVE` to shard 1. The `KEY_REMOVE` is a leaf of the shard-1 trie
/// that no snapchain store keeps, so shard 1 keeps it, and a DA challenge
/// of the leaf has an answer (FIP §5.1, §16.13).
#[tokio::test]
async fn shard_1_keeps_the_key_remove_that_shard_0_sends() {
    use crate::chain::checkpoints::Checkpoints;
    use crate::storage::db::RocksDbTransactionBatch;
    use crate::storage::store::account::{get_gasless_key_count, get_key_remove_message};
    use crate::storage::trie::merkle_trie::TrieKey;
    use crate::utils::factory::{messages_factory::keys, signers::generate_signer};

    let mut net = Net::new(1);
    let mut shard1 = Shard1::new(&net).await;
    let ts = |net: &Net| net.proposal(vec![]).timestamp as u32;
    let p0 = |net: &Net, messages: Vec<proto::Message>| Shard0Proposal {
        shard_links: vec![genesis_link(1), genesis_link(2)],
        ..net.proposal(messages)
    };
    net.run(p0(&net, vec![]));
    let params = net.nodes[0].engine.params().clone();
    let fid = (2000..).find(|f| params.shard_of(*f) == 1).unwrap();
    let app = fid + 1;
    let custody = PrivateKeySigner::random();
    let app_custody = PrivateKeySigner::random();
    let mut p = p0(&net, vec![]);
    p.onchain_events = [(fid, &custody), (app, &app_custody)]
        .iter()
        .map(|(f, c)| {
            events_factory::create_id_register_event(
                *f,
                proto::IdRegisterEventType::Register,
                c.address().to_vec(),
                Some(1_700_000_000),
            )
        })
        .collect();
    net.run(p);

    let key = generate_signer();
    let t = ts(&net);
    let add = keys::create_key_add(
        fid,
        &custody,
        app,
        &app_custody,
        &key,
        vec![MessageType::CastAdd],
        3_600,
        1,
        t + 1_000_000,
        Some(t),
    );
    assert_eq!(net.run(p0(&net, vec![add])).messages.len(), 1, "KEY_ADD");
    let t = ts(&net);
    let remove = keys::create_key_remove_custody(
        fid,
        &custody,
        &key,
        &key.verifying_key().to_bytes(),
        2,
        t + 1_000_000,
        Some(t),
    );
    assert_eq!(
        net.run(p0(&net, vec![remove.clone()])).messages.len(),
        1,
        "KEY_REMOVE"
    );
    shard1.run(&net, vec![]).await;

    let none = RocksDbTransactionBatch::new();
    assert_eq!(get_gasless_key_count(&shard1.db, &none, fid).unwrap(), 0);
    assert_eq!(
        get_key_remove_message(&shard1.db, fid, &remove.hash).unwrap(),
        Some(remove.clone())
    );
    let dir = tempfile::TempDir::new().unwrap();
    let checkpoints = Checkpoints::new(dir.path(), FarcasterNetwork::Devnet);
    checkpoints.take(&shard1.db, 1, 1).unwrap();
    let leaf = TrieKey::for_message(&remove).remove(0);
    let answer = checkpoints
        .challenged_leaf(1, 1, &hypersnap_ktrie::path_of(&leaf))
        .expect("an answer for the KEY_REMOVE leaf");
    assert_eq!(answer.key, leaf);
    assert_eq!(answer.value, remove.encode_to_vec());
}

fn stored_casts(shard1: &Shard1, fid: u64) -> usize {
    shard1
        .producer
        .engine
        .get_casts_by_fid(fid)
        .map(|page| page.messages.len())
        .unwrap_or(0)
}

#[tokio::test]
async fn a_commit_does_not_reuse_the_execution_of_another_proposal() {
    // Two proposals of one height with no messages and other shard-0
    // references: node `b` runs the first, and another round decides the
    // second, which applies the outbox of the migration.
    let mut net = Net::new(1);
    let mut a = Shard1::new(&net).await;
    let mut b = Shard1::new(&net).await;
    net.run(p0(&net, vec![]));
    let pivot = a.run(&net, vec![]).await;
    b.producer.commit(pivot).await.unwrap();
    let before = net.nodes[0].engine.tip().unwrap().header.unwrap().height;
    migrated_fid(&mut net, 3_600);
    let after = net.nodes[0].engine.tip().unwrap().header.unwrap().height;

    let first = b
        .producer
        .propose(ProposalInputs {
            timestamp: Shard1::time(&net),
            epoch_ref_height: before,
            messages: vec![],
        })
        .unwrap();
    let mut decided = a
        .producer
        .propose(ProposalInputs {
            timestamp: Shard1::time(&net),
            epoch_ref_height: after,
            messages: vec![],
        })
        .unwrap();
    assert_eq!(first.transactions, decided.transactions);
    assert_ne!(first.header, decided.header);
    certify(&net, &mut decided);
    let root_a = a.producer.commit(decided.clone()).await.unwrap();
    let root_b = b.producer.commit(decided.clone()).await.unwrap();
    assert_eq!(root_a, root_b);
    assert_eq!(
        root_b.as_slice(),
        decided.header.unwrap().state_root.as_slice()
    );
    assert!(
        BlockState::new(b.db.clone())
            .txn()
            .exists(&keys::custody(1000))
            .unwrap(),
        "the replica of the decided block"
    );
}

#[tokio::test]
async fn a_commit_does_not_reuse_the_execution_of_a_proposal_with_other_messages() {
    // Two proposals of one height with the same shard-0 reference and time
    // and other casts (the events hash covers no user message): node `b`
    // runs its own, and the other one is decided.
    let mut net = Net::new(1);
    let mut a = Shard1::new(&net).await;
    let mut b = Shard1::new(&net).await;
    let signer = migrated_fid(&mut net, 3_600);
    let pivot = a.run(&net, vec![]).await;
    b.producer.commit(pivot).await.unwrap();
    let now = Shard1::time(&net);
    let tip0 = net.nodes[0].engine.tip().unwrap().header.unwrap().height;
    let inputs = |text: &str| ProposalInputs {
        timestamp: now,
        epoch_ref_height: tip0,
        messages: vec![MempoolMessage::UserMessage(falcon_message(
            &signer,
            cast(1000, text, now),
        ))],
    };
    let first = b.producer.propose(inputs("not decided")).unwrap();
    let mut decided = a.producer.propose(inputs("decided")).unwrap();
    assert_ne!(first.transactions, decided.transactions);
    certify(&net, &mut decided);
    let root_a = a.producer.commit(decided.clone()).await.unwrap();
    let root_b = b.producer.commit(decided.clone()).await.unwrap();
    assert_eq!(root_a, root_b);
    let casts = b.producer.engine.get_casts_by_fid(1000).unwrap().messages;
    assert_eq!(casts.len(), 1);
    assert_eq!(casts[0].hash, decided.transactions[0].user_messages[0].hash);
}

#[tokio::test]
async fn a_migrated_fid_sends_a_10k_cast() {
    // Every FID is Pro after the pivot (§17.6): a Falcon-signed 10K cast
    // has the snapchain limit of a Pro FID, not 2,048 bytes.
    let mut net = Net::new(1);
    let mut shard1 = Shard1::new(&net).await;
    let signer = migrated_fid(&mut net, 3_600);
    let now = Shard1::time(&net);
    let mut data = cast(1000, &"ten thousand ".repeat(700), now);
    if let Some(Body::CastAddBody(body)) = data.body.as_mut() {
        body.r#type = proto::CastType::TenKCast as i32;
    }
    let long = falcon_message(&signer, data);
    assert!(long.data.as_ref().unwrap().encoded_len() > 2_048);
    shard1
        .run(&net, vec![MempoolMessage::UserMessage(long)])
        .await;
    assert_eq!(stored_casts(&shard1, 1000), 1);
}

#[tokio::test]
async fn a_falcon_signer_expires_ttl_seconds_after_its_last_use() {
    let mut net = Net::new(1);
    let mut shard1 = Shard1::new(&net).await;
    let signer = migrated_fid(&mut net, 600);
    // The KEY_ADD is at the time of the shard-0 tip.
    let added = Shard1::time(&net);
    shard1.run(&net, vec![]).await;
    let advance = |net: &mut Net, to: u64| {
        let mut p = p0(net, vec![]);
        p.timestamp = to;
        net.run(p);
    };
    let used = |shard1: &Shard1| {
        let key = crate::chain::replica::last_use_key(
            1000,
            &crate::chain::shard0::auth::falcon_key_hash(&falcon_public(&signer)),
        );
        shard1.db.get(&key).unwrap().map(|v| keys::decode_u64(&v))
    };

    // A use 400 s after the KEY_ADD moves the last use.
    advance(&mut net, added + 400);
    shard1
        .run(
            &net,
            vec![MempoolMessage::UserMessage(falcon_message(
                &signer,
                cast(1000, "one", added + 400),
            ))],
        )
        .await;
    assert_eq!(stored_casts(&shard1, 1000), 1);
    assert_eq!(used(&shard1), Some(added + 400));

    // 700 s after the KEY_ADD the signer is valid because of that use. The
    // use is within the throttle, so the last use does not move.
    advance(&mut net, added + 700);
    shard1
        .run(
            &net,
            vec![MempoolMessage::UserMessage(falcon_message(
                &signer,
                cast(1000, "two", added + 700),
            ))],
        )
        .await;
    assert_eq!(stored_casts(&shard1, 1000), 2);
    assert_eq!(used(&shard1), Some(added + 400));

    // More than 600 s after the last use, the signer expired.
    advance(&mut net, added + 1_100);
    let late = falcon_message(&signer, cast(1000, "three", added + 1_100));
    let t = FarcasterTime::new(added + 1_100);
    let v = shard1.producer.engine.version_for(&t);
    let err = shard1
        .producer
        .engine
        .validate_user_message(
            &late,
            &t,
            v,
            &mut crate::storage::db::RocksDbTransactionBatch::new(),
        )
        .unwrap_err();
    assert!(
        format!("{:?}", err).contains("the signer expired"),
        "{:?}",
        err
    );
    shard1
        .run(&net, vec![MempoolMessage::UserMessage(late)])
        .await;
    assert_eq!(stored_casts(&shard1, 1000), 2);
}

/// FIP §17.7: a verification that shard 0 merges reaches the FID's shard
/// through the replica, with no fee, and that shard rejects a verification
/// that a user sends to it directly.
#[tokio::test]
async fn a_shard0_verification_reaches_the_fid_shard() {
    use crate::storage::store::account::VerificationStore;
    let mut net = Net::new(1);
    let mut shard1 = Shard1::new(&net).await;
    net.run(p0(&net, vec![]));
    // FID 1000 (shard 1, not migrated) with an on-chain Ed25519 signer.
    let owner = PrivateKeySigner::from_bytes(&[5u8; 32].into()).unwrap();
    let signer = ed25519_dalek::SigningKey::from_bytes(&[23u8; 32]);
    let mut p = p0(&net, vec![]);
    let mut key_event = events_factory::create_signer_event(
        1000,
        signer.clone(),
        proto::SignerEventType::Add,
        Some(1_700_000_100),
        None,
    );
    key_event.transaction_hash = vec![78u8; 32];
    p.onchain_events = vec![
        events_factory::create_id_register_event(
            1000,
            proto::IdRegisterEventType::Register,
            owner.address().to_vec(),
            Some(1_700_000_000),
        ),
        key_event,
    ];
    net.run(p);

    let address = vec![0xA7u8; 20];
    let add = ed25519_message(
        &signer,
        data(
            1000,
            MessageType::VerificationAddEthAddress,
            Body::VerificationAddAddressBody(proto::VerificationAddAddressBody {
                address: address.clone(),
                verification_type: 1,
                block_hash: vec![0xB6; 32],
                ..Default::default()
            }),
            net.proposal(vec![]).timestamp,
        ),
    );
    assert_eq!(net.run(p0(&net, vec![add.clone()])).messages.len(), 1);
    shard1.run(&net, vec![]).await;
    // Shard 1 has FID 1000 now, and still rejects a verification as a user
    // message: its rules put verifications on shard 0.
    let t = FarcasterTime::new(Shard1::time(&net));
    let v = shard1.producer.engine.version_for(&t);
    let err = shard1
        .producer
        .engine
        .validate_user_message(
            &add,
            &t,
            v,
            &mut crate::storage::db::RocksDbTransactionBatch::new(),
        )
        .unwrap_err();
    assert!(
        matches!(
            err,
            crate::storage::store::engine::MessageValidationError::InvalidMessageType(_)
        ),
        "{:?}",
        err
    );
    let stored = VerificationStore::get_verification_add(
        &shard1.producer.engine.get_stores().verification_store,
        1000,
        &address,
        None,
    )
    .unwrap();
    assert_eq!(stored.map(|m| m.hash), Some(add.hash.clone()));
    // No fee charge for the replay.
    assert_eq!(
        shard1
            .db
            .get(&keys::fee_balance(1000))
            .unwrap()
            .map(|v| keys::decode_u64(&v)),
        None
    );
}
