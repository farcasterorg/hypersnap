//! Full blocks (FIP §4.2) in one process: 12,000 Falcon-512 messages from
//! 1,000 migrated FIDs, on a data shard and on shard 0. Prints the time of
//! the proposal, the validation on a second node and the commit, and the
//! size of the block against `MAX_BLOCK_BYTES`.
//!
//! ```sh
//! cargo test --release --lib chain::load_test -- --ignored --nocapture --test-threads 1
//! ```

use crate::chain::block::{MAX_BLOCK_BYTES, PULL_BYTES};
use crate::chain::certificate;
use crate::chain::replica_test::{genesis_link, Shard1};
use crate::chain::shard0::auth::test_keys::*;
use crate::chain::shard0::engine::Shard0Proposal;
use crate::chain::shard0::test_support::{self as s0, Net};
use crate::chain::shard_blocks::{ProposalInputs, ValidationInputs};
use crate::core::consensus_keys::ConsensusDomain;
use crate::proto::{
    self, link_body, message_data::Body, reaction_body, CastAddBody, CastId, CastType,
    FarcasterNetwork, FeeDepositBody, HyperInboundBurn, KeyAddBody, LinkBody, MessageData,
    MessageType, ReactionBody, ReactionType,
};
use crate::storage::store::mempool_poller::MempoolMessage;
use crate::utils::factory::events_factory;
use alloy_primitives::keccak256;
use alloy_signer_local::PrivateKeySigner;
use hypersnap_falcon::{domains, FalconSecretKey};
use prost::Message as _;
use std::collections::BTreeMap;
use std::time::{Duration, Instant};

const FIDS: usize = 1_000;
const PER_FID: usize = 12;

struct User {
    fid: u64,
    custody: FalconSecretKey,
    signer: FalconSecretKey,
}

/// `f` over `items` on all cores, in order.
fn par_map<T: Sync, U: Send>(items: &[T], f: impl Fn(&T) -> U + Sync) -> Vec<U> {
    let threads = std::thread::available_parallelism().map_or(1, |n| n.get());
    let chunk = items.len().div_ceil(threads).max(1);
    std::thread::scope(|s| {
        let handles: Vec<_> = items
            .chunks(chunk)
            .map(|c| s.spawn(|| c.iter().map(&f).collect::<Vec<_>>()))
            .collect();
        handles
            .into_iter()
            .flat_map(|h| h.join().unwrap())
            .collect()
    })
}

fn key(tag: u8, fid: u64) -> FalconSecretKey {
    let mut seed = [tag; 32];
    seed[..8].copy_from_slice(&fid.to_be_bytes());
    hypersnap_falcon::keygen_from_seed(seed)
}

fn owner(fid: u64) -> PrivateKeySigner {
    PrivateKeySigner::from_bytes(&keccak256(fid.to_be_bytes())).unwrap()
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

fn p0(net: &Net, messages: Vec<proto::Message>) -> Shard0Proposal {
    Shard0Proposal {
        shard_links: vec![genesis_link(1), genesis_link(2)],
        ..net.proposal(messages)
    }
}

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1e3
}

/// Shard 0: the pivot, then `FIDS` FIDs of shard 1 register, get 100
/// tokens, migrate, add a Falcon-512 signer and deposit 5 tokens of fees.
fn users(net: &mut Net) -> Vec<User> {
    let params = net.nodes[0].engine.params().clone();
    let fids: Vec<u64> = (10_000u64..)
        .filter(|f| params.shard_of(*f) == 1)
        .take(FIDS)
        .collect();
    let t = Instant::now();
    let users = par_map(&fids, |&fid| User {
        fid,
        custody: key(1, fid),
        signer: key(2, fid),
    });
    println!("keygen: {:.1} s", t.elapsed().as_secs_f64());

    net.run(p0(net, vec![]));
    let mut p = p0(net, vec![]);
    for (i, u) in users.iter().enumerate() {
        let mut event = s0::id_register(u.fid, owner(u.fid).address().as_slice(), 0);
        event.transaction_hash = keccak256((i as u64).to_be_bytes()).to_vec();
        event.block_number = 1_000 + i as u32;
        p.onchain_events.push(event);
        p.inbound_burns.push(HyperInboundBurn {
            source_chain_id: 1,
            burn_id: keccak256((u.fid + 1).to_be_bytes()).to_vec(),
            recipient_fid: u.fid,
            amount: 100_000_000,
            ..Default::default()
        });
    }
    let b = net.run(p);
    assert_eq!(b.system_messages.len(), 2 * FIDS, "registrations and burns");

    let migrations = users
        .iter()
        .map(|u| s0::migration(net, u.fid, &u.custody, &owner(u.fid)))
        .collect();
    let b = net.run(p0(net, migrations));
    assert_eq!(b.messages.len(), FIDS, "migrations");

    let ts = s0::block_time(net);
    let mut messages = Vec::new();
    for u in &users {
        let mut body = KeyAddBody {
            key: falcon_public(&u.signer),
            key_type: crate::chain::shard0::registry::KEY_TYPE_FALCON512,
            deadline: (ts + 3_600) as u32,
            nonce: 1,
            scopes: vec![
                MessageType::CastAdd as i32,
                MessageType::ReactionAdd as i32,
                MessageType::LinkAdd as i32,
            ],
            ttl: 3_600,
            ..Default::default()
        };
        let unsigned = data(
            u.fid,
            MessageType::KeyAdd,
            Body::KeyAddBody(body.clone()),
            ts,
        );
        body.custody_signature = falcon_sign(
            &u.custody,
            domains::KEY_ADD_FALCON,
            &unsigned.encode_to_vec(),
        );
        messages.push(falcon_message(
            &u.signer,
            data(u.fid, MessageType::KeyAdd, Body::KeyAddBody(body), ts),
        ));
        messages.push(falcon_message(
            &u.custody,
            data(
                u.fid,
                MessageType::FeeDeposit,
                Body::FeeDepositBody(FeeDepositBody {
                    amount: 5_000_000,
                    nonce: 1,
                }),
                ts,
            ),
        ));
    }
    let b = net.run(p0(net, messages));
    assert_eq!(b.messages.len(), 2 * FIDS, "signers and deposits");
    users
}

/// Two shard-1 nodes with the outbox of `users` and storage for each FID.
async fn shard1_pair(net: &Net, users: &[User]) -> (Shard1, Shard1) {
    let mut a = Shard1::new(net).await;
    let mut b = Shard1::new(net).await;
    let now = crate::utils::factory::time::current_timestamp();
    let rents = users
        .iter()
        .map(|u| {
            MempoolMessage::OnchainEvent(events_factory::create_rent_event_with_timestamp(
                u.fid, 10, now,
            ))
        })
        .collect();
    let (_, timing) = step(&mut a, &mut b, net, rents).await;
    timing.expect("the rent block is valid");
    (a, b)
}

struct Timing {
    bytes: usize,
    messages: usize,
    propose: Duration,
    validate: Duration,
    commit: Duration,
}

/// Propose on `a`, validate on `b`, certify, commit on both. The timing is
/// `Err` (and nothing commits) if `b` rejects the block.
async fn step(
    a: &mut Shard1,
    b: &mut Shard1,
    net: &Net,
    messages: Vec<MempoolMessage>,
) -> (proto::HypersnapBlock, Result<Timing, String>) {
    let tip0 = net.nodes[0].engine.tip().unwrap().header.unwrap().height;
    let t = Instant::now();
    let mut block = a
        .producer
        .propose(ProposalInputs {
            timestamp: Shard1::time(net),
            epoch_ref_height: tip0,
            messages,
        })
        .unwrap();
    let propose = t.elapsed();
    let bytes = block.encoded_len();
    let count = block
        .transactions
        .iter()
        .map(|t| t.user_messages.len())
        .sum();
    let header = block.header.clone().unwrap();
    let set = net.nodes[0]
        .engine
        .epoch_set(header.epoch)
        .unwrap()
        .unwrap();
    let parent_set = block.parent_certificate.as_ref().map(|c| {
        net.nodes[0]
            .engine
            .epoch_set(c.epoch)
            .unwrap()
            .expect("set of the parent epoch")
    });
    let t = Instant::now();
    let validated = b.producer.validate(
        &block,
        &ValidationInputs {
            highest_certified_shard0: tip0,
            max_timestamp: u64::MAX,
            parent_set: parent_set.as_ref(),
        },
    );
    let validate = t.elapsed();
    if let Err(e) = validated {
        return (block, Err(format!("{bytes} bytes, {count} messages: {e}")));
    }
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
    let t = Instant::now();
    let root_a = a.producer.commit(block.clone()).await.unwrap();
    let commit = t.elapsed();
    let root_b = b.producer.commit(block.clone()).await.unwrap();
    assert_eq!(root_a, root_b, "the two nodes have one root");
    (
        block,
        Ok(Timing {
            bytes,
            messages: count,
            propose,
            validate,
            commit,
        }),
    )
}

fn report(name: &str, timing: &Result<Timing, String>) {
    match timing {
        Ok(t) => println!(
            "{name}: {} messages, {:.2} MiB ({:.0}% of MAX_BLOCK_BYTES); propose {:.0} ms, validate {:.0} ms, commit {:.0} ms",
            t.messages,
            t.bytes as f64 / (1 << 20) as f64,
            100.0 * t.bytes as f64 / MAX_BLOCK_BYTES as f64,
            ms(t.propose),
            ms(t.validate),
            ms(t.commit)
        ),
        Err(e) => println!("{name}: rejected by the validator: {e}"),
    }
}

/// `len` bytes of text that is not a near-duplicate of another message:
/// hex of a hash chain over `fid` and `ts`.
fn distinct_text(fid: u64, ts: u64, len: usize) -> String {
    let mut text = String::new();
    let mut h = keccak256([fid.to_be_bytes(), ts.to_be_bytes()].concat());
    while text.len() < len {
        text.push_str(&hex::encode(h));
        text.push(' ');
        h = keccak256(h);
    }
    text.truncate(len);
    text
}

/// `PER_FID` messages of each user: half casts, a third likes, the rest
/// follows; or casts of `text` bytes of `kind` only.
fn load(users: &[User], now: u64, casts_only: Option<(CastType, usize)>) -> Vec<MempoolMessage> {
    let fids: Vec<u64> = users.iter().map(|u| u.fid).collect();
    let t = Instant::now();
    let out: Vec<Vec<MempoolMessage>> = par_map(users, |u| {
        (0..PER_FID)
            .map(|j| {
                let ts = now - 100 + j as u64;
                let other = fids[(u.fid as usize * 7 + j * 13) % fids.len()];
                let (t, body) = match (casts_only, j % 6) {
                    (Some((kind, len)), _) => (
                        MessageType::CastAdd,
                        Body::CastAddBody(CastAddBody {
                            text: distinct_text(u.fid, ts, len),
                            r#type: kind as i32,
                            ..Default::default()
                        }),
                    ),
                    (None, 0..=2) => (
                        MessageType::CastAdd,
                        Body::CastAddBody(CastAddBody {
                            text: format!("load test cast {j} of FID {}: a short line", u.fid),
                            ..Default::default()
                        }),
                    ),
                    (None, 3 | 4) => (
                        MessageType::ReactionAdd,
                        Body::ReactionBody(ReactionBody {
                            r#type: ReactionType::Like as i32,
                            target: Some(reaction_body::Target::TargetCastId(CastId {
                                fid: other,
                                hash: keccak256((u.fid * 100 + j as u64).to_be_bytes())[..20]
                                    .to_vec(),
                            })),
                        }),
                    ),
                    _ => (
                        MessageType::LinkAdd,
                        Body::LinkBody(LinkBody {
                            r#type: "follow".into(),
                            target: Some(link_body::Target::TargetFid(other)),
                            ..Default::default()
                        }),
                    ),
                };
                // As the mempool keeps it (`compact_message`).
                let mut m = falcon_message(&u.signer, data(u.fid, t, body, ts));
                crate::chain::block::compact_message(&mut m);
                MempoolMessage::UserMessage(m)
            })
            .collect()
    });
    println!(
        "signed {} messages in {:.1} s",
        FIDS * PER_FID,
        t.elapsed().as_secs_f64()
    );
    out.into_iter().flatten().collect()
}

#[tokio::test]
#[ignore = "load test: run in release with --ignored --nocapture"]
async fn a_full_data_shard_block() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new("warn"))
        .try_init();
    let mut net = Net::new(1);
    let users = users(&mut net);
    let (mut a, mut b) = shard1_pair(&net, &users).await;
    let now = Shard1::time(&net);

    let messages = load(&users, now, None);
    let mean = messages
        .iter()
        .map(|m| match m {
            MempoolMessage::UserMessage(m) => m.encoded_len(),
            _ => 0,
        })
        .sum::<usize>()
        / messages.len();
    println!("mean message: {mean} bytes");
    let (_, timing) = step(&mut a, &mut b, &net, messages).await;
    report("casts, likes and follows", &timing);
    let t = timing.unwrap();
    assert_eq!(t.messages, FIDS * PER_FID);

    // Long casts (1,000 bytes of text): 12,000 of them are twice
    // MAX_BLOCK_BYTES. The mempool gives `PULL_BYTES` of them; without that
    // limit, the proposer drops the last ones and proposes again.
    let messages = load(&users, now + 1, Some((CastType::LongCast, 1_000)));
    let mut bytes = 0;
    let pulled: Vec<MempoolMessage> = messages
        .iter()
        .take_while(|m| {
            bytes += m.encoded_len();
            bytes <= PULL_BYTES
        })
        .cloned()
        .collect();
    let (_, timing) = step(&mut a, &mut b, &net, pulled).await;
    report("long casts, PULL_BYTES from the mempool", &timing);
    let t = timing.unwrap();
    assert!(t.bytes <= MAX_BLOCK_BYTES);

    let messages = load(&users, now + 100, Some((CastType::LongCast, 1_000)));
    let (_, timing) = step(&mut a, &mut b, &net, messages).await;
    report("long casts, 12,000 to the proposer", &timing);
    let t = timing.unwrap();
    assert!(t.bytes <= MAX_BLOCK_BYTES && t.messages < FIDS * PER_FID);

    // 10K casts (10,000 bytes of text): the slowest block to validate.
    let messages = load(&users, now + 200, Some((CastType::TenKCast, 10_000)));
    let (_, timing) = step(&mut a, &mut b, &net, messages).await;
    report("10K casts, 12,000 to the proposer", &timing);
    let t = timing.unwrap();
    assert!(t.bytes <= MAX_BLOCK_BYTES);
}

#[tokio::test]
#[ignore = "load test: run in release with --ignored --nocapture"]
async fn a_full_shard0_block() {
    let mut net = Net::new(2);
    let users = users(&mut net);
    let ts = s0::block_time(&net);
    let t = Instant::now();
    let indexed: Vec<(usize, &User)> = users.iter().enumerate().collect();
    let transfers: Vec<Vec<proto::Message>> = par_map(&indexed, |&(i, u)| {
        (0..PER_FID as u64)
            .map(|j| {
                let mut m = falcon_message(
                    &u.custody,
                    data(
                        u.fid,
                        MessageType::TokenTransfer,
                        Body::TokenTransferBody(proto::TokenTransferBody {
                            recipient_fid: users[(i + 1 + j as usize) % FIDS].fid,
                            amount: 1_000 + j,
                            nonce: 2 + j,
                            memo: vec![],
                        }),
                        ts,
                    ),
                );
                crate::chain::block::compact_message(&mut m);
                m
            })
            .collect()
    });
    println!(
        "signed {} transfers in {:.1} s",
        FIDS * PER_FID,
        t.elapsed().as_secs_f64()
    );
    let transfers: Vec<proto::Message> = transfers.into_iter().flatten().collect();

    let proposal = p0(&net, transfers);
    let t = Instant::now();
    let mut block = net.nodes[0].engine.propose(&net.inputs, proposal).unwrap();
    let propose = t.elapsed();
    let parent_set = block.parent_certificate.as_ref().map(|c| {
        net.nodes[0]
            .engine
            .epoch_set(c.epoch)
            .unwrap()
            .expect("set of the parent epoch")
    });
    let t = Instant::now();
    net.nodes[1]
        .engine
        .validate(&block, &net.inputs, parent_set.as_ref(), u64::MAX)
        .unwrap();
    let validate = t.elapsed();
    let t = Instant::now();
    net.commit_certified(&mut block);
    let commit = t.elapsed() / 2;
    let timing = Ok(Timing {
        bytes: block.encoded_len(),
        messages: block.messages.len(),
        propose,
        validate,
        commit,
    });
    report("shard 0, token transfers", &timing);
    assert_eq!(block.messages.len(), FIDS * PER_FID);
}

/// The submit check of a node (`MyHubService::simulate_hypersnap`): a
/// read-only engine for each message, then `simulate_message`.
#[tokio::test]
#[ignore = "load test: run with --ignored --nocapture"]
async fn the_submit_check_of_a_message() {
    let mut net = Net::new(1);
    let users = users(&mut net);
    let (mut a, mut b) = shard1_pair(&net, &users).await;
    let now = Shard1::time(&net);
    // A block of history, then 2,000 new messages to check.
    let (_, timing) = step(&mut a, &mut b, &net, load(&users, now, None)).await;
    timing.unwrap();
    let messages = load(&users, now + 100, None);
    let stores = a.producer.engine.get_stores();
    let t = Instant::now();
    let mut building = Duration::ZERO;
    for m in messages.iter().take(2_000) {
        let MempoolMessage::UserMessage(m) = m else {
            continue;
        };
        let built = Instant::now();
        let mut engine = crate::storage::store::engine::ShardEngine::new_readonly(
            stores.db.clone(),
            FarcasterNetwork::Devnet,
            stores.trie.clone(),
            1,
            stores.store_limits.clone(),
            crate::utils::statsd_wrapper::StatsdClientWrapper::new(
                cadence::StatsdClient::builder("", cadence::NopMetricSink {}).build(),
                false,
            ),
        );
        engine
            .enter_hypersnap_mode(None, crate::version::version::EngineVersion::latest())
            .unwrap();
        building += built.elapsed();
        engine
            .simulate_message_at(m, &crate::core::util::FarcasterTime::new(now + 100))
            .unwrap();
    }
    println!(
        "submit check: {:?} a message, of which {:?} to make the engine",
        t.elapsed() / 2_000,
        building / 2_000
    );
}
