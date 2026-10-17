//! The wallet builders (`crates/hypersnap-wallet`) against the node (FIP §13,
//! §16.8-§16.11): each message that the wallet builds is accepted by the
//! shard-0 engine, or by a shard-1 replica for a cast.

use super::keys;
use super::state::BlockState;
use super::test_support::*;
use crate::chain::replica_test::{genesis_link, Shard1};
use crate::chain::shard0::engine::Shard0Proposal;
use crate::core::util::FarcasterTime;
use crate::proto::{
    self, FarcasterNetwork, HyperInboundBurn, IdRegisterEventType, MessageType, OnChainEvent,
    StakeType,
};
use crate::storage::store::mempool_poller::MempoolMessage;
use crate::utils::factory::messages_factory;
use alloy_signer_local::PrivateKeySigner;
use hypersnap_falcon::FalconSecretKey;
use hypersnap_messages::falcon_key_hash;
use hypersnap_wallet::tx::escrow::{EscrowBridge, EscrowClaim, EscrowOwner};
use hypersnap_wallet::tx::signer::{KeyGrant, KeyRemoval};
use hypersnap_wallet::tx::spend_key::SpendKeyLimits;
use hypersnap_wallet::tx::{self, Eip712Auth, Header, MessageSigner};
use rand::SeedableRng;

type Rng = rand_chacha::ChaCha20Rng;

fn rng() -> Rng {
    Rng::from_seed([11u8; 32])
}

fn falcon(seed: u8) -> FalconSecretKey {
    hypersnap_falcon::keygen_from_seed([seed; 32])
}

fn eth(seed: u8) -> PrivateKeySigner {
    PrivateKeySigner::from_bytes(&[seed; 32].into()).unwrap()
}

fn address(signer: &PrivateKeySigner) -> [u8; 20] {
    signer.address().0 .0
}

fn id_event(fid: u64, to: &[u8], n: u8, event_type: IdRegisterEventType) -> OnChainEvent {
    OnChainEvent {
        r#type: proto::OnChainEventType::EventTypeIdRegister as i32,
        chain_id: 10,
        block_number: 1_000 + n as u32,
        block_timestamp: 1_700_000_000 + n as u64,
        transaction_hash: vec![n; 32],
        log_index: 0,
        fid,
        version: 1,
        body: Some(proto::on_chain_event::Body::IdRegisterEventBody(
            proto::IdRegisterEventBody {
                to: to.to_vec(),
                event_type: event_type as i32,
                ..Default::default()
            },
        )),
        ..Default::default()
    }
}

fn burn(fid: u64, amount: u64, n: u8) -> HyperInboundBurn {
    HyperInboundBurn {
        source_chain_id: 1,
        burn_id: vec![n; 32],
        recipient_fid: fid,
        amount,
        ..Default::default()
    }
}

fn get_u64(net: &Net, key: &[u8]) -> u64 {
    let state = BlockState::new(net.nodes[0].engine.db().clone());
    let txn = state.txn();
    txn.get_u64(key).unwrap()
}

fn read<T: prost::Message + Default>(net: &Net, key: &[u8]) -> Option<T> {
    let state = BlockState::new(net.nodes[0].engine.db().clone());
    let txn = state.txn();
    txn.get_proto(key).unwrap()
}

fn block_time(net: &Net) -> u32 {
    net.proposal(vec![]).timestamp as u32
}

fn header(net: &Net, fid: u64) -> Header {
    Header::new(fid, FarcasterNetwork::Devnet, block_time(net))
}

fn epoch(net: &Net) -> u64 {
    net.nodes[0].engine.tip().unwrap().header.unwrap().epoch
}

/// Run one block with `messages`; the number of messages it accepted.
fn accepted(net: &mut Net, messages: Vec<proto::Message>) -> usize {
    net.run(net.proposal(messages)).messages.len()
}

/// Pivot block; FIDs 1000 (custody `eth(5)`, 100 tokens), 2000 (`eth(6)`)
/// and 3000 (`eth(7)`); FID 1000 migrates with a software custody key.
fn funded_net(rng: &mut Rng) -> (Net, FalconSecretKey) {
    let mut net = Net::new(3);
    net.run_empty();
    let mut p = net.proposal(vec![]);
    p.onchain_events = vec![
        id_event(1000, &address(&eth(5)), 1, IdRegisterEventType::Register),
        id_event(2000, &address(&eth(6)), 2, IdRegisterEventType::Register),
        id_event(3000, &address(&eth(7)), 3, IdRegisterEventType::Register),
    ];
    p.inbound_burns = vec![burn(1000, 100_000_000, 1)];
    net.run(p);

    let custody = falcon(11);
    let recovery = falcon(12);
    let m = tx::custody::build_custody_migration(
        &header(&net, 1000),
        &custody,
        Some(recovery.public_key()),
        0,
        block_time(&net) + 3_600,
        &Eip712Auth::Signer(&eth(5)),
        rng,
    )
    .unwrap();
    assert_eq!(accepted(&mut net, vec![m]), 1, "migration");
    let record: proto::FidCustodyRecord = read(&net, &keys::custody(1000)).unwrap();
    assert_eq!(record.falcon_recovery_key, recovery.public_key().as_bytes());
    (net, custody)
}

#[test]
fn wallet_token_operations_and_spend_keys() {
    let mut rng = rng();
    let (mut net, account) = funded_net(&mut rng);

    // Migration of FID 3000 with a hardware wallet: the digest, then the
    // signature made outside the wallet.
    let custody_3000 = falcon(13);
    let h = header(&net, 3000);
    let deadline = h.timestamp + 3_600;
    let digest =
        tx::custody::custody_migration_digest(&h, custody_3000.public_key(), None, 7, deadline);
    let signature = hypersnap_messages::eip712_sign_hash(&eth(7), &digest).unwrap();
    let m = tx::custody::build_custody_migration(
        &h,
        &custody_3000,
        None,
        7,
        deadline,
        &Eip712Auth::Signature(signature),
        &mut rng,
    )
    .unwrap();
    assert_eq!(accepted(&mut net, vec![m]), 1, "hardware-wallet migration");

    // Account-key operations on the account nonce stream.
    let h = header(&net, 1000);
    let transfer = tx::token::build_token_transfer(
        &h,
        &account,
        2000,
        10_000_000,
        1,
        b"hi".to_vec(),
        &mut rng,
    )
    .unwrap();
    let deposit =
        tx::token::build_fee_deposit(&h, &MessageSigner::Falcon(&account), 3_000_000, 2, &mut rng)
            .unwrap();
    let stake = tx::token::build_token_stake(
        &h,
        &account,
        StakeType::Credibility,
        4_000_000,
        0,
        3,
        &mut rng,
    )
    .unwrap();
    let unstake = tx::token::build_token_unstake(
        &h,
        &account,
        StakeType::Credibility,
        1_000_000,
        0,
        4,
        &mut rng,
    )
    .unwrap();
    let lock =
        tx::token::build_token_lock(&h, &account, 2_000_000, 10, [0xab; 20], 5, &mut rng).unwrap();
    assert_eq!(
        accepted(&mut net, vec![transfer, deposit, stake, unstake, lock]),
        5,
        "transfer, fee deposit, stake, unstake, lock"
    );
    assert_eq!(get_u64(&net, &keys::balance(2000)), 10_000_000);
    assert_eq!(get_u64(&net, &keys::fee_balance(1000)), 3_000_000);
    assert_eq!(get_u64(&net, &keys::balance(1000)), 81_000_000);

    // A spend key with a cap of 5 tokens per epoch, for FID 2000 only.
    let spend = falcon(14);
    let add = tx::spend_key::build_spend_key_add(
        &header(&net, 1000),
        &account,
        &spend,
        &SpendKeyLimits {
            app_fid: 2000,
            epoch_cap: 5_000_000,
            expires_at_epoch: epoch(&net) + 2,
            allowed_recipients: vec![2000],
        },
        6,
        &mut rng,
    )
    .unwrap();
    assert_eq!(accepted(&mut net, vec![add]), 1, "spend key add");

    // The spend key transfers on its own nonce stream, within its limits.
    let h = header(&net, 1000);
    let ok =
        tx::token::build_token_transfer(&h, &spend, 2000, 5_000_000, 1, vec![], &mut rng).unwrap();
    let over = tx::token::build_token_transfer(&h, &spend, 2000, 1, 2, vec![], &mut rng).unwrap();
    let elsewhere =
        tx::token::build_token_transfer(&h, &spend, 3000, 1, 2, vec![], &mut rng).unwrap();
    assert_eq!(accepted(&mut net, vec![ok, over, elsewhere]), 1);
    assert_eq!(get_u64(&net, &keys::balance(2000)), 15_000_000);

    // The spend key revokes itself.
    let hash = falcon_key_hash(spend.public_key().as_bytes());
    let revoke =
        tx::spend_key::build_spend_key_revoke(&header(&net, 1000), &spend, hash, 2, &mut rng)
            .unwrap();
    assert_eq!(accepted(&mut net, vec![revoke]), 1, "spend key revoke");
    let record: proto::SpendKeyRecord = read(&net, &keys::spend_key(1000, &hash)).unwrap();
    assert!(record.revoked);
}

#[test]
fn wallet_rotation_and_escrow_messages() {
    let mut rng = rng();
    let (mut net, custody) = funded_net(&mut rng);

    // Rotation by the custody key: the balance goes to the escrow of the old
    // key.
    let new_custody = falcon(21);
    let rotation = tx::custody::build_custody_rotation(
        &header(&net, 1000),
        &custody,
        &new_custody,
        None,
        1,
        block_time(&net) + 3_600,
        &mut rng,
    )
    .unwrap();
    assert_eq!(accepted(&mut net, vec![rotation]), 1, "rotation");
    let falcon_escrow = keys::escrow_id_falcon(&falcon_key_hash(custody.public_key().as_bytes()));
    assert_eq!(get_u64(&net, &keys::escrow(&falcon_escrow)), 100_000_000);

    // The old Falcon-512 key claims its escrow to FID 2000.
    let claim = tx::escrow::build_escrow_claim(
        FarcasterNetwork::Devnet,
        block_time(&net),
        &EscrowClaim {
            destination_fid: 2000,
            nonce: 1,
        },
        &EscrowOwner::Falcon(&custody),
        &mut rng,
    )
    .unwrap();
    assert_eq!(
        accepted(&mut net, vec![claim]),
        1,
        "Falcon-512 escrow claim"
    );
    assert_eq!(get_u64(&net, &keys::balance(2000)), 100_000_000);

    // An IdRegistry transfer of FID 2000 (not migrated) moves its balance to
    // the escrow of eth(6).
    let mut p = net.proposal(vec![]);
    p.onchain_events = vec![id_event(
        2000,
        &address(&eth(8)),
        4,
        IdRegisterEventType::Transfer,
    )];
    net.run(p);
    let eth_escrow = keys::escrow_id_optimism(&address(&eth(6)));
    assert_eq!(get_u64(&net, &keys::escrow(&eth_escrow)), 100_000_000);

    // eth(6) bridges 10 tokens of it, then claims the rest with a signature
    // made from the digest (a hardware wallet).
    let bridge = tx::escrow::build_escrow_bridge(
        FarcasterNetwork::Devnet,
        block_time(&net),
        &EscrowBridge {
            amount: 10_000_000,
            destination_chain_id: 10,
            destination_address: [0xcd; 20],
            nonce: 1,
        },
        &EscrowOwner::Address {
            address: address(&eth(6)),
            auth: Eip712Auth::Signer(&eth(6)),
        },
        &mut rng,
    )
    .unwrap();
    let ts = block_time(&net);
    let claim = EscrowClaim {
        destination_fid: 1000,
        nonce: 2,
    };
    let digest =
        tx::escrow::escrow_claim_digest(FarcasterNetwork::Devnet, ts, &claim, address(&eth(6)));
    let signature = hypersnap_messages::eip712_sign_hash(&eth(6), &digest).unwrap();
    let claim = tx::escrow::build_escrow_claim(
        FarcasterNetwork::Devnet,
        ts,
        &claim,
        &EscrowOwner::Address {
            address: address(&eth(6)),
            auth: Eip712Auth::Signature(signature),
        },
        &mut rng,
    )
    .unwrap();
    assert_eq!(
        accepted(&mut net, vec![bridge, claim]),
        2,
        "EIP-712 escrow bridge and claim"
    );
    assert_eq!(get_u64(&net, &keys::balance(1000)), 90_000_000);
    assert_eq!(get_u64(&net, &keys::escrow(&eth_escrow)), 0);
}

#[tokio::test]
async fn wallet_signers_attestation_and_a_dual_cast_on_shard_1() {
    let mut rng = rng();
    let mut net = Net::new(1);
    let mut shard1 = Shard1::new(&net).await;
    let p0 = |net: &Net, messages: Vec<proto::Message>| Shard0Proposal {
        shard_links: vec![genesis_link(1), genesis_link(2)],
        ..net.proposal(messages)
    };
    let run0 = |net: &mut Net, messages: Vec<proto::Message>| -> usize {
        let p = p0(net, messages);
        net.run(p).messages.len()
    };

    // Shard 0: pivot; FIDs 1000 and 2000 register; FID 1000 gets 10 tokens.
    net.run(p0(&net, vec![]));
    let owner = eth(5);
    let app_owner = eth(6);
    let mut p = p0(&net, vec![]);
    p.onchain_events = vec![
        id_event(1000, &address(&owner), 1, IdRegisterEventType::Register),
        id_event(2000, &address(&app_owner), 2, IdRegisterEventType::Register),
    ];
    p.inbound_burns = vec![burn(1000, 10_000_000, 1)];
    net.run(p);

    // Migration, a signer pair (request FID 2000), a Falcon-512 signer, and a
    // fee deposit, in one block.
    let custody = falcon(31);
    let t = block_time(&net);
    let h = header(&net, 1000);
    let migration = tx::custody::build_custody_migration(
        &h,
        &custody,
        None,
        0,
        t + 3_600,
        &Eip712Auth::Signer(&owner),
        &mut rng,
    )
    .unwrap();
    let p_key = ed25519_dalek::SigningKey::from_bytes(&[32u8; 32]);
    let pf = falcon(33);
    let snapchain_key_add = messages_factory::keys::create_key_add(
        1000,
        &owner,
        2000,
        &app_owner,
        &p_key,
        vec![MessageType::CastAdd],
        3_600,
        1,
        t + 3_600,
        Some(t),
    );
    let pair_add = tx::signer::build_pair_key_add(
        snapchain_key_add.data.unwrap(),
        &p_key,
        &pf,
        &custody,
        &mut rng,
    )
    .unwrap();
    let signer = falcon(34);
    let falcon_add = tx::signer::build_falcon_key_add(
        &h,
        &custody,
        &signer,
        &KeyGrant {
            scopes: vec![MessageType::CastAdd, MessageType::NodeAttestation],
            ttl: 3_600,
            nonce: 2,
            deadline: (FarcasterTime::current().to_u64() + 3_600) as u32,
        },
        &mut rng,
    )
    .unwrap();
    let deposit =
        tx::token::build_fee_deposit(&h, &MessageSigner::Falcon(&custody), 5_000_000, 1, &mut rng)
            .unwrap();
    // A Falcon-512 KEY_ADD whose deadline is before the block time is not
    // valid, even if the deadline is after the message timestamp (§16.10).
    let short = tx::signer::build_falcon_key_add(
        &h,
        &custody,
        &signer,
        &KeyGrant {
            scopes: vec![MessageType::CastAdd],
            ttl: 3_600,
            nonce: 2,
            deadline: h.timestamp + 100,
        },
        &mut rng,
    )
    .unwrap();
    let late = net.nodes[0].engine.simulate_messages(
        &[migration.clone(), pair_add.clone(), short],
        h.timestamp as u64 + 200,
    );
    assert!(late[0].is_ok() && late[1].is_ok(), "{:?}", late);
    assert!(
        matches!(&late[2], Err(e) if e.to_string().contains("deadline has passed")),
        "{:?}",
        late[2]
    );
    assert_eq!(
        run0(&mut net, vec![migration, pair_add, falcon_add, deposit]),
        4,
        "migration, pair KEY_ADD, Falcon-512 KEY_ADD, fee deposit"
    );

    // The Falcon-512 signer attests a node.
    let node = falcon(35);
    let attestation = tx::node::build_node_attestation(
        &header(&net, 1000),
        &MessageSigner::Falcon(&signer),
        &node,
        vec![1, 2, 3],
        2,
        &mut rng,
    )
    .unwrap();
    assert_eq!(run0(&mut net, vec![attestation]), 1, "node attestation");
    let state: proto::NodeAttestationState = read(
        &net,
        &keys::node_attestation(&falcon_key_hash(node.public_key().as_bytes())),
    )
    .unwrap();
    assert_eq!(state.fid, 1000);

    // Shard 1 applies the outbox. A dual-signed cast of the pair and a
    // Falcon-512 cast are accepted; the FID has no storage units (§17.6).
    shard1.run(&net, vec![]).await;
    let now = Shard1::time(&net);
    let cast_header = Header::new(1000, FarcasterNetwork::Devnet, now as u32);
    let pair = MessageSigner::Pair {
        ed25519: &p_key,
        falcon: &pf,
    };
    let dual = tx::cast::build_cast_add(&cast_header, "dual hello", &pair, &mut rng).unwrap();
    assert_eq!(
        dual.signature_scheme,
        proto::SignatureScheme::Ed25519Falcon512 as i32
    );
    let falcon_cast = tx::cast::build_cast_add(
        &cast_header,
        "falcon hello",
        &MessageSigner::Falcon(&signer),
        &mut rng,
    )
    .unwrap();
    let v = shard1.producer.engine.version_for(&FarcasterTime::new(now));
    shard1
        .producer
        .engine
        .validate_user_message(
            &dual,
            &FarcasterTime::new(now),
            v,
            &mut crate::storage::db::RocksDbTransactionBatch::new(),
        )
        .unwrap();
    let b = shard1
        .run(
            &net,
            vec![
                MempoolMessage::UserMessage(dual),
                MempoolMessage::UserMessage(falcon_cast),
            ],
        )
        .await;
    assert_eq!(
        b.transactions
            .iter()
            .map(|t| t.user_messages.len())
            .sum::<usize>(),
        2,
        "the dual-signed and the Falcon-512 casts"
    );

    // Custody removes the pair; the Falcon-512 signer revokes itself.
    let h = header(&net, 1000);
    let removal = KeyRemoval {
        key: p_key.verifying_key().to_bytes().to_vec(),
        nonce: 3,
        deadline: h.timestamp + 3_600,
    };
    let remove_pair =
        tx::signer::build_key_remove_by_custody(&h, &custody, &removal, &mut rng).unwrap();
    let remove_signer =
        tx::signer::build_falcon_signer_self_remove(&h, &signer, 4, h.timestamp + 3_600, &mut rng)
            .unwrap();
    // Only the custody key signs a custody KEY_REMOVE (§16.10).
    let by_signer =
        tx::signer::build_key_remove_by_custody(&h, &signer, &removal, &mut rng).unwrap();
    let wrong = net.nodes[0]
        .engine
        .simulate_messages(&[by_signer], h.timestamp as u64);
    assert!(
        matches!(&wrong[0], Err(e) if e.to_string().contains("does not match the signer")),
        "{:?}",
        wrong[0]
    );
    // The custody KEY_REMOVE deadline counts against the block time.
    let late = net.nodes[0]
        .engine
        .simulate_messages(&[remove_pair.clone()], (h.timestamp + 3_600) as u64);
    assert!(
        matches!(&late[0], Err(e) if e.to_string().contains("deadline has passed")),
        "{:?}",
        late[0]
    );
    assert_eq!(
        run0(&mut net, vec![remove_pair, remove_signer]),
        2,
        "custody KEY_REMOVE and Falcon-512 self-revocation"
    );
    let state = BlockState::new(net.nodes[0].engine.db().clone());
    assert!(!state
        .txn()
        .exists(&keys::signer_pair(1000, &p_key.verifying_key().to_bytes()))
        .unwrap());
    assert!(!state
        .txn()
        .exists(&keys::falcon_signer(
            1000,
            &falcon_key_hash(signer.public_key().as_bytes())
        ))
        .unwrap());

    // Shard 1 gets the removals: the pair no longer signs.
    shard1.run(&net, vec![]).await;
    let later = tx::cast::build_cast_add(&cast_header, "after removal", &pair, &mut rng).unwrap();
    assert!(shard1
        .producer
        .engine
        .validate_user_message(
            &later,
            &FarcasterTime::new(now),
            v,
            &mut crate::storage::db::RocksDbTransactionBatch::new(),
        )
        .is_err());
}
