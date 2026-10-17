//! Shard-0 engine tests: blocks run through propose, validate and commit on
//! several nodes, which must reach the same state root.

use super::auth::test_keys::*;
use super::keys;
use super::state::BlockState;
use super::test_support::*;
use crate::chain::block::seal;
use crate::proto::{
    self, message_data::Body, CustodyMigrationBody, CustodyRotationBody, FarcasterNetwork,
    HyperInboundBurn, HyperValidatorEventBody, HyperValidatorEventType, IdRegisterEventType,
    KeyAddBody, MessageData, MessageType, NodeAttestationBody, OnChainEvent, SpendKeyAddBody,
    TokenEscrowClaimBody, TokenTransferBody, ValidatorRecord,
};
use alloy_signer_local::PrivateKeySigner;
use hypersnap_falcon::{domains, FalconSecretKey};
use prost::Message as _;

fn data(fid: u64, t: MessageType, body: Body, timestamp: u64) -> MessageData {
    MessageData {
        r#type: t as i32,
        fid,
        timestamp: timestamp as u32,
        network: FarcasterNetwork::Devnet as i32,
        body: Some(body),
    }
}

fn id_register(fid: u64, custody: &[u8], n: u8) -> OnChainEvent {
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

fn burn(fid: u64, amount: u64, n: u8) -> HyperInboundBurn {
    HyperInboundBurn {
        source_chain_id: 1,
        burn_id: vec![n; 32],
        recipient_fid: fid,
        amount,
        ..Default::default()
    }
}

fn eth(seed: u8) -> PrivateKeySigner {
    PrivateKeySigner::from_bytes(&[seed; 32].into()).unwrap()
}

fn balance(net: &Net, fid: u64) -> u64 {
    let state = BlockState::new(net.nodes[0].engine.db().clone());
    let txn = state.txn();
    txn.get_u64(&keys::balance(fid)).unwrap()
}

fn read<T: prost::Message + Default>(net: &Net, key: &[u8]) -> Option<T> {
    let state = BlockState::new(net.nodes[0].engine.db().clone());
    let txn = state.txn();
    txn.get_proto(key).unwrap()
}

fn block_time(net: &Net) -> u64 {
    net.proposal(vec![]).timestamp
}

fn migration(
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

fn transfer(
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
fn funded_net() -> (Net, FalconSecretKey, PrivateKeySigner) {
    let mut net = Net::new(3);
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

#[test]
fn pivot_and_epoch_boundaries_agree_across_nodes() {
    let mut net = Net::new(3);
    let pivot = net.run_empty();
    let header = pivot.header.clone().unwrap();
    assert_eq!(header.height, PIVOT);
    assert!(!header.pivot_record_hash.is_empty());
    assert!(!header.epoch_record_hash.is_empty());
    // [PivotRecord, EpochBoundaryRecord(1)]
    assert_eq!(pivot.system_messages.len(), 2);

    for _ in 0..EPOCH_LEN {
        net.run_empty();
    }
    // The boundary of epoch 2 wrote set(3); every node has the same root.
    let tip = net.nodes[0].engine.tip().unwrap().header.unwrap();
    assert_eq!(tip.epoch, 2);
    assert!(net.nodes[2].engine.set_record(3).unwrap().is_some());
    // Its seed needs the last block of epoch 2.
    assert!(net.nodes[2].engine.epoch_set(3).unwrap().is_none());
    assert!(net.nodes[2].engine.epoch_set(2).unwrap().is_some());
    let state = BlockState::new(net.nodes[0].engine.db().clone());
    let txn = state.txn();
    let rec: proto::EpochBoundaryRecord = txn
        .get_proto(&keys::epoch_boundary_record(2))
        .unwrap()
        .unwrap();
    assert_eq!(rec.block_height, PIVOT + EPOCH_LEN);
    assert_eq!(rec.next_total_weight, 4);
}

#[test]
fn transfers_spend_keys_rotation_and_escrow() {
    let (mut net, custody, _) = funded_net();

    // Account-key transfer.
    let t = transfer(&net, 1000, &custody, 2000, 10_000_000, 1);
    let b = net.run(net.proposal(vec![t]));
    assert_eq!(b.messages.len(), 1);
    assert_eq!(balance(&net, 1000), 90_000_000);
    assert_eq!(balance(&net, 2000), 10_000_000);
    // A replay (same nonce) is dropped.
    let t = transfer(&net, 1000, &custody, 2000, 1, 1);
    let b = net.run(net.proposal(vec![t]));
    assert!(b.messages.is_empty());

    // A spend key with a cap of 5 tokens per epoch.
    let spend = falcon(12);
    let epoch = net.nodes[0].engine.tip().unwrap().header.unwrap().epoch;
    let mut body = SpendKeyAddBody {
        spend_key: falcon_public(&spend),
        app_fid: 2000,
        epoch_cap: 5_000_000,
        expires_at_epoch: epoch + 2,
        nonce: 2,
        ..Default::default()
    };
    let unsigned = data(
        1000,
        MessageType::SpendKeyAdd,
        Body::SpendKeyAddBody(body.clone()),
        block_time(&net),
    );
    body.spend_key_signature = falcon_sign(
        &spend,
        domains::SPEND_KEY_ADD_POP,
        &unsigned.encode_to_vec(),
    );
    let add = falcon_message(
        &custody,
        data(
            1000,
            MessageType::SpendKeyAdd,
            Body::SpendKeyAddBody(body),
            block_time(&net),
        ),
    );
    let b = net.run(net.proposal(vec![add]));
    assert_eq!(b.messages.len(), 1);

    // Within the cap, then above it.
    let ok = transfer(&net, 1000, &spend, 2000, 5_000_000, 1);
    let over = transfer(&net, 1000, &spend, 2000, 1, 2);
    let b = net.run(net.proposal(vec![ok, over]));
    assert_eq!(b.messages.len(), 1);
    assert_eq!(balance(&net, 1000), 85_000_000);

    // Rotation: the balance goes to the escrow of the old key, the spend key
    // is revoked.
    let new_custody = falcon(13);
    let mut body = CustodyRotationBody {
        new_falcon_custody_key: falcon_public(&new_custody),
        nonce: 1,
        deadline: (block_time(&net) + 3_600) as u32,
        ..Default::default()
    };
    let unsigned = data(
        1000,
        MessageType::CustodyRotation,
        Body::CustodyRotationBody(body.clone()),
        block_time(&net),
    );
    body.new_key_signature = falcon_sign(
        &new_custody,
        domains::CUSTODY_ROTATION_POP,
        &unsigned.encode_to_vec(),
    );
    let rot = falcon_message(
        &custody,
        data(
            1000,
            MessageType::CustodyRotation,
            Body::CustodyRotationBody(body),
            block_time(&net),
        ),
    );
    let b = net.run(net.proposal(vec![rot]));
    assert_eq!(b.messages.len(), 1);
    assert_eq!(balance(&net, 1000), 0);
    let escrow_id = keys::escrow_id_falcon(&super::auth::falcon_key_hash(&falcon_public(&custody)));
    let state = BlockState::new(net.nodes[0].engine.db().clone());
    assert_eq!(
        state.txn().get_u64(&keys::escrow(&escrow_id)).unwrap(),
        85_000_000
    );
    let record: proto::SpendKeyRecord = read(
        &net,
        &keys::spend_key(1000, &super::auth::falcon_key_hash(&falcon_public(&spend))),
    )
    .unwrap();
    assert!(record.revoked);
    // The old key no longer signs for the FID.
    let t = transfer(&net, 1000, &custody, 2000, 1, 2);
    assert!(net.run(net.proposal(vec![t])).messages.is_empty());

    // The previous custodian claims the escrow to FID 2000.
    let mut body = TokenEscrowClaimBody {
        destination_fid: 2000,
        nonce: 1,
        falcon_custody_key: falcon_public(&custody),
        ..Default::default()
    };
    let unsigned = data(
        0,
        MessageType::TokenEscrowClaim,
        Body::TokenEscrowClaimBody(body.clone()),
        block_time(&net),
    );
    body.falcon_signature = falcon_sign(
        &custody,
        domains::TOKEN_ESCROW_CLAIM,
        &unsigned.encode_to_vec(),
    );
    let claim = unsigned_message(data(
        0,
        MessageType::TokenEscrowClaim,
        Body::TokenEscrowClaimBody(body),
        block_time(&net),
    ));
    let b = net.run(net.proposal(vec![claim]));
    assert_eq!(b.messages.len(), 1);
    assert_eq!(balance(&net, 2000), 100_000_000);
}

#[test]
fn falcon_signer_signs_a_node_attestation() {
    let (mut net, custody, _) = funded_net();
    let signer = falcon(21);
    let mut body = KeyAddBody {
        key: falcon_public(&signer),
        key_type: super::registry::KEY_TYPE_FALCON512,
        deadline: (block_time(&net) + 3_600) as u32,
        nonce: 1,
        scopes: vec![
            MessageType::NodeAttestation as i32,
            MessageType::CastAdd as i32,
        ],
        ttl: 3_600,
        ..Default::default()
    };
    let unsigned = data(
        1000,
        MessageType::KeyAdd,
        Body::KeyAddBody(body.clone()),
        block_time(&net),
    );
    body.custody_signature =
        falcon_sign(&custody, domains::KEY_ADD_FALCON, &unsigned.encode_to_vec());
    let add = falcon_message(
        &signer,
        data(
            1000,
            MessageType::KeyAdd,
            Body::KeyAddBody(body),
            block_time(&net),
        ),
    );
    let b = net.run(net.proposal(vec![add]));
    assert_eq!(b.messages.len(), 1);
    // The signer record goes to the outbox of the FID's shard.
    let state = BlockState::new(net.nodes[0].engine.db().clone());
    let height = b.header.unwrap().height;
    let entries: Vec<proto::OutboxEntry> = state
        .txn()
        .scan(&keys::outbox_of_height(height))
        .unwrap()
        .values()
        .map(|v| proto::OutboxEntry::decode(v.as_slice()).unwrap())
        .filter(|e| e.fid == 1000)
        .collect();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].shard_id, 1);

    let node_key = falcon(22);
    let mut body = NodeAttestationBody {
        node_public_key: falcon_public(&node_key),
        nonce: 1,
        libp2p_peer_id: vec![1, 2, 3],
        ..Default::default()
    };
    let unsigned = data(
        1000,
        MessageType::NodeAttestation,
        Body::NodeAttestationBody(body.clone()),
        block_time(&net),
    );
    body.node_signature = falcon_sign(
        &node_key,
        domains::NODE_ATTESTATION_POP,
        &unsigned.encode_to_vec(),
    );
    let att = falcon_message(
        &signer,
        data(
            1000,
            MessageType::NodeAttestation,
            Body::NodeAttestationBody(body),
            block_time(&net),
        ),
    );
    let b = net.run(net.proposal(vec![att]));
    assert_eq!(b.messages.len(), 1);
    let hash = super::auth::falcon_key_hash(&falcon_public(&node_key));
    let state: proto::NodeAttestationState = read(&net, &keys::node_attestation(&hash)).unwrap();
    assert_eq!(state.fid, 1000);
}

/// A `VALIDATOR_REGISTER` of FID 1000 for the current epoch, with the proofs
/// of possession of `consensus` (under `consensus_pop`) and `node_key`.
fn registration(
    net: &Net,
    custody: &FalconSecretKey,
    consensus: &FalconSecretKey,
    consensus_pop: hypersnap_falcon::Domain,
    node_key: &FalconSecretKey,
) -> proto::Message {
    let mut body = HyperValidatorEventBody {
        event_type: HyperValidatorEventType::Register as i32,
        validator_key: super::auth::falcon_key_hash(&falcon_public(consensus)).to_vec(),
        registration_epoch: net.nodes[0].engine.tip().unwrap().header.unwrap().epoch,
        consensus_key: falcon_public(consensus),
        falcon_node_key: falcon_public(node_key),
        ..Default::default()
    };
    let payload = data(
        1000,
        MessageType::ValidatorRegister,
        Body::ValidatorEventBody(body.clone()),
        block_time(net),
    )
    .encode_to_vec();
    body.signature = falcon_sign(consensus, consensus_pop, &payload);
    body.node_signature = falcon_sign(node_key, domains::VALIDATOR_NODE_POP, &payload);
    falcon_message(
        custody,
        data(
            1000,
            MessageType::ValidatorRegister,
            Body::ValidatorEventBody(body),
            block_time(net),
        ),
    )
}

#[test]
fn validator_registration_joins_two_epochs_later() {
    let (mut net, custody, _) = funded_net();
    let node_key = falcon(31);
    let mut body = NodeAttestationBody {
        node_public_key: falcon_public(&node_key),
        nonce: 1,
        ..Default::default()
    };
    let unsigned = data(
        1000,
        MessageType::NodeAttestation,
        Body::NodeAttestationBody(body.clone()),
        block_time(&net),
    );
    body.node_signature = falcon_sign(
        &node_key,
        domains::NODE_ATTESTATION_POP,
        &unsigned.encode_to_vec(),
    );
    let att = falcon_message(
        &custody,
        data(
            1000,
            MessageType::NodeAttestation,
            Body::NodeAttestationBody(body),
            block_time(&net),
        ),
    );
    assert_eq!(net.run(net.proposal(vec![att])).messages.len(), 1);

    let consensus = falcon(77);
    let consensus_hash = super::auth::falcon_key_hash(&falcon_public(&consensus));
    let epoch = net.nodes[0].engine.tip().unwrap().header.unwrap().epoch;
    // The proof of possession of the consensus key has its own domain, and
    // the consensus key is not the node key (§3, §4.5).
    let t = block_time(&net);
    for bad in [
        registration(
            &net,
            &custody,
            &consensus,
            domains::VALIDATOR_NODE_POP,
            &node_key,
        ),
        registration(
            &net,
            &custody,
            &node_key,
            domains::VALIDATOR_CONSENSUS_POP,
            &node_key,
        ),
    ] {
        assert!(net.nodes[0].engine.simulate_messages(&[bad], t)[0].is_err());
    }
    let reg = registration(
        &net,
        &custody,
        &consensus,
        domains::VALIDATOR_CONSENSUS_POP,
        &node_key,
    );
    let simulated = net.nodes[0].engine.simulate_messages(&[reg.clone()], t);
    assert!(simulated[0].is_ok(), "{:?}", simulated[0]);
    assert_eq!(net.run(net.proposal(vec![reg])).messages.len(), 1);
    let record: ValidatorRecord = read(&net, &keys::validator(&consensus_hash)).unwrap();
    assert_eq!(record.join_epoch, epoch + 2);

    // Run to the boundary of epoch + 1: set(epoch + 2) has 5 members.
    while net.nodes[0].engine.tip().unwrap().header.unwrap().epoch < epoch + 1 {
        net.run_empty();
    }
    let set = net.nodes[0].engine.set_record(epoch + 2).unwrap().unwrap();
    assert_eq!(set.members.len(), 5);
    assert_eq!(
        net.nodes[0]
            .engine
            .set_record(epoch + 1)
            .unwrap()
            .unwrap()
            .members
            .len(),
        4
    );
    // The new validator signs in epoch + 2.
    while net.nodes[0].engine.tip().unwrap().header.unwrap().epoch < epoch + 2 {
        net.run_empty();
    }
    let set = net.nodes[0].engine.epoch_set(epoch + 2).unwrap().unwrap();
    assert!(set.record.members.iter().any(|m| m.fid == 1000));
}

#[test]
fn a_block_with_an_invalid_message_is_rejected() {
    let (mut net, custody, _) = funded_net();
    let good = transfer(&net, 1000, &custody, 2000, 1, 1);
    let proposal = net.proposal(vec![good]);
    let mut block = net.nodes[0].engine.propose(&net.inputs, proposal).unwrap();
    // Swap in a transfer with a nonce gap, and seal the block again.
    let bad = transfer(&net, 1000, &custody, 2000, 1, 5);
    block.messages = vec![bad];
    seal(&mut block);
    let parent_set = net.nodes[1]
        .engine
        .epoch_set(block.parent_certificate.as_ref().unwrap().epoch)
        .unwrap();
    let err = net.nodes[1]
        .engine
        .validate(&block, &net.inputs, parent_set.as_ref(), u64::MAX)
        .unwrap_err();
    assert!(err.to_string().contains("nonce"), "{}", err);
}

#[test]
fn scoring_result_is_included_and_checked_at_its_height() {
    let (mut net, custody, _) = funded_net();
    // A credibility stake and a vouch for FID 2000 (evaluated two epochs on).
    let stake = |amount, t: proto::StakeType, vouchee, nonce, net: &Net| {
        falcon_message(
            &custody,
            data(
                1000,
                MessageType::TokenStake,
                Body::TokenStakeBody(proto::TokenStakeBody {
                    amount,
                    stake_type: t as i32,
                    nonce,
                    vouchee_fid: vouchee,
                }),
                block_time(net),
            ),
        )
    };
    let m1 = stake(2_000_000, proto::StakeType::Credibility, 0, 1, &net);
    let m2 = stake(3_000_000, proto::StakeType::Vouch, 2000, 2, &net);
    assert_eq!(net.run(net.proposal(vec![m1, m2])).messages.len(), 2);

    // Node 0 takes a checkpoint at each boundary; run to the boundary of
    // epoch 2 and score epoch 1 from its checkpoint.
    let ckpt_dir = tempfile::TempDir::new().unwrap();
    let checkpoints = std::sync::Arc::new(crate::chain::checkpoints::Checkpoints::new(
        ckpt_dir.path(),
        FarcasterNetwork::Devnet,
    ));
    net.nodes[0].engine.set_checkpoints(checkpoints.clone());
    while net.nodes[0].engine.tip().unwrap().header.unwrap().epoch < 2 {
        net.run_empty();
    }
    assert!(checkpoints.exists(0, 2));
    let service = crate::chain::scoring::ScoringService::new(
        checkpoints.clone(),
        net.nodes[0].engine.params().clone(),
        vec![],
        0,
        Some(ckpt_dir.path().join("scoring")),
    );
    // A later block does not change the result: it reads the checkpoint.
    net.run_empty();
    let result = service.try_run(1).unwrap().expect("checkpoints complete");
    assert_eq!(result.epoch, 1);
    // The result survives a restart of the service.
    let again = crate::chain::scoring::ScoringService::new(
        checkpoints,
        net.nodes[0].engine.params().clone(),
        vec![],
        0,
        Some(ckpt_dir.path().join("scoring")),
    );
    use crate::chain::shard0::views::ScoringSource;
    assert_eq!(again.scoring_result(1), Some(result.clone()));
    net.inputs.scoring.lock().unwrap().insert(1, result.clone());

    // The block at boundary(2) + SCORING_DELAY carries it; all nodes agree.
    let due = PIVOT + EPOCH_LEN + params().scoring_delay;
    while net.next_height() < due {
        net.run_empty();
    }
    let b = net.run_empty();
    assert_eq!(b.header.as_ref().unwrap().height, due);
    let carried = b
        .system_messages
        .iter()
        .find_map(|m| match &m.message {
            Some(proto::hypersnap_system_message::Message::ScoringResult(r)) => Some(r.clone()),
            _ => None,
        })
        .expect("ScoringResult at its height");
    assert_eq!(carried.trust, result.trust);
    let stored: proto::ScoringResult = read(&net, &keys::scoring_result(1)).unwrap();
    assert_eq!(stored.epoch, 1);

    // FID 1000 has a trust snapshot entry from the seed cohort, and its
    // shard got it in the replica outbox.
    assert!(carried.trust.iter().any(|t| t.fid == 1000));
    let state = BlockState::new(net.nodes[0].engine.db().clone());
    let entries = state.txn().scan(&keys::outbox_of_height(due)).unwrap();
    assert!(!entries.is_empty());
}

#[test]
fn a_new_validator_answers_a_da_challenge_from_its_checkpoint() {
    let (mut net, custody, _) = funded_net();
    // Every node takes checkpoints and checks DA responses against them.
    let dirs: Vec<tempfile::TempDir> = (0..net.nodes.len())
        .map(|_| tempfile::TempDir::new().unwrap())
        .collect();
    let checkpoints: Vec<std::sync::Arc<crate::chain::checkpoints::Checkpoints>> = dirs
        .iter()
        .map(|d| {
            std::sync::Arc::new(crate::chain::checkpoints::Checkpoints::new(
                d.path(),
                FarcasterNetwork::Devnet,
            ))
        })
        .collect();
    for (n, c) in net.nodes.iter_mut().zip(&checkpoints) {
        n.engine.set_checkpoints(c.clone());
    }

    // Attest a node key and register a validator (joins at epoch + 2).
    let node_key = falcon(51);
    let mut body = NodeAttestationBody {
        node_public_key: falcon_public(&node_key),
        nonce: 1,
        ..Default::default()
    };
    let unsigned = data(
        1000,
        MessageType::NodeAttestation,
        Body::NodeAttestationBody(body.clone()),
        block_time(&net),
    );
    body.node_signature = falcon_sign(
        &node_key,
        domains::NODE_ATTESTATION_POP,
        &unsigned.encode_to_vec(),
    );
    let att = falcon_message(
        &custody,
        data(
            1000,
            MessageType::NodeAttestation,
            Body::NodeAttestationBody(body),
            block_time(&net),
        ),
    );
    assert_eq!(net.run(net.proposal(vec![att])).messages.len(), 1);
    let consensus = falcon(78);
    let consensus_hash = super::auth::falcon_key_hash(&falcon_public(&consensus));
    let epoch = net.nodes[0].engine.tip().unwrap().header.unwrap().epoch;
    let reg = registration(
        &net,
        &custody,
        &consensus,
        domains::VALIDATOR_CONSENSUS_POP,
        &node_key,
    );
    assert_eq!(net.run(net.proposal(vec![reg])).messages.len(), 1);

    // Run to the boundary of epoch + 2, where the validator is in the set.
    let joined = epoch + 2;
    while net.nodes[0].engine.tip().unwrap().header.unwrap().epoch < joined {
        net.run_empty();
    }
    assert!(checkpoints.iter().all(|c| c.exists(0, joined)));

    // A challenge of shard 0 for this node.
    let node_hash = super::auth::falcon_key_hash(&falcon_public(&node_key));
    let state = BlockState::new(net.nodes[0].engine.db().clone());
    let seed = super::validators::epoch_seed(&state.txn(), joined)
        .unwrap()
        .unwrap();
    let da_seed = super::work::da_seed(joined, &seed);
    let index = (0..100u32)
        .find(|&i| super::work::challenge(&da_seed, &node_hash, i, 3).shard_id == 0)
        .expect("a shard-0 challenge");
    let c = super::work::challenge(&da_seed, &node_hash, index, 3);
    let leaf = checkpoints[0]
        .challenged_leaf(joined, 0, &c.target_path)
        .unwrap();
    let respond = |key: Vec<u8>, net: &Net| {
        falcon_message(
            &node_key,
            data(
                1000,
                MessageType::DaChallengeResponse,
                Body::DaChallengeResponseBody(proto::DaChallengeResponseBody {
                    epoch: joined,
                    challenge_index: index,
                    leaf_key: key,
                    leaf_value: leaf.value.clone(),
                    proof: leaf.proof.clone(),
                }),
                block_time(net),
            ),
        )
    };
    // The inputs check DA responses against the checkpoints of node 1 (the
    // validator of the block).
    struct DaInputs<'a> {
        base: &'a TestInputs,
        checkpoints: &'a crate::chain::checkpoints::Checkpoints,
    }
    impl super::engine::Shard0Inputs for DaInputs<'_> {
        fn onchain_event_ok(&self, e: &OnChainEvent) -> bool {
            self.base.onchain_event_ok(e)
        }
        fn inbound_burn_ok(&self, b: &HyperInboundBurn) -> bool {
            self.base.inbound_burn_ok(b)
        }
        fn shard_link_ok(&self, l: &proto::ShardLink) -> bool {
            self.base.shard_link_ok(l)
        }
        fn fee_settlements(&self, s: u32, a: u64, u: u64) -> Option<Vec<proto::FeeSettlement>> {
            self.base.fee_settlements(s, a, u)
        }
        fn scoring_result(&self, e: u64) -> Option<proto::ScoringResult> {
            self.base.scoring_result(e)
        }
        fn pivot_record(&self) -> Option<proto::PivotRecord> {
            self.base.pivot_record()
        }
        fn da_checkpoints(&self) -> &dyn super::work::DaCheckpoints {
            self.checkpoints
        }
        fn shard_tips(&self) -> Vec<proto::ShardLink> {
            self.base.shard_tips()
        }
    }
    // A wrong leaf is dropped; the right one is accepted.
    let wrong = respond(vec![1, 2, 3], &net);
    let right = respond(leaf.key.clone(), &net);
    let proposal = net.proposal(vec![wrong, right]);
    let inputs0 = DaInputs {
        base: &net.inputs,
        checkpoints: &checkpoints[0],
    };
    let block = net.nodes[0].engine.propose(&inputs0, proposal).unwrap();
    assert_eq!(block.messages.len(), 1);
    let parent_set = net.nodes[1]
        .engine
        .epoch_set(block.parent_certificate.as_ref().unwrap().epoch)
        .unwrap();
    let inputs1 = DaInputs {
        base: &net.inputs,
        checkpoints: &checkpoints[1],
    };
    net.nodes[1]
        .engine
        .validate(&block, &inputs1, parent_set.as_ref(), u64::MAX)
        .unwrap();

    // The responder of the node key answers each challenge that has a
    // checkpoint (shard 0 only in this net), and only once.
    let shard0_challenges = (0..net.nodes[0].engine.params().da_challenges_per_epoch)
        .filter(|&i| super::work::challenge(&da_seed, &node_hash, i, 3).shard_id == 0)
        .count();
    let mut responder = crate::chain::da_responder::DaResponder::new(falcon(51));
    let after = |net: &Net, responder: &mut crate::chain::da_responder::DaResponder| {
        let tip = net.nodes[0].engine.tip().unwrap().header.unwrap();
        responder
            .after_block(
                net.nodes[0].engine.db(),
                net.nodes[0].engine.params(),
                &checkpoints[0],
                tip.height,
                tip.timestamp,
                &mut rand::rngs::OsRng,
            )
            .unwrap()
    };
    let answers = after(&net, &mut responder);
    assert_eq!(answers.len(), shard0_challenges);
    let inputs0 = DaInputs {
        base: &net.inputs,
        checkpoints: &checkpoints[0],
    };
    let proposal = net.proposal(answers);
    let mut block = net.nodes[0].engine.propose(&inputs0, proposal).unwrap();
    assert_eq!(block.messages.len(), shard0_challenges, "all answers valid");
    // The other nodes commit the decided block as from sync: the
    // certificate covers the checkpoint check (FIP §4.3).
    net.commit_certified(&mut block);
    let state = BlockState::new(net.nodes[0].engine.db().clone());
    assert_eq!(
        state
            .txn()
            .scan(&keys::da_answered_of_epoch(joined))
            .unwrap()
            .len(),
        shard0_challenges
    );
    assert!(
        after(&net, &mut responder).is_empty(),
        "nothing to send again"
    );
    // After the window, no answer for the epoch.
    let mut fresh = crate::chain::da_responder::DaResponder::new(falcon(51));
    let window = net.nodes[0].engine.params().challenge_response_window;
    while net.nodes[0].engine.tip().unwrap().header.unwrap().height
        < net.nodes[0].engine.params().epochs.boundary_height(joined) + window
    {
        net.run_empty();
    }
    assert!(after(&net, &mut fresh).iter().all(|m| {
        match m.data.as_ref().and_then(|d| d.body.as_ref()) {
            Some(Body::DaChallengeResponseBody(b)) => b.epoch != joined,
            _ => false,
        }
    }));
}

fn onboard_message(
    net: &Net,
    owner: &PrivateKeySigner,
    gate: proto::hyper_native_onboard_body::GateProof,
    falcon_custody: Option<&FalconSecretKey>,
) -> proto::Message {
    use super::onboarding::*;
    use alloy_signer::SignerSync;
    let tip = net.nodes[0].engine.tip().unwrap().header.unwrap();
    let anchor = crate::chain::block::block_hash(&tip);
    let custody: [u8; 20] = owner.address().0 .0;
    let commitment = match &gate {
        proto::hyper_native_onboard_body::GateProof::Pow(p) => {
            pow_gate_commitment(&p.nonce, p.difficulty_bits)
        }
        proto::hyper_native_onboard_body::GateProof::Stake(s) => {
            stake_gate_commitment(&s.stake_lock_id, s.amount_atoms, s.lock_duration_blocks)
        }
    };
    let hash = typed_hash(onboard_typed_data(
        params().protocol_chain_id,
        &custody,
        tip.height,
        &anchor,
        &commitment,
    ))
    .unwrap();
    let sig = owner
        .sign_hash_sync(&hash.into())
        .unwrap()
        .as_bytes()
        .to_vec();
    let body = proto::HyperNativeOnboardBody {
        custody_address: custody.to_vec(),
        custody_signature: sig,
        anchor_block_height: tip.height,
        anchor_block_hash: anchor.to_vec(),
        gate_proof: Some(gate),
        falcon_custody_key: falcon_custody.map(falcon_public).unwrap_or_default(),
        ..Default::default()
    };
    let d = data(
        0,
        MessageType::NativeOnboard,
        Body::NativeOnboardBody(body),
        block_time(net),
    );
    match falcon_custody {
        Some(sk) => falcon_message(sk, d),
        None => unsigned_message(d),
    }
}

fn solve_pow(custody: &[u8; 20], anchor: &[u8; 32], bits: u32) -> proto::PowSolution {
    for i in 0u64.. {
        let nonce = i.to_be_bytes().to_vec();
        if super::onboarding::pow_target_met(
            &super::onboarding::pow_hash(custody, anchor, &nonce),
            bits,
        ) {
            return proto::PowSolution {
                nonce,
                difficulty_bits: bits,
            };
        }
    }
    unreachable!()
}

#[test]
fn native_onboarding_by_pow_and_by_stake() {
    let (mut net, custody, _) = funded_net();
    // PoW gate, with a Falcon-512 custody key: migrated from the first block.
    let user = eth(31);
    let native_custody = falcon(32);
    let tip = net.nodes[0].engine.tip().unwrap().header.unwrap();
    let pow = solve_pow(
        &user.address().0 .0,
        &crate::chain::block::block_hash(&tip),
        8,
    );
    let m = onboard_message(
        &net,
        &user,
        proto::hyper_native_onboard_body::GateProof::Pow(pow),
        Some(&native_custody),
    );
    assert_eq!(net.run(net.proposal(vec![m.clone()])).messages.len(), 1);
    let first = super::onboarding::FIRST_NATIVE_FID;
    let rec: proto::FidCustodyRecord = read(&net, &keys::custody(first)).unwrap();
    assert_eq!(rec.falcon_custody_key, falcon_public(&native_custody));
    // The same custody cannot onboard again (and the anchor moved on).
    assert!(net.run(net.proposal(vec![m])).messages.is_empty());

    // The native FID can receive and send tokens with its account key.
    let t = transfer(&net, 1000, &custody, first, 2_000_000, 1);
    assert_eq!(net.run(net.proposal(vec![t])).messages.len(), 1);
    let back = transfer(&net, first, &native_custody, 1000, 1_000_000, 1);
    assert_eq!(net.run(net.proposal(vec![back])).messages.len(), 1);
    assert_eq!(balance(&net, first), 1_000_000);

    // Stake gate: FID 1000 sponsors a lock; a second user onboards with it.
    let lock_id = super::onboarding::derive_stake_lock_id(1000, 2);
    let lock = falcon_message(
        &custody,
        data(
            1000,
            MessageType::OnboardingStakeLock,
            Body::OnboardingStakeLockBody(proto::OnboardingStakeLockBody {
                stake_lock_id: lock_id.to_vec(),
                amount_atoms: 1_000_000_000,
                lock_duration_blocks: 2,
                nonce: 2,
            }),
            block_time(&net),
        ),
    );
    // The sponsor has 89 tokens; the minimum stake is 1,000 tokens.
    assert!(net.run(net.proposal(vec![lock])).messages.is_empty());
    let mut p = net.proposal(vec![]);
    p.inbound_burns = vec![burn(1000, 1_000_000_000, 9)];
    net.run(p);
    let lock = falcon_message(
        &custody,
        data(
            1000,
            MessageType::OnboardingStakeLock,
            Body::OnboardingStakeLockBody(proto::OnboardingStakeLockBody {
                stake_lock_id: lock_id.to_vec(),
                amount_atoms: 1_000_000_000,
                lock_duration_blocks: 2,
                nonce: 2,
            }),
            block_time(&net),
        ),
    );
    assert_eq!(net.run(net.proposal(vec![lock])).messages.len(), 1);
    let second = eth(33);
    let stake = proto::StakeProof {
        stake_lock_id: lock_id.to_vec(),
        amount_atoms: 1_000_000_000,
        lock_duration_blocks: 2,
    };
    let m = onboard_message(
        &net,
        &second,
        proto::hyper_native_onboard_body::GateProof::Stake(stake),
        None,
    );
    assert_eq!(net.run(net.proposal(vec![m])).messages.len(), 1);
    let state = BlockState::new(net.nodes[0].engine.db().clone());
    assert!(state
        .txn()
        .exists(&super::onboarding::native_fid_key(first + 1))
        .unwrap());
    // A consumed stake is not refundable.
    net.run_empty();
    net.run_empty();
    let release = falcon_message(
        &custody,
        data(
            1000,
            MessageType::OnboardingStakeRelease,
            Body::OnboardingStakeReleaseBody(proto::OnboardingStakeReleaseBody {
                stake_lock_id: lock_id.to_vec(),
                nonce: 3,
            }),
            block_time(&net),
        ),
    );
    assert!(net.run(net.proposal(vec![release])).messages.is_empty());
}

#[test]
fn miniapp_register_add_and_receipt() {
    let (mut net, custody, owner) = funded_net();
    // JFS proof: custody address of FID 1000 over header.payload.
    use alloy_signer::SignerSync;
    use base64::Engine as _;
    let header = format!(
        "{{\"fid\":1000,\"type\":\"custody\",\"key\":\"0x{}\"}}",
        hex::encode(owner.address())
    )
    .into_bytes();
    let payload = format!(
        "{{\"domain\":\"example.com\",\"chain_id\":{}}}",
        params().protocol_chain_id
    )
    .into_bytes();
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let input = format!("{}.{}", b64.encode(&header), b64.encode(&payload));
    let signature = owner
        .sign_message_sync(input.as_bytes())
        .unwrap()
        .as_bytes()
        .to_vec();
    let metadata = proto::MiniappMetadata {
        name: "Example".into(),
        home_url: "https://example.com".into(),
        icon_url: "https://example.com/icon.png".into(),
        ..Default::default()
    };
    let reg = falcon_message(
        &custody,
        data(
            1000,
            MessageType::MiniappRegister,
            Body::MiniappRegisterBody(proto::MiniappRegisterBody {
                domain: "example.com".into(),
                metadata: Some(metadata),
                proof: Some(proto::AccountAssociationProof {
                    header,
                    payload,
                    signature,
                }),
            }),
            block_time(&net),
        ),
    );
    assert_eq!(net.run(net.proposal(vec![reg])).messages.len(), 1);
    let add = falcon_message(
        &custody,
        data(
            1000,
            MessageType::MiniappAdd,
            Body::MiniappAddBody(proto::MiniappAddBody {
                domain: "example.com".into(),
            }),
            block_time(&net),
        ),
    );
    let epoch = net.nodes[0].engine.tip().unwrap().header.unwrap().epoch;
    let receipt = falcon_message(
        &custody,
        data(
            1000,
            MessageType::AppUsageReceipt,
            Body::AppUsageReceiptBody(proto::AppUsageReceiptBody {
                miniapp_id: crate::chain::shard0::miniapp_rules::miniapp_id_from_domain(
                    "example.com",
                )
                .to_vec(),
                action_type: "open".into(),
                epoch,
                nonce: 1,
            }),
            block_time(&net),
        ),
    );
    // A receipt must be signed by an app signer of the user: the account
    // key is not one, so only the add is accepted.
    let b = net.run(net.proposal(vec![add, receipt]));
    assert_eq!(b.messages.len(), 1);
    let state: proto::MiniappState = read(
        &net,
        &super::miniapp::state_key(
            &crate::chain::shard0::miniapp_rules::miniapp_id_from_domain("example.com"),
        ),
    )
    .unwrap();
    assert_eq!(state.add_count, 1);
    assert_eq!(state.author_fid, 1000);
}

#[test]
fn scoring_an_epoch_with_no_registered_fids() {
    let mut net = Net::new(1);
    let dir = tempfile::TempDir::new().unwrap();
    let checkpoints = std::sync::Arc::new(crate::chain::checkpoints::Checkpoints::new(
        dir.path(),
        FarcasterNetwork::Devnet,
    ));
    net.nodes[0].engine.set_checkpoints(checkpoints.clone());
    while net.next_height() <= PIVOT + EPOCH_LEN {
        net.run_empty();
    }
    let service =
        crate::chain::scoring::ScoringService::new(checkpoints, params(), vec![], 0, None);
    let result = service.try_run(1).unwrap().expect("checkpoint present");
    assert!(result.rewards.is_empty());
    // After the windows of epoch 3 close, the boundary-2 checkpoint goes.
    let ckpts = crate::chain::checkpoints::Checkpoints::new(dir.path(), FarcasterNetwork::Devnet);
    assert!(ckpts.exists(0, 2));
    let close = PIVOT
        + 2 * EPOCH_LEN
        + params()
            .scoring_delay
            .max(params().challenge_response_window)
        + 1;
    while net.next_height() <= close {
        net.run_empty();
    }
    assert!(!ckpts.exists(0, 2));
    assert!(ckpts.exists(0, 3));
}

/// WS6 exit: conservation. After every block, the tokens in the ledger
/// (balances, stakes, unstaking, escrows, fee balances, onboarding locks and
/// bridge locks) equal bridged in + minted − burned.
fn ledger_total(net: &Net) -> (u128, u128) {
    use crate::storage::constants::RootPrefix as P;
    let state = BlockState::new(net.nodes[0].engine.db().clone());
    let txn = state.txn();
    let sum = |prefix: P, skip: &dyn Fn(&[u8]) -> bool| -> u128 {
        txn.scan(&[prefix as u8])
            .unwrap()
            .iter()
            .filter(|(k, _)| !skip(k))
            .map(|(_, v)| keys::decode_u64(v) as u128)
            .sum()
    };
    let none = |_: &[u8]| false;
    let mut held = sum(P::HyperRewardBalance, &none)
        // [68][fid][type]; 0xff is the received-vouch index, not tokens.
        + sum(P::HyperTokenStaked, &|k: &[u8]| k.last() == Some(&keys::STAKE_VOUCH_RECEIVED))
        + sum(P::HyperTokenUnstakeQueue, &none)
        + sum(P::HyperTokenEscrow, &none)
        + sum(P::HyperFeeBalance, &none);
    for (_, v) in txn.scan(&[P::HyperTokenLocked as u8]).unwrap() {
        held += <proto::TokenLockState as prost::Message>::decode(v.as_slice())
            .unwrap()
            .amount as u128;
    }
    for (_, v) in txn.scan(&[P::HyperOnboardingStakeLock as u8]).unwrap() {
        held += keys::decode_u64(&v[8..16]) as u128;
    }
    let meta = |m: keys::Meta| txn.get_u64(&keys::meta(m)).unwrap() as u128;
    let issued = meta(keys::Meta::BridgedIn) + meta(keys::Meta::Minted) - meta(keys::Meta::Burned);
    (held, issued)
}

#[test]
fn ledger_conservation_over_random_operations() {
    use rand::{Rng, SeedableRng};
    let (mut net, custody, _) = funded_net();
    // FID 2000 migrates too, so both FIDs can send.
    let other_eth = eth(6);
    let other = falcon(71);
    let m = migration(&net, 2000, &other, &other_eth);
    assert_eq!(net.run(net.proposal(vec![m])).messages.len(), 1);
    let fids = [(1000u64, custody), (2000u64, other)];
    let mut nonces = std::collections::BTreeMap::from([(1000u64, 0u64), (2000u64, 0u64)]);
    let mut rng = rand_chacha::ChaCha20Rng::from_seed([5u8; 32]);
    let mut burn_id = 50u8;
    for round in 0..40 {
        let mut messages = Vec::new();
        for _ in 0..3 {
            let i = rng.gen_range(0..2);
            let (fid, key) = (&fids[i].0, &fids[i].1);
            let to = fids[1 - i].0;
            let amount = rng.gen_range(0..3_000_000u64);
            let nonce = nonces[fid] + 1;
            let body = match rng.gen_range(0..6) {
                0 | 1 => Body::TokenTransferBody(TokenTransferBody {
                    recipient_fid: to,
                    amount,
                    nonce,
                    memo: vec![],
                }),
                2 => Body::TokenStakeBody(proto::TokenStakeBody {
                    amount: amount + 1,
                    stake_type: proto::StakeType::Credibility as i32,
                    nonce,
                    vouchee_fid: 0,
                }),
                3 => Body::TokenStakeBody(proto::TokenStakeBody {
                    amount: amount + 1,
                    stake_type: proto::StakeType::Vouch as i32,
                    nonce,
                    vouchee_fid: to,
                }),
                4 => Body::TokenUnstakeBody(proto::TokenUnstakeBody {
                    amount: amount / 2 + 1,
                    stake_type: if rng.gen_bool(0.5) {
                        proto::StakeType::Credibility
                    } else {
                        proto::StakeType::Vouch
                    } as i32,
                    nonce,
                    vouchee_fid: if rng.gen_bool(0.5) { to } else { 0 },
                }),
                _ => Body::FeeDepositBody(proto::FeeDepositBody {
                    amount: amount + 1,
                    nonce,
                }),
            };
            let t = match &body {
                Body::TokenTransferBody(_) => MessageType::TokenTransfer,
                Body::TokenStakeBody(_) => MessageType::TokenStake,
                Body::TokenUnstakeBody(_) => MessageType::TokenUnstake,
                _ => MessageType::FeeDeposit,
            };
            messages.push(falcon_message(key, data(*fid, t, body, block_time(&net))));
        }
        if round % 7 == 3 {
            // A lock to the bridge (activation epoch 1 in the test params).
            let fid = fids[0].0;
            let nonce = nonces[&fid] + 1;
            messages.push(falcon_message(
                &fids[0].1,
                data(
                    fid,
                    MessageType::TokenLock,
                    Body::TokenLockBody(proto::TokenLockBody {
                        amount: 1_000_000,
                        nonce,
                        destination_chain_id: 10,
                        destination_address: vec![9u8; 20],
                    }),
                    block_time(&net),
                ),
            ));
        }
        let mut p = net.proposal(messages);
        if round % 5 == 0 {
            burn_id += 1;
            p.inbound_burns = vec![burn(fids[round % 2].0, 4_000_000, burn_id)];
        }
        let b = net.run(p);
        // Advance the nonces of the accepted messages.
        for m in &b.messages {
            let d = m.data.clone().unwrap();
            *nonces.get_mut(&d.fid).unwrap() += 1;
        }
        let (held, issued) = ledger_total(&net);
        assert_eq!(held, issued, "round {}", round);
    }
    // Crossing epoch boundaries releases unstakes and evaluates vouches; the
    // invariant still holds.
    for _ in 0..(3 * EPOCH_LEN) {
        net.run_empty();
        let (held, issued) = ledger_total(&net);
        assert_eq!(held, issued);
    }
}

/// WS5 exit: the §16.8 acceptance table and the §16.10 signer kinds on
/// shard 0, for a type that a signer of the FID signs (NODE_ATTESTATION)
/// and one that needs the account key (TOKEN_TRANSFER), and the
/// self-revocation of a signer pair.
#[test]
fn signature_acceptance_matrix() {
    use crate::utils::factory::messages_factory;
    let (mut net, custody, owner) = funded_net();
    let other_owner = eth(6); // custody of FID 2000 (not migrated)

    // FID 2000: an on-chain Ed25519 signer.
    let s2 = ed25519_dalek::SigningKey::from_bytes(&[21u8; 32]);
    let mut signer_event = crate::utils::factory::events_factory::create_signer_event(
        2000,
        s2.clone(),
        proto::SignerEventType::Add,
        Some(1_700_000_100),
        None,
    );
    signer_event.transaction_hash = vec![77u8; 32];
    let mut p = net.proposal(vec![]);
    p.onchain_events = vec![signer_event];
    // FID 2000 has tokens, so a rejected transfer is the signer rule.
    p.inbound_burns = vec![burn(2000, 1_000, 9)];
    assert_eq!(
        net.run(p).system_messages.len(),
        2,
        "the KeyRegistry event and the burn"
    );

    // FID 1000 (migrated): a signer pair (gasless Ed25519 key P with
    // Falcon-512 key PF; request FID 2000) and a Falcon-512 signer F.
    let p_key = ed25519_dalek::SigningKey::from_bytes(&[22u8; 32]);
    let pf = falcon(23);
    let t = block_time(&net) as u32;
    let snap = messages_factory::keys::create_key_add(
        1000,
        &owner,
        2000,
        &other_owner,
        &p_key,
        vec![MessageType::NodeAttestation, MessageType::CastAdd],
        3_600,
        1,
        t + 3_600,
        Some(t),
    );
    let data_bytes = snap.data.as_ref().unwrap().encode_to_vec();
    let ext = proto::HyperSignatureExtension {
        falcon_signer_key: falcon_public(&pf),
        falcon_custody_signature: {
            let mut rng = <rand_chacha::ChaCha20Rng as rand::SeedableRng>::from_seed([3u8; 32]);
            hypersnap_falcon::sign_parts(
                &custody,
                domains::KEY_ADD,
                &[&data_bytes, &falcon_public(&pf)],
                &mut rng,
            )
            .unwrap()
            .as_bytes()
            .to_vec()
        },
        ..Default::default()
    };
    // The Ed25519 key of the pair signs its KEY_ADD (proof of possession).
    let other_key = dual_message(&s2, &pf, snap.data.clone().unwrap(), ext.clone());
    let r = net.nodes[0]
        .engine
        .simulate_messages(&[other_key], block_time(&net));
    assert!(
        matches!(&r[0], Err(e) if e.to_string().contains("Ed25519 key of the pair signs")),
        "{:?}",
        r[0]
    );
    let pair_add = dual_message(&p_key, &pf, snap.data.clone().unwrap(), ext);
    assert_eq!(
        net.run(net.proposal(vec![pair_add])).messages.len(),
        1,
        "pair KEY_ADD"
    );
    let f = falcon(24);
    let mut body = KeyAddBody {
        key: falcon_public(&f),
        key_type: super::registry::KEY_TYPE_FALCON512,
        deadline: t + 3_600,
        nonce: 2,
        scopes: vec![MessageType::NodeAttestation as i32],
        ttl: 3_600,
        ..Default::default()
    };
    let unsigned = data(
        1000,
        MessageType::KeyAdd,
        Body::KeyAddBody(body.clone()),
        block_time(&net),
    );
    body.custody_signature =
        falcon_sign(&custody, domains::KEY_ADD_FALCON, &unsigned.encode_to_vec());
    let f_add = falcon_message(
        &f,
        data(
            1000,
            MessageType::KeyAdd,
            Body::KeyAddBody(body),
            block_time(&net),
        ),
    );
    assert_eq!(
        net.run(net.proposal(vec![f_add])).messages.len(),
        1,
        "Falcon KEY_ADD"
    );

    // One cell = one block with one message.
    let mut nonces = std::collections::BTreeMap::from([(1000u64, 0u64), (2000u64, 0u64)]);
    let mut seed = 100u8;
    let mut attest =
        |net: &mut Net, fid: u64, sign: &dyn Fn(MessageData) -> proto::Message| -> bool {
            seed += 1;
            let node = falcon(seed);
            let nonce = nonces[&fid] + 1;
            let mut body = NodeAttestationBody {
                node_public_key: falcon_public(&node),
                nonce,
                ..Default::default()
            };
            let unsigned = data(
                fid,
                MessageType::NodeAttestation,
                Body::NodeAttestationBody(body.clone()),
                block_time(net),
            );
            body.node_signature = falcon_sign(
                &node,
                domains::NODE_ATTESTATION_POP,
                &unsigned.encode_to_vec(),
            );
            let m = sign(data(
                fid,
                MessageType::NodeAttestation,
                Body::NodeAttestationBody(body),
                block_time(net),
            ));
            let ok = net.run(net.proposal(vec![m])).messages.len() == 1;
            if ok {
                *nonces.get_mut(&fid).unwrap() += 1;
            }
            ok
        };
    let pay = |net: &mut Net,
               fid: u64,
               nonce: u64,
               sign: &dyn Fn(MessageData) -> proto::Message|
     -> bool {
        let d = data(
            fid,
            MessageType::TokenTransfer,
            Body::TokenTransferBody(TokenTransferBody {
                recipient_fid: 3000u64.min(2000),
                amount: 1,
                nonce,
                memo: vec![],
            }),
            block_time(net),
        );
        net.run(net.proposal(vec![sign(d)])).messages.len() == 1
    };
    let stranger = falcon(99);

    // Not migrated: Ed25519 only, and an app signer cannot move tokens.
    assert!(
        attest(&mut net, 2000, &|d| ed25519_message(&s2, d)),
        "2000 Ed25519 signer"
    );
    assert!(
        !attest(&mut net, 2000, &|d| falcon_message(&stranger, d)),
        "2000 Falcon-512"
    );
    assert!(
        !pay(&mut net, 2000, 2, &|d| ed25519_message(&s2, d)),
        "2000 transfer"
    );

    // Migrated: no Ed25519-only message, a pair or a Falcon-512 signer for
    // app messages, the account key for tokens.
    assert!(
        !attest(&mut net, 1000, &|d| ed25519_message(&p_key, d)),
        "1000 Ed25519 half"
    );
    assert!(
        attest(&mut net, 1000, &|d| dual_message(
            &p_key,
            &pf,
            d,
            Default::default()
        )),
        "1000 pair"
    );
    assert!(
        !attest(&mut net, 1000, &|d| dual_message(
            &p_key,
            &f,
            d,
            Default::default()
        )),
        "1000 wrong pair"
    );
    assert!(
        attest(&mut net, 1000, &|d| falcon_message(&f, d)),
        "1000 Falcon signer"
    );
    assert!(
        !pay(&mut net, 1000, 3, &|d| falcon_message(&f, d)),
        "1000 transfer by app signer"
    );
    assert!(
        attest(&mut net, 1000, &|d| falcon_message(&custody, d)),
        "1000 account key"
    );
    assert!(
        pay(&mut net, 1000, 4, &|d| falcon_message(&custody, d)),
        "1000 transfer by account key"
    );

    // The pair revokes itself with a dual signature: both halves go.
    let remove = dual_message(
        &p_key,
        &pf,
        data(
            1000,
            MessageType::KeyRemove,
            Body::KeyRemoveBody(proto::KeyRemoveBody {
                key: p_key.verifying_key().to_bytes().to_vec(),
                signature_type: 2,
                deadline: t + 3_600,
                nonce: 1,
                ..Default::default()
            }),
            block_time(&net),
        ),
        Default::default(),
    );
    assert_eq!(
        net.run(net.proposal(vec![remove])).messages.len(),
        1,
        "pair self-revocation"
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
            &super::auth::falcon_key_hash(&falcon_public(&pf))
        ))
        .unwrap());
}

#[test]
fn simulate_checks_messages_in_order_and_keeps_nothing() {
    let (mut net, custody, _) = funded_net();
    let first = transfer(&net, 1000, &custody, 2000, 60_000_000, 1);
    let second = transfer(&net, 1000, &custody, 2000, 60_000_000, 2);
    let t = block_time(&net);
    let engine = &net.nodes[0].engine;

    // After the first, the second overdraws.
    let results = engine.simulate_messages(&[first.clone(), second.clone()], t);
    assert!(results[0].is_ok(), "{:?}", results[0]);
    assert!(
        matches!(&results[1], Err(super::Shard0Error::Invalid(_))),
        "{:?}",
        results[1]
    );
    // A Hypersnap message without its signatures.
    let mut unsigned = first.clone();
    unsigned.signature.clear();
    assert!(engine.simulate_messages(&[unsigned], t)[0].is_err());

    // Nothing was written.
    assert_eq!(balance(&net, 1000), 100_000_000);
    let b = net.run(net.proposal(vec![first]));
    assert_eq!(b.messages.len(), 1);
    assert_eq!(balance(&net, 1000), 40_000_000);
}

#[test]
fn a_proposer_behind_on_a_shard_keeps_the_parents_link() {
    let mut net = Net::new(3);
    for _ in 0..3 {
        net.run_empty();
    }
    let parent = net.nodes[0].engine.tip().unwrap().header.unwrap();
    let before: Vec<u64> = parent.shard_links.iter().map(|l| l.height).collect();
    assert!(before.iter().all(|&h| h > 0));

    // This proposer's view of shard 1 is behind the parent's link.
    let mut p = net.proposal(vec![]);
    p.shard_links[0] = link(1, 0);
    let b = net.run(p);
    let links = &b.header.unwrap().shard_links;
    assert_eq!(links[0], parent.shard_links[0], "the parent's link is kept");
    assert!(links[1].height > before[1]);
}

#[test]
fn a_transfer_of_zero_is_not_valid() {
    let (mut net, custody, _) = funded_net();
    let zero = transfer(&net, 1000, &custody, 2000, 0, 1);
    let err = net.nodes[0]
        .engine
        .simulate_messages(&[zero.clone()], block_time(&net));
    assert_eq!(err[0], Err(super::Shard0Error::invalid("amount is 0")));
    assert!(net.run(net.proposal(vec![zero])).messages.is_empty());
    // The nonce is not used: nonce 1 still works.
    let one = transfer(&net, 1000, &custody, 2000, 1, 1);
    assert_eq!(net.run(net.proposal(vec![one])).messages.len(), 1);
}

#[test]
fn lend_storage_is_not_valid_after_the_pivot() {
    let (mut net, _, _) = funded_net();
    let lend = crate::utils::factory::messages_factory::storage_lend::create_storage_lend(
        1000,
        2000,
        1,
        crate::proto::StorageUnitType::UnitType2025,
        Some(block_time(&net) as u32),
        None,
    );
    let err = net.nodes[0]
        .engine
        .simulate_messages(&[lend.clone()], block_time(&net));
    assert!(
        matches!(&err[0], Err(e) if e.to_string().contains("LEND_STORAGE is not valid")),
        "{:?}",
        err[0]
    );
    assert!(net.run(net.proposal(vec![lend])).messages.is_empty());
}

fn has_burn(block: &proto::HypersnapBlock) -> bool {
    block.system_messages.iter().any(|m| {
        matches!(
            m.message,
            Some(proto::hypersnap_system_message::Message::InboundBurn(_))
        )
    })
}

#[test]
fn a_burn_to_an_fid_that_is_not_registered_waits_for_the_fid() {
    let mut net = Net::new(3);
    net.run_empty();
    let held = burn(3000, 5_000_000, 1);
    let mut p = net.proposal(vec![]);
    p.onchain_events = vec![id_register(1000, eth(5).address().as_slice(), 1)];
    p.inbound_burns = vec![held.clone(), burn(1000, 7, 2)];
    let b = net.run(p);
    // The event and the burn to FID 1000. The burn to FID 3000 waits.
    assert_eq!(b.system_messages.len(), 2);
    assert_eq!(balance(&net, 1000), 7);

    let mut p = net.proposal(vec![]);
    p.onchain_events = vec![id_register(3000, eth(6).address().as_slice(), 2)];
    p.inbound_burns = vec![held.clone()];
    let b = net.run(p);
    assert!(has_burn(&b));
    assert_eq!(balance(&net, 3000), 5_000_000);

    // A processed burn is not credited again.
    let mut p = net.proposal(vec![]);
    p.inbound_burns = vec![held];
    let b = net.run(p);
    assert!(!has_burn(&b));
    assert_eq!(balance(&net, 3000), 5_000_000);
}

#[test]
fn a_proposal_fills_the_block_by_bytes() {
    let mut net = Net::new(3);
    net.run_empty();
    let mut p = net.proposal(vec![]);
    p.onchain_events = vec![id_register(1000, eth(5).address().as_slice(), 1)];
    net.run(p);

    let burns: Vec<HyperInboundBurn> = (1..=200u8).map(|n| burn(1000, n as u64, n)).collect();
    let limit = 12 * 1024;
    net.nodes[0].engine.max_block_bytes = limit;
    let mut p = net.proposal(vec![]);
    p.inbound_burns = burns.clone();
    let b = net.run(p);
    let first = b.system_messages.len();
    assert!(
        first > 0 && first < burns.len(),
        "{} of {} burns",
        first,
        burns.len()
    );
    assert!(b.encoded_len() <= limit, "{} bytes", b.encoded_len());

    // The burns that did not fit go into the next block.
    net.nodes[0].engine.max_block_bytes = crate::chain::block::MAX_BLOCK_BYTES;
    let mut p = net.proposal(vec![]);
    p.inbound_burns = burns;
    let b = net.run(p);
    assert_eq!(first + b.system_messages.len(), 200);
    assert_eq!(balance(&net, 1000), (1..=200u64).sum::<u64>());
}

#[test]
fn hyper_v1_reads_the_shard0_state() {
    use crate::node::hyper_v1::{HyperV1, ReadError};
    let (mut net, custody, _) = funded_net();
    let lock = falcon_message(
        &custody,
        data(
            1000,
            MessageType::TokenLock,
            Body::TokenLockBody(proto::TokenLockBody {
                amount: 1_000_000,
                nonce: 1,
                destination_chain_id: 10,
                destination_address: vec![9u8; 20],
            }),
            block_time(&net),
        ),
    );
    let b = net.run(net.proposal(vec![lock]));
    assert_eq!(b.messages.len(), 1, "the lock is accepted");
    let header = b.header.unwrap();
    let reads = HyperV1::new(net.nodes[0].engine.db().clone(), None);
    let read = |path: &str| reads.read(&format!("/hyper/v1/{}", path));

    assert_eq!(read("head").unwrap()["height"], header.height);
    assert_eq!(read("rewards/1000").unwrap()["balance"], 99_000_000u64);
    assert_eq!(read("nonce/1000").unwrap()["nonce"], 1);
    let burn = read(&format!("bridge/inbound-burn/1/{}", hex::encode([1u8; 32]))).unwrap();
    assert_eq!(burn["processed"], true);
    assert_eq!(burn["amount"], 100_000_000u64);

    // The lock, its leaf and a proof against the block's lock root.
    let root = read("lock-tree/root").unwrap()["root_hex"].clone();
    assert_eq!(root, format!("0x{}", hex::encode(&header.bridge_lock_root)));
    let id = hex::encode(super::ledger::lock_id(1000, 1));
    let lock = read(&format!("lock/1000/{}", id)).unwrap();
    assert_eq!(lock["state"]["amount"], 1_000_000);
    let proof = read(&format!("lock-tree/proof/{}", id)).unwrap();
    assert_eq!(proof["included"], true);
    assert_eq!(proof["leaf_hex"], lock["leaf_hex"]);
    let b256 = |v: &serde_json::Value| {
        let bytes = hex::decode(v.as_str().unwrap().trim_start_matches("0x")).unwrap();
        alloy_primitives::B256::from_slice(&bytes)
    };
    let siblings: Vec<_> = proof["proof_hex"]
        .as_array()
        .unwrap()
        .iter()
        .map(b256)
        .collect();
    assert!(hypersnap_crypto::merkle::verify(
        b256(&proof["leaf_hex"]),
        &siblings,
        b256(&root)
    ));

    assert_eq!(read("nope"), Err(ReadError::NotFound));
    assert!(matches!(read("rewards/x"), Err(ReadError::BadRequest(_))));
}
