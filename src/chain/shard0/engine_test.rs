//! Shard-0 engine tests: blocks run through propose, validate and commit on
//! several nodes, which must reach the same state root.

use super::auth::test_keys::*;
use super::keys;
use super::state::BlockState;
use super::test_support::*;
use crate::chain::block::seal;
use crate::proto::{
    self, message_data::Body, CustodyRotationBody, FarcasterNetwork, HyperInboundBurn,
    HyperValidatorEventBody, HyperValidatorEventType, KeyAddBody, MessageData, MessageType,
    NodeAttestationBody, OnChainEvent, SpendKeyAddBody, TokenEscrowClaimBody, TokenTransferBody,
    ValidatorRecord,
};
use alloy_signer_local::PrivateKeySigner;
use hypersnap_falcon::{domains, FalconSecretKey};
use prost::Message as _;

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

/// FID 1000 attests `node_key` (account nonce `nonce`).
fn attest_node_key(
    net: &mut Net,
    custody: &FalconSecretKey,
    node_key: &FalconSecretKey,
    nonce: u64,
) {
    let mut body = NodeAttestationBody {
        node_public_key: falcon_public(node_key),
        nonce,
        ..Default::default()
    };
    let unsigned = data(
        1000,
        MessageType::NodeAttestation,
        Body::NodeAttestationBody(body.clone()),
        block_time(net),
    );
    body.node_signature = falcon_sign(
        node_key,
        domains::NODE_ATTESTATION_POP,
        &unsigned.encode_to_vec(),
    );
    let att = falcon_message(
        custody,
        data(
            1000,
            MessageType::NodeAttestation,
            Body::NodeAttestationBody(body),
            block_time(net),
        ),
    );
    assert_eq!(net.run(net.proposal(vec![att])).messages.len(), 1);
}

#[test]
fn validator_registration_joins_two_epochs_later() {
    let (mut net, custody, _) = funded_net();
    let node_key = falcon(31);
    attest_node_key(&mut net, &custody, &node_key, 1);

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

fn tip_epoch(net: &Net) -> u64 {
    net.nodes[0].engine.tip().unwrap().header.unwrap().epoch
}

fn validator_record(net: &Net, hash: &[u8]) -> ValidatorRecord {
    read(net, &keys::validator(hash)).unwrap()
}

/// Run one block. If `missing` is the round-0 proposer of the block, the
/// block is decided in round 1, so that `missing` misses its proposal
/// (§4.7). The next block records the miss.
fn run_missing(net: &mut Net, missing: &[u8]) {
    let height = net.next_height();
    let epoch = params().epochs.epoch_of(height).unwrap();
    let set = net.nodes[0].engine.epoch_set(epoch).unwrap().unwrap();
    let round = u32::from(set.proposer(0, height, 0).consensus_key_hash == missing);
    let p = net.proposal(vec![]);
    net.run_at_round(p, round);
}

/// Run blocks with `missing` missing its proposals until `done`.
fn miss_until(net: &mut Net, missing: &[u8], done: impl Fn(&ValidatorRecord) -> bool) {
    for _ in 0..200 {
        if done(&validator_record(net, missing)) {
            return;
        }
        run_missing(net, missing);
    }
    panic!("{:?}", validator_record(net, missing));
}

/// Register FID 1000 as a validator (node key 31, consensus key 77, account
/// nonce `nonce`): it joins two epochs later. Returns the consensus key hash.
fn register_1000(net: &mut Net, custody: &FalconSecretKey, nonce: u64) -> Vec<u8> {
    let node_key = falcon(31);
    attest_node_key(net, custody, &node_key, nonce);
    let consensus = falcon(77);
    let reg = registration(
        net,
        custody,
        &consensus,
        domains::VALIDATOR_CONSENSUS_POP,
        &node_key,
    );
    assert_eq!(net.run(net.proposal(vec![reg])).messages.len(), 1);
    super::auth::falcon_key_hash(&falcon_public(&consensus)).to_vec()
}

/// A `VALIDATOR_DEREGISTER` of `validator` by the account key of FID 1000.
fn deregistration(net: &Net, custody: &FalconSecretKey, validator: &[u8]) -> proto::Message {
    falcon_message(
        custody,
        data(
            1000,
            MessageType::ValidatorDeregister,
            Body::ValidatorEventBody(HyperValidatorEventBody {
                event_type: HyperValidatorEventType::Deregister as i32,
                validator_key: validator.to_vec(),
                registration_epoch: tip_epoch(net),
                ..Default::default()
            }),
            block_time(net),
        ),
    )
}

fn members(net: &Net, epoch: u64) -> Vec<Vec<u8>> {
    net.nodes[0]
        .engine
        .set_record(epoch)
        .unwrap()
        .unwrap()
        .members
        .into_iter()
        .map(|m| m.consensus_key_hash)
        .collect()
}

/// §4.7: a validator that misses `AUTO_DEREGISTER_THRESHOLD` consecutive
/// proposals leaves the set two epochs after the block that finds it.
#[test]
fn a_validator_that_misses_its_proposals_leaves_two_epochs_later() {
    let mut p = params();
    p.auto_deregister_threshold = 3;
    let mut net = Net::with_params(3, p);
    net.run_empty();
    let x = members(&net, 1)[0].clone();

    miss_until(&mut net, &x, |r| r.auto_deregistered);
    let record = validator_record(&net, &x);
    assert_eq!(record.consecutive_missed, 3);
    assert_eq!(record.leave_epoch, tip_epoch(&net) + 2);
    assert!(!record.inactive);

    while tip_epoch(&net) < record.leave_epoch {
        net.run_empty();
    }
    let set = members(&net, record.leave_epoch);
    assert_eq!(set.len(), 3);
    assert!(!set.contains(&x));
}

/// §4.7: the missed proposals of shards 1 and 2 count too. Shard 0 reads
/// the round of each shard-s block from its `FeeSettlement`.
#[test]
fn missed_proposals_of_shards_1_and_2_count() {
    let mut net = Net::new(3);
    net.run_empty();
    let set = net.nodes[0].engine.epoch_set(1).unwrap().unwrap();
    let x = members(&net, 1)[0].clone();
    // The shard-1 heights 1 to 12 that `x` proposes in round 0 are decided
    // in round 1.
    let mut shard1_misses = 0;
    for k in 1..=12u64 {
        if set.proposer(1, k, 0).consensus_key_hash == x {
            net.inputs.settlements.lock().unwrap().insert(
                (1, k),
                proto::FeeSettlement {
                    shard_id: 1,
                    height: k,
                    proposer_fid: set.proposer(1, k, 1).fid,
                    epoch: 1,
                    round: 1,
                    ..Default::default()
                },
            );
            shard1_misses += 1;
        }
    }
    assert!(shard1_misses >= 2);
    // Shard 0 also decides the heights of `x` in round 1, so that no
    // proposal of `x` is decided.
    let mut shard0_misses = 0;
    for h in 101..=115u64 {
        if h <= 114 && set.proposer(0, h, 0).consensus_key_hash == x {
            shard0_misses += 1;
        }
        run_missing(&mut net, &x);
    }
    assert_eq!(
        validator_record(&net, &x).consecutive_missed,
        shard0_misses + shard1_misses
    );

    // A settlement with a wrong proposer is not valid.
    let settled = BlockState::new(net.nodes[0].engine.db().clone())
        .txn()
        .get_u64(&keys::settled_height(1))
        .unwrap();
    assert_eq!(settled, 14, "the block below the link");
    let k = settled + 1;
    net.inputs.settlements.lock().unwrap().insert(
        (1, k),
        proto::FeeSettlement {
            shard_id: 1,
            height: k,
            proposer_fid: set.proposer(1, k, 0).fid + 1,
            epoch: 1,
            round: 0,
            ..Default::default()
        },
    );
    let p = net.proposal(vec![]);
    let e = net.nodes[0].engine.propose(&net.inputs, p).unwrap_err();
    assert!(e.to_string().contains("proposer_fid"), "{}", e);
}

/// §4.8: an auto-deregistration that leaves fewer than `MIN_VALIDATORS`
/// marks the validator `INACTIVE`; it stays in the set and the rebalance
/// window asks for new validators. A proposal does not end `INACTIVE`.
#[test]
fn an_inactive_validator_stays_in_the_set() {
    let mut p = params();
    p.auto_deregister_threshold = 3;
    p.min_validators = 4;
    let mut net = Net::with_params(3, p);
    net.run_empty();
    let x = members(&net, 1)[0].clone();

    miss_until(&mut net, &x, |r| r.inactive);
    let record = validator_record(&net, &x);
    assert_eq!(record.leave_epoch, 0);
    assert!(!record.auto_deregistered);
    let epoch = tip_epoch(&net);
    assert_eq!(
        crate::chain::transitions::transition(&record, epoch + 1),
        proto::TransitionType::TransitionInactive
    );
    // It misses more proposals and stays.
    miss_until(&mut net, &x, |r| r.consecutive_missed >= 5);
    assert!(validator_record(&net, &x).inactive);
    while tip_epoch(&net) < epoch + 2 {
        run_missing(&mut net, &x);
    }
    assert!(members(&net, epoch + 2).contains(&x));

    // Its next proposal is decided: the count of misses starts again, and it
    // stays `INACTIVE`.
    for _ in 0..8 {
        net.run_empty();
    }
    let record = validator_record(&net, &x);
    assert!(record.inactive);
    assert_eq!(record.consecutive_missed, 0);
}

/// §4.8: a new registration of the key ends `INACTIVE`.
#[test]
fn a_registration_ends_inactive() {
    let mut p = params();
    p.auto_deregister_threshold = 3;
    p.min_validators = 5;
    let (mut net, custody, _) = funded_net_with(p);
    let new = register_1000(&mut net, &custody, 1);
    let join = validator_record(&net, &new).join_epoch;
    while tip_epoch(&net) < join {
        net.run_empty();
    }
    miss_until(&mut net, &new, |r| r.inactive);
    assert_eq!(validator_record(&net, &new).leave_epoch, 0);

    let reg = registration(
        &net,
        &custody,
        &falcon(77),
        domains::VALIDATOR_CONSENSUS_POP,
        &falcon(31),
    );
    assert_eq!(net.run(net.proposal(vec![reg])).messages.len(), 1);
    let record = validator_record(&net, &new);
    assert!(!record.inactive);
    assert_eq!(record.consecutive_missed, 0);
    assert_eq!(record.leave_epoch, 0);
}

/// §4.8: an `INACTIVE` validator leaves when the set has room for its
/// departure; a deregistration that leaves fewer than `MIN_VALIDATORS` is
/// not valid.
#[test]
fn an_inactive_validator_leaves_when_a_new_validator_registers() {
    let mut p = params();
    p.auto_deregister_threshold = 3;
    p.min_validators = 4;
    let (mut net, custody, _) = funded_net_with(p);
    let x = members(&net, 1)[0].clone();
    miss_until(&mut net, &x, |r| r.inactive);

    let new = register_1000(&mut net, &custody, 1);
    miss_until(&mut net, &x, |r| r.auto_deregistered);
    let record = validator_record(&net, &x);
    assert!(!record.inactive);
    while tip_epoch(&net) < record.leave_epoch {
        net.run_empty();
    }
    let set = members(&net, record.leave_epoch);
    assert_eq!(set.len(), 4);
    assert!(set.contains(&new) && !set.contains(&x));

    // FID 1000 cannot leave now: the set would have 3 validators.
    let m = deregistration(&net, &custody, &new);
    let r = net.nodes[0]
        .engine
        .simulate_messages(&[m], block_time(&net));
    assert!(
        matches!(&r[0], Err(e) if e.to_string().contains("fewer than MIN_VALIDATORS")),
        "{:?}",
        r[0]
    );
}

/// §4.7: a registration during the two-epoch buffer cancels the
/// auto-deregistration; §4.5: a voluntary deregistration leaves two epochs
/// later.
#[test]
fn a_registration_in_the_buffer_cancels_the_auto_deregistration() {
    let mut p = params();
    p.auto_deregister_threshold = 3;
    let (mut net, custody, _) = funded_net_with(p);
    let new = register_1000(&mut net, &custody, 1);
    let join = validator_record(&net, &new).join_epoch;
    while tip_epoch(&net) < join {
        net.run_empty();
    }

    miss_until(&mut net, &new, |r| r.auto_deregistered);
    let leave = validator_record(&net, &new).leave_epoch;
    assert_eq!(leave, tip_epoch(&net) + 2);
    let reg = registration(
        &net,
        &custody,
        &falcon(77),
        domains::VALIDATOR_CONSENSUS_POP,
        &falcon(31),
    );
    assert_eq!(net.run(net.proposal(vec![reg])).messages.len(), 1);
    let record = validator_record(&net, &new);
    assert_eq!(record.leave_epoch, 0);
    assert!(!record.auto_deregistered);
    assert_eq!(record.consecutive_missed, 0);
    while tip_epoch(&net) < leave {
        net.run_empty();
    }
    assert!(members(&net, leave).contains(&new));

    // A voluntary deregistration (4 validators stay).
    let m = deregistration(&net, &custody, &new);
    assert_eq!(net.run(net.proposal(vec![m])).messages.len(), 1);
    let leave = validator_record(&net, &new).leave_epoch;
    assert_eq!(leave, tip_epoch(&net) + 2);
    while tip_epoch(&net) < leave {
        net.run_empty();
    }
    assert!(!members(&net, leave).contains(&new));
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
    // Falcon-512 key PF; request FID 2000) and a Falcon-512 signer F. A pair
    // has snapchain scopes only, so that snapchain accepts its relayed
    // KEY_ADD; a Hypersnap type is a scope of a Falcon-512 signer.
    let p_key = ed25519_dalek::SigningKey::from_bytes(&[22u8; 32]);
    let pf = falcon(23);
    let t = block_time(&net) as u32;
    let snap = messages_factory::keys::create_key_add(
        1000,
        &owner,
        2000,
        &other_owner,
        &p_key,
        vec![MessageType::CastAdd],
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
        !attest(&mut net, 1000, &|d| dual_message(
            &p_key,
            &pf,
            d,
            Default::default()
        )),
        "1000 pair: NODE_ATTESTATION is not in its scopes"
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
        pay(&mut net, 1000, 3, &|d| falcon_message(&custody, d)),
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

/// FIP §17.7: when the snapchain rules put verifications on the block shard
/// (V23), shard 0 merges them with no fee, keeps the records of each FID
/// under `MAX_VERIFICATIONS_PER_FID`, and sends each one to the FID's shard.
#[test]
fn shard0_takes_verifications_when_the_rules_put_them_there() {
    use super::verifications::MAX_VERIFICATIONS_PER_FID;
    let (mut net, _custody, _owner) = funded_net();
    let s2 = signer_of_2000(&mut net);

    let address = |i: u32| {
        let mut a = vec![0xA5u8; 20];
        a[..4].copy_from_slice(&i.to_be_bytes());
        a
    };
    // Contract verifications: the claim is checked by an L1 call at
    // admission, not by the block rules.
    let add = |net: &Net, i: u32| {
        ed25519_message(
            &s2,
            data(
                2000,
                MessageType::VerificationAddEthAddress,
                Body::VerificationAddAddressBody(proto::VerificationAddAddressBody {
                    address: address(i),
                    verification_type: 1,
                    block_hash: vec![0xB6; 32],
                    ..Default::default()
                }),
                block_time(net),
            ),
        )
    };
    let remove = |net: &Net, i: u32| {
        ed25519_message(
            &s2,
            data(
                2000,
                MessageType::VerificationRemove,
                Body::VerificationRemoveBody(proto::VerificationRemoveBody {
                    address: address(i),
                    protocol: 0,
                }),
                block_time(net),
            ),
        )
    };
    let counts = |net: &Net| {
        let state = BlockState::new(net.nodes[0].engine.db().clone());
        state
            .txn()
            .get(&keys::verification_counts(2000))
            .unwrap()
            .map(|v| {
                (
                    u32::from_be_bytes(v[0..4].try_into().unwrap()),
                    u32::from_be_bytes(v[4..8].try_into().unwrap()),
                )
            })
            .unwrap_or((0, 0))
    };

    let b = net.run(net.proposal(vec![add(&net, 0)]));
    assert_eq!(b.messages.len(), 1, "verification on shard 0");
    assert_eq!(counts(&net), (1, 0));
    // It goes to the FID's shard, in its snapchain form.
    let state = BlockState::new(net.nodes[0].engine.db().clone());
    let height = b.header.unwrap().height;
    let entries: Vec<proto::OutboxEntry> = state
        .txn()
        .scan(&keys::outbox_of_height(height))
        .unwrap()
        .values()
        .map(|v| proto::OutboxEntry::decode(v.as_slice()).unwrap())
        .filter(|e| e.fid == 2000)
        .collect();
    assert_eq!(entries.len(), 1);
    assert_eq!(
        entries[0].replay_message.as_ref().unwrap().msg_type(),
        MessageType::VerificationAddEthAddress
    );
    // No fee: FID 2000 has no fee balance.
    assert_eq!(
        state.txn().get(&keys::fee_balance(2000)).unwrap(),
        None,
        "no fee balance is needed"
    );

    // A removal of the verification, and a new verification of the address.
    assert_eq!(
        net.run(net.proposal(vec![remove(&net, 0)])).messages.len(),
        1
    );
    assert_eq!(counts(&net), (0, 1));
    assert_eq!(net.run(net.proposal(vec![add(&net, 0)])).messages.len(), 1);
    assert_eq!(
        counts(&net),
        (1, 0),
        "the record of the removal is used again"
    );

    // The cap: MAX_VERIFICATIONS_PER_FID live verifications.
    for i in 1..MAX_VERIFICATIONS_PER_FID {
        let m = add(&net, i);
        assert_eq!(net.run(net.proposal(vec![m])).messages.len(), 1, "add {i}");
    }
    assert_eq!(counts(&net), (MAX_VERIFICATIONS_PER_FID, 0));
    let over = add(&net, MAX_VERIFICATIONS_PER_FID);
    let r = net.nodes[0]
        .engine
        .simulate_messages(&[over], block_time(&net));
    assert!(
        matches!(&r[0], Err(e) if e.to_string().contains("maximum of verifications")),
        "{:?}",
        r[0]
    );
    // A removal of an existing verification is always valid.
    assert_eq!(
        net.run(net.proposal(vec![remove(&net, 5)])).messages.len(),
        1
    );
    assert_eq!(counts(&net), (MAX_VERIFICATIONS_PER_FID - 1, 1));
}

/// FIP §17.7: on a network whose snapchain rules keep verifications on the
/// FID's shard (V20), shard 0 does not take them.
#[test]
fn shard0_rejects_verifications_under_v20_rules() {
    let (mut net, _custody, _owner) = funded_net();
    for node in net.nodes.iter_mut() {
        node.engine.snapchain_version = crate::version::version::EngineVersion::V20;
    }
    let s2 = ed25519_dalek::SigningKey::from_bytes(&[21u8; 32]);
    let m = ed25519_message(
        &s2,
        data(
            2000,
            MessageType::VerificationRemove,
            Body::VerificationRemoveBody(proto::VerificationRemoveBody {
                address: vec![1u8; 20],
                protocol: 0,
            }),
            block_time(&net),
        ),
    );
    let r = net.nodes[0]
        .engine
        .simulate_messages(&[m], block_time(&net));
    assert!(
        matches!(&r[0], Err(e) if e.to_string().contains("not a shard-0 message type")),
        "{:?}",
        r[0]
    );
}

/// FID 2000 (not migrated) gets an on-chain Ed25519 signer.
fn signer_of_2000(net: &mut Net) -> ed25519_dalek::SigningKey {
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
    net.run(p);
    s2
}

/// FIP §17.7: shard 0 does not take the snapchain channel messages and
/// registrar events, also when the snapchain rules put them on the block
/// shard (V23). Hypersnap channels are the ones of FIP-native-channels.
#[test]
fn shard0_rejects_snapchain_channels() {
    let (mut net, _custody, _owner) = funded_net();
    let s2 = signer_of_2000(&mut net);
    let label = alloy_primitives::keccak256(b"hypersnap").to_vec();

    let event = crate::utils::factory::events_factory::create_channel_register_event(
        "hypersnap",
        label.clone(),
        vec![0xC1u8; 20],
        4_000_000_000,
        proto::ChannelRegisterEventType::Register,
        1_000,
        0,
    );
    let mut p = net.proposal(vec![]);
    p.onchain_events = vec![event];
    assert!(
        net.run(p).system_messages.is_empty(),
        "no registrar event on shard 0"
    );

    let m = ed25519_message(
        &s2,
        data(
            2000,
            MessageType::ChannelUpdate,
            Body::ChannelUpdateBody(proto::ChannelUpdateBody {
                channel_id: label,
                name: Some("hypersnap".to_string()),
                ..Default::default()
            }),
            block_time(&net),
        ),
    );
    let r = net.nodes[0]
        .engine
        .simulate_messages(&[m], block_time(&net));
    assert!(
        matches!(&r[0], Err(e) if e.to_string().contains("not a shard-0 message type")),
        "{:?}",
        r[0]
    );
}

// ---- Bridge actions (§13.7) and the seed beacon (§4.9) ----

/// A message of bootstrap validator `s` (FID 1001 + s), signed by its node
/// key.
fn node_message(net: &Net, s: usize, t: MessageType, body: Body) -> proto::Message {
    falcon_message(
        &net.genesis.node_keys[s],
        data(1001 + s as u64, t, body, block_time(net)),
    )
}

fn bridge_vote(net: &Net, s: usize, kind: u32, chain_id: u32) -> proto::Message {
    node_message(
        net,
        s,
        MessageType::BridgeActionVote,
        Body::BridgeActionVoteBody(proto::BridgeActionVoteBody {
            kind,
            chain_id,
            target: vec![0; 20],
            epoch: tip_epoch(net),
        }),
    )
}

fn burns_in(block: &proto::HypersnapBlock) -> Vec<u32> {
    block
        .system_messages
        .iter()
        .filter_map(|m| match &m.message {
            Some(proto::hypersnap_system_message::Message::InboundBurn(b)) => {
                Some(b.source_chain_id)
            }
            _ => None,
        })
        .collect()
}

/// FIP §13.7: 3 of 4 votes decide a pause; the pause holds the inbound burns
/// of its chain until `PAUSE_DURATION` ends, and the watcher keeps them.
#[test]
fn a_bridge_pause_holds_the_inbound_burns_of_its_chain() {
    use super::bridge_actions::{action_hash, KIND_PAUSE};
    let mut p = params();
    p.pause_duration_secs = 120;
    let (mut net, _, _) = funded(Net::with_genesis(3, p, Genesis::with_node_keys(4)));

    let votes = vec![
        bridge_vote(&net, 0, KIND_PAUSE, 1),
        bridge_vote(&net, 1, KIND_PAUSE, 1),
    ];
    let b = net.run(net.proposal(votes));
    assert_eq!(b.messages.len(), 2);
    assert!(b.header.unwrap().bridge_action_hash.is_empty(), "2 of 4");
    let b = net.run(net.proposal(vec![bridge_vote(&net, 2, KIND_PAUSE, 1)]));
    assert_eq!(
        b.header.unwrap().bridge_action_hash,
        action_hash(KIND_PAUSE, 1, &[0; 20]).to_vec()
    );
    let late = bridge_vote(&net, 3, KIND_PAUSE, 1);
    let r = net.nodes[0]
        .engine
        .simulate_messages(&[late], block_time(&net));
    assert!(
        matches!(&r[0], Err(e) if e.to_string().contains("decided")),
        "{:?}",
        r[0]
    );

    // A burn from chain 1 waits; a burn from chain 10 is credited.
    let held = burn(1000, 5_000_000, 7);
    let other = HyperInboundBurn {
        source_chain_id: 10,
        ..burn(1000, 6_000_000, 8)
    };
    let before = balance(&net, 1000);
    let mut p = net.proposal(vec![]);
    p.inbound_burns = vec![held.clone(), other];
    assert_eq!(burns_in(&net.run(p)), vec![10]);
    assert_eq!(balance(&net, 1000), before + 6_000_000);

    // 120 s are 10 blocks: then the held burn is credited.
    for _ in 0..10 {
        net.run_empty();
    }
    let mut p = net.proposal(vec![]);
    p.inbound_burns = vec![held];
    assert_eq!(burns_in(&net.run(p)), vec![1]);
    assert_eq!(balance(&net, 1000), before + 11_000_000);
}

/// FIP §13.7: a block decides at most one action; the next block decides
/// the other one that passed.
#[test]
fn a_block_decides_one_bridge_action() {
    use super::bridge_actions::{action_hash, KIND_PAUSE};
    let mut net = Net::with_genesis(3, params(), Genesis::with_node_keys(4));
    net.run_empty();
    let mut votes = vec![];
    for s in 0..3 {
        votes.push(bridge_vote(&net, s, KIND_PAUSE, 1));
        votes.push(bridge_vote(&net, s, KIND_PAUSE, 10));
    }
    let b = net.run(net.proposal(votes));
    assert_eq!(b.messages.len(), 6);
    let (a1, a10) = (
        action_hash(KIND_PAUSE, 1, &[0; 20]).to_vec(),
        action_hash(KIND_PAUSE, 10, &[0; 20]).to_vec(),
    );
    let (first, second) = if a1 < a10 { (a1, a10) } else { (a10, a1) };
    assert_eq!(b.header.unwrap().bridge_action_hash, first);
    assert_eq!(net.run_empty().header.unwrap().bridge_action_hash, second);
    assert!(net
        .run_empty()
        .header
        .unwrap()
        .bridge_action_hash
        .is_empty());
}

fn seed_commit(net: &Net, s: usize, t: u64, secret: &[u8; 32]) -> proto::Message {
    node_message(
        net,
        s,
        MessageType::SeedCommit,
        Body::SeedCommitBody(proto::SeedCommitBody {
            target_epoch: t,
            commitment: super::seed::commitment(t, secret).to_vec(),
        }),
    )
}

fn seed_reveal(net: &Net, s: usize, t: u64, secret: &[u8; 32]) -> proto::Message {
    node_message(
        net,
        s,
        MessageType::SeedReveal,
        Body::SeedRevealBody(proto::SeedRevealBody {
            target_epoch: t,
            secret: secret.to_vec(),
        }),
    )
}

fn stored_seed(net: &Net, epoch: u64) -> [u8; 32] {
    let state = BlockState::new(net.nodes[0].engine.db().clone());
    super::validators::epoch_seed(&state.txn(), epoch)
        .unwrap()
        .unwrap()
}

fn run_to_height(net: &mut Net, height: u64) {
    while net.next_height() < height {
        net.run_empty();
    }
}

/// FIP §4.9: the members of `set(t − 1)` commit in `t − 2` and reveal in
/// `t − 1`; the boundary of `t` makes the seed from the reveals; a member
/// that does not reveal forfeits its DA reward of `t − 1`; an epoch with no
/// reveal keeps the seed of the last block.
#[test]
fn the_epoch_seed_comes_from_the_reveals() {
    let mut net = Net::with_genesis(3, params(), Genesis::with_node_keys(4));
    net.run_empty();
    let secrets: Vec<[u8; 32]> = (0..4u8).map(|i| [i + 1; 32]).collect();
    let t = 3;

    // Epoch 1: the commits for epoch 3. A commit for epoch 4 is not valid.
    let commits: Vec<_> = (0..4)
        .map(|s| seed_commit(&net, s, t, &secrets[s]))
        .collect();
    assert_eq!(net.run(net.proposal(commits)).messages.len(), 4);
    let early = seed_commit(&net, 0, t + 1, &secrets[0]);
    let r = net.nodes[0]
        .engine
        .simulate_messages(&[early], block_time(&net));
    assert!(r[0].is_err());

    // Epoch 2: three members reveal; a wrong secret is not valid.
    run_to_height(&mut net, PIVOT + EPOCH_LEN);
    let wrong = seed_reveal(&net, 3, t, &[9; 32]);
    let r = net.nodes[0]
        .engine
        .simulate_messages(&[wrong], block_time(&net));
    assert!(
        matches!(&r[0], Err(e) if e.to_string().contains("does not match")),
        "{:?}",
        r[0]
    );
    let reveals: Vec<_> = (0..3)
        .map(|s| seed_reveal(&net, s, t, &secrets[s]))
        .collect();
    assert_eq!(net.run(net.proposal(reveals)).messages.len(), 3);

    // The window closes SEED_REVEAL_MARGIN blocks before the boundary.
    run_to_height(
        &mut net,
        PIVOT + 2 * EPOCH_LEN - params().seed_reveal_margin,
    );
    let late = seed_reveal(&net, 3, t, &secrets[3]);
    let r = net.nodes[0]
        .engine
        .simulate_messages(&[late], block_time(&net));
    assert!(
        matches!(&r[0], Err(e) if e.to_string().contains("window has closed")),
        "{:?}",
        r[0]
    );

    // The boundary of epoch 3.
    run_to_height(&mut net, PIVOT + 2 * EPOCH_LEN + 1);
    let mut revealed: Vec<([u8; 32], [u8; 32])> = (0..3)
        .map(|s| {
            (
                super::auth::falcon_key_hash(&falcon_public(&net.genesis.node_keys[s])),
                secrets[s],
            )
        })
        .collect();
    revealed.sort();
    let mut pre = b"hypersnap-epoch-seed-v2".to_vec();
    pre.extend_from_slice(&t.to_be_bytes());
    for (_, secret) in &revealed {
        pre.extend_from_slice(secret);
    }
    assert_eq!(
        stored_seed(&net, t),
        alloy_primitives::keccak256(&pre).0,
        "the seed of the reveals"
    );
    let state = BlockState::new(net.nodes[0].engine.db().clone());
    let hash = |s: usize| super::auth::falcon_key_hash(&falcon_public(&net.genesis.node_keys[s]));
    assert!(super::seed::forfeited(&state.txn(), t - 1, &hash(3)).unwrap());
    assert!(!super::seed::forfeited(&state.txn(), t - 1, &hash(0)).unwrap());

    // Epoch 4 has no reveal: the seed of the last block of epoch 3.
    run_to_height(&mut net, PIVOT + 3 * EPOCH_LEN + 1);
    let last = net.nodes[0]
        .engine
        .store()
        .get(PIVOT + 3 * EPOCH_LEN - 1)
        .unwrap();
    assert_eq!(
        stored_seed(&net, 4),
        crate::chain::epoch::epoch_seed(4, &last.hash.as_slice().try_into().unwrap())
    );
}

/// FIP §4.9: the node of each validator commits and reveals by itself; a
/// node that restarts between its commit and its reveal reveals the secret
/// that it committed.
#[test]
fn the_validator_nodes_commit_and_reveal_the_seed() {
    use crate::chain::seed_responder::{secret, SeedResponder};
    let mut net = Net::with_genesis(3, params(), Genesis::with_node_keys(4));
    net.run_empty();
    let reload = |net: &Net, s: usize| {
        FalconSecretKey::from_bytes(net.genesis.node_keys[s].as_bytes()).unwrap()
    };
    let mut responders: Vec<SeedResponder> = (0..4)
        .map(|s| SeedResponder::new(reload(&net, s)))
        .collect();
    while net.next_height() <= PIVOT + 2 * EPOCH_LEN {
        if net.next_height() == PIVOT + EPOCH_LEN {
            responders[3] = SeedResponder::new(reload(&net, 3));
        }
        let tip = net.nodes[0].engine.tip().unwrap().header.unwrap();
        let db = net.nodes[0].engine.db().clone();
        let mut messages = vec![];
        for r in responders.iter_mut() {
            messages.extend(
                r.after_block(
                    &db,
                    &params(),
                    tip.height,
                    tip.timestamp,
                    &mut rand::rngs::OsRng,
                )
                .unwrap(),
            );
        }
        net.run(net.proposal(messages));
    }
    let mut revealed: Vec<([u8; 32], [u8; 32])> = (0..4)
        .map(|s| {
            let key = &net.genesis.node_keys[s];
            (
                super::auth::falcon_key_hash(&falcon_public(key)),
                secret(key, 3),
            )
        })
        .collect();
    revealed.sort();
    let mut pre = b"hypersnap-epoch-seed-v2".to_vec();
    pre.extend_from_slice(&3u64.to_be_bytes());
    for (_, s) in &revealed {
        pre.extend_from_slice(s);
    }
    assert_eq!(stored_seed(&net, 3), alloy_primitives::keccak256(&pre).0);
    let state = BlockState::new(net.nodes[0].engine.db().clone());
    assert!(state
        .txn()
        .scan(&keys::seed_records(keys::SEED_FORFEIT, 2))
        .unwrap()
        .is_empty());
}
