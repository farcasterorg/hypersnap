//! Node attestations and the validator registry of shard 0 (FIP §3, §4.1,
//! §4.5, §4.7, §4.8, §4.9).

use super::auth::{self, Envelope, Role};
use super::keys::{self, KeyHash};
use super::registry::effective_age;
use super::state::MsgTxn;
use super::{BlockCtx, Shard0Error};
use crate::chain::validator_sets::{build_record, EpochSet};
use crate::proto::{
    HyperValidatorEventBody, HyperValidatorEventType, HyperValidatorSetMember,
    HyperValidatorSetRecord, NodeAttestationBody, NodeAttestationState, ValidatorRecord,
};
use hypersnap_falcon::{domains, FalconPublicKey};
use std::sync::Arc;

fn invalid(reason: &str) -> Shard0Error {
    Shard0Error::invalid(reason)
}

fn bump_account_nonce(txn: &mut MsgTxn, fid: u64, nonce: u64) -> Result<(), Shard0Error> {
    let current = txn.get_u64(&keys::account_nonce(fid))?;
    if nonce != current + 1 {
        return Err(invalid("nonce is not the next nonce of the FID"));
    }
    txn.put_u64(keys::account_nonce(fid), nonce);
    Ok(())
}

/// "Signer of the FID" (FIP §14.2): an app signer, or the account key of a
/// migrated FID. A genesis entry signs its attestation with the account key,
/// because a new migration has no signers yet (§17.3).
fn fid_signer(role: &Role) -> Result<(), Shard0Error> {
    match role {
        Role::AppSigner | Role::AccountKey => Ok(()),
        _ => Err(invalid("the message needs a signer of the FID")),
    }
}

// ---- Node attestations (§3) ----

pub fn node_attestation(
    ctx: &BlockCtx,
    txn: &mut MsgTxn,
    env: &Envelope,
    role: &Role,
    body: &NodeAttestationBody,
) -> Result<(), Shard0Error> {
    fid_signer(role)?;
    let fid = env.fid();
    let payload = env.second_signature_payload(hypersnap_messages::clear_node_attestation);
    auth::verify_falcon_body(
        &body.node_public_key,
        domains::NODE_ATTESTATION_POP,
        &payload,
        &body.node_signature,
    )?;
    let hash: KeyHash = auth::falcon_key_hash(&body.node_public_key);
    if txn.exists(&keys::node_attestation(&hash))? {
        return Err(invalid("the node key already has an attestation"));
    }
    if txn.scan(&keys::node_attestations_of(fid))?.len() >= ctx.params.max_nodes_per_fid {
        return Err(invalid("the FID has MAX_NODES_PER_FID attestations"));
    }
    bump_account_nonce(txn, fid, body.nonce)?;
    txn.put_proto(
        keys::node_attestation(&hash),
        &NodeAttestationState {
            fid,
            node_public_key: body.node_public_key.clone(),
            attested_at_block: ctx.height,
            attested_at_epoch: ctx.epoch,
            libp2p_peer_id: body.libp2p_peer_id.clone(),
        },
    );
    txn.put(keys::node_attestation_by_fid(fid, &hash), vec![]);
    Ok(())
}

pub fn node_attestation_revoke(
    txn: &mut MsgTxn,
    env: &Envelope,
    role: &Role,
    body: &NodeAttestationBody,
) -> Result<(), Shard0Error> {
    fid_signer(role)?;
    let fid = env.fid();
    let hash: KeyHash = auth::falcon_key_hash(&body.node_public_key);
    let state: NodeAttestationState = txn
        .get_proto(&keys::node_attestation(&hash))?
        .ok_or_else(|| invalid("no attestation for the node key"))?;
    if state.fid != fid {
        return Err(invalid("the attestation belongs to a different FID"));
    }
    let in_use = validators(txn)?
        .iter()
        .any(|v| v.node_key_hash == hash && v.leave_epoch == 0);
    if in_use {
        return Err(invalid(
            "a validator uses the node key; deregister it first",
        ));
    }
    bump_account_nonce(txn, fid, body.nonce)?;
    txn.delete(keys::node_attestation(&hash));
    txn.delete(keys::node_attestation_by_fid(fid, &hash));
    Ok(())
}

// ---- Registry (§4.5) ----

pub fn validators(txn: &MsgTxn) -> Result<Vec<ValidatorRecord>, Shard0Error> {
    txn.scan(&keys::validators_prefix())?
        .values()
        .map(|v| {
            <ValidatorRecord as prost::Message>::decode(v.as_slice())
                .map_err(|e| Shard0Error::Internal(e.to_string()))
        })
        .collect()
}

pub fn is_member(v: &ValidatorRecord, epoch: u64) -> bool {
    v.join_epoch != 0 && v.join_epoch <= epoch && (v.leave_epoch == 0 || epoch < v.leave_epoch)
}

/// The members of `set(epoch)` from the registry (FIP §4.1, §4.9).
pub fn members_at(records: &[ValidatorRecord], epoch: u64) -> Vec<HyperValidatorSetMember> {
    records
        .iter()
        .filter(|v| is_member(v, epoch))
        .map(|v| HyperValidatorSetMember {
            consensus_key_hash: v.consensus_key_hash.clone(),
            weight: 1,
            node_key_hash: v.node_key_hash.clone(),
            fid: v.fid,
        })
        .collect()
}

fn registration_payload(env: &Envelope) -> Vec<u8> {
    env.second_signature_payload(hypersnap_messages::clear_validator_registration)
}

pub fn register(
    ctx: &BlockCtx,
    txn: &mut MsgTxn,
    env: &Envelope,
    role: &Role,
    body: &HyperValidatorEventBody,
    genesis: bool,
) -> Result<(), Shard0Error> {
    if *role != Role::AccountKey {
        return Err(invalid("VALIDATOR_REGISTER needs the account key"));
    }
    if body.event_type() != HyperValidatorEventType::Register {
        return Err(invalid("event_type is not REGISTER"));
    }
    if body.registration_epoch != ctx.epoch {
        return Err(invalid("registration_epoch is not the epoch of the block"));
    }
    let fid = env.fid();
    let consensus_hash: KeyHash = FalconPublicKey::from_bytes(&body.consensus_key)
        .map_err(|_| invalid("consensus_key is not a Falcon-512 public key"))?
        .key_id();
    if body.validator_key.as_slice() != consensus_hash {
        return Err(invalid("validator_key is not keccak256(consensus_key)"));
    }
    let payload = registration_payload(env);
    auth::verify_falcon_body(
        &body.consensus_key,
        domains::VALIDATOR_CONSENSUS_POP,
        &payload,
        &body.signature,
    )?;
    auth::verify_falcon_body(
        &body.falcon_node_key,
        domains::VALIDATOR_NODE_POP,
        &payload,
        &body.node_signature,
    )?;
    let node_hash: KeyHash = auth::falcon_key_hash(&body.falcon_node_key);
    if node_hash == consensus_hash {
        return Err(invalid("the consensus key is the node key"));
    }
    let attestation: NodeAttestationState = txn
        .get_proto(&keys::node_attestation(&node_hash))?
        .ok_or_else(|| invalid("the node key has no attestation"))?;
    if attestation.fid != fid {
        return Err(invalid("the node key is attested by a different FID"));
    }
    // Credibility (§4.5): age_factor ≥ 0.5 and the trust gate.
    if effective_age(txn, fid, ctx.unix_time())? < ctx.params.min_validator_fid_age_secs {
        return Err(invalid("the FID is younger than MIN_VALIDATOR_FID_AGE"));
    }
    let trust = txn
        .get(&keys::trust_score(fid))?
        .and_then(|v| <[u8; 4]>::try_from(v.as_slice()).ok())
        .map(u32::from_be_bytes)
        .unwrap_or(0);
    if trust < ctx.params.min_validator_trust_fp {
        return Err(invalid("trust score is below min_validator_trust_score"));
    }

    let records = validators(txn)?;
    if records.iter().any(|v| {
        v.node_key_hash == node_hash && v.consensus_key_hash != consensus_hash && v.leave_epoch == 0
    }) {
        return Err(invalid("another validator uses the node key"));
    }
    let key = keys::validator(&consensus_hash);
    if let Some(mut existing) = txn.get_proto::<ValidatorRecord>(&key)? {
        // A registration during the buffer cancels an auto-deregistration
        // (§4.7). Otherwise the key must not be active or announced.
        if existing.auto_deregistered && existing.leave_epoch > ctx.epoch && existing.fid == fid {
            existing.leave_epoch = 0;
            existing.auto_deregistered = false;
            existing.inactive = false;
            existing.consecutive_missed = 0;
            txn.put_proto(key, &existing);
            return Ok(());
        }
        if existing.leave_epoch == 0 || existing.leave_epoch > ctx.epoch {
            return Err(invalid("the key is active or announced"));
        }
    }
    let join_epoch = if genesis { 1 } else { ctx.epoch + 2 };
    txn.put_proto(
        key,
        &ValidatorRecord {
            fid,
            consensus_key_hash: consensus_hash.to_vec(),
            consensus_key: body.consensus_key.clone(),
            node_key_hash: node_hash.to_vec(),
            libp2p_peer_id: body.libp2p_peer_id.clone(),
            operator_address: body.operator_address.clone(),
            registration_epoch: body.registration_epoch,
            join_epoch,
            leave_epoch: 0,
            auto_deregistered: false,
            inactive: false,
            consecutive_missed: 0,
        },
    );
    Ok(())
}

pub fn deregister(
    ctx: &BlockCtx,
    txn: &mut MsgTxn,
    env: &Envelope,
    role: &Role,
    body: &HyperValidatorEventBody,
) -> Result<(), Shard0Error> {
    if body.event_type() != HyperValidatorEventType::Deregister {
        return Err(invalid("event_type is not DEREGISTER"));
    }
    if body.registration_epoch != ctx.epoch {
        return Err(invalid("registration_epoch is not the epoch of the block"));
    }
    let key = keys::validator(&body.validator_key);
    let mut record: ValidatorRecord = txn
        .get_proto(&key)?
        .ok_or_else(|| invalid("unknown validator"))?;
    if record.fid != env.fid() {
        return Err(invalid("the validator belongs to a different FID"));
    }
    match role {
        Role::AccountKey => {}
        Role::NodeKey { key_hash, .. } if key_hash.as_slice() == record.node_key_hash => {}
        _ => {
            return Err(invalid(
                "a deregistration needs the account key or the node key",
            ))
        }
    }
    if !is_member(&record, ctx.epoch) || record.leave_epoch != 0 {
        return Err(invalid("the validator is not in the active set"));
    }
    let leave = ctx.epoch + 2;
    let records = validators(txn)?;
    let remaining = records
        .iter()
        .filter(|v| v.consensus_key_hash != record.consensus_key_hash && is_member(v, leave))
        .count();
    if remaining < ctx.params.min_validators {
        return Err(invalid(
            "the set would have fewer than MIN_VALIDATORS validators",
        ));
    }
    record.leave_epoch = leave;
    txn.put_proto(key, &record);
    Ok(())
}

// ---- Set records (§4.9) and consensus participation (§4.7, §5.4) ----

pub fn set_record(
    txn: &MsgTxn,
    epoch: u64,
) -> Result<Option<HyperValidatorSetRecord>, Shard0Error> {
    txn.get_proto(&keys::validator_set(epoch))
}

pub fn epoch_seed(txn: &MsgTxn, epoch: u64) -> Result<Option<[u8; 32]>, Shard0Error> {
    Ok(txn
        .get(&keys::epoch_seed(epoch))?
        .and_then(|v| <[u8; 32]>::try_from(v.as_slice()).ok()))
}

/// The set of `epoch` with its keys and seed, from shard-0 state.
pub fn epoch_set(txn: &MsgTxn, epoch: u64) -> Result<Option<EpochSet>, Shard0Error> {
    let (Some(record), Some(seed)) = (set_record(txn, epoch)?, epoch_seed(txn, epoch)?) else {
        return Ok(None);
    };
    let mut publics = Vec::with_capacity(record.members.len());
    for m in &record.members {
        let v: ValidatorRecord = txn
            .get_proto(&keys::validator(&m.consensus_key_hash))?
            .ok_or_else(|| Shard0Error::Internal("set member has no registration".into()))?;
        let pk = FalconPublicKey::from_bytes(&v.consensus_key)
            .map_err(|e| Shard0Error::Internal(format!("consensus key: {}", e)))?;
        publics.push(Arc::new(pk));
    }
    EpochSet::new(record, seed, publics)
        .map(Some)
        .map_err(Shard0Error::Internal)
}

/// Write `set(epoch)` from the registry.
pub fn write_set_record(
    txn: &mut MsgTxn,
    epoch: u64,
) -> Result<HyperValidatorSetRecord, Shard0Error> {
    let records = validators(txn)?;
    let record = build_record(epoch, members_at(&records, epoch));
    txn.put_proto(keys::validator_set(epoch), &record);
    Ok(record)
}

/// Record the proposals that the rounds before the decided round of the
/// parent certificate of a shard-0 block missed (§4.7).
pub fn record_participation(
    ctx: &BlockCtx,
    txn: &mut MsgTxn,
    set: &EpochSet,
    certificate: &crate::proto::CommitCertificate,
) -> Result<(), Shard0Error> {
    let shard = certificate.shard_id;
    let height = certificate.height;
    for round in 0..=certificate.round {
        let proposer = set.proposer(shard, height, round);
        let key = keys::validator(&proposer.consensus_key_hash);
        let Some(mut record) = txn.get_proto::<ValidatorRecord>(&key)? else {
            continue;
        };
        if round == certificate.round {
            record.consecutive_missed = 0;
        } else {
            record.consecutive_missed += 1;
            if record.consecutive_missed >= ctx.params.auto_deregister_threshold
                && record.leave_epoch == 0
                && !record.inactive
            {
                auto_deregister(ctx, txn, &mut record)?;
            }
        }
        txn.put_proto(key, &record);
    }
    Ok(())
}

/// §4.7, §4.8: deregister at `epoch + 2`, or mark `INACTIVE` if the set
/// would be smaller than `MIN_VALIDATORS`.
fn auto_deregister(
    ctx: &BlockCtx,
    txn: &MsgTxn,
    record: &mut ValidatorRecord,
) -> Result<(), Shard0Error> {
    let leave = ctx.epoch + 2;
    let remaining = validators(txn)?
        .iter()
        .filter(|v| v.consensus_key_hash != record.consensus_key_hash && is_member(v, leave))
        .count();
    if remaining < ctx.params.min_validators {
        record.inactive = true;
    } else {
        record.leave_epoch = leave;
        record.auto_deregistered = true;
    }
    Ok(())
}
