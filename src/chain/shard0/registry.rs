//! The FID registry and the signer records of shard 0 (FIP §2, §16.9,
//! §16.10, §17.6).
//!
//! For an FID that is not migrated, signers come from the Optimism
//! `KeyRegistry` and from `KEY_ADD` messages, through the snapchain stores, so
//! Hypersnap accepts the same signers as snapchain. A migrated FID has a
//! Falcon-512 custody key in the registry. Its signers are signer pairs (an
//! Ed25519 key from a `KEY_ADD`, plus a Falcon-512 key) and Falcon-512
//! signers, and Hypersnap ignores its Optimism transfers and `KeyRegistry`
//! events.

use super::auth::{self, Envelope, Role, Scheme};
use super::keys::{self, FidClock};
use super::ledger;
use super::state::{BlockState, MsgTxn};
use super::{BlockCtx, Outbox, Shard0Error};
use crate::core::validations::key as key_rules;
use crate::proto::{
    self, on_chain_event, CustodyMigrationBody, CustodyRotationBody, FalconSignerRecord,
    FidCustodyRecord, IdRegisterEventType, KeyAddBody, KeyRemoveBody, OnChainEvent,
    OnChainEventType, OutboxEntry,
};
use crate::storage::db::{RocksDB, RocksDbTransactionBatch};
use crate::storage::store::account::{
    self as account, check_and_set_app_nonce, check_and_set_user_nonce, get_from_db_or_txn,
    get_gasless_key_record, make_onchain_event_primary_key, OnchainEventStore,
};
use alloy_primitives::Address;
use hypersnap_falcon::domains;
use std::sync::Arc;

fn invalid(reason: &str) -> Shard0Error {
    Shard0Error::invalid(reason)
}

fn hub(e: impl std::fmt::Display) -> Shard0Error {
    Shard0Error::invalid(e.to_string())
}

/// The FID has an `IdRegistry` registration, or a custody record (a
/// hyper-native FID).
pub fn is_registered(
    txn: &MsgTxn,
    onchain: &OnchainEventStore,
    fid: u64,
) -> Result<bool, Shard0Error> {
    if fid == 0 {
        return Ok(false);
    }
    if txn.exists(&keys::custody(fid))? || txn.exists(&super::onboarding::native_fid_key(fid))? {
        return Ok(true);
    }
    Ok(onchain
        .get_id_register_event_by_fid(fid, Some(txn.base().batch()))
        .map_err(|e| Shard0Error::Internal(e.to_string()))?
        .is_some())
}

/// The classical custody address of an FID: the `to` of its latest
/// `IdRegistry` event. For a migrated FID, this is the address at the time
/// of the migration, because later transfers are not applied.
pub fn classical_custody(
    batch: &RocksDbTransactionBatch,
    onchain: &OnchainEventStore,
    fid: u64,
) -> Result<Option<[u8; 20]>, Shard0Error> {
    let event = onchain
        .get_id_register_event_by_fid(fid, Some(batch))
        .map_err(|e| Shard0Error::Internal(e.to_string()))?;
    Ok(match event.and_then(|e| e.body) {
        Some(on_chain_event::Body::IdRegisterEventBody(b)) => b.to.as_slice().try_into().ok(),
        _ => None,
    })
}

/// The classical custody address of any FID: the hyper-native registry for a
/// native FID, else `IdRegistry` (FIP §16.9).
pub fn classical_custody_of(
    txn: &MsgTxn,
    onchain: &OnchainEventStore,
    fid: u64,
) -> Result<Option<[u8; 20]>, Shard0Error> {
    if super::onboarding::is_native_fid(fid) {
        return super::onboarding::native_custody(txn, fid);
    }
    classical_custody(txn.base().batch(), onchain, fid)
}

/// `effective_age(fid)` at `now` (FIP §2). 0 if the FID has no clock.
pub fn effective_age(txn: &MsgTxn, fid: u64, now: u64) -> Result<u64, Shard0Error> {
    let clock = txn
        .get(&keys::fid_clock(fid))?
        .and_then(|v| FidClock::decode(&v));
    Ok(match clock {
        Some(c) => now.saturating_sub(c.age_base()),
        None => 0,
    })
}

fn set_clock(txn: &mut MsgTxn, fid: u64, f: impl FnOnce(&mut FidClock)) -> Result<(), Shard0Error> {
    let mut clock = txn
        .get(&keys::fid_clock(fid))?
        .and_then(|v| FidClock::decode(&v))
        .unwrap_or_default();
    f(&mut clock);
    txn.put(keys::fid_clock(fid), clock.encode());
    Ok(())
}

// ---- On-chain events (§17.6) ----

/// The unique key of an on-chain event (transaction hash, log index).
fn event_seen(state: &BlockState, event: &OnChainEvent) -> Result<bool, Shard0Error> {
    if state
        .get(&keys::onchain_ignored(
            &event.transaction_hash,
            event.log_index,
        ))?
        .is_some()
    {
        return Ok(true);
    }
    let primary = make_onchain_event_primary_key(event);
    Ok(get_from_db_or_txn(state.db(), state.batch(), &primary)?.is_some())
}

/// Apply an `IdRegistry` or `KeyRegistry` event (a system message).
pub fn apply_onchain_event(
    ctx: &BlockCtx,
    state: &mut BlockState,
    onchain: &OnchainEventStore,
    event: &OnChainEvent,
    outbox: &mut Outbox,
) -> Result<(), Shard0Error> {
    let kind = event.r#type();
    if !matches!(
        kind,
        OnChainEventType::EventTypeIdRegister
            | OnChainEventType::EventTypeSigner
            | OnChainEventType::EventTypeSignerMigrated
    ) {
        return Err(invalid(
            "shard 0 takes IdRegistry and KeyRegistry events only",
        ));
    }
    if event_seen(state, event)? {
        return Err(invalid("on-chain event already applied"));
    }
    let fid = event.fid;
    let mut txn = state.txn();
    let migrated = auth::custody_of(&txn, fid)?.is_some();
    let id_body = match &event.body {
        Some(on_chain_event::Body::IdRegisterEventBody(b)) => Some(b.clone()),
        _ => None,
    };
    let id_type = id_body.as_ref().map(|b| b.event_type());

    // A migrated FID does not use Optimism transfers, recovery changes and
    // signer events (§16.9).
    let ignore = migrated
        && match kind {
            OnChainEventType::EventTypeSigner => true,
            OnChainEventType::EventTypeIdRegister => matches!(
                id_type,
                Some(IdRegisterEventType::Transfer | IdRegisterEventType::ChangeRecovery)
            ),
            _ => false,
        };
    if ignore {
        txn.put_proto(
            keys::onchain_ignored(&event.transaction_hash, event.log_index),
            event,
        );
        let writes = txn.into_writes();
        state.apply(writes);
        return Ok(());
    }

    if kind == OnChainEventType::EventTypeIdRegister {
        let body = id_body.ok_or_else(|| invalid("IdRegistry event has no body"))?;
        match body.event_type() {
            IdRegisterEventType::Register => {
                set_clock(&mut txn, fid, |c| {
                    if c.registered_at == 0 {
                        c.registered_at = event.block_timestamp;
                    }
                })?;
            }
            IdRegisterEventType::Transfer => {
                // Custody change: escrow to the previous custodian (§13.9),
                // and reset the age unless the transfer is an exempt
                // recovery (§2).
                let old = classical_custody(state.batch(), onchain, fid)?
                    .ok_or_else(|| invalid("transfer of an FID with no registration"))?;
                ledger::custody_change(ctx, &mut txn, fid, &keys::escrow_id_optimism(&old))?;
                let exempt = txn.exists(&keys::exempt_recovery(
                    fid,
                    &event.transaction_hash,
                    event.log_index,
                ))?;
                if !exempt {
                    set_clock(&mut txn, fid, |c| {
                        c.last_custody_change = c.last_custody_change.max(event.block_timestamp);
                    })?;
                }
            }
            _ => {}
        }
    }
    let writes = txn.into_writes();
    state.apply(writes);
    onchain
        .merge_onchain_event(event.clone(), state.batch_mut())
        .map_err(|e| Shard0Error::Internal(e.to_string()))?;
    if fid != 0 {
        outbox.push(OutboxEntry {
            shard_id: ctx.params.shard_of(fid),
            fid,
            replay_event: Some(event.clone()),
            ..Default::default()
        });
    }
    Ok(())
}

// ---- Custody (§16.9) ----

fn check_falcon_key(key: &[u8], what: &str) -> Result<(), Shard0Error> {
    hypersnap_falcon::FalconPublicKey::from_bytes(key)
        .map(|_| ())
        .map_err(|_| Shard0Error::invalid(format!("{} is not a Falcon-512 public key", what)))
}

pub fn custody_migration(
    ctx: &BlockCtx,
    txn: &mut MsgTxn,
    onchain: &OnchainEventStore,
    env: &Envelope,
    body: &CustodyMigrationBody,
) -> Result<(), Shard0Error> {
    let fid = env.fid();
    if env.scheme != Scheme::Falcon {
        return Err(invalid(
            "CUSTODY_MIGRATION is signed by the new custody key",
        ));
    }
    check_falcon_key(&body.falcon_custody_key, "falcon_custody_key")?;
    // The message signature by the new key is its proof of possession.
    env.verify_falcon(&body.falcon_custody_key)?;
    if !body.falcon_recovery_key.is_empty() {
        check_falcon_key(&body.falcon_recovery_key, "falcon_recovery_key")?;
        if body.falcon_recovery_key == body.falcon_custody_key {
            return Err(invalid("the recovery key is the custody key"));
        }
    }
    if auth::custody_of(txn, fid)?.is_some() {
        return Err(invalid("FID is already migrated"));
    }
    if (body.deadline as u64) <= ctx.timestamp {
        return Err(invalid("deadline has passed"));
    }
    let address = classical_custody_of(txn, onchain, fid)?
        .ok_or_else(|| invalid("FID has no classical custody address"))?;
    let payload = env.second_signature_payload(hypersnap_messages::clear_custody_migration);
    let signer = auth::recover_eip712(
        auth::EIP712_CUSTODY_MIGRATION,
        &payload,
        &body.eip712_signature,
    )?;
    if signer != Address::from(address) {
        return Err(invalid(
            "eip712_signature is not by the classical custody address",
        ));
    }
    txn.put_proto(
        keys::custody(fid),
        &FidCustodyRecord {
            falcon_custody_key: body.falcon_custody_key.clone(),
            falcon_recovery_key: body.falcon_recovery_key.clone(),
            migrated_at_block: ctx.height,
            migrated_at_timestamp: ctx.unix_time(),
            last_rotation_timestamp: 0,
            nonce: body.nonce,
        },
    );
    Ok(())
}

pub fn custody_rotation(
    ctx: &BlockCtx,
    txn: &mut MsgTxn,
    env: &Envelope,
    role: &Role,
    body: &CustodyRotationBody,
) -> Result<(), Shard0Error> {
    if !matches!(role, Role::AccountKey | Role::RecoveryKey) {
        return Err(invalid(
            "CUSTODY_ROTATION needs the custody key or the recovery key",
        ));
    }
    let fid = env.fid();
    let mut record = auth::custody_of(txn, fid)?.ok_or_else(|| invalid("FID is not migrated"))?;
    check_falcon_key(&body.new_falcon_custody_key, "new_falcon_custody_key")?;
    if body.new_falcon_custody_key == record.falcon_custody_key {
        return Err(invalid("the new custody key is the current key"));
    }
    if !body.new_falcon_recovery_key.is_empty() {
        check_falcon_key(&body.new_falcon_recovery_key, "new_falcon_recovery_key")?;
        if body.new_falcon_recovery_key == body.new_falcon_custody_key {
            return Err(invalid("the recovery key is the custody key"));
        }
    }
    if (body.deadline as u64) <= ctx.timestamp {
        return Err(invalid("deadline has passed"));
    }
    if body.nonce != record.nonce + 1 {
        return Err(invalid("nonce is not the next custody nonce"));
    }
    let payload = env.second_signature_payload(hypersnap_messages::clear_custody_rotation);
    auth::verify_falcon_body(
        &body.new_falcon_custody_key,
        domains::CUSTODY_ROTATION_POP,
        &payload,
        &body.new_key_signature,
    )?;

    let old = auth::falcon_key_hash(&record.falcon_custody_key);
    ledger::custody_change(ctx, txn, fid, &keys::escrow_id_falcon(&old))?;
    set_clock(txn, fid, |c| c.last_custody_change = ctx.unix_time())?;
    record.falcon_custody_key = body.new_falcon_custody_key.clone();
    record.falcon_recovery_key = body.new_falcon_recovery_key.clone();
    record.last_rotation_timestamp = ctx.unix_time();
    record.nonce = body.nonce;
    txn.put_proto(keys::custody(fid), &record);
    Ok(())
}

// ---- Signers (§16.10) ----

pub const KEY_TYPE_FALCON512: u32 = 2;

pub fn key_add(
    ctx: &BlockCtx,
    state: &mut BlockState,
    onchain: &OnchainEventStore,
    message: &proto::Message,
    env: &Envelope,
    body: &KeyAddBody,
    outbox: &mut Outbox,
) -> Result<(), Shard0Error> {
    let fid = env.fid();
    let txn = state.txn();
    let custody = auth::custody_of(&txn, fid)?;
    match (custody, body.key_type) {
        // An FID that is not migrated: the snapchain rules.
        (None, key_rules::KEY_TYPE_ED25519) => {
            drop(txn);
            if env.scheme != Scheme::Ed25519 {
                return Err(invalid(
                    "an FID that is not migrated signs KEY_ADD with Ed25519",
                ));
            }
            key_rules::validate_key_add_body(body).map_err(hub)?;
            merge_snapchain_key_add(state, onchain, message)?;
            outbox.push(replay(ctx, fid, message));
            Ok(())
        }
        (None, _) => Err(invalid(
            "an FID that is not migrated cannot add Falcon-512 signers",
        )),

        // A signer pair (§16.10, items 1-5).
        (Some(custody), key_rules::KEY_TYPE_ED25519) => {
            if env.scheme != Scheme::Dual {
                return Err(invalid("a pair KEY_ADD is dual-signed"));
            }
            key_rules::validate_key_add_body(body).map_err(hub)?;
            let ext = env.extension.as_ref().unwrap();
            check_falcon_key(&ext.falcon_signer_key, "falcon_signer_key")?;
            // The new pair signs the message (its proof of possession) and
            // custody approves the pair.
            if env.ed25519_key.map(|k| k.to_vec()) != Some(body.key.clone()) {
                return Err(invalid("the Ed25519 key of the pair signs its KEY_ADD"));
            }
            env.verify_falcon(&ext.falcon_signer_key)?;
            hypersnap_falcon::verify_parts(
                &hypersnap_falcon::FalconPublicKey::from_bytes(&custody.falcon_custody_key)
                    .map_err(hub)?,
                domains::KEY_ADD,
                &hypersnap_messages::pair_key_add_custody_parts(
                    &env.data_bytes,
                    &ext.falcon_signer_key,
                ),
                &hypersnap_falcon::FalconSignature::from_bytes(&ext.falcon_custody_signature)
                    .map_err(|_| invalid("bad falcon_custody_signature"))?,
            )
            .map_err(|_| invalid("falcon_custody_signature does not verify"))?;
            let hash = auth::falcon_key_hash(&ext.falcon_signer_key);
            if txn.exists(&keys::falcon_signer(fid, &hash))? {
                return Err(invalid("the Falcon-512 key is already a signer"));
            }
            let mut pair = state.txn();
            pair.put_proto(
                keys::falcon_signer(fid, &hash),
                &FalconSignerRecord {
                    falcon_key: ext.falcon_signer_key.clone(),
                    paired_ed25519_key: body.key.clone(),
                    scopes: body.scopes.clone(),
                    ttl: body.ttl,
                    added_at: ctx.height,
                    added_at_time: env.data.timestamp as u64,
                },
            );
            pair.put(keys::signer_pair(fid, &body.key), hash.to_vec());
            let writes = pair.into_writes();
            drop(txn);
            // The Ed25519 half follows the snapchain rules (EIP-712 by the
            // classical custody address), so snapchain accepts the relay.
            merge_snapchain_key_add(state, onchain, message)?;
            outbox.push(replay(ctx, fid, message));
            outbox.record_writes(ctx.params, &writes);
            state.apply(writes);
            Ok(())
        }

        // A Falcon-512 signer.
        (Some(custody), KEY_TYPE_FALCON512) => {
            if env.scheme != Scheme::Falcon {
                return Err(invalid("a Falcon-512 KEY_ADD is signed by the new key"));
            }
            check_falcon_key(&body.key, "key")?;
            env.verify_falcon(&body.key)?;
            check_deadline(ctx, env, body.deadline)?;
            if body.ttl == 0 || body.ttl > key_rules::MAX_KEY_TTL_SECONDS {
                return Err(invalid("ttl is out of range"));
            }
            key_rules::validate_falcon_signer_scopes(&body.scopes).map_err(hub)?;
            let payload = env.second_signature_payload(hypersnap_messages::clear_key_add_falcon);
            auth::verify_falcon_body(
                &custody.falcon_custody_key,
                domains::KEY_ADD_FALCON,
                &payload,
                &body.custody_signature,
            )?;
            let hash = auth::falcon_key_hash(&body.key);
            if txn.exists(&keys::falcon_signer(fid, &hash))? {
                return Err(invalid("the Falcon-512 key is already a signer"));
            }
            let mut add = state.txn();
            add.put_proto(
                keys::falcon_signer(fid, &hash),
                &FalconSignerRecord {
                    falcon_key: body.key.clone(),
                    paired_ed25519_key: vec![],
                    scopes: body.scopes.clone(),
                    ttl: body.ttl,
                    added_at: ctx.height,
                    added_at_time: env.data.timestamp as u64,
                },
            );
            let writes = add.into_writes();
            drop(txn);
            let db = state.db().clone();
            check_and_set_user_nonce(&db, state.batch_mut(), fid, body.nonce).map_err(hub)?;
            outbox.record_writes(ctx.params, &writes);
            state.apply(writes);
            Ok(())
        }
        (Some(_), _) => Err(invalid("unknown key_type")),
    }
}

fn merge_snapchain_key_add(
    state: &mut BlockState,
    onchain: &OnchainEventStore,
    message: &proto::Message,
) -> Result<(), Shard0Error> {
    let db = state.db().clone();
    account::merge_key_add(&db, onchain, message, state.batch_mut(), false)
        .map(|_| ())
        .map_err(hub)
}

/// An outbox entry that sends `message` to the shard of `fid` in its
/// snapchain form, for shard `s` to merge it again (FIP §17.7).
pub(crate) fn replay(ctx: &BlockCtx, fid: u64, message: &proto::Message) -> OutboxEntry {
    let mut relay = message.clone();
    // The replica merges the snapchain form: the Ed25519 half only.
    if relay.signature_scheme == proto::SignatureScheme::Ed25519Falcon512 as i32 {
        relay.signature.truncate(64);
        relay.signature_scheme = proto::SignatureScheme::Ed25519 as i32;
    }
    OutboxEntry {
        shard_id: ctx.params.shard_of(fid),
        fid,
        replay_message: Some(relay),
        ..Default::default()
    }
}

/// Remove the gasless record of an Ed25519 key, with the writes of the
/// snapchain `merge_key_remove` (the half of a pair that custody removes).
pub fn remove_gasless_key(
    db: &Arc<RocksDB>,
    batch: &mut RocksDbTransactionBatch,
    fid: u64,
    key: &[u8],
) -> Result<(), Shard0Error> {
    let record = get_gasless_key_record(db, batch, fid, key)
        .map_err(hub)?
        .ok_or_else(|| invalid("the Ed25519 key is not registered"))?;
    account::delete_gasless_key_record(db, batch, fid, key).map_err(hub)?;
    account::delete_gasless_key_owner(db, batch, key).map_err(hub)?;
    account::delete_last_used_at(db, batch, fid, key).map_err(hub)?;
    account::decrement_gasless_key_count(db, batch, fid).map_err(hub)?;
    account::signer_auth_index::dec(db, batch, record.request_fid, fid).map_err(hub)?;
    Ok(())
}

/// The deadline of a Falcon-512 `KEY_ADD` or of a migrated FID's
/// `KEY_REMOVE` (FIP §16.10): not before the message timestamp, and after
/// the block time.
fn check_deadline(ctx: &BlockCtx, env: &Envelope, deadline: u32) -> Result<(), Shard0Error> {
    if deadline == 0 || (deadline as u64) < env.data.timestamp as u64 {
        return Err(invalid("deadline is before the message timestamp"));
    }
    if (deadline as u64) <= ctx.timestamp {
        return Err(invalid("deadline has passed"));
    }
    Ok(())
}

pub fn key_remove(
    ctx: &BlockCtx,
    state: &mut BlockState,
    onchain: &OnchainEventStore,
    message: &proto::Message,
    env: &Envelope,
    body: &KeyRemoveBody,
    outbox: &mut Outbox,
) -> Result<(), Shard0Error> {
    let fid = env.fid();
    let txn = state.txn();
    let Some(custody) = auth::custody_of(&txn, fid)? else {
        drop(txn);
        if env.scheme != Scheme::Ed25519 {
            return Err(invalid(
                "an FID that is not migrated signs KEY_REMOVE with Ed25519",
            ));
        }
        key_rules::validate_key_remove_body(body).map_err(hub)?;
        let db = state.db().clone();
        account::merge_key_remove(&db, onchain, message, state.batch_mut()).map_err(hub)?;
        outbox.push(replay(ctx, fid, message));
        return Ok(());
    };
    if body.key.len() != 32 {
        return Err(invalid("malformed KEY_REMOVE"));
    }
    check_deadline(ctx, env, body.deadline)?;
    let pair_hash: Option<[u8; 32]> = txn
        .get(&keys::signer_pair(fid, &body.key))?
        .and_then(|v| v.as_slice().try_into().ok());
    let key32: [u8; 32] = body.key.as_slice().try_into().unwrap();
    // `body.key` is an Ed25519 key of a pair, or keccak256 of a Falcon-512
    // signer.
    let (falcon_hash, ed25519) = match pair_hash {
        Some(h) => (h, Some(body.key.clone())),
        None if txn.exists(&keys::falcon_signer(fid, &key32))? => (key32, None),
        None => return Err(invalid("the key is not a signer of the FID")),
    };
    let record: FalconSignerRecord = txn
        .get_proto(&keys::falcon_signer(fid, &falcon_hash))?
        .ok_or_else(|| invalid("Falcon-512 signer is missing"))?;
    let sig_type = key_rules::KeyRemoveSignatureType::try_from(body.signature_type).map_err(hub)?;
    // The nonce stream: the user stream for custody and for a Falcon-512
    // signer; the app stream of the request FID for a pair.
    let mut app_nonce_of = None;
    match sig_type {
        // The custody key signs the message. The holder of the removed key
        // need not take part.
        key_rules::KeyRemoveSignatureType::Custody => {
            if env.scheme != Scheme::Falcon {
                return Err(invalid("the custody key signs a custody KEY_REMOVE"));
            }
            if !body.signature.is_empty() {
                return Err(invalid(
                    "a custody KEY_REMOVE of a migrated FID has no body signature",
                ));
            }
            env.verify_falcon(&custody.falcon_custody_key)?;
        }
        key_rules::KeyRemoveSignatureType::SelfRevoke => match &ed25519 {
            // A pair revokes itself with a dual signature by the pair.
            Some(ed) => {
                if env.scheme != Scheme::Dual
                    || env.ed25519_key.map(|k| k.to_vec()) != Some(ed.clone())
                {
                    return Err(invalid(
                        "a pair revokes itself with a dual signature by the pair",
                    ));
                }
                env.verify_falcon(&record.falcon_key)?;
                let gasless = get_gasless_key_record(state.db(), state.batch(), fid, ed)
                    .map_err(hub)?
                    .ok_or_else(|| invalid("the Ed25519 half is not registered"))?;
                app_nonce_of = Some(gasless.request_fid);
            }
            None => {
                if env.scheme != Scheme::Falcon {
                    return Err(invalid(
                        "a Falcon-512 signer revokes itself with Falcon-512",
                    ));
                }
                env.verify_falcon(&record.falcon_key)?;
            }
        },
    }
    let mut remove = state.txn();
    remove.delete(keys::falcon_signer(fid, &falcon_hash));
    if let Some(ed) = &ed25519 {
        remove.delete(keys::signer_pair(fid, ed));
    }
    let writes = remove.into_writes();
    drop(txn);
    let db = state.db().clone();
    match app_nonce_of {
        Some(request_fid) => {
            check_and_set_app_nonce(&db, state.batch_mut(), request_fid, body.nonce)
        }
        None => check_and_set_user_nonce(&db, state.batch_mut(), fid, body.nonce),
    }
    .map_err(hub)?;
    if let Some(ed) = &ed25519 {
        remove_gasless_key(&db, state.batch_mut(), fid, ed)?;
        outbox.push(OutboxEntry {
            shard_id: ctx.params.shard_of(fid),
            fid,
            remove_gasless_key: ed.clone(),
            ..Default::default()
        });
    }
    outbox.record_writes(ctx.params, &writes);
    state.apply(writes);
    Ok(())
}

/// The roles that a `Role::AppSigner` resolution needs nothing more for.
pub fn is_app_signer(role: &Role) -> bool {
    matches!(role, Role::AppSigner)
}
