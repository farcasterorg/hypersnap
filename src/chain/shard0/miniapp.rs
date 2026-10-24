//! The miniapp registry and user collections on shard 0 (Native Miniapp
//! Index FIP §3-§9, in the message model of PoW FIP §14.1 and §17.9).

use super::auth::{Envelope, Role};
use super::keys;
use super::registry;
use super::state::MsgTxn;
use super::{BlockCtx, Shard0Error};
use crate::chain::shard0::miniapp_rules::{
    miniapp_id_from_domain, validate_domain, validate_metadata,
};
use crate::core::error::HubError;
use crate::proto::{
    MiniappAddBody, MiniappAddState, MiniappRegisterBody, MiniappRemoveBody, MiniappState,
    MiniappUnregisterBody, MiniappUpdateBody,
};
use crate::storage::constants::RootPrefix;
use crate::storage::store::account::OnchainEventStore;

pub const MAX_REGISTRATIONS_PER_FID: usize = 10;
pub const MAX_ADDS_PER_FID: usize = 100;

fn invalid(reason: impl Into<String>) -> Shard0Error {
    Shard0Error::Invalid(reason.into())
}

pub fn state_key(id: &[u8; 16]) -> Vec<u8> {
    keys::prefix(RootPrefix::HyperMiniappState, &[id])
}

pub fn by_author_key(author: u64, id: &[u8; 16]) -> Vec<u8> {
    keys::prefix(
        RootPrefix::HyperMiniappByAuthor,
        &[&author.to_be_bytes(), id],
    )
}

pub fn by_author_prefix(author: u64) -> Vec<u8> {
    keys::prefix(RootPrefix::HyperMiniappByAuthor, &[&author.to_be_bytes()])
}

pub fn add_key(fid: u64, id: &[u8; 16]) -> Vec<u8> {
    keys::prefix(RootPrefix::HyperMiniappAdd, &[&fid.to_be_bytes(), id])
}

pub fn adds_of(fid: u64) -> Vec<u8> {
    keys::prefix(RootPrefix::HyperMiniappAdd, &[&fid.to_be_bytes()])
}

/// `[79][epoch][owner][user]` → adds in the epoch (App PoW input, FIP §7.2).
pub fn adds_by_epoch_key(epoch: u64, owner: u64, user: u64) -> Vec<u8> {
    keys::prefix(
        RootPrefix::HyperMiniappAddByEpoch,
        &[
            &epoch.to_be_bytes(),
            &owner.to_be_bytes(),
            &user.to_be_bytes(),
        ],
    )
}

pub fn adds_by_epoch_prefix(epoch: u64) -> Vec<u8> {
    keys::prefix(RootPrefix::HyperMiniappAddByEpoch, &[&epoch.to_be_bytes()])
}

/// The active miniapp of `domain`.
pub fn active(txn: &MsgTxn, domain: &str) -> Result<(MiniappState, [u8; 16]), Shard0Error> {
    let id = miniapp_id_from_domain(domain);
    let state: MiniappState = txn
        .get_proto(&state_key(&id))?
        .filter(|s: &MiniappState| s.active)
        .ok_or_else(|| invalid("no active miniapp for the domain"))?;
    Ok((state, id))
}

/// The FIP's "signer" of these messages is a signer of the FID (an app
/// signer, or the account key of a migrated FID).
fn fid_signer(role: &Role) -> Result<(), Shard0Error> {
    match role {
        Role::AppSigner | Role::AccountKey => Ok(()),
        _ => Err(invalid("the message needs a signer of the FID")),
    }
}

struct Custody<'a, 'b> {
    txn: &'a MsgTxn<'b>,
    onchain: &'a OnchainEventStore,
}

impl crate::chain::shard0::account_association::CustodyResolver for Custody<'_, '_> {
    fn custody_address_for_fid(&self, fid: u64) -> Result<Option<[u8; 20]>, HubError> {
        registry::classical_custody_of(self.txn, self.onchain, fid)
            .map_err(|e| HubError::invalid_internal_state(&e.to_string()))
    }
}

pub fn register(
    ctx: &BlockCtx,
    txn: &mut MsgTxn,
    onchain: &OnchainEventStore,
    env: &Envelope,
    role: &Role,
    body: &MiniappRegisterBody,
) -> Result<(), Shard0Error> {
    fid_signer(role)?;
    let fid = env.fid();
    validate_domain(&body.domain).map_err(|e| invalid(e.to_string()))?;
    let metadata = body
        .metadata
        .as_ref()
        .ok_or_else(|| invalid("no metadata"))?;
    validate_metadata(metadata).map_err(|e| invalid(e.to_string()))?;
    let proof = body
        .proof
        .as_ref()
        .ok_or_else(|| invalid("no account association proof"))?;
    crate::chain::shard0::account_association::verify_account_association(
        proof,
        fid,
        &body.domain,
        ctx.params.protocol_chain_id,
        &Custody { txn, onchain },
    )
    .map_err(|e| invalid(e.to_string()))?;
    let id = miniapp_id_from_domain(&body.domain);
    if let Some(existing) = txn.get_proto::<MiniappState>(&state_key(&id))? {
        if existing.active {
            return Err(invalid("the domain is already registered"));
        }
    }
    if txn.scan(&by_author_prefix(fid))?.len() >= MAX_REGISTRATIONS_PER_FID {
        return Err(invalid("the FID has MAX_REGISTRATIONS_PER_FID miniapps"));
    }
    txn.put_proto(
        state_key(&id),
        &MiniappState {
            miniapp_id: id.to_vec(),
            domain: body.domain.clone(),
            author_fid: fid,
            metadata: Some(metadata.clone()),
            registered_at_block: ctx.height,
            updated_at_timestamp: env.data.timestamp as u64,
            active: true,
            add_count: 0,
        },
    );
    txn.put(by_author_key(fid, &id), vec![]);
    Ok(())
}

pub fn unregister(
    txn: &mut MsgTxn,
    env: &Envelope,
    role: &Role,
    body: &MiniappUnregisterBody,
) -> Result<(), Shard0Error> {
    fid_signer(role)?;
    let (mut state, id) = active(txn, &body.domain)?;
    if state.author_fid != env.fid() {
        return Err(invalid("only the registering FID can unregister"));
    }
    state.active = false;
    txn.put_proto(state_key(&id), &state);
    txn.delete(by_author_key(state.author_fid, &id));
    Ok(())
}

pub fn update(
    txn: &mut MsgTxn,
    env: &Envelope,
    role: &Role,
    body: &MiniappUpdateBody,
) -> Result<(), Shard0Error> {
    fid_signer(role)?;
    let metadata = body
        .metadata
        .as_ref()
        .ok_or_else(|| invalid("no metadata"))?;
    validate_metadata(metadata).map_err(|e| invalid(e.to_string()))?;
    let (mut state, id) = active(txn, &body.domain)?;
    if state.author_fid != env.fid() {
        return Err(invalid("only the registering FID can update"));
    }
    // Last write wins by Farcaster timestamp; block order decides a tie.
    let ts = env.data.timestamp as u64;
    if ts < state.updated_at_timestamp {
        return Err(invalid("the update is older than the current metadata"));
    }
    state.metadata = Some(metadata.clone());
    state.updated_at_timestamp = ts;
    txn.put_proto(state_key(&id), &state);
    Ok(())
}

pub fn add(
    ctx: &BlockCtx,
    txn: &mut MsgTxn,
    env: &Envelope,
    role: &Role,
    body: &MiniappAddBody,
) -> Result<(), Shard0Error> {
    fid_signer(role)?;
    let fid = env.fid();
    let (mut state, id) = active(txn, &body.domain)?;
    let key = add_key(fid, &id);
    if txn.exists(&key)? {
        return Err(invalid("the FID already added the miniapp"));
    }
    if txn.scan(&adds_of(fid))?.len() >= MAX_ADDS_PER_FID {
        return Err(invalid("the FID has MAX_ADDS_PER_FID miniapps"));
    }
    txn.put_proto(
        key,
        &MiniappAddState {
            fid,
            domain: body.domain.clone(),
            added_at_timestamp: env.data.timestamp as u64,
        },
    );
    state.add_count += 1;
    txn.put_proto(state_key(&id), &state);
    txn.add_u64(adds_by_epoch_key(ctx.epoch, state.author_fid, fid), 1)?;
    Ok(())
}

pub fn remove(
    txn: &mut MsgTxn,
    env: &Envelope,
    role: &Role,
    body: &MiniappRemoveBody,
) -> Result<(), Shard0Error> {
    fid_signer(role)?;
    let fid = env.fid();
    let id = miniapp_id_from_domain(&body.domain);
    let key = add_key(fid, &id);
    if !txn.exists(&key)? {
        return Err(invalid("the FID did not add the miniapp"));
    }
    txn.delete(key);
    if let Some(mut state) = txn.get_proto::<MiniappState>(&state_key(&id))? {
        state.add_count = state.add_count.saturating_sub(1);
        txn.put_proto(state_key(&id), &state);
    }
    Ok(())
}
