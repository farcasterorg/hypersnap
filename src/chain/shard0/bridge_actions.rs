//! Bridge actions (FIP §13.7): the votes of the validators, the decision in a
//! shard-0 header (`bridge_action_hash`), and the pause of the inbound
//! bridge.
//!
//! A member of `set(e)` votes with its node key in epoch `e`. The block in
//! which the votes for an action pass 2/3 of the weight of the set decides
//! it, at most one action in each block. A pause stops the credit of inbound
//! burns from its chain (or from all chains) for `PAUSE_DURATION`; a later
//! pause extends it. An upgrade and a cancel are header records for the
//! bridge contract.

use super::auth::{Envelope, Role};
use super::keys;
use super::state::{BlockState, MsgTxn};
use super::{BlockCtx, Shard0Error};
use crate::proto::BridgeActionVoteBody;
use alloy_primitives::keccak256;

pub const KIND_UPGRADE: u32 = 1;
pub const KIND_CANCEL: u32 = 2;
pub const KIND_PAUSE: u32 = 3;

fn invalid(reason: &str) -> Shard0Error {
    Shard0Error::invalid(reason)
}

/// `keccak256("hypersnap-bridge-action-v1" || kind || chain_id || target)`,
/// with `kind` one byte and `chain_id` a big-endian u32.
pub fn action_hash(kind: u32, chain_id: u32, target: &[u8]) -> [u8; 32] {
    let mut pre = b"hypersnap-bridge-action-v1".to_vec();
    pre.push(kind as u8);
    pre.extend_from_slice(&chain_id.to_be_bytes());
    pre.extend_from_slice(target);
    keccak256(&pre).0
}

/// A `BRIDGE_ACTION_VOTE`.
pub fn vote(
    ctx: &BlockCtx,
    txn: &mut MsgTxn,
    env: &Envelope,
    role: &Role,
    body: &BridgeActionVoteBody,
) -> Result<(), Shard0Error> {
    let Role::NodeKey { key_hash, .. } = role else {
        return Err(invalid("a bridge action vote is signed by the node key"));
    };
    if body.epoch != ctx.epoch {
        return Err(invalid("the vote is not for the epoch of the block"));
    }
    if !(KIND_UPGRADE..=KIND_PAUSE).contains(&body.kind) {
        return Err(invalid("unknown bridge action kind"));
    }
    if body.target.len() != 20 {
        return Err(invalid("target is not 20 bytes"));
    }
    if body.kind == KIND_PAUSE && body.target.iter().any(|b| *b != 0) {
        return Err(invalid("the target of a pause is zero"));
    }
    let set = super::validators::set_record(txn, ctx.epoch)?
        .ok_or_else(|| Shard0Error::Internal("no set record for the epoch".into()))?;
    if !set
        .members
        .iter()
        .any(|m| m.node_key_hash.as_slice() == key_hash && m.fid == env.fid())
    {
        return Err(invalid("the node is not a validator of the epoch"));
    }
    let action = action_hash(body.kind, body.chain_id, &body.target);
    if txn.exists(&keys::bridge_action_key(
        keys::BRIDGE_DECIDED,
        ctx.epoch,
        &action,
    ))? {
        return Err(invalid("the bridge action is decided"));
    }
    let vote = keys::bridge_vote(ctx.epoch, &action, key_hash);
    if txn.exists(&vote)? {
        return Err(invalid("the validator voted for the action"));
    }
    txn.put(vote, vec![]);
    let count = keys::bridge_action_key(keys::BRIDGE_VOTE_COUNT, ctx.epoch, &action);
    if txn.add_u64(count, 1)? == 1 {
        txn.put_proto(
            keys::bridge_action_key(keys::BRIDGE_ACTION, ctx.epoch, &action),
            &BridgeActionVoteBody {
                epoch: ctx.epoch,
                ..body.clone()
            },
        );
    }
    Ok(())
}

/// Decide the first action of the epoch, in the order of the action hashes,
/// whose votes pass 2/3 of the weight of the set and that is not decided.
/// Its hash goes into the header.
pub fn decide(ctx: &BlockCtx, state: &mut BlockState) -> Result<Option<[u8; 32]>, Shard0Error> {
    let mut txn = state.txn();
    let Some(set) = super::validators::set_record(&txn, ctx.epoch)? else {
        return Ok(None);
    };
    let prefix = keys::bridge_votes_of_epoch(keys::BRIDGE_VOTE_COUNT, ctx.epoch);
    let mut decided = None;
    for (k, v) in txn.scan(&prefix)? {
        let Ok(action) = <[u8; 32]>::try_from(&k[prefix.len()..]) else {
            continue;
        };
        let votes = keys::decode_u64(&v);
        if votes * 3 <= set.total_weight * 2
            || txn.exists(&keys::bridge_action_key(
                keys::BRIDGE_DECIDED,
                ctx.epoch,
                &action,
            ))?
        {
            continue;
        }
        let body: BridgeActionVoteBody = txn
            .get_proto(&keys::bridge_action_key(
                keys::BRIDGE_ACTION,
                ctx.epoch,
                &action,
            ))?
            .ok_or_else(|| Shard0Error::Internal("a voted action has no record".into()))?;
        txn.put_u64(
            keys::bridge_action_key(keys::BRIDGE_DECIDED, ctx.epoch, &action),
            ctx.height,
        );
        if body.kind == KIND_PAUSE {
            let key = keys::bridge_pause(body.chain_id);
            let until = txn
                .get_u64(&key)?
                .max(ctx.timestamp + ctx.params.pause_duration_secs);
            txn.put_u64(key, until);
        }
        decided = Some(action);
        break;
    }
    let writes = txn.into_writes();
    state.apply(writes);
    Ok(decided)
}

/// `true` if the inbound bridge of `chain_id` is paused at `timestamp`
/// (Farcaster time).
pub fn paused(txn: &MsgTxn, chain_id: u32, timestamp: u64) -> Result<bool, Shard0Error> {
    Ok(timestamp < txn.get_u64(&keys::bridge_pause(chain_id))?
        || timestamp < txn.get_u64(&keys::bridge_pause(0))?)
}

/// At the boundary of epoch `e`: drop the votes and the records of earlier
/// epochs. An action that an epoch does not decide needs new votes.
pub fn on_boundary(txn: &mut MsgTxn, epoch: u64) -> Result<(), Shard0Error> {
    for sub in [
        keys::BRIDGE_VOTE_COUNT,
        keys::BRIDGE_VOTE,
        keys::BRIDGE_ACTION,
        keys::BRIDGE_DECIDED,
    ] {
        for e in epoch.saturating_sub(2)..epoch {
            for k in txn.scan(&keys::bridge_votes_of_epoch(sub, e))?.into_keys() {
                txn.delete(k);
            }
        }
    }
    Ok(())
}
