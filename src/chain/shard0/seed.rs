//! The epoch seed beacon (FIP §4.9): commit and reveal by the validators.
//!
//! A member of `set(t − 1)` commits in epoch `t − 2` to a secret for the
//! seed of epoch `t`, and reveals it in epoch `t − 1`, before
//! `boundary_height(t) − SEED_REVEAL_MARGIN`. The boundary block of `t`
//! makes `epoch_seed(t)` from the reveals, so the seed is fixed before the
//! last block of `t − 1`. A member that commits and does not reveal forfeits
//! its DA reward of epoch `t − 1`. Epochs 1 and 2, and an epoch with no
//! reveal, use the seed of the last block of the previous epoch.

use super::auth::{Envelope, Role};
use super::keys;
use super::state::MsgTxn;
use super::{BlockCtx, Shard0Error};
use crate::proto::{SeedCommitBody, SeedRevealBody};
use alloy_primitives::keccak256;

/// The first epoch whose seed the beacon makes.
pub const FIRST_BEACON_EPOCH: u64 = 3;

const SEED_DOMAIN_V2: &[u8] = b"hypersnap-epoch-seed-v2";
const REVEAL_DOMAIN: &[u8] = b"hypersnap-seed-reveal-v1";

fn invalid(reason: &str) -> Shard0Error {
    Shard0Error::invalid(reason)
}

/// `keccak256("hypersnap-seed-reveal-v1" || target_epoch || secret)`.
pub fn commitment(target_epoch: u64, secret: &[u8]) -> [u8; 32] {
    let mut pre = REVEAL_DOMAIN.to_vec();
    pre.extend_from_slice(&target_epoch.to_be_bytes());
    pre.extend_from_slice(secret);
    keccak256(&pre).0
}

/// The node key hash of a member of `set(epoch)` that signs with its node
/// key.
fn member_key<'a>(
    txn: &MsgTxn,
    env: &Envelope,
    role: &'a Role,
    epoch: u64,
) -> Result<&'a [u8; 32], Shard0Error> {
    let Role::NodeKey { key_hash, .. } = role else {
        return Err(invalid("a seed message is signed by the node key"));
    };
    let set = super::validators::set_record(txn, epoch)?
        .ok_or_else(|| invalid("the validator set of the epoch is not known"))?;
    if !set
        .members
        .iter()
        .any(|m| m.node_key_hash.as_slice() == key_hash && m.fid == env.fid())
    {
        return Err(invalid("the node is not a validator of the epoch"));
    }
    Ok(key_hash)
}

/// A `SEED_COMMIT`: in epoch `t − 2`, by a member of `set(t − 1)`.
pub fn commit(
    ctx: &BlockCtx,
    txn: &mut MsgTxn,
    env: &Envelope,
    role: &Role,
    body: &SeedCommitBody,
) -> Result<(), Shard0Error> {
    let t = body.target_epoch;
    if t < FIRST_BEACON_EPOCH || t != ctx.epoch + 2 {
        return Err(invalid(
            "a commit is for the seed of the epoch after the next",
        ));
    }
    if body.commitment.len() != 32 {
        return Err(invalid("commitment is not 32 bytes"));
    }
    let member = member_key(txn, env, role, t - 1)?;
    let key = keys::seed_record(keys::SEED_COMMIT, t, member);
    if txn.exists(&key)? {
        return Err(invalid("the validator committed for the epoch"));
    }
    txn.put(key, body.commitment.clone());
    Ok(())
}

/// A `SEED_REVEAL`: in epoch `t − 1`, before
/// `boundary_height(t) − SEED_REVEAL_MARGIN`, of a commitment.
pub fn reveal(
    ctx: &BlockCtx,
    txn: &mut MsgTxn,
    env: &Envelope,
    role: &Role,
    body: &SeedRevealBody,
) -> Result<(), Shard0Error> {
    let t = body.target_epoch;
    if t != ctx.epoch + 1 {
        return Err(invalid("a reveal is for the seed of the next epoch"));
    }
    if ctx.height + ctx.params.seed_reveal_margin >= ctx.params.epochs.boundary_height(t) {
        return Err(invalid("the reveal window has closed"));
    }
    if body.secret.len() != 32 {
        return Err(invalid("secret is not 32 bytes"));
    }
    let member = member_key(txn, env, role, ctx.epoch)?;
    let committed = txn
        .get(&keys::seed_record(keys::SEED_COMMIT, t, member))?
        .ok_or_else(|| invalid("the validator has no commitment for the epoch"))?;
    if committed != commitment(t, &body.secret) {
        return Err(invalid("the secret does not match the commitment"));
    }
    let key = keys::seed_record(keys::SEED_REVEAL, t, member);
    if txn.exists(&key)? {
        return Err(invalid("the validator revealed for the epoch"));
    }
    txn.put(key, body.secret.clone());
    Ok(())
}

/// `epoch_seed(e)` at the boundary block of `e`, and the forfeits of the
/// members that committed for `e` and did not reveal. The records of `e`
/// are then dropped.
pub fn on_boundary(
    txn: &mut MsgTxn,
    epoch: u64,
    parent_hash: &[u8; 32],
) -> Result<[u8; 32], Shard0Error> {
    let reveals = txn.scan(&keys::seed_records(keys::SEED_REVEAL, epoch))?;
    let commits = txn.scan(&keys::seed_records(keys::SEED_COMMIT, epoch))?;
    let commit_prefix = keys::seed_records(keys::SEED_COMMIT, epoch).len();
    let seed = if epoch >= FIRST_BEACON_EPOCH && !reveals.is_empty() {
        // The reveals in the order of the node key hashes (the key order).
        let mut pre = SEED_DOMAIN_V2.to_vec();
        pre.extend_from_slice(&epoch.to_be_bytes());
        for secret in reveals.values() {
            pre.extend_from_slice(secret);
        }
        keccak256(&pre).0
    } else {
        crate::chain::epoch::epoch_seed(epoch, parent_hash)
    };
    for k in commits.keys() {
        let member = &k[commit_prefix..];
        if !txn.exists(&keys::seed_record(keys::SEED_REVEAL, epoch, member))? {
            txn.put(
                keys::seed_record(keys::SEED_FORFEIT, epoch - 1, member),
                vec![],
            );
        }
    }
    for k in commits.into_keys().chain(reveals.into_keys()) {
        txn.delete(k);
    }
    // The scoring of epoch `e − 1` reads the forfeits from the checkpoint of
    // this boundary; older ones are not read again.
    if epoch >= 3 {
        for k in txn
            .scan(&keys::seed_records(keys::SEED_FORFEIT, epoch - 3))?
            .into_keys()
        {
            txn.delete(k);
        }
    }
    Ok(seed)
}

/// `true` if the member with `node_key_hash` forfeited its DA reward of
/// `epoch`.
pub fn forfeited(txn: &MsgTxn, epoch: u64, node_key_hash: &[u8]) -> Result<bool, Shard0Error> {
    txn.exists(&keys::seed_record(keys::SEED_FORFEIT, epoch, node_key_hash))
}
