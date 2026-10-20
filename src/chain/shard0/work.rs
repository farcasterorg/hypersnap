//! Work-market messages of shard 0: DA challenge responses (FIP §5.1, §5.2)
//! and app usage receipts (FIP §7.3).

use super::auth::{Envelope, Role};
use super::keys::{self, KeyHash};
use super::state::MsgTxn;
use super::{BlockCtx, Shard0Error};
use crate::proto::{AppUsageReceiptBody, DaChallengeResponseBody};
use crate::storage::constants::RootPrefix;
use alloy_primitives::keccak256;

fn invalid(reason: &str) -> Shard0Error {
    Shard0Error::invalid(reason)
}

const DA_SEED_DOMAIN: &[u8] = b"hypersnap-da-seed-v1";

/// `da_seed(e) = keccak256("hypersnap-da-seed-v1" || e || epoch_seed(e))`.
pub fn da_seed(epoch: u64, epoch_seed: &[u8; 32]) -> [u8; 32] {
    let mut pre = Vec::with_capacity(DA_SEED_DOMAIN.len() + 8 + 32);
    pre.extend_from_slice(DA_SEED_DOMAIN);
    pre.extend_from_slice(&epoch.to_be_bytes());
    pre.extend_from_slice(epoch_seed);
    keccak256(&pre).0
}

/// One challenge (FIP §5.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Challenge {
    pub shard_id: u32,
    /// `seed[2..18] || 16 zero bytes`.
    pub target_path: [u8; 32],
}

/// `challenge_seed = keccak256(da_seed(e) || keccak256(falcon_node_key) ||
/// challenge_index)`, with the index as a big-endian u32.
pub fn challenge(
    da_seed: &[u8; 32],
    node_key_hash: &KeyHash,
    challenge_index: u32,
    num_shards: u32,
) -> Challenge {
    let mut pre = Vec::with_capacity(32 + 32 + 4);
    pre.extend_from_slice(da_seed);
    pre.extend_from_slice(node_key_hash);
    pre.extend_from_slice(&challenge_index.to_be_bytes());
    let seed = keccak256(&pre).0;
    let shard_id = (u16::from_be_bytes([seed[0], seed[1]]) as u32) % num_shards;
    let mut target_path = [0u8; 32];
    target_path[..16].copy_from_slice(&seed[2..18]);
    Challenge {
        shard_id,
        target_path,
    }
}

/// The epoch-start state of each shard (FIP §5.2, §17.7 checkpoints).
pub trait DaCheckpoints {
    /// The challenged leaf (`key`, `value_hash`) and the root of the
    /// checkpoint of `shard_id` for `epoch`, from the checkpoint trie: the
    /// check of an answer reads no store. `None` if this node has no
    /// checkpoint.
    fn expected_leaf(
        &self,
        epoch: u64,
        shard_id: u32,
        target_path: &[u8; 32],
    ) -> Option<(Vec<u8>, [u8; 32], [u8; 32])>;

    /// True if the node runs a certified block without its views (FIP
    /// §4.3): the certificate covers the check of the leaf.
    fn certified(&self) -> bool {
        false
    }
}

pub fn da_response(
    ctx: &BlockCtx,
    txn: &mut MsgTxn,
    env: &Envelope,
    role: &Role,
    body: &DaChallengeResponseBody,
    checkpoints: &dyn DaCheckpoints,
) -> Result<(), Shard0Error> {
    let Role::NodeKey { key_hash, .. } = role else {
        return Err(invalid("a DA response is signed by the node key"));
    };
    if body.epoch != ctx.epoch {
        return Err(invalid("the response is not for the epoch of the block"));
    }
    if body.challenge_index >= ctx.params.da_challenges_per_epoch {
        return Err(invalid("challenge_index is out of range"));
    }
    let boundary = ctx.params.epochs.boundary_height(ctx.epoch);
    if ctx.height > boundary + ctx.params.challenge_response_window {
        return Err(invalid("the response window has closed"));
    }
    // The node must be a validator of the epoch.
    let set = super::validators::set_record(txn, ctx.epoch)?
        .ok_or_else(|| Shard0Error::Internal("no set record for the epoch".into()))?;
    if !set
        .members
        .iter()
        .any(|m| m.node_key_hash.as_slice() == key_hash && m.fid == env.fid())
    {
        return Err(invalid("the node is not a validator of the epoch"));
    }
    let answered = keys::da_answered(ctx.epoch, key_hash, body.challenge_index);
    if txn.exists(&answered)? {
        return Err(invalid("the challenge is already answered"));
    }
    let seed = super::validators::epoch_seed(txn, ctx.epoch)?
        .ok_or_else(|| Shard0Error::Internal("no epoch seed".into()))?;
    let c = challenge(
        &da_seed(ctx.epoch, &seed),
        key_hash,
        body.challenge_index,
        ctx.params.num_shards,
    );
    if !checkpoints.certified() {
        let (key, value_hash, root) = checkpoints
            .expected_leaf(ctx.epoch, c.shard_id, &c.target_path)
            .ok_or_else(|| Shard0Error::Internal("no checkpoint for the challenge".into()))?;
        if body.leaf_key != key || hypersnap_ktrie::value_hash(&body.leaf_value) != value_hash {
            return Err(invalid("the response is not the challenged leaf"));
        }
        if !hypersnap_ktrie::proof::verify_proof_bytes(
            &root,
            &key,
            Some(&body.leaf_value),
            &body.proof,
        ) {
            return Err(invalid(
                "the proof does not verify against the checkpoint root",
            ));
        }
    }
    txn.put_u64(answered, ctx.height);
    Ok(())
}

/// The owner FID of an active miniapp (Native Miniapp Index FIP §5).
pub fn miniapp_owner(txn: &MsgTxn, miniapp_id: &[u8]) -> Result<Option<u64>, Shard0Error> {
    let mut k = vec![RootPrefix::HyperMiniappState as u8];
    k.extend_from_slice(miniapp_id);
    Ok(txn
        .get_proto::<crate::proto::MiniappState>(&k)?
        .filter(|s| s.active)
        .map(|s| s.author_fid))
}

pub fn app_receipt(
    ctx: &BlockCtx,
    txn: &mut MsgTxn,
    env: &Envelope,
    role: &Role,
    body: &AppUsageReceiptBody,
) -> Result<(), Shard0Error> {
    if !matches!(role, Role::AppSigner) {
        return Err(invalid("a receipt is signed by a signer of the user"));
    }
    if body.epoch != ctx.epoch {
        return Err(invalid("the receipt is not for the epoch of the block"));
    }
    if body.miniapp_id.len() != 16 {
        return Err(invalid("miniapp_id is not 16 bytes"));
    }
    let owner = miniapp_owner(txn, &body.miniapp_id)?.ok_or_else(|| invalid("unknown miniapp"))?;
    let user = env.fid();
    let key = keys::app_receipt(ctx.epoch, owner, user, body.nonce);
    if txn.exists(&key)? {
        return Err(invalid("the receipt nonce is already used"));
    }
    let count_key = keys::prefix(
        RootPrefix::HyperAppReceiptCount,
        &[
            &ctx.epoch.to_be_bytes(),
            &owner.to_be_bytes(),
            &user.to_be_bytes(),
        ],
    );
    let count = txn.get_u64(&count_key)?;
    if count >= ctx.params.max_receipts_per_app_per_epoch {
        return Err(invalid("MAX_RECEIPTS_PER_APP_PER_EPOCH reached"));
    }
    txn.put_u64(count_key, count + 1);
    txn.put(key, body.action_type.as_bytes().to_vec());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenges_cover_the_shards() {
        let seed = da_seed(3, &[1u8; 32]);
        let mut shards = [0usize; 3];
        for i in 0..300 {
            let c = challenge(&seed, &[2u8; 32], i, 3);
            shards[c.shard_id as usize] += 1;
            assert_eq!(&c.target_path[16..], &[0u8; 16]);
        }
        assert!(shards.iter().all(|n| *n > 50), "{:?}", shards);
        assert_ne!(da_seed(3, &[1u8; 32]), da_seed(4, &[1u8; 32]));
    }
}
