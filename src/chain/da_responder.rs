//! The DA challenge responses of this validator (FIP §5.1, §5.2).
//!
//! In epoch `e`, a validator answers its `DA_CHALLENGES_PER_EPOCH`
//! challenges in the shard-0 blocks up to `boundary_height(e) +
//! CHALLENGE_RESPONSE_WINDOW`. An answer is the challenged leaf of the
//! node's boundary checkpoint of the target shard, with its proof, signed
//! by the node key. A checkpoint of shard 1 or 2 can come after the
//! boundary block, so the responder tries again after each shard-0 block of
//! the window. An answer that no block includes goes again after
//! `RESEND_AFTER` blocks.

use crate::chain::checkpoints::Checkpoints;
use crate::chain::shard0::keys::{self, KeyHash};
use crate::chain::shard0::state::BlockState;
use crate::chain::shard0::work::{challenge, da_seed};
use crate::chain::shard0::{validators, Shard0Params};
use crate::proto::{self, message_data::Body, DaChallengeResponseBody, MessageData, MessageType};
use crate::storage::db::RocksDB;
use hypersnap_falcon::FalconSecretKey;
use rand::{CryptoRng, RngCore};
use std::collections::BTreeMap;
use std::sync::Arc;

/// Shard-0 blocks after which an answer that no block includes is sent
/// again.
pub const RESEND_AFTER: u64 = 5;

pub struct DaResponder {
    node_key: FalconSecretKey,
    node_key_hash: KeyHash,
    /// (epoch, challenge index) → the shard-0 height after which the
    /// answer went to the mempool.
    sent: BTreeMap<(u64, u32), u64>,
}

impl DaResponder {
    pub fn new(node_key: FalconSecretKey) -> Self {
        let node_key_hash = hypersnap_messages::falcon_key_hash(node_key.public_key().as_bytes());
        DaResponder {
            node_key,
            node_key_hash,
            sent: BTreeMap::new(),
        }
    }

    pub fn node_key_hash(&self) -> &KeyHash {
        &self.node_key_hash
    }

    /// The answers to send after the committed shard-0 block at `height`
    /// with `timestamp` (Farcaster time). Nothing if the node key is not in
    /// the set of the epoch, or if the next block is after the window.
    pub fn after_block<R: CryptoRng + RngCore>(
        &mut self,
        shard0: &Arc<RocksDB>,
        params: &Shard0Params,
        checkpoints: &Checkpoints,
        height: u64,
        timestamp: u64,
        rng: &mut R,
    ) -> Result<Vec<proto::Message>, String> {
        let Some(epoch) = params.epochs.epoch_of(height) else {
            return Ok(vec![]);
        };
        self.sent.retain(|(e, _), _| *e >= epoch);
        if height + 1 > params.epochs.boundary_height(epoch) + params.challenge_response_window {
            return Ok(vec![]);
        }
        let state = BlockState::new(shard0.clone());
        let txn = state.txn();
        let err = |e: crate::chain::shard0::Shard0Error| e.to_string();
        let Some(set) = validators::set_record(&txn, epoch).map_err(err)? else {
            return Ok(vec![]);
        };
        let Some(member) = set
            .members
            .iter()
            .find(|m| m.node_key_hash.as_slice() == self.node_key_hash)
        else {
            return Ok(vec![]);
        };
        let Some(epoch_seed) = validators::epoch_seed(&txn, epoch).map_err(err)? else {
            return Ok(vec![]);
        };
        let seed = da_seed(epoch, &epoch_seed);
        let mut out = vec![];
        for index in 0..params.da_challenges_per_epoch {
            if self
                .sent
                .get(&(epoch, index))
                .is_some_and(|h| height < h + RESEND_AFTER)
                || txn
                    .exists(&keys::da_answered(epoch, &self.node_key_hash, index))
                    .map_err(err)?
            {
                continue;
            }
            let c = challenge(&seed, &self.node_key_hash, index, params.num_shards);
            // No checkpoint of the shard yet: try after the next block.
            let Some(leaf) = checkpoints.challenged_leaf(epoch, c.shard_id, &c.target_path) else {
                continue;
            };
            let data = MessageData {
                r#type: MessageType::DaChallengeResponse as i32,
                fid: member.fid,
                timestamp: timestamp as u32,
                network: params.network as i32,
                body: Some(Body::DaChallengeResponseBody(DaChallengeResponseBody {
                    epoch,
                    challenge_index: index,
                    leaf_key: leaf.key,
                    leaf_value: leaf.value,
                    proof: leaf.proof,
                })),
            };
            out.push(
                hypersnap_messages::falcon_message(&self.node_key, data, rng)
                    .map_err(|e| e.to_string())?,
            );
            self.sent.insert((epoch, index), height);
        }
        Ok(out)
    }
}
