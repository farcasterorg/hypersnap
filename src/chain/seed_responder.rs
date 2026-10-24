//! The seed commits and reveals of this validator (FIP §4.9).
//!
//! After each committed shard-0 block, a member of `set(t − 1)` commits in
//! epoch `t − 2` and reveals in epoch `t − 1`, before
//! `boundary_height(t) − SEED_REVEAL_MARGIN`. The secret comes from the node
//! key, so a node that restarts reveals the secret that it committed. A
//! message that no block includes goes again after `RESEND_AFTER` blocks.

use crate::chain::da_responder::RESEND_AFTER;
use crate::chain::shard0::keys::{self, KeyHash};
use crate::chain::shard0::seed::{commitment, FIRST_BEACON_EPOCH};
use crate::chain::shard0::state::BlockState;
use crate::chain::shard0::{validators, Shard0Params};
use crate::proto::{
    self, message_data::Body, MessageData, MessageType, SeedCommitBody, SeedRevealBody,
};
use crate::storage::db::RocksDB;
use alloy_primitives::keccak256;
use hypersnap_falcon::FalconSecretKey;
use rand::{CryptoRng, RngCore};
use std::collections::BTreeMap;
use std::sync::Arc;

/// The secret of the node for the seed of `target_epoch`.
pub fn secret(node_key: &FalconSecretKey, target_epoch: u64) -> [u8; 32] {
    let mut pre = b"hypersnap-seed-secret-v1".to_vec();
    pre.extend_from_slice(node_key.as_bytes());
    pre.extend_from_slice(&target_epoch.to_be_bytes());
    keccak256(&pre).0
}

pub struct SeedResponder {
    node_key: FalconSecretKey,
    node_key_hash: KeyHash,
    /// (message type, target epoch) → the shard-0 height after which the
    /// message went to the mempool.
    sent: BTreeMap<(i32, u64), u64>,
}

impl SeedResponder {
    pub fn new(node_key: FalconSecretKey) -> Self {
        let node_key_hash = hypersnap_messages::falcon_key_hash(node_key.public_key().as_bytes());
        SeedResponder {
            node_key,
            node_key_hash,
            sent: BTreeMap::new(),
        }
    }

    /// The commit and the reveal to send after the committed shard-0 block at
    /// `height` with `timestamp` (Farcaster time).
    pub fn after_block<R: CryptoRng + RngCore>(
        &mut self,
        shard0: &Arc<RocksDB>,
        params: &Shard0Params,
        height: u64,
        timestamp: u64,
        rng: &mut R,
    ) -> Result<Vec<proto::Message>, String> {
        let next = height + 1;
        let Some(epoch) = params.epochs.epoch_of(next) else {
            return Ok(vec![]);
        };
        self.sent.retain(|(_, t), _| *t > epoch);
        let state = BlockState::new(shard0.clone());
        let txn = state.txn();
        let err = |e: crate::chain::shard0::Shard0Error| e.to_string();
        let node_key_hash = self.node_key_hash;
        let member = |e: u64| -> Result<Option<u64>, String> {
            Ok(validators::set_record(&txn, e)
                .map_err(err)?
                .and_then(|set| {
                    set.members
                        .into_iter()
                        .find(|m| m.node_key_hash.as_slice() == node_key_hash)
                })
                .map(|m| m.fid))
        };
        let mut out = vec![];

        // The commit for the seed of `epoch + 2`, by a member of `set(epoch + 1)`.
        let t = epoch + 2;
        let committed = keys::seed_record(keys::SEED_COMMIT, t, &self.node_key_hash);
        if t >= FIRST_BEACON_EPOCH && !txn.exists(&committed).map_err(err)? {
            if let Some(fid) = member(epoch + 1)? {
                let body = Body::SeedCommitBody(SeedCommitBody {
                    target_epoch: t,
                    commitment: commitment(t, &secret(&self.node_key, t)).to_vec(),
                });
                out.extend(self.message(
                    MessageType::SeedCommit,
                    t,
                    fid,
                    body,
                    height,
                    timestamp,
                    params,
                    rng,
                )?);
            }
        }

        // The reveal for the seed of `epoch + 1`, before the margin.
        let t = epoch + 1;
        let open = next + params.seed_reveal_margin < params.epochs.boundary_height(t);
        if open
            && txn
                .exists(&keys::seed_record(
                    keys::SEED_COMMIT,
                    t,
                    &self.node_key_hash,
                ))
                .map_err(err)?
            && !txn
                .exists(&keys::seed_record(
                    keys::SEED_REVEAL,
                    t,
                    &self.node_key_hash,
                ))
                .map_err(err)?
        {
            if let Some(fid) = member(epoch)? {
                let body = Body::SeedRevealBody(SeedRevealBody {
                    target_epoch: t,
                    secret: secret(&self.node_key, t).to_vec(),
                });
                out.extend(self.message(
                    MessageType::SeedReveal,
                    t,
                    fid,
                    body,
                    height,
                    timestamp,
                    params,
                    rng,
                )?);
            }
        }
        Ok(out)
    }

    #[allow(clippy::too_many_arguments)]
    fn message<R: CryptoRng + RngCore>(
        &mut self,
        t: MessageType,
        target_epoch: u64,
        fid: u64,
        body: Body,
        height: u64,
        timestamp: u64,
        params: &Shard0Params,
        rng: &mut R,
    ) -> Result<Option<proto::Message>, String> {
        let key = (t as i32, target_epoch);
        if self
            .sent
            .get(&key)
            .is_some_and(|h| height < h + RESEND_AFTER)
        {
            return Ok(None);
        }
        let data = MessageData {
            r#type: t as i32,
            fid,
            timestamp: timestamp as u32,
            network: params.network as i32,
            body: Some(body),
        };
        let m = hypersnap_messages::falcon_message(&self.node_key, data, rng)
            .map_err(|e| e.to_string())?;
        self.sent.insert(key, height);
        Ok(Some(m))
    }
}
