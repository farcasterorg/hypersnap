//! Validator set records of the Hypersnap chain (FIP §4.9, §16.6).
//!
//! All three shards use the set of the epoch. The shard-0 state holds one
//! `HyperValidatorSetRecord` per epoch; the Falcon-512 consensus keys live in
//! the registration records (or, for epochs 1 and 2, in the genesis validator
//! file), keyed by `consensus_key_hash`.

use super::merkle;
use crate::core::types::{ShardId, SnapchainShard, SnapchainValidator, SnapchainValidatorSet};
use crate::proto::{HyperValidatorSetMember, HyperValidatorSetRecord};
use hypersnap_falcon::FalconPublicKey;
use std::collections::BTreeMap;
use std::sync::Arc;

/// Leaf of `set_root`: `consensus_key_hash (32) || weight (u64 BE) ||
/// node_key_hash (32) || fid (u64 BE)`. `consensus_key_hash =
/// keccak256(consensus_key)` commits the full Falcon-512 public key.
pub fn member_leaf(member: &HyperValidatorSetMember) -> Vec<u8> {
    let mut leaf = Vec::with_capacity(32 + 8 + 32 + 8);
    leaf.extend_from_slice(&member.consensus_key_hash);
    leaf.extend_from_slice(&member.weight.to_be_bytes());
    leaf.extend_from_slice(&member.node_key_hash);
    leaf.extend_from_slice(&member.fid.to_be_bytes());
    leaf
}

/// `set_root(e)`: ordered Keccak Merkle root (`chain::merkle`) over the member
/// leaves, in `consensus_key_hash` order.
pub fn set_root(members: &[HyperValidatorSetMember]) -> [u8; 32] {
    let leaves: Vec<Vec<u8>> = members.iter().map(member_leaf).collect();
    merkle::root(&leaves)
}

/// The record of `epoch`: members sorted by `consensus_key_hash`, one weight
/// each.
pub fn build_record(
    epoch: u64,
    mut members: Vec<HyperValidatorSetMember>,
) -> HyperValidatorSetRecord {
    members.sort_by(|a, b| a.consensus_key_hash.cmp(&b.consensus_key_hash));
    members.dedup_by(|a, b| a.consensus_key_hash == b.consensus_key_hash);
    let total_weight = members.iter().map(|m| m.weight).sum();
    let root = set_root(&members);
    HyperValidatorSetRecord {
        epoch,
        members,
        total_weight,
        set_root: root.to_vec(),
    }
}

/// A set record with the keys of its members and its `epoch_seed`.
#[derive(Clone)]
pub struct EpochSet {
    pub record: HyperValidatorSetRecord,
    pub seed: [u8; 32],
    keys: BTreeMap<[u8; 32], Arc<FalconPublicKey>>,
}

impl EpochSet {
    /// Fails if a member has no key, or a key does not hash to its member.
    pub fn new(
        record: HyperValidatorSetRecord,
        seed: [u8; 32],
        keys: impl IntoIterator<Item = Arc<FalconPublicKey>>,
    ) -> Result<EpochSet, String> {
        let keys: BTreeMap<[u8; 32], Arc<FalconPublicKey>> =
            keys.into_iter().map(|k| (k.key_id(), k)).collect();
        for member in &record.members {
            let hash: [u8; 32] = member
                .consensus_key_hash
                .as_slice()
                .try_into()
                .map_err(|_| "consensus_key_hash is not 32 bytes".to_string())?;
            if !keys.contains_key(&hash) {
                return Err(format!("no consensus key for member {}", hex::encode(hash)));
            }
        }
        if set_root(&record.members).as_slice() != record.set_root.as_slice() {
            return Err("set_root does not match the members".to_string());
        }
        Ok(EpochSet { record, seed, keys })
    }

    pub fn epoch(&self) -> u64 {
        self.record.epoch
    }

    /// The Malachite validator set of this epoch for `shard_id`, with the
    /// proposer order of FIP §4.9.
    pub fn validator_set(&self, shard_id: u32) -> SnapchainValidatorSet {
        let validators = self
            .record
            .members
            .iter()
            .map(|m| {
                let hash: [u8; 32] = m.consensus_key_hash.as_slice().try_into().unwrap();
                SnapchainValidator::new_falcon(
                    SnapchainShard::new(shard_id),
                    self.keys[&hash].clone(),
                    0,
                )
            })
            .collect();
        SnapchainValidatorSet::new_epoch(validators, self.seed)
    }

    /// The proposer of `(shard_id, height, round)` (FIP §4.9):
    /// `order(e)[(h + r + shard) mod |order(e)|]`, with `order(e)` the members
    /// sorted by `keccak256(epoch_seed || consensus_key_hash)`.
    pub fn proposer(&self, shard_id: u32, height: u64, round: u32) -> &HyperValidatorSetMember {
        let members = &self.record.members;
        let mut order: Vec<([u8; 32], usize)> = members
            .iter()
            .enumerate()
            .map(|(i, m)| {
                let mut pre = Vec::with_capacity(64);
                pre.extend_from_slice(&self.seed);
                pre.extend_from_slice(&m.consensus_key_hash);
                (alloy_primitives::keccak256(&pre).0, i)
            })
            .collect();
        order.sort();
        let n = order.len() as u64;
        let slot = (height % n + round as u64 % n + shard_id as u64 % n) % n;
        &members[order[slot as usize].1]
    }

    /// More than 2/3 of the total weight.
    pub fn is_quorum(&self, signer_weight: u64) -> bool {
        3 * signer_weight > 2 * self.record.total_weight
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::consensus_keys::test_key;

    fn member(pk: &FalconPublicKey, fid: u64) -> HyperValidatorSetMember {
        HyperValidatorSetMember {
            consensus_key_hash: pk.key_id().to_vec(),
            weight: 1,
            node_key_hash: vec![fid as u8; 32],
            fid,
        }
    }

    #[test]
    fn record_and_set_agree() {
        let keys: Vec<Arc<FalconPublicKey>> = (1..=4u8)
            .map(|s| Arc::new(test_key(s).public_key().as_falcon().unwrap().clone()))
            .collect();
        let members = keys
            .iter()
            .enumerate()
            .map(|(i, k)| member(k, 100 + i as u64))
            .collect();
        let record = build_record(1, members);
        assert_eq!(record.total_weight, 4);
        assert!(record
            .members
            .windows(2)
            .all(|w| w[0].consensus_key_hash < w[1].consensus_key_hash));

        let set = EpochSet::new(record.clone(), [5u8; 32], keys.clone()).unwrap();
        let vset = set.validator_set(1);
        assert_eq!(vset.validators.len(), 4);
        assert!(vset.epoch_order.is_some());
        assert!(set.is_quorum(3));
        // The proposer agrees with the Malachite context.
        use informalsystems_malachitebft_core_types::{Context, Round};
        let ctx = crate::core::types::SnapchainValidatorContext::new_with_key(test_key(1));
        for (h, r) in [(7u64, 0u32), (8, 1), (9, 3)] {
            let chosen = ctx.select_proposer(&vset, crate::proto::Height::new(1, h), Round::new(r));
            assert_eq!(
                chosen.address.to_vec(),
                set.proposer(1, h, r).consensus_key_hash,
                "h {} r {}",
                h,
                r
            );
        }
        assert!(!set.is_quorum(2));

        // A missing key or a changed member is rejected.
        assert!(EpochSet::new(record.clone(), [5u8; 32], keys[..3].to_vec()).is_err());
        let mut tampered = record;
        tampered.members[0].fid += 1;
        assert!(EpochSet::new(tampered, [5u8; 32], keys).is_err());
    }
}
