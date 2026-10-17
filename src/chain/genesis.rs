//! Genesis state of shard 0 (FIP §17.3, §17.4).
//!
//! `write_bootstrap_set` writes the parts that a synthetic genesis (a devnet
//! with no snapchain history) needs: the bootstrap validator records, `set(1)`
//! and the epoch-1 seed. The pivot builder adds the epoch-0 state to it.

use crate::chain::epoch::epoch_seed;
use crate::chain::shard0::keys;
use crate::chain::shard0::state::{BlockState, Shard0Trie};
use crate::chain::shard0::validators::members_at;
use crate::chain::shard0::Shard0Error;
use crate::chain::validator_sets::build_record;
use crate::proto::ValidatorRecord;
use crate::storage::db::{RocksDB, RocksDbTransactionBatch};
use std::sync::Arc;

/// A bootstrap validator of a synthetic genesis.
#[derive(Clone)]
pub struct BootstrapValidator {
    pub fid: u64,
    /// The encoded Falcon-512 consensus public key (§16.4).
    pub consensus_key: Vec<u8>,
    pub node_key_hash: [u8; 32],
    /// The Falcon-512 node public key, if the genesis attests it (FIP §3):
    /// then the node key signs for the FID, for example DA responses.
    pub node_public_key: Vec<u8>,
}

/// Write the bootstrap set (`set(1) = set(2)`, FIP §4.1) and the epoch-1
/// seed into the shard-0 DB, through the state trie. `fork_hash` is the
/// hash of the fork block (`H_last(0)`).
pub fn write_bootstrap_set(
    db: &Arc<RocksDB>,
    validators: &[BootstrapValidator],
    fork_hash: &[u8; 32],
) -> Result<(), Shard0Error> {
    let mut state = BlockState::new(db.clone());
    let mut txn = state.txn();
    let mut records = Vec::with_capacity(validators.len());
    for v in validators {
        let pk = hypersnap_falcon::FalconPublicKey::from_bytes(&v.consensus_key)
            .map_err(|e| Shard0Error::invalid(format!("bootstrap consensus key: {}", e)))?;
        let record = ValidatorRecord {
            fid: v.fid,
            consensus_key_hash: pk.key_id().to_vec(),
            consensus_key: v.consensus_key.clone(),
            node_key_hash: v.node_key_hash.to_vec(),
            registration_epoch: 1,
            join_epoch: 1,
            ..Default::default()
        };
        txn.put_proto(keys::validator(&record.consensus_key_hash), &record);
        records.push(record);
        if !v.node_public_key.is_empty() {
            if crate::chain::shard0::auth::falcon_key_hash(&v.node_public_key) != v.node_key_hash {
                return Err(Shard0Error::invalid(
                    "the bootstrap node key is not the node key hash",
                ));
            }
            txn.put_proto(
                keys::node_attestation(&v.node_key_hash),
                &crate::proto::NodeAttestationState {
                    fid: v.fid,
                    node_public_key: v.node_public_key.clone(),
                    attested_at_epoch: 1,
                    ..Default::default()
                },
            );
            txn.put(
                keys::node_attestation_by_fid(v.fid, &v.node_key_hash),
                vec![],
            );
        }
    }
    txn.put_proto(
        keys::validator_set(1),
        &build_record(1, members_at(&records, 1)),
    );
    txn.put(keys::epoch_seed(1), epoch_seed(1, fork_hash).to_vec());
    let writes = txn.into_writes();
    state.apply(writes);
    let mut trie = Shard0Trie::open(db.clone())?;
    let mut batch = RocksDbTransactionBatch::new();
    trie.stage(&state, &mut batch)?;
    batch.merge(state.into_batch());
    db.commit(batch)
        .map_err(|e| Shard0Error::Internal(e.to_string()))
}

/// `true` if the shard-0 DB has a genesis (a set record of epoch 1).
pub fn has_genesis(db: &Arc<RocksDB>) -> bool {
    db.get(&keys::validator_set(1)).ok().flatten().is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::shard0::auth::{self, test_keys::*, Role};
    use crate::proto::{message_data::Body, FarcasterNetwork, MessageData, MessageType};
    use crate::storage::store::account::{OnchainEventStore, StoreEventHandler};

    fn validator(fid: u64, node_public_key: Vec<u8>) -> BootstrapValidator {
        BootstrapValidator {
            fid,
            consensus_key: falcon_public(&falcon(fid as u8 + 100)),
            node_key_hash: auth::falcon_key_hash(&falcon_public(&falcon(fid as u8))),
            node_public_key,
        }
    }

    /// A synthetic genesis attests the node key of a bootstrap validator, so
    /// the node key signs for the FID, which is not migrated (FIP §3).
    #[test]
    fn a_bootstrap_node_key_signs_for_its_fid() {
        let dir = tempfile::TempDir::new().unwrap();
        let db = Arc::new(RocksDB::new(dir.path().to_str().unwrap()));
        db.open().unwrap();
        assert!(write_bootstrap_set(&db, &[validator(1, vec![1u8; 897])], &[7u8; 32]).is_err());
        write_bootstrap_set(
            &db,
            &[
                validator(1, falcon_public(&falcon(1))),
                validator(2, vec![]),
            ],
            &[7u8; 32],
        )
        .unwrap();
        let onchain = OnchainEventStore::new(db.clone(), StoreEventHandler::new());
        let state = BlockState::new(db.clone());
        let txn = state.txn();
        let role = |key: u8, fid: u64| {
            let m = falcon_message(
                &falcon(key),
                MessageData {
                    r#type: MessageType::DaChallengeResponse as i32,
                    fid,
                    timestamp: 10,
                    network: FarcasterNetwork::Devnet as i32,
                    body: Some(Body::DaChallengeResponseBody(Default::default())),
                },
            );
            let env = auth::open(&m, FarcasterNetwork::Devnet, 1_000_000_000).unwrap();
            auth::resolve(&txn, &onchain, &env)
        };
        assert!(matches!(role(1, 1), Ok(Role::NodeKey { .. })));
        // Not attested, or attested for another FID.
        assert!(role(2, 2).is_err());
        assert!(role(1, 2).is_err());
    }
}
