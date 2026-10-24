//! Genesis state of shard 0 (FIP §17.3, §17.4).
//!
//! `write_bootstrap_set` writes the parts that a synthetic genesis (a devnet
//! with no snapchain history) needs: the bootstrap validator records, their
//! custody records and node attestations, `set(1)` and the epoch-1 seed. The
//! pivot builder adds the epoch-0 state to it.

use crate::chain::epoch::epoch_seed;
use crate::chain::shard0::keys;
use crate::chain::shard0::state::{BlockState, Shard0Trie};
use crate::chain::shard0::validators::members_at;
use crate::chain::shard0::{registry, BlockCtx, Outbox, Shard0Error, Shard0Params};
use crate::chain::validator_sets::build_record;
use crate::proto::{self, FidCustodyRecord, ValidatorRecord};
use crate::storage::db::{RocksDB, RocksDbTransactionBatch};
use crate::storage::store::account::{OnchainEventStore, StoreEventHandler};
use alloy_primitives::keccak256;
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
    /// The Falcon-512 custody key, if the FID is migrated from the genesis.
    /// A node key needs it: a node key signs only for a migrated FID (FIP §3).
    pub custody_key: Vec<u8>,
}

/// The IdRegistry registration of a bootstrap FID of a synthetic genesis,
/// which has no snapchain history.
fn bootstrap_registration(fid: u64) -> proto::OnChainEvent {
    let custody = keccak256([b"hypersnap-devnet-custody".as_slice(), &fid.to_be_bytes()].concat());
    proto::OnChainEvent {
        r#type: proto::OnChainEventType::EventTypeIdRegister as i32,
        chain_id: 10,
        block_number: 1,
        transaction_hash: keccak256(
            [
                b"hypersnap-devnet-registration".as_slice(),
                &fid.to_be_bytes(),
            ]
            .concat(),
        )
        .to_vec(),
        fid,
        version: 1,
        body: Some(proto::on_chain_event::Body::IdRegisterEventBody(
            proto::IdRegisterEventBody {
                to: custody[12..].to_vec(),
                event_type: proto::IdRegisterEventType::Register as i32,
                ..Default::default()
            },
        )),
        ..Default::default()
    }
}

/// Write the bootstrap set (`set(1) = set(2)`, FIP §4.1) and the epoch-1
/// seed into the shard-0 DB, through the state trie. `fork_hash` is the
/// hash of the fork block (`H_last(0)`). Each bootstrap FID gets an
/// IdRegistry registration, as shard 0 applies one. The registrations and
/// the custody records go to the outbox of `pivot_height − 1`, as the genesis
/// entries of a pivot do, so the data shards replicate them from their pivot
/// blocks.
pub fn write_bootstrap_set(
    db: &Arc<RocksDB>,
    validators: &[BootstrapValidator],
    fork_hash: &[u8; 32],
    params: &Shard0Params,
) -> Result<(), Shard0Error> {
    let mut state = BlockState::new(db.clone());
    let mut outbox = Outbox::default();
    let onchain = OnchainEventStore::new(db.clone(), StoreEventHandler::new());
    let genesis_height = params.epochs.pivot_height_0.saturating_sub(1);
    let ctx = BlockCtx {
        params,
        height: genesis_height,
        epoch: 1,
        timestamp: 0,
        genesis: true,
    };
    let mut records = Vec::with_capacity(validators.len());
    for v in validators {
        registry::apply_onchain_event(
            &ctx,
            &mut state,
            &onchain,
            &bootstrap_registration(v.fid),
            &mut outbox,
        )?;
        let mut txn = state.txn();
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
        if !v.custody_key.is_empty() {
            hypersnap_falcon::FalconPublicKey::from_bytes(&v.custody_key)
                .map_err(|e| Shard0Error::invalid(format!("bootstrap custody key: {}", e)))?;
            txn.put_proto(
                keys::custody(v.fid),
                &FidCustodyRecord {
                    falcon_custody_key: v.custody_key.clone(),
                    ..Default::default()
                },
            );
        } else if !v.node_public_key.is_empty() {
            return Err(Shard0Error::invalid(
                "a bootstrap node key needs a migrated FID (a custody key)",
            ));
        }
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
        let writes = txn.into_writes();
        outbox.record_writes(params, &writes);
        state.apply(writes);
    }
    let mut txn = state.txn();
    txn.put_proto(
        keys::validator_set(1),
        &build_record(1, members_at(&records, 1)),
    );
    txn.put(keys::epoch_seed(1), epoch_seed(1, fork_hash).to_vec());
    for (i, entry) in outbox.into_entries().into_iter().enumerate() {
        txn.put_proto(keys::outbox(genesis_height, i as u32), &entry);
    }
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

    fn validator(fid: u64, node_public_key: Vec<u8>, migrated: bool) -> BootstrapValidator {
        BootstrapValidator {
            fid,
            consensus_key: falcon_public(&falcon(fid as u8 + 100)),
            node_key_hash: auth::falcon_key_hash(&falcon_public(&falcon(fid as u8))),
            node_public_key,
            custody_key: if migrated {
                falcon_public(&falcon(fid as u8 + 200))
            } else {
                vec![]
            },
        }
    }

    /// The data shards replicate the registrations and the custody records of
    /// the bootstrap FIDs from the outbox of `pivot_height − 1` (FIP §17.7).
    #[test]
    fn the_bootstrap_registration_and_custody_go_to_the_outbox() {
        let params = Shard0Params::new(FarcasterNetwork::Devnet, 5);
        let dir = tempfile::TempDir::new().unwrap();
        let db = Arc::new(RocksDB::new(dir.path().to_str().unwrap()));
        db.open().unwrap();
        write_bootstrap_set(
            &db,
            &[
                validator(1, falcon_public(&falcon(1)), true),
                validator(2, vec![], false),
            ],
            &[7u8; 32],
            &params,
        )
        .unwrap();
        let entry = |i: u32| -> Option<crate::proto::OutboxEntry> {
            db.get(&keys::outbox(4, i))
                .unwrap()
                .map(|v| prost::Message::decode(v.as_slice()).unwrap())
        };
        // FID 1: its registration and its custody record; FID 2 (not
        // migrated): its registration.
        let registration = entry(0).unwrap();
        assert_eq!(
            (registration.shard_id, registration.fid),
            (params.shard_of(1), 1)
        );
        assert_eq!(registration.replay_event, Some(bootstrap_registration(1)));
        let custody = entry(1).unwrap();
        assert_eq!((custody.shard_id, custody.fid), (params.shard_of(1), 1));
        assert_eq!(custody.writes.len(), 1);
        assert_eq!(custody.writes[0].key, keys::custody(1));
        assert_eq!(
            entry(2).unwrap().replay_event,
            Some(bootstrap_registration(2))
        );
        assert!(entry(3).is_none());
    }

    /// A synthetic genesis migrates a bootstrap FID and attests its node key,
    /// so the node key signs for the FID (FIP §3). A node key of an FID that
    /// is not migrated signs nothing.
    #[test]
    fn a_bootstrap_node_key_signs_for_its_migrated_fid() {
        let params = Shard0Params::new(FarcasterNetwork::Devnet, 1);
        let dir = tempfile::TempDir::new().unwrap();
        let db = Arc::new(RocksDB::new(dir.path().to_str().unwrap()));
        db.open().unwrap();
        assert!(write_bootstrap_set(
            &db,
            &[validator(1, vec![1u8; 897], true)],
            &[7u8; 32],
            &params
        )
        .is_err());
        assert!(write_bootstrap_set(
            &db,
            &[validator(1, falcon_public(&falcon(1)), false)],
            &[7u8; 32],
            &params
        )
        .is_err());
        write_bootstrap_set(
            &db,
            &[
                validator(1, falcon_public(&falcon(1)), true),
                validator(2, vec![], false),
            ],
            &[7u8; 32],
            &params,
        )
        .unwrap();
        // An attestation of FID 3, which is not migrated.
        let mut batch = RocksDbTransactionBatch::new();
        batch.put(
            keys::node_attestation(&auth::falcon_key_hash(&falcon_public(&falcon(3)))),
            prost::Message::encode_to_vec(&crate::proto::NodeAttestationState {
                fid: 3,
                node_public_key: falcon_public(&falcon(3)),
                attested_at_epoch: 1,
                ..Default::default()
            }),
        );
        db.commit(batch).unwrap();
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
        // Not attested, attested for another FID, or for an FID that is not
        // migrated.
        assert!(role(2, 2).is_err());
        assert!(role(1, 2).is_err());
        assert!(role(3, 3).is_err());
    }
}
