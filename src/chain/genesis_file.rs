//! The genesis validator file (FIP §17.3): the three signed messages of each
//! bootstrap validator, and the assembly of the file.
//!
//! An operator makes an entry in two steps. `custody_migration_hash` gives
//! the EIP-712 hash that the current custody address of the FID signs (a
//! hardware wallet can sign it). `entry` then makes the three messages with
//! that signature and the Falcon-512 custody, node and consensus keys of the
//! validator. The coordinator collects the entries and calls `assemble`; the
//! keccak256 of the encoded file is `GENESIS_VALIDATORS_HASH`.

use crate::chain::epoch::epoch_seed;
use crate::chain::shard0::auth;
use crate::chain::validator_sets::{build_record, EpochSet};
use crate::proto::{
    message_data::Body, CustodyMigrationBody, FarcasterNetwork, GenesisValidator,
    GenesisValidatorFile, HyperValidatorEventBody, HyperValidatorEventType,
    HyperValidatorSetMember, Message, MessageData, MessageType, NodeAttestationBody,
};
use hypersnap_falcon::{domains, FalconPublicKey, FalconSecretKey};
use hypersnap_messages::{
    clear_custody_migration, clear_node_attestation, clear_validator_registration, falcon_public,
    second_signature_payload, EIP712_CUSTODY_MIGRATION,
};
use rand::{CryptoRng, RngCore};
use std::collections::BTreeSet;
use std::sync::Arc;

pub const GENESIS_FILE_VERSION: u32 = 1;

/// The keys and fields of one genesis entry.
pub struct EntryKeys<'a> {
    pub fid: u64,
    pub network: FarcasterNetwork,
    /// Farcaster time of the three messages.
    pub timestamp: u32,
    /// Farcaster time after which the custody migration is void. It must be
    /// after the fork block.
    pub deadline: u32,
    /// The new Falcon-512 custody key of the FID.
    pub custody: &'a FalconSecretKey,
    /// The Falcon-512 node key.
    pub node: &'a FalconSecretKey,
    /// The Falcon-512 consensus key (§16.4).
    pub consensus: &'a FalconSecretKey,
}

fn data(keys: &EntryKeys, t: MessageType, body: Body) -> MessageData {
    MessageData {
        r#type: t as i32,
        fid: keys.fid,
        timestamp: keys.timestamp,
        network: keys.network as i32,
        body: Some(body),
    }
}

fn falcon_sign<R: CryptoRng + RngCore>(
    sk: &FalconSecretKey,
    domain: hypersnap_falcon::Domain,
    payload: &[u8],
    rng: &mut R,
) -> Result<Vec<u8>, String> {
    hypersnap_messages::falcon_sign(sk, domain, payload, rng).map_err(|e| format!("{:?}", e))
}

/// A `SIGNATURE_SCHEME_FALCON512` message signed by `sk` (FIP §16.8).
pub fn falcon_message<R: CryptoRng + RngCore>(
    sk: &FalconSecretKey,
    data: MessageData,
    rng: &mut R,
) -> Result<Message, String> {
    hypersnap_messages::falcon_message(sk, data, rng).map_err(|e| format!("{:?}", e))
}

fn migration_data(keys: &EntryKeys) -> MessageData {
    data(
        keys,
        MessageType::CustodyMigration,
        Body::CustodyMigrationBody(CustodyMigrationBody {
            falcon_custody_key: falcon_public(keys.custody),
            deadline: keys.deadline,
            ..Default::default()
        }),
    )
}

/// The EIP-712 hash that the current custody address of the FID signs for
/// its `CUSTODY_MIGRATION` (FIP §16.7, §16.9).
pub fn custody_migration_hash(keys: &EntryKeys) -> [u8; 32] {
    auth::eip712_hash(
        EIP712_CUSTODY_MIGRATION,
        &second_signature_payload(&migration_data(keys), clear_custody_migration),
    )
}

/// The three messages of a genesis entry: the custody migration, the node
/// attestation and the registration for epoch 1. `eip712_signature` is the
/// signature of the custody address over `custody_migration_hash`.
pub fn entry<R: CryptoRng + RngCore>(
    keys: &EntryKeys,
    eip712_signature: Vec<u8>,
    rng: &mut R,
) -> Result<GenesisValidator, String> {
    let mut d = migration_data(keys);
    if let Some(Body::CustodyMigrationBody(b)) = d.body.as_mut() {
        b.eip712_signature = eip712_signature;
    }
    let migration = falcon_message(keys.custody, d, rng)?;

    let mut d = data(
        keys,
        MessageType::NodeAttestation,
        Body::NodeAttestationBody(NodeAttestationBody {
            node_public_key: falcon_public(keys.node),
            nonce: 1,
            ..Default::default()
        }),
    );
    let node_signature = falcon_sign(
        keys.node,
        domains::NODE_ATTESTATION_POP,
        &second_signature_payload(&d, clear_node_attestation),
        rng,
    )?;
    if let Some(Body::NodeAttestationBody(b)) = d.body.as_mut() {
        b.node_signature = node_signature;
    }
    let attestation = falcon_message(keys.custody, d, rng)?;

    let mut d = data(
        keys,
        MessageType::ValidatorRegister,
        Body::ValidatorEventBody(HyperValidatorEventBody {
            event_type: HyperValidatorEventType::Register as i32,
            validator_key: hypersnap_falcon::key_id(keys.consensus.public_key()).to_vec(),
            registration_epoch: 1,
            consensus_key: falcon_public(keys.consensus),
            falcon_node_key: falcon_public(keys.node),
            ..Default::default()
        }),
    );
    let payload = second_signature_payload(&d, clear_validator_registration);
    let consensus_pop = falcon_sign(
        keys.consensus,
        domains::VALIDATOR_CONSENSUS_POP,
        &payload,
        rng,
    )?;
    let node_signature = falcon_sign(keys.node, domains::VALIDATOR_NODE_POP, &payload, rng)?;
    if let Some(Body::ValidatorEventBody(b)) = d.body.as_mut() {
        b.signature = consensus_pop;
        b.node_signature = node_signature;
    }
    let register = falcon_message(keys.custody, d, rng)?;

    Ok(GenesisValidator {
        custody_migration: Some(migration),
        node_attestation: Some(attestation),
        validator_register: Some(register),
    })
}

/// The checks of an entry that need no state: three messages of the right
/// types, one FID, valid hashes and signatures (FIP §16.8). The genesis
/// builder checks the rest against the epoch-0 state.
pub fn check_entry(entry: &GenesisValidator, network: FarcasterNetwork) -> Result<u64, String> {
    let expected = [
        (&entry.custody_migration, MessageType::CustodyMigration),
        (&entry.node_attestation, MessageType::NodeAttestation),
        (&entry.validator_register, MessageType::ValidatorRegister),
    ];
    let mut fid = None;
    for (m, t) in expected {
        let m = m.as_ref().ok_or_else(|| format!("no {:?} message", t))?;
        let env = auth::open(m, network, u64::MAX / 2).map_err(|e| e.to_string())?;
        if env.msg_type != t {
            return Err(format!("{:?} where {:?} is expected", env.msg_type, t));
        }
        match fid {
            None => fid = Some(env.data.fid),
            Some(f) if f != env.data.fid => {
                return Err(format!("messages of FIDs {} and {}", f, env.data.fid))
            }
            Some(_) => {}
        }
    }
    fid.ok_or_else(|| "empty entry".into())
}

/// The genesis validator file of `entries`, sorted by FID.
pub fn assemble(
    mut entries: Vec<GenesisValidator>,
    network: FarcasterNetwork,
) -> Result<GenesisValidatorFile, String> {
    let mut fids = BTreeSet::new();
    let mut keyed = Vec::with_capacity(entries.len());
    for e in entries.drain(..) {
        let fid = check_entry(&e, network).map_err(|err| format!("an entry: {}", err))?;
        if !fids.insert(fid) {
            return Err(format!("two entries for FID {}", fid));
        }
        keyed.push((fid, e));
    }
    keyed.sort_by_key(|(fid, _)| *fid);
    Ok(GenesisValidatorFile {
        version: GENESIS_FILE_VERSION,
        validators: keyed.into_iter().map(|(_, e)| e).collect(),
    })
}

/// `set(1)` from the file alone (FIP §17.3): the genesis build applies each
/// entry or fails, so each entry is a member of the bootstrap set. A node
/// that does not have the genesis state yet checks the certificate of the
/// shard-0 pivot block with it.
pub fn epoch1_set(
    file: &GenesisValidatorFile,
    network: FarcasterNetwork,
    fork_block_hash: &[u8; 32],
) -> Result<EpochSet, String> {
    let mut members = Vec::with_capacity(file.validators.len());
    let mut publics = Vec::with_capacity(file.validators.len());
    for entry in &file.validators {
        let fid = check_entry(entry, network)?;
        let register = entry
            .validator_register
            .as_ref()
            .ok_or("no VALIDATOR_REGISTER message")?;
        let env = auth::open(register, network, u64::MAX / 2).map_err(|e| e.to_string())?;
        let Some(Body::ValidatorEventBody(body)) = &env.data.body else {
            return Err(format!("the VALIDATOR_REGISTER of FID {} has no body", fid));
        };
        let consensus = FalconPublicKey::from_bytes(&body.consensus_key)
            .map_err(|_| format!("the consensus key of FID {} is not Falcon-512", fid))?;
        members.push(HyperValidatorSetMember {
            consensus_key_hash: consensus.key_id().to_vec(),
            weight: 1,
            node_key_hash: auth::falcon_key_hash(&body.falcon_node_key).to_vec(),
            fid,
        });
        publics.push(Arc::new(consensus));
    }
    EpochSet::new(
        build_record(1, members),
        epoch_seed(1, fork_block_hash),
        publics,
    )
}
