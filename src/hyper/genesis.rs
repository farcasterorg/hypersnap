//! Genesis bootstrap helpers for `HyperRuntime`.
//!
//! At chain start, a `HyperRuntime` needs:
//!   1. An initial set of bootstrap validators (their Ed25519 keys, transport
//!      keys, and 20-byte DKLS23 secp256k1 addresses).
//!   2. The genesis epoch's DKLS23 group address (the 20-byte secp256k1
//!      address derived from the DKG group public key).
//!
//! `GenesisConfig` captures these inputs; `bootstrap_runtime` applies them.

use crate::hyper::runtime::HyperRuntime;

#[derive(thiserror::Error, Debug)]
pub enum GenesisError {
    #[error("bootstrap validators must be non-empty")]
    NoBootstrapValidators,
}

/// Per-validator bootstrap material.
#[derive(Clone, Debug)]
pub struct BootstrapValidator {
    /// 32-byte Ed25519 identity public key.
    pub validator_key: Vec<u8>,
    /// 32-byte X25519 transport public key. Reserved for the
    /// out-of-band coordination layer that delivers DKG kick-off
    /// metadata between operators; unused at the cryptographic
    /// layer (DKLS23's protocols are authenticated via gossip).
    pub transport_pubkey: Vec<u8>,
    /// 20-byte secp256k1 address — this validator's identity in the
    /// post-migration DKLS23 group. Required at genesis since the
    /// initial group address is computed from these.
    pub validator_address: alloy_primitives::Address,
}

/// Genesis configuration: bootstrap validator set + a pre-computed
/// DKLS23 group address.
#[derive(Clone)]
pub struct GenesisConfig {
    pub bootstrap_validators: Vec<BootstrapValidator>,
    /// Genesis DKLS23 group address — the 20-byte secp256k1 address
    /// recovered from the DKG group public key.
    pub genesis_group_address: alloy_primitives::Address,
    /// This node's own DKLS23 `Party` state for the genesis epoch
    /// (if this node is a bootstrap signer). `(participant_index,
    /// party)`. `None` on validator hosts that aren't part of the
    /// genesis bootstrap signing committee.
    pub local_dkls_party: Option<(
        u64,
        Box<hypersnap_crypto::dkls23::protocols::Party<hypersnap_crypto::k256::Secp256k1>>,
    )>,
}

/// Apply genesis configuration to a fresh `HyperRuntime`.
///   - Populates `runtime.bootstrap_validators` from the config (so
///     active-set computation has the genesis members)
///   - Persists the genesis DKLS23 group address into the registry
///   - Installs the local DKLS23 share (if this node is a bootstrap signer)
pub fn bootstrap_runtime(
    runtime: &mut HyperRuntime,
    config: &GenesisConfig,
) -> Result<(), GenesisError> {
    if config.bootstrap_validators.is_empty() {
        return Err(GenesisError::NoBootstrapValidators);
    }

    // Mirror the genesis validator set into the runtime so
    // `active_validators(epoch)` works without out-of-band wiring.
    // The third tuple element here is unused (legacy slot from the
    // BLS-era 3-tuple shape); we keep the type stable for now and
    // pass empty bytes.
    runtime.bootstrap_validators = config
        .bootstrap_validators
        .iter()
        .map(|v| {
            (
                v.validator_key.clone(),
                Vec::new(),
                v.transport_pubkey.clone(),
            )
        })
        .collect();

    // Install genesis group address (every node needs it for verification).
    runtime.install_dkls_group_address(0, config.genesis_group_address);

    // If this node is a genesis signer, install our local share.
    if let Some((idx, party)) = &config.local_dkls_party {
        runtime.install_local_dkls_share(0, *idx, (**party).clone(), config.genesis_group_address);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hyper::runtime::{HyperRuntime, HyperRuntimeConfig};
    use crate::hyper::validator_score::ScoreWeights;
    use crate::storage::db::RocksDB;
    use hypersnap_crypto::kzg::KzgSrs;
    use hypersnap_crypto::kzg_lagrange::VERKLE_DOMAIN;
    use rand::rngs::OsRng;
    use std::sync::Arc;
    use tempfile::TempDir;

    fn make_runtime() -> (HyperRuntime, TempDir) {
        let dir = TempDir::new().unwrap();
        let db = RocksDB::new(dir.path().to_str().unwrap());
        db.open().unwrap();
        let mut rng = OsRng;
        let srs = Arc::new(KzgSrs::random_unsafe(&mut rng, VERKLE_DOMAIN));
        let config = HyperRuntimeConfig {
            db: Arc::new(db),
            srs,
            mempool_capacity: 100,
            score_weights: ScoreWeights::default(),
            starting_epoch: 0,
            bootstrap_validators: vec![],
            max_reward_per_epoch: None,
            max_reward_per_epoch_per_market: std::collections::HashMap::new(),
            cutover_snapchain_block: 0,
            min_validator_trust_score: 0.0,
            protocol_chain_id: crate::hyper::DEFAULT_PROTOCOL_CHAIN_ID,
            scoring_params: proof_of_quality::ScoringParams::default(),
            seed_max_fid: 50_000,
            retro_vesting_on_protocol_epochs:
                crate::hyper::runtime::RETRO_VESTING_ON_PROTOCOL_EPOCHS_DEFAULT,
            local_transport_secret_bytes: [0u8; 32],
        };
        (HyperRuntime::new(config), dir)
    }

    fn sample_bootstrap_validator(idx: u8) -> BootstrapValidator {
        BootstrapValidator {
            validator_key: vec![idx; 32],
            transport_pubkey: vec![idx; 32],
            validator_address: alloy_primitives::Address::repeat_byte(idx),
        }
    }

    #[test]
    fn bootstrap_with_no_validators_errors() {
        let (mut runtime, _dir) = make_runtime();
        let config = GenesisConfig {
            bootstrap_validators: vec![],
            genesis_group_address: alloy_primitives::Address::ZERO,
            local_dkls_party: None,
        };
        assert!(matches!(
            bootstrap_runtime(&mut runtime, &config),
            Err(GenesisError::NoBootstrapValidators)
        ));
    }

    #[test]
    fn bootstrap_populates_runtime_validator_set() {
        let (mut runtime, _dir) = make_runtime();
        assert!(runtime.bootstrap_validators.is_empty());

        let dkg = hypersnap_crypto::dkls_threshold::run_honest_dkg(1, 1, [0xb1; 32]).unwrap();
        let config = GenesisConfig {
            bootstrap_validators: vec![
                sample_bootstrap_validator(1),
                sample_bootstrap_validator(2),
                sample_bootstrap_validator(3),
            ],
            genesis_group_address: dkg.group_address,
            local_dkls_party: None,
        };
        bootstrap_runtime(&mut runtime, &config).unwrap();

        assert_eq!(runtime.bootstrap_validators.len(), 3);
        let active = runtime.active_validators(0).unwrap();
        assert_eq!(active.len(), 3);
        assert!(active.contains_key(&vec![1u8; 32]));
        assert!(active.contains_key(&vec![2u8; 32]));
        assert!(active.contains_key(&vec![3u8; 32]));
    }

    #[test]
    fn bootstrap_persists_genesis_group_address() {
        let (mut runtime, _dir) = make_runtime();
        let dkg = hypersnap_crypto::dkls_threshold::run_honest_dkg(1, 1, [0xb2; 32]).unwrap();

        let config = GenesisConfig {
            bootstrap_validators: vec![sample_bootstrap_validator(1)],
            genesis_group_address: dkg.group_address,
            local_dkls_party: None,
        };
        bootstrap_runtime(&mut runtime, &config).unwrap();

        assert_eq!(
            runtime.dkls_group_address_for_epoch(0),
            Some(dkg.group_address)
        );
    }

    #[test]
    fn bootstrap_with_local_party_installs_signer() {
        let (mut runtime, _dir) = make_runtime();
        let dkg = hypersnap_crypto::dkls_threshold::run_honest_dkg(1, 1, [0xb3; 32]).unwrap();

        let config = GenesisConfig {
            bootstrap_validators: vec![sample_bootstrap_validator(1)],
            genesis_group_address: dkg.group_address,
            local_dkls_party: Some((1, Box::new(dkg.parties[0].clone()))),
        };
        bootstrap_runtime(&mut runtime, &config).unwrap();

        // Local share installed for epoch 0.
        let stored = runtime.dkls_share_for_epoch(0).expect("share installed");
        assert_eq!(stored.participant_index, 1);
        assert_eq!(stored.group_address, dkg.group_address);
    }
}
