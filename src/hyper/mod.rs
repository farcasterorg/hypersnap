//! # Hyper layer architecture
//!
//! The hyper layer is structured as a set of cooperating modules, each with
//! a single well-defined responsibility. Their relationships:
//!
//! ## Cryptographic primitives (in `hypersnap-crypto` crate, not here)
//! - BLS12-381 sign/verify/aggregate; threshold sigs; Pedersen DKG
//! - KZG commitments; ceremony loader; 256-ary verkle tree
//! - Decaf448 Pedersen, Bulletproofs, Schnorr signatures
//! - Stealth addresses, AEAD note payloads, NoteStore abstraction
//!
//! ## Per-message handlers
//! - `lock_event` — encode/decode/validate `HyperLockEvent`, insert into
//!   verkle tree at `lock_id`. Includes Schnorr-signed authorization.
//! - `transfer_codec` — proto ↔ Rust conversions for token transfers.
//! - `validator_registry` — Ed25519-authenticated `HyperValidatorEventBody`
//!   storage + per-epoch active set computation with EPOCH_BUFFER buffering.
//!
//! ## Block lifecycle
//! - `mempool` — capacity-bounded LRU-evicted pending message queue.
//! - `builder` — proposer-side: drain → apply → root → envelope.
//!   Verkle keys are domain-prefixed (lock=0x01, nullifier=0x02, commitment=0x03).
//! - `importer` — full validation pipeline: signature, state convergence,
//!   chain continuity, score updates, block index persistence.
//! - `chain` — canonical block hashing, parent_hash linking, monotonic height
//!   enforcement (`ChainTracker`).
//! - `block_index` — RocksDB index by height + hash for historical queries.
//! - `proofs` — high-level helpers for nullifier inclusion + note commitment
//!   inclusion proofs against the verkle tree.
//!
//! ## Validator lifecycle
//! - `validator_score` — per-validator per-epoch counters with FIP §5.4
//!   weighted scoring + auto-deregistration thresholds.
//! - `epoch` — `EpochManager` watches snapchain anchor heights, emits
//!   transition events at boundaries.
//! - `epoch_resolver` — combines `EpochManager` + per-epoch threshold key
//!   store; `current_group_pubkey()` and `group_pubkey_for(epoch)`.
//!
//! ## DKG ceremony (DKLS23 threshold ECDSA)
//! - `dkls_ceremony` (in `hypersnap-crypto`) — 4-phase DKLS23 DKG
//!   state machine.
//! - `dkls_driver` — runtime-aware shell that finalizes a ceremony
//!   into [`HyperRuntime::install_local_dkls_share`].
//! - `dkls_supervisor` — epoch-boundary supervisor that fires
//!   `StartDkls` on the actor with a fresh driver.
//!
//! ## Bridge
//! - `claim_verifier` — pure Rust reference implementation of the L1
//!   `HypersnapBridge::claim` verification path. Solidity port pending.
//!
//! ## Storage indexes
//! - `note_store` — RocksDB-backed `NoteStore` impl for transfer validation.
//!
//! ## Operational glue
//! - `runtime` — `HyperRuntime` ties together all of the above into a single
//!   coherent struct with high-level methods.
//! - `config` — TOML-deserializable runtime configuration loader.
//! - `router` — transport-agnostic dispatch from `proto::HyperMessage` to
//!   the right handler (mempool / registry).
//! - `topics` — gossip topic name constants.
//! - `actor` — tokio actor wrapping `HyperRuntime` with mpsc channels;
//!   accepts `HyperActorEvent`s and emits `HyperActorOutbound`s.
//! - `gossip_adapter` — pure translation between
//!   `proto::HyperWireMessage` (gossip wire frames) and the actor event
//!   types. Carries blocks, hyper messages, and DKG round messages
//!   (DKLS23 round messages live in `hypersnap_crypto::dkls_ceremony`).
//! - `network_loop` — `bootstrap` helper that spawns the actor, calls
//!   `SnapchainGossip::attach_hyper_actor`, and runs the outbound pump
//!   (actor outbound → `GossipEvent::BroadcastHyperWire`).
//! - `slashing` — observational evidence detection for conflicting blocks
//!   at the same height.
//!
//! ## What's deliberately NOT in this module
//! libp2p swarm + transport setup — that lives in the network layer. The
//! integration is one-call: `network_loop::bootstrap(runtime, gossip, …)`
//! returns the actor's inbound sender and a pump join handle. Once that's
//! called the libp2p task forwards every hyper-topic gossip frame into
//! the actor and publishes every outbound on the right topic.
//!
//! ## End-to-end node lifecycle
//!
//! 1. Operator authors `runtime.toml` and `genesis.toml`.
//! 2. Operator places the KZG ceremony file at the path declared in `runtime.toml`.
//! 3. `HyperRuntimeFileConfig::build_runtime(db)` returns a `HyperRuntime`
//!    with epoch-0 keys persisted (from `genesis.toml`).
//! 4. If this node is a bootstrap validator with a local share, the operator
//!    additionally calls `runtime.install_local_dkg_share(0, idx, share, ...)`.
//! 5. The actor system layer subscribes to the topics in `topics::all_*`,
//!    routes inbound gossip via `HyperRuntime::submit_message`, and on a
//!    per-block-time cadence drains pending messages, builds an envelope,
//!    threshold-signs it, and publishes the resulting `HyperBlock`.
//! 6. On block import, the actor calls
//!    `import_hyper_block_chain_aware` (or the scoring/index variants) to
//!    enforce all checks and update local state.
//! 7. At epoch boundaries, the DKLS23 DKG driver runs a fresh round of
//!    `DklsCeremonyCoordinator` against the next epoch's active set and
//!    finalizes the result into the runtime via
//!    `DklsDriver::finalize_into_runtime`.
//!
//! ## Complete coverage
//!
//! Every layer of the above is covered by automated tests, with end-to-end
//! integration tests at the proposer↔importer round-trip level. The protocol
//! surface is structurally complete; the operational-actor wiring follows
//! snapchain's existing patterns and consumes the same well-defined API.

pub mod account_association;
pub mod actor;

/// Default protocol chain id (OP Mainnet). Production overrides
/// via `HyperRuntimeConfig::protocol_chain_id`. Embedded in every
/// Ed25519-signed canonical payload (v2 DSTs) so a message signed
/// for chain A cannot replay on chain B. EIP-712 paths already
/// bind chain_id via their typed-data domain.
pub const DEFAULT_PROTOCOL_CHAIN_ID: u64 = 10;

pub mod app_usage_receipt;
pub mod backfill;
pub mod block_index;
pub mod bridge_burn_store;
pub mod bridge_burn_watcher;
pub mod builder;
pub mod chain;
pub mod claim_verifier;
pub mod config;
pub mod custody_escrow;
pub mod da_pow;
pub mod da_pow_driver;
pub mod da_response_producer_prod;
pub mod da_trie_lookup_prod;
pub mod dkls_address_store;
pub mod dkls_committee;
pub mod dkls_driver;
pub mod dkls_sign_driver;
pub mod dkls_supervisor;
pub mod dkls_wire_codec;
pub mod epoch;
pub mod epoch_resolver;
pub mod genesis;
pub mod gossip_adapter;
pub mod http_handler;
pub mod importer;
pub mod inbound_burn;
pub mod lock_event;
pub mod lock_tree;
pub mod mempool;
pub mod miniapp;
pub mod network_loop;
pub mod node_attestation;
pub mod note_store;
pub mod poq_reader;
pub mod proofs;
pub mod proposer;
pub mod recovery_store;
pub mod recovery_watcher;
pub mod retro_store;
pub mod rewards;
pub mod router;
pub mod runtime;
pub mod scheduler;
pub mod scoring_driver;
pub mod sig_verify;
pub mod slashing;
pub mod slashing_store;
pub mod token_escrow_bridge;
pub mod token_escrow_claim;
pub mod token_lock;
pub mod token_stake;
pub mod token_transfer;
pub mod topics;
pub mod transfer_codec;
pub mod trust_store;
pub mod validator_registry;
pub mod validator_score;

#[cfg(test)]
mod determinism_test;
#[cfg(test)]
mod dkls_integration_test;
#[cfg(test)]
mod multi_validator_integration_test;
#[cfg(test)]
mod network_simulation_test;
#[cfg(test)]
mod poq_integration_test;

use crate::proto;
use crate::storage::constants::RootPrefix;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Execution context for state mutations.
///
/// `Legacy` follows the current pruning rules while `Hyper` keeps
/// every message/transaction unbounded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StateContext {
    Legacy,
    Hyper,
}

impl StateContext {
    /// Prefix that can be used when namespacing storage keys.
    pub const fn namespace_prefix(self) -> &'static [u8] {
        match self {
            StateContext::Legacy => b"legacy",
            StateContext::Hyper => b"hyper",
        }
    }

    /// Whether this context allows the store to prune data.
    pub const fn allows_pruning(self) -> bool {
        matches!(self, StateContext::Legacy)
    }

    pub const fn is_hyper(self) -> bool {
        matches!(self, StateContext::Hyper)
    }

    /// Map a RootPrefix to the appropriate value for this context.
    ///
    /// Legacy context returns the original prefix (snapchain-compatible).
    /// Hyper context returns the shadow prefix for user-data key spaces,
    /// keeping non-user infrastructure prefixes unchanged.
    pub fn root_prefix(self, prefix: RootPrefix) -> u8 {
        if self.is_hyper() {
            match prefix {
                RootPrefix::User => RootPrefix::HyperUser as u8,
                RootPrefix::CastsByParent => RootPrefix::HyperCastsByParent as u8,
                RootPrefix::CastsByMention => RootPrefix::HyperCastsByMention as u8,
                RootPrefix::LinksByTarget => RootPrefix::HyperLinksByTarget as u8,
                RootPrefix::ReactionsByTarget => RootPrefix::HyperReactionsByTarget as u8,
                RootPrefix::VerificationByAddress => RootPrefix::HyperVerificationByAddress as u8,
                RootPrefix::UserNameProofByName => RootPrefix::HyperUserNameProofByName as u8,
                RootPrefix::LendStorageByRecipient => RootPrefix::HyperLendStorageByRecipient as u8,
                other => other as u8,
            }
        } else {
            prefix as u8
        }
    }
}

/// Capability advertised during peer handshakes to signal that
/// additional hyper envelopes may follow legacy block messages.
pub const CAPABILITY_HYPER: &str = "hyper:v1";

/// Configuration toggles for the hyper pipeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HyperConfig {
    pub enabled: bool,
    /// Optional retention hint for operators who want alerts when
    /// storage grows past a defined message count.
    pub retention_soft_cap: Option<u64>,
    /// Interval for emitting hyper metrics/diff comparisons.
    #[serde(with = "humantime_serde")]
    pub metrics_interval: Duration,
    /// Optional TOML path to a `HyperRuntimeFileConfig`. When present and
    /// `enabled`, the snapchain main binary builds a `HyperRuntime` from
    /// it, spawns the actor, and attaches it to the gossip layer.
    #[serde(default)]
    pub runtime_config_path: Option<String>,
}

impl Default for HyperConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            retention_soft_cap: None,
            metrics_interval: Duration::from_secs(60),
            runtime_config_path: None,
        }
    }
}

impl HyperConfig {
    pub fn can_start_pipeline(&self) -> bool {
        self.enabled
    }

    pub fn retention_soft_cap(&self) -> Option<u64> {
        self.retention_soft_cap
    }
}

/// Metadata describing the hyper block that mirrors a canonical block.
///
/// `hyper_state_root` holds the 48-byte compressed KZG commitment to the
/// verkle tree of all retained hyper-state at this block height. Verifiers
/// of bridge claims and inclusion proofs use this commitment as the root
/// against which verkle openings are checked.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HyperBlockMetadata {
    pub canonical_block_id: u64,
    pub parent_hash: Vec<u8>,
    pub hyper_state_root: Vec<u8>,
    pub extra_rules_version: u32,
    pub retained_message_count: u64,
    /// FIP §5.1 missed-proposal entries to credit on import.
    #[serde(default)]
    pub missed_proposals: Vec<MissedProposal>,
    /// Snapchain anchor block number this hyper block is anchored to.
    /// END (inclusive) of the snapchain block range this hyper block
    /// covers. The first hyper block (`canonical_id == 0`) anchors to
    /// the protocol-defined cutover block.
    #[serde(default)]
    pub snapchain_anchor_block: u64,
    /// 32-byte snapchain block hash for the anchor block.
    #[serde(default)]
    pub snapchain_anchor_hash: Vec<u8>,
    /// FIRST snapchain block (inclusive) covered by this hyper block.
    /// For hyperblock 0 this equals the cutover block; for subsequent
    /// hyperblocks this equals the previous hyperblock's
    /// `snapchain_anchor_block + 1`. Empty range (start == 0 and end ==
    /// 0) is permitted only for cutover/genesis fixtures.
    #[serde(default)]
    pub snapchain_range_start_block: u64,
    /// SHA-256 Merkle root over canonical-ordered snapchain block
    /// hashes in `[range_start_block, anchor_block]` (inclusive). Empty
    /// vec when the range is empty (e.g. genesis fixture).
    #[serde(default)]
    pub snapchain_range_root: Vec<u8>,
    /// Unix timestamp (seconds) of the snapchain anchor block. The
    /// proposer reads this from snapchain's block events and commits
    /// it via `signing_payload`, so importers + the scoring auto-
    /// trigger have a byte-deterministic `now_unix` to feed into
    /// `evaluate_epoch`.
    #[serde(default)]
    pub snapchain_anchor_timestamp: u64,
}

/// Records a validator who was selected as proposer for an earlier
/// round at this canonical_block_id but timed out.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MissedProposal {
    pub validator_key: Vec<u8>,
    pub round: i64,
}

impl HyperBlockMetadata {
    /// Encode a verkle root commitment as a 48-byte compressed G1 point and
    /// return it in the form expected by `hyper_state_root`.
    pub fn encode_state_root(commitment: &hypersnap_crypto::kzg::KzgCommitment) -> Vec<u8> {
        commitment.to_bytes().to_vec()
    }

    /// Decode `hyper_state_root` as a verkle root commitment. Returns `None`
    /// if the bytes are not a valid 48-byte compressed G1 point — older blocks
    /// using a different state-root scheme produce `None` here.
    pub fn decode_state_root(&self) -> Option<hypersnap_crypto::kzg::KzgCommitment> {
        hypersnap_crypto::kzg::KzgCommitment::from_bytes(&self.hyper_state_root)
    }
}

/// Envelope that is only shared with peers that advertise
/// [`CAPABILITY_HYPER`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HyperEnvelope {
    pub metadata: HyperBlockMetadata,
    /// Hyper-only payload that may include new message types or
    /// rule-specific annotations.
    pub payload: Vec<u8>,
}

/// DKLS23 threshold ECDSA signature attached to a hyperblock by the
/// active validator set of `epoch`. Verifiers look up `group_address`
/// for `epoch` from the runtime registry and confirm the recovered
/// signer of `ecdsa_signature` over
/// [`HyperBlockMetadata::signing_payload`] matches.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HyperBlockSignature {
    pub epoch: u64,
    /// 1-based committee party indices that participated in the
    /// signing ceremony. Length is exactly the DKG threshold (DKLS23
    /// requires an exact-threshold signing committee).
    pub signer_indices: Vec<u64>,
    /// 20-byte secp256k1 address derived from the DKLS23 group
    /// public key for `epoch`.
    pub group_address: Vec<u8>,
    /// 65-byte ECDSA `(r ‖ s ‖ v)` from the DKLS23 threshold
    /// signing ceremony.
    pub ecdsa_signature: Vec<u8>,
}

/// A hyperblock paired with its threshold signature. This is what gets
/// gossiped on the `hyper` topic and persisted as a [`proto::DecidedValue`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HyperBlock {
    pub envelope: HyperEnvelope,
    pub signature: HyperBlockSignature,
}

impl HyperBlockMetadata {
    /// Canonical byte sequence threshold-signed by the validator set.
    /// Domain-separated so the signature cannot collide with anything else
    /// signed under the same group key. Commits to: epoch, block height,
    /// parent hash, hyper state root, missed-proposal entries, and the
    /// snapchain anchor (block number + hash).
    pub fn signing_payload(&self, epoch: u64) -> Vec<u8> {
        const DST: &[u8] = b"hypersnap-hyperblock-v1:";
        let mut buf = Vec::new();
        buf.extend_from_slice(DST);
        buf.extend_from_slice(&epoch.to_be_bytes());
        buf.extend_from_slice(&self.canonical_block_id.to_be_bytes());
        buf.extend_from_slice(&(self.parent_hash.len() as u32).to_be_bytes());
        buf.extend_from_slice(&self.parent_hash);
        buf.extend_from_slice(&(self.hyper_state_root.len() as u32).to_be_bytes());
        buf.extend_from_slice(&self.hyper_state_root);
        // Missed-proposal commitment: u32 count, then for each entry
        // u32 key_len, key_bytes, i64 round (BE).
        buf.extend_from_slice(&(self.missed_proposals.len() as u32).to_be_bytes());
        for mp in &self.missed_proposals {
            buf.extend_from_slice(&(mp.validator_key.len() as u32).to_be_bytes());
            buf.extend_from_slice(&mp.validator_key);
            buf.extend_from_slice(&mp.round.to_be_bytes());
        }
        // Snapchain anchor commitment (END of the range).
        buf.extend_from_slice(&self.snapchain_anchor_block.to_be_bytes());
        buf.extend_from_slice(&(self.snapchain_anchor_hash.len() as u32).to_be_bytes());
        buf.extend_from_slice(&self.snapchain_anchor_hash);
        // Snapchain range commitment: range start + Merkle root over
        // every snapchain block hash in [start, end].
        buf.extend_from_slice(&self.snapchain_range_start_block.to_be_bytes());
        buf.extend_from_slice(&(self.snapchain_range_root.len() as u32).to_be_bytes());
        buf.extend_from_slice(&self.snapchain_range_root);
        // Anchor block timestamp — committed so importers and the
        // scoring auto-trigger see a byte-deterministic `now_unix`.
        buf.extend_from_slice(&self.snapchain_anchor_timestamp.to_be_bytes());
        buf
    }
}

/// SHA-256-based binary Merkle root over an ordered list of leaf hashes.
/// Domain-separated leaf and inner-node hashing prevent second-preimage
/// attacks. Empty input → empty vec (callers treat this as "no range
/// commitment", e.g. genesis fixtures).
///
/// Construction: leaves are hashed once (with leaf domain), then pairs
/// are concatenated and hashed (with inner domain) until a single root
/// remains. Odd levels duplicate the last hash to pair, matching
/// Bitcoin-style Merkle. Determinism is guaranteed by ascending input
/// order — callers pass snapchain block hashes sorted by block number.
pub fn snapchain_range_merkle_root(leaves: &[Vec<u8>]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    const LEAF_DST: &[u8] = b"hypersnap-snapchain-range-leaf:";
    const NODE_DST: &[u8] = b"hypersnap-snapchain-range-node:";

    if leaves.is_empty() {
        return Vec::new();
    }

    let mut current: Vec<[u8; 32]> = leaves
        .iter()
        .map(|leaf| {
            let mut h = Sha256::new();
            h.update(LEAF_DST);
            h.update(leaf);
            h.finalize().into()
        })
        .collect();

    while current.len() > 1 {
        let mut next = Vec::with_capacity((current.len() + 1) / 2);
        let mut i = 0;
        while i < current.len() {
            let left = current[i];
            let right = if i + 1 < current.len() {
                current[i + 1]
            } else {
                left
            };
            let mut h = Sha256::new();
            h.update(NODE_DST);
            h.update(left);
            h.update(right);
            next.push(h.finalize().into());
            i += 2;
        }
        current = next;
    }
    current[0].to_vec()
}

/// Summary emitted by diff tooling when comparing legacy and hyper
/// stores for a particular block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HyperDiffReport {
    pub block_id: u64,
    pub legacy_state_root: Option<Vec<u8>>,
    pub hyper_state_root: Vec<u8>,
    pub retained_message_delta: i64,
    pub notes: Vec<String>,
}

impl HyperDiffReport {
    pub fn diverged(&self) -> bool {
        self.legacy_state_root
            .as_ref()
            .map(|legacy| legacy != &self.hyper_state_root)
            .unwrap_or(false)
            || self.retained_message_delta != 0
    }
}

impl From<HyperBlockMetadata> for proto::HyperBlockMetadata {
    fn from(value: HyperBlockMetadata) -> Self {
        proto::HyperBlockMetadata {
            canonical_block_id: value.canonical_block_id,
            parent_hash: value.parent_hash,
            hyper_state_root: value.hyper_state_root,
            extra_rules_version: value.extra_rules_version,
            retained_message_count: value.retained_message_count,
            missed_proposals: value
                .missed_proposals
                .into_iter()
                .map(|mp| proto::MissedProposal {
                    validator_key: mp.validator_key,
                    round: mp.round,
                })
                .collect(),
            snapchain_anchor_block: value.snapchain_anchor_block,
            snapchain_anchor_hash: value.snapchain_anchor_hash,
            snapchain_range_start_block: value.snapchain_range_start_block,
            snapchain_range_root: value.snapchain_range_root,
            snapchain_anchor_timestamp: value.snapchain_anchor_timestamp,
        }
    }
}

impl From<proto::HyperBlockMetadata> for HyperBlockMetadata {
    fn from(value: proto::HyperBlockMetadata) -> Self {
        HyperBlockMetadata {
            canonical_block_id: value.canonical_block_id,
            parent_hash: value.parent_hash,
            hyper_state_root: value.hyper_state_root,
            extra_rules_version: value.extra_rules_version,
            retained_message_count: value.retained_message_count,
            missed_proposals: value
                .missed_proposals
                .into_iter()
                .map(|mp| MissedProposal {
                    validator_key: mp.validator_key,
                    round: mp.round,
                })
                .collect(),
            snapchain_anchor_block: value.snapchain_anchor_block,
            snapchain_anchor_hash: value.snapchain_anchor_hash,
            snapchain_range_start_block: value.snapchain_range_start_block,
            snapchain_range_root: value.snapchain_range_root,
            snapchain_anchor_timestamp: value.snapchain_anchor_timestamp,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_context_helpers() {
        assert_eq!(StateContext::Legacy.namespace_prefix(), b"legacy");
        assert!(StateContext::Legacy.allows_pruning());
        assert!(!StateContext::Legacy.is_hyper());

        assert_eq!(StateContext::Hyper.namespace_prefix(), b"hyper");
        assert!(!StateContext::Hyper.allows_pruning());
        assert!(StateContext::Hyper.is_hyper());
    }

    #[test]
    fn hyper_config_defaults_and_accessors() {
        let cfg = HyperConfig::default();
        assert!(!cfg.can_start_pipeline());
        assert_eq!(cfg.retention_soft_cap(), None);

        let cfg = HyperConfig {
            enabled: true,
            retention_soft_cap: Some(42),
            metrics_interval: Duration::from_secs(10),
            runtime_config_path: None,
        };
        assert!(cfg.can_start_pipeline());
        assert_eq!(cfg.retention_soft_cap(), Some(42));
        assert_eq!(cfg.metrics_interval, Duration::from_secs(10));
    }

    #[test]
    fn hyper_envelope_round_trips_to_proto() {
        let metadata = HyperBlockMetadata {
            canonical_block_id: 99,
            parent_hash: vec![0xaa, 0xbb],
            hyper_state_root: vec![0x01, 0x02],
            extra_rules_version: 3,
            retained_message_count: 7,
            missed_proposals: vec![],
            snapchain_anchor_block: 0,
            snapchain_anchor_hash: vec![],
            snapchain_range_start_block: 0,
            snapchain_range_root: vec![],
            snapchain_anchor_timestamp: 0,
        };
        let envelope = HyperEnvelope {
            metadata: metadata.clone(),
            payload: vec![0x10, 0x20, 0x30],
        };

        let proto_envelope: proto::HyperEnvelope = envelope.clone().into();
        assert_eq!(proto_envelope.payload, envelope.payload);
        assert_eq!(
            proto_envelope.metadata.as_ref().unwrap().canonical_block_id,
            metadata.canonical_block_id
        );
        assert_eq!(
            proto_envelope
                .metadata
                .as_ref()
                .unwrap()
                .retained_message_count,
            metadata.retained_message_count
        );
    }

    #[test]
    fn hyper_block_round_trips_to_proto() {
        let metadata = HyperBlockMetadata {
            canonical_block_id: 12345,
            parent_hash: vec![0xff; 32],
            hyper_state_root: vec![0xaa; 48],
            extra_rules_version: 1,
            retained_message_count: 42,
            missed_proposals: vec![],
            snapchain_anchor_block: 0,
            snapchain_anchor_hash: vec![],
            snapchain_range_start_block: 0,
            snapchain_range_root: vec![],
            snapchain_anchor_timestamp: 0,
        };
        let envelope = HyperEnvelope {
            metadata,
            payload: vec![],
        };
        let signature = HyperBlockSignature {
            epoch: 7,
            signer_indices: vec![1, 2, 3],
            group_address: vec![0xee; 20],
            ecdsa_signature: vec![0xff; 65],
        };
        let block = HyperBlock {
            envelope: envelope.clone(),
            signature: signature.clone(),
        };

        let proto_block: proto::HyperBlock = block.into();
        let proto_sig = proto_block.signature.as_ref().unwrap();
        assert_eq!(proto_sig.epoch, signature.epoch);
        assert_eq!(proto_sig.signer_indices, signature.signer_indices);
        assert_eq!(proto_sig.group_address, signature.group_address);
        assert_eq!(proto_sig.ecdsa_signature, signature.ecdsa_signature);

        let proto_env = proto_block.envelope.as_ref().unwrap();
        assert_eq!(
            proto_env.metadata.as_ref().unwrap().canonical_block_id,
            envelope.metadata.canonical_block_id
        );
    }

    #[test]
    fn state_root_round_trip_from_verkle_tree() {
        use hypersnap_crypto::kzg::KzgSrs;
        use hypersnap_crypto::kzg_lagrange::VERKLE_DOMAIN;
        use hypersnap_crypto::verkle::VerkleTree;
        use rand::rngs::OsRng;
        use std::sync::Arc;

        let mut rng = OsRng;
        let srs = Arc::new(KzgSrs::random_unsafe(&mut rng, VERKLE_DOMAIN));
        let mut tree = VerkleTree::new(srs);
        tree.insert(b"alice", b"100".to_vec());
        tree.insert(b"bobby", b"200".to_vec());
        let commitment = tree.root_commitment().unwrap();

        let encoded = HyperBlockMetadata::encode_state_root(&commitment);
        assert_eq!(encoded.len(), 48);

        let metadata = HyperBlockMetadata {
            canonical_block_id: 7,
            parent_hash: vec![0u8; 32],
            hyper_state_root: encoded,
            extra_rules_version: 0,
            retained_message_count: 2,
            missed_proposals: vec![],
            snapchain_anchor_block: 0,
            snapchain_anchor_hash: vec![],
            snapchain_range_start_block: 0,
            snapchain_range_root: vec![],
            snapchain_anchor_timestamp: 0,
        };
        let decoded = metadata.decode_state_root().expect("must decode");
        assert_eq!(decoded, commitment);
    }

    #[test]
    fn decode_state_root_returns_none_for_invalid_bytes() {
        let metadata = HyperBlockMetadata {
            canonical_block_id: 0,
            parent_hash: vec![],
            hyper_state_root: vec![0xff; 16], // wrong length
            extra_rules_version: 0,
            retained_message_count: 0,
            missed_proposals: vec![],
            snapchain_anchor_block: 0,
            snapchain_anchor_hash: vec![],
            snapchain_range_start_block: 0,
            snapchain_range_root: vec![],
            snapchain_anchor_timestamp: 0,
        };
        assert!(metadata.decode_state_root().is_none());

        let metadata2 = HyperBlockMetadata {
            canonical_block_id: 0,
            parent_hash: vec![],
            hyper_state_root: vec![0xff; 48], // right length, invalid point
            extra_rules_version: 0,
            retained_message_count: 0,
            missed_proposals: vec![],
            snapchain_anchor_block: 0,
            snapchain_anchor_hash: vec![],
            snapchain_range_start_block: 0,
            snapchain_range_root: vec![],
            snapchain_anchor_timestamp: 0,
        };
        assert!(metadata2.decode_state_root().is_none());
    }

    #[test]
    fn signing_payload_is_deterministic() {
        let metadata = HyperBlockMetadata {
            canonical_block_id: 100,
            parent_hash: vec![0x01, 0x02, 0x03],
            hyper_state_root: vec![0xaa, 0xbb, 0xcc],
            extra_rules_version: 0,
            retained_message_count: 0,
            missed_proposals: vec![],
            snapchain_anchor_block: 0,
            snapchain_anchor_hash: vec![],
            snapchain_range_start_block: 0,
            snapchain_range_root: vec![],
            snapchain_anchor_timestamp: 0,
        };
        let p1 = metadata.signing_payload(5);
        let p2 = metadata.signing_payload(5);
        assert_eq!(p1, p2);

        // Different epoch must produce different bytes.
        let p3 = metadata.signing_payload(6);
        assert_ne!(p1, p3);

        // Different state root must produce different bytes.
        let mut metadata2 = metadata.clone();
        metadata2.hyper_state_root = vec![0xaa, 0xbb, 0xcd];
        let p4 = metadata2.signing_payload(5);
        assert_ne!(p1, p4);
    }

    #[test]
    fn snapchain_range_merkle_root_is_deterministic_and_input_sensitive() {
        let leaves: Vec<Vec<u8>> = (0u8..5).map(|i| vec![i; 32]).collect();
        let r1 = snapchain_range_merkle_root(&leaves);
        let r2 = snapchain_range_merkle_root(&leaves);
        assert_eq!(r1, r2);
        assert_eq!(r1.len(), 32);

        // Single-leaf range works (degenerate Merkle tree of height 0).
        let single = vec![vec![0xaa; 32]];
        let r_single = snapchain_range_merkle_root(&single);
        assert_eq!(r_single.len(), 32);
        assert_ne!(r_single, r1);

        // Empty range produces empty output.
        let empty: Vec<Vec<u8>> = Vec::new();
        assert!(snapchain_range_merkle_root(&empty).is_empty());

        // Reordering changes the root (canonical input order matters).
        let mut reordered = leaves.clone();
        reordered.swap(0, 4);
        let r_reordered = snapchain_range_merkle_root(&reordered);
        assert_ne!(r1, r_reordered);

        // Odd-leaf count works (last leaf duplicates to form a pair).
        let odd_leaves: Vec<Vec<u8>> = (0u8..3).map(|i| vec![i; 32]).collect();
        let r_odd = snapchain_range_merkle_root(&odd_leaves);
        assert_eq!(r_odd.len(), 32);
    }

    #[test]
    fn signing_payload_commits_to_snapchain_range() {
        // Verify that the Merkle root is actually mixed into the
        // signing payload — a fork that produces a different range
        // root must surface as a different signing payload.
        let mut m = HyperBlockMetadata {
            canonical_block_id: 1,
            parent_hash: vec![0u8; 32],
            hyper_state_root: vec![0u8; 48],
            extra_rules_version: 0,
            retained_message_count: 0,
            missed_proposals: vec![],
            snapchain_anchor_block: 100,
            snapchain_anchor_hash: vec![0xaa; 32],
            snapchain_range_start_block: 91,
            snapchain_range_root: snapchain_range_merkle_root(
                &(0u8..10).map(|i| vec![i; 32]).collect::<Vec<_>>(),
            ),
            snapchain_anchor_timestamp: 1_700_000_000,
        };
        let baseline = m.signing_payload(0);

        // Same range, different start block → different payload.
        let mut m_b = m.clone();
        m_b.snapchain_range_start_block = 90;
        assert_ne!(baseline, m_b.signing_payload(0));

        // Tampered range root → different payload.
        let mut m_root = m.clone();
        m_root.snapchain_range_root = vec![0xff; 32];
        assert_ne!(baseline, m_root.signing_payload(0));

        // Tampered anchor timestamp → different payload.
        let mut m_ts = m.clone();
        m_ts.snapchain_anchor_timestamp = m.snapchain_anchor_timestamp.wrapping_add(1);
        assert_ne!(baseline, m_ts.signing_payload(0));
    }
}

impl From<HyperEnvelope> for proto::HyperEnvelope {
    fn from(value: HyperEnvelope) -> Self {
        proto::HyperEnvelope {
            metadata: Some(value.metadata.into()),
            payload: value.payload,
        }
    }
}

impl From<HyperBlockSignature> for proto::HyperBlockSignature {
    fn from(value: HyperBlockSignature) -> Self {
        proto::HyperBlockSignature {
            epoch: value.epoch,
            signer_indices: value.signer_indices,
            group_address: value.group_address,
            ecdsa_signature: value.ecdsa_signature,
        }
    }
}

impl From<proto::HyperBlockSignature> for HyperBlockSignature {
    fn from(value: proto::HyperBlockSignature) -> Self {
        HyperBlockSignature {
            epoch: value.epoch,
            signer_indices: value.signer_indices,
            group_address: value.group_address,
            ecdsa_signature: value.ecdsa_signature,
        }
    }
}

impl From<HyperBlock> for proto::HyperBlock {
    fn from(value: HyperBlock) -> Self {
        proto::HyperBlock {
            envelope: Some(value.envelope.into()),
            signature: Some(value.signature.into()),
        }
    }
}

pub fn build_envelope_for_block(block: &proto::Block, hyper_state_root: Vec<u8>) -> HyperEnvelope {
    let canonical_block_id = block
        .header
        .as_ref()
        .and_then(|header| header.height.clone())
        .map(|height| height.block_number)
        .unwrap_or_default();
    let parent_hash = block
        .header
        .as_ref()
        .map(|header| header.parent_hash.clone())
        .unwrap_or_default();

    HyperEnvelope {
        metadata: HyperBlockMetadata {
            canonical_block_id,
            parent_hash,
            hyper_state_root,
            extra_rules_version: 0,
            retained_message_count: block.transactions.len() as u64,
            missed_proposals: vec![],
            snapchain_anchor_block: 0,
            snapchain_anchor_hash: vec![],
            snapchain_range_start_block: 0,
            snapchain_range_root: vec![],
            snapchain_anchor_timestamp: 0,
        },
        payload: Vec::new(),
    }
}
