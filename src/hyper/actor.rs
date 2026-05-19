//! Tokio actor wrapping `HyperRuntime`.
//!
//! Single-threaded ownership of the runtime, multi-producer access via
//! channels. The actor is the integration seam between libp2p gossip and
//! the protocol surface: gossip handlers send `HyperActorEvent`s in,
//! the actor drains them, advances the runtime, and emits
//! `HyperActorOutbound`s for the gossip layer to broadcast.
//!
//! The actor is transport-agnostic. It does not know about libp2p — only
//! about decoded events. Wiring to gossip is done by a thin adapter (see
//! the network layer).

use crate::hyper::builder::BuilderError;
use crate::hyper::importer::ImportError;
use crate::hyper::router::RoutingError;
use crate::hyper::runtime::{HyperRuntime, RuntimeProduceError};
use crate::hyper::slashing::{
    detect_conflicting_blocks, verify_evidence_signatures, ConflictingBlocksEvidence, EvidenceError,
};
use crate::hyper::HyperBlock;
use crate::proto;
use crate::utils::statsd_wrapper::StatsdClientWrapper;
use rand::rngs::OsRng;
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot};

/// A request submitted to the actor.
///
/// All variants are advisory — the actor will log and continue on errors
/// rather than panicking, since gossip-driven input is untrusted.
pub enum HyperActorEvent {
    /// A hyper-layer message from gossip (lock event, transfer, validator
    /// registration). Routed via `HyperRuntime::submit_message`.
    InboundMessage(proto::HyperMessage),
    /// A hyper-layer message originated by this node (typically via
    /// HTTP). Routed locally AND emitted as `BroadcastMessage` so peers
    /// see it. Lock/transfer messages can use either path — they're
    /// re-broadcast for free at block production via the mempool.
    /// Validator events and reward issuances need this path because
    /// they don't go through a block.
    LocalSubmitMessage(proto::HyperMessage),
    /// A hyper block from gossip, with the locks/validator-events that
    /// produced its state. The actor calls `import_block` to validate +
    /// persist + update scores.
    InboundBlock {
        block: HyperBlock,
        locks: Vec<proto::HyperLockEvent>,
        transfers: Vec<proto::HyperTransferTx>,
    },
    /// Tick from the block-production scheduler — propose a block at this
    /// height with the given `parent_hash`. The actor signs and emits the
    /// resulting block on the outbound channel.
    ///
    /// `extra_rules_version` is forwarded to the envelope as-is; pass `0`
    /// unless a rule upgrade is in progress.
    ///
    /// The snapchain anchor fields commit the produced block to the
    /// snapchain head observed at production. `snapchain_anchor_hash`
    /// empty + `snapchain_anchor_block == 0` is the legacy/test path
    /// (treated as "no anchor commitment"). Production schedulers
    /// always populate all three.
    /// DKLS23 block production. The actor:
    ///  1. Builds an unsigned block via `produce_unsigned_block_dkls`,
    ///  2. Picks the signing committee via
    ///     `dkls_committee::select_signing_committee` keyed on
    ///     `(epoch, keccak256(signing_payload))`,
    ///  3. If this node is in the committee, spawns a
    ///     `DklsSignDriver`, stashes the unsigned block in
    ///     `pending_dkls_blocks`, and starts the ceremony.
    ///  4. On `AdvanceDklsSign` completion, the pending block is
    ///     fetched, the sig attached, the block imported locally,
    ///     and `BroadcastBlock` emitted.
    /// If this node is *not* in the committee, the event is a no-op
    /// — some peer that is in the committee will produce + sign +
    /// broadcast the block.
    ProduceBlockDkls {
        height: u64,
        parent_hash: Vec<u8>,
        extra_rules_version: u32,
        snapchain_anchor_block: u64,
        snapchain_anchor_hash: Vec<u8>,
        snapchain_anchor_timestamp: u64,
    },
    /// A DKLS23 ceremony message from gossip. The actor decodes the
    /// codec-wrapped `encoded` bytes using the local transport
    /// secret (decrypting P2P-addressed messages, accepting
    /// broadcast variants plaintext) before routing into the active
    /// driver.
    ///
    /// `encoded` includes the discriminator prefix from
    /// [`crate::hyper::dkls_wire_codec`]. If the message is sealed
    /// to a different party, the actor application-layer-filters
    /// it (`NotForUs`) without attempting decryption.
    InboundDkls { target_epoch: u64, encoded: Vec<u8> },
    /// Begin a DKLS23 ceremony. Driver carries the per-epoch
    /// parameters + this node's party index, assembled out-of-band by
    /// `dkls_supervisor`.
    StartDkls {
        driver: Box<crate::hyper::dkls_driver::DklsDriver>,
    },
    /// Drive the DKLS23 ceremony forward. Fired on a timer.
    AdvanceDkls,
    /// Inbound DKLS23 *signing* round message from gossip. Same
    /// codec-wrapped `encoded` shape as `InboundDkls`.
    InboundDklsSign { epoch: u64, encoded: Vec<u8> },
    /// Begin a DKLS23 signing ceremony. The actor takes ownership of
    /// the driver; subsequent `InboundDklsSign` and `AdvanceDklsSign`
    /// events feed it. On completion, the actor surfaces the
    /// finalized signature on the outbound channel and drops the
    /// driver.
    StartDklsSign {
        driver: Box<crate::hyper::dkls_sign_driver::DklsSignDriver>,
    },
    /// Drive the active signing ceremony forward.
    AdvanceDklsSign,
    /// Run the in-protocol Proof-of-Quality scoring pass for `epoch`.
    ///
    /// All inputs are derived deterministically from runtime state +
    /// protocol constants — payload carries only the epoch number and
    /// the snapchain anchor that scopes the read window. The actor
    /// builds a `PoqReader` over `runtime.db_handle()`, computes the
    /// FID universe via `runtime.fids_for_scoring()`, derives the seed
    /// set via `runtime.seeds_for_scoring(universe)`, and uses
    /// `runtime.scoring_params`. This guarantees every validator
    /// running the same code against the same on-disk state at the
    /// same anchor block produces byte-identical scoring output and
    /// therefore byte-identical threshold sigs.
    ///
    /// The actor threshold-signs each output via DKLS23, applies
    /// locally via `apply_reward_issuance` / `apply_trust_snapshot_update`,
    /// and broadcasts each as `BroadcastMessage`. Auto-fired from
    /// the block-import dispatch when an anchor crosses an epoch
    /// boundary; can also be sent directly for tests / manual triggers.
    /// 1-of-1 DKLS shares finalize all four signatures synchronously
    /// inside the dispatch handler; ≥2-of-N shares enqueue the
    /// unsigned messages and let the actor's sign queue drain over
    /// subsequent `AdvanceDklsSign` ticks.
    EvaluateEpochDkls {
        epoch: u64,
        anchor_block: u64,
        anchor_timestamp: u64,
    },
    /// Inbound slashing evidence — two purportedly-conflicting blocks at
    /// the same canonical_block_id. The actor re-runs
    /// `detect_conflicting_blocks` locally to confirm the conflict before
    /// surfacing it on the outbound channel as a `EvidenceConfirmed`
    /// signal. Persistence and epoch-boundary enforcement are the
    /// supervisor's responsibility (track via outbound).
    InboundEvidence {
        block_a: HyperBlock,
        block_b: HyperBlock,
    },
    /// Read-only state query. Reply is sent on the embedded oneshot.
    /// Variants are read-only because the actor remains the sole writer.
    Query(HyperActorQuery),
    /// Graceful shutdown.
    Shutdown,
}

/// Read-only queries the actor answers. Each variant carries a
/// `oneshot::Sender` for the reply; if the receiver is dropped, the
/// actor silently ignores the send-error.
///
/// These are the surface RPC/HTTP layers consume — they never touch the
/// runtime directly.
pub enum HyperActorQuery {
    LastBlockHeight {
        reply: oneshot::Sender<Option<u64>>,
    },
    LastBlockHash {
        reply: oneshot::Sender<Option<[u8; 32]>>,
    },
    CurrentEpoch {
        reply: oneshot::Sender<u64>,
    },
    /// Fetch a stored block by canonical id.
    GetBlockByHeight {
        height: u64,
        reply: oneshot::Sender<Option<proto::HyperBlock>>,
    },
    /// Fetch a stored block by hash.
    GetBlockByHash {
        hash: [u8; 32],
        reply: oneshot::Sender<Option<proto::HyperBlock>>,
    },
    /// Check whether a nullifier is present in the verkle tree.
    IsNullifierSpent {
        nullifier: [u8; 32],
        reply: oneshot::Sender<bool>,
    },
    /// Verkle inclusion proof for a spent nullifier. Result encoded
    /// as the hex of `bincode::serialize(&VerkleProof)` so the wire
    /// shape stays stable across crate-level type changes.
    NullifierInclusionProof {
        nullifier: [u8; 32],
        reply: oneshot::Sender<Result<Option<Vec<u8>>, String>>,
    },
    /// Verkle inclusion proof for a note commitment.
    NoteCommitmentInclusionProof {
        commitment: [u8; 56],
        reply: oneshot::Sender<Result<Option<Vec<u8>>, String>>,
    },
    /// Pending mempool size across types.
    PendingCount {
        reply: oneshot::Sender<usize>,
    },
    /// Wall-clock time the last block was imported, as Unix ms.
    LastImportedAtUnixMs {
        reply: oneshot::Sender<Option<u64>>,
    },
    /// Configured ScoreWeights — clients computing scores locally
    /// can match the runtime's policy.
    ScoreWeights {
        reply: oneshot::Sender<crate::hyper::validator_score::ScoreWeights>,
    },
    /// Validator score record at a given epoch. Returns the zero record
    /// (non-error) if the validator hasn't been touched yet — score
    /// tracker semantics.
    ValidatorScore {
        epoch: u64,
        validator_key: Vec<u8>,
        reply: oneshot::Sender<Result<proto::ValidatorScoreRecord, String>>,
    },
    /// Persisted slashing evidence for a given epoch.
    EvidenceForEpoch {
        epoch: u64,
        reply: oneshot::Sender<Result<Vec<proto::HyperWireEvidence>, String>>,
    },
    /// Active validator set at `epoch`. If `enforced`, applies
    /// auto-deregister + slashing eviction filters; otherwise returns
    /// the raw set (after registry events but no policy filters).
    ActiveValidators {
        epoch: u64,
        enforced: bool,
        reply: oneshot::Sender<
            Result<std::collections::BTreeMap<Vec<u8>, (Vec<u8>, Vec<u8>)>, String>,
        >,
    },
    /// Validators slashable at `epoch` — i.e. whose signer indices
    /// appear in any persisted evidence, mapped through the active set
    /// at that epoch (sourced from the runtime's bootstrap).
    SlashedValidators {
        epoch: u64,
        reply: oneshot::Sender<Result<std::collections::BTreeSet<Vec<u8>>, String>>,
    },
    /// Validator's registry event history up to `max_epoch`.
    ValidatorEvents {
        validator_key: Vec<u8>,
        max_epoch: u64,
        reply: oneshot::Sender<Result<Vec<proto::HyperValidatorEventBody>, String>>,
    },
    /// Per-FID reward balance.
    RewardBalance {
        fid: u64,
        reply: oneshot::Sender<Result<u64, String>>,
    },
    /// Per-FID transparent-transfer nonce (FIP §13.1). Zero for FIDs
    /// that have never transacted.
    TokenNonce {
        fid: u64,
        reply: oneshot::Sender<Result<u64, String>>,
    },
    /// Look up the persisted `TokenLockState` for a transparent
    /// token lock at `(fid, lock_id)` (FIP §13.5). Returns `None`
    /// if no such lock exists. The bridge merkle leaf is recomputed
    /// from the state via `hypersnap_crypto::bridge_payload::
    /// lock_leaf_evm`.
    TokenLockState {
        fid: u64,
        lock_id: Vec<u8>,
        reply: oneshot::Sender<Result<Option<crate::proto::TokenLockState>, String>>,
    },
    /// FIP §13.5: current canonical merkle root over all
    /// unclaimed transparent locks. The root the validator set
    /// threshold-signs and posts to `HypersnapBridge.claim`.
    LockMerkleRoot {
        reply: oneshot::Sender<Result<alloy_primitives::B256, String>>,
    },
    /// FIP §13.5: per-lock claim proof against the current
    /// canonical merkle tree. Returns `None` if `lock_id` isn't
    /// in the unclaimed set. The (leaf, proof, root) trio is what
    /// `MerkleProof.verifyCalldata` accepts on chain.
    LockMerkleProof {
        lock_id: Vec<u8>,
        reply: oneshot::Sender<
            Result<Option<(alloy_primitives::B256, Vec<alloy_primitives::B256>)>, String>,
        >,
    },
    /// FIP §13.5/§13.4: latest threshold-signed merkle-root update
    /// applied locally. `None` if no signed update has landed yet.
    LatestSignedLockMerkleRoot {
        reply: oneshot::Sender<Result<Option<crate::proto::HyperLockMerkleRootUpdate>, String>>,
    },
    /// FIP §13.5: latest bridge owner-rotation message applied
    /// locally. `None` if no rotation has landed yet.
    LatestOwnerRotation {
        reply: oneshot::Sender<Result<Option<crate::proto::HyperOwnerRotation>, String>>,
    },
    /// FIP §13.6: look up the historical record for a processed
    /// inbound burn. `None` if `(source_chain_id, burn_id)` hasn't
    /// been credited.
    InboundBurnRecord {
        source_chain_id: u32,
        burn_id: Vec<u8>,
        reply: oneshot::Sender<Result<Option<crate::proto::HyperInboundBurn>, String>>,
    },
    /// FIP §12: per-FID staked balances across all three
    /// categories. Returned as a struct so the HTTP surface can
    /// dump a single JSON object.
    StakedBreakdown {
        fid: u64,
        reply: oneshot::Sender<Result<StakedBreakdownReply, String>>,
    },
    /// FIP §12: all pending unstake-queue entries for an FID,
    /// regardless of maturation. UI surface for "pending unstakes
    /// (matures at epoch N)".
    UnstakeQueueForFid {
        fid: u64,
        reply: oneshot::Sender<Result<Vec<UnstakeQueueEntry>, String>>,
    },
    /// FIP §13.6: snapshot of the local `BridgeBurnStore`. Returns
    /// every observed burn that hasn't yet been pruned (i.e.
    /// pending or already-applied — the queue isn't auto-pruned
    /// in Phase 3c, only the processed-marker is checked at sign
    /// time). Diagnostic-quality.
    ObservedBurns {
        reply: oneshot::Sender<Result<Vec<crate::proto::HyperObservedBurn>, String>>,
    },
    /// Per-FID trust score (Phase B/D). `None` if no score is recorded.
    TrustScore {
        fid: u64,
        reply: oneshot::Sender<Result<Option<f64>, String>>,
    },
    /// Number of currently-active validator slots for `fid` per the
    /// per-FID secondary index (FIP §2.1, max 3).
    ValidatorCountForFid {
        fid: u64,
        reply: oneshot::Sender<Result<u32, String>>,
    },
    /// Highest epoch for which the in-protocol scoring auto-trigger
    /// has fired. `None` until the first epoch transition is observed.
    LastScoredEpoch {
        reply: oneshot::Sender<Option<u64>>,
    },
    /// Configured cutover snapchain block + whether the runtime has
    /// crossed it.
    CutoverStatus {
        reply: oneshot::Sender<CutoverStatusReply>,
    },
}

#[derive(Debug, Clone)]
pub struct CutoverStatusReply {
    pub configured_block: u64,
    pub is_post_cutover: bool,
    pub min_validator_trust_score: f64,
    pub protocol_chain_id: u64,
    pub seed_max_fid: u64,
}

/// FIP §12 stake breakdown: per-category staked balances.
///
/// Vouch stake is per-pair under the §12 Phase 5d design, so we
/// surface two views: `vouch_outgoing_atoms` (sum of all (this →
/// other) vouches — atoms this FID has locked vouching) and
/// `vouch_incoming_atoms` (sum of all (other → this) vouches —
/// reputational signal). `total_atoms` only includes outgoing,
/// since incoming is other FIDs' stake.
#[derive(Debug, Clone)]
pub struct StakedBreakdownReply {
    pub fid: u64,
    pub validator_atoms: u64,
    pub vouch_outgoing_atoms: u64,
    pub vouch_incoming_atoms: u64,
    pub credibility_atoms: u64,
}

/// FIP §12 unstake-queue entry view (read-only).
#[derive(Debug, Clone)]
pub struct UnstakeQueueEntry {
    pub maturation_epoch: u64,
    pub stake_type: i32,
    pub nonce: u64,
    pub amount: u64,
}

impl std::fmt::Debug for HyperActorQuery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LastBlockHeight { .. } => f.write_str("LastBlockHeight"),
            Self::LastBlockHash { .. } => f.write_str("LastBlockHash"),
            Self::CurrentEpoch { .. } => f.write_str("CurrentEpoch"),
            Self::GetBlockByHeight { height, .. } => f
                .debug_struct("GetBlockByHeight")
                .field("height", height)
                .finish(),
            Self::GetBlockByHash { hash, .. } => f
                .debug_struct("GetBlockByHash")
                .field("hash_prefix", &hex_prefix(hash))
                .finish(),
            Self::IsNullifierSpent { nullifier, .. } => f
                .debug_struct("IsNullifierSpent")
                .field("nullifier_prefix", &hex_prefix(nullifier))
                .finish(),
            Self::NullifierInclusionProof { nullifier, .. } => f
                .debug_struct("NullifierInclusionProof")
                .field("nullifier_prefix", &hex_prefix(nullifier))
                .finish(),
            Self::NoteCommitmentInclusionProof { commitment, .. } => f
                .debug_struct("NoteCommitmentInclusionProof")
                .field("commitment_prefix", &hex_prefix(commitment))
                .finish(),
            Self::PendingCount { .. } => f.write_str("PendingCount"),
            Self::LastImportedAtUnixMs { .. } => f.write_str("LastImportedAtUnixMs"),
            Self::ScoreWeights { .. } => f.write_str("ScoreWeights"),
            Self::ValidatorScore { epoch, .. } => f
                .debug_struct("ValidatorScore")
                .field("epoch", epoch)
                .finish(),
            Self::EvidenceForEpoch { epoch, .. } => f
                .debug_struct("EvidenceForEpoch")
                .field("epoch", epoch)
                .finish(),
            Self::ActiveValidators {
                epoch, enforced, ..
            } => f
                .debug_struct("ActiveValidators")
                .field("epoch", epoch)
                .field("enforced", enforced)
                .finish(),
            Self::SlashedValidators { epoch, .. } => f
                .debug_struct("SlashedValidators")
                .field("epoch", epoch)
                .finish(),
            Self::ValidatorEvents { max_epoch, .. } => f
                .debug_struct("ValidatorEvents")
                .field("max_epoch", max_epoch)
                .finish(),
            Self::RewardBalance { fid, .. } => {
                f.debug_struct("RewardBalance").field("fid", fid).finish()
            }
            Self::TokenNonce { fid, .. } => f.debug_struct("TokenNonce").field("fid", fid).finish(),
            Self::TokenLockState { fid, lock_id, .. } => f
                .debug_struct("TokenLockState")
                .field("fid", fid)
                .field("lock_id_hex", &hex::encode(lock_id))
                .finish(),
            Self::LockMerkleRoot { .. } => f.debug_struct("LockMerkleRoot").finish(),
            Self::LockMerkleProof { lock_id, .. } => f
                .debug_struct("LockMerkleProof")
                .field("lock_id_hex", &hex::encode(lock_id))
                .finish(),
            Self::LatestSignedLockMerkleRoot { .. } => {
                f.debug_struct("LatestSignedLockMerkleRoot").finish()
            }
            Self::LatestOwnerRotation { .. } => f.debug_struct("LatestOwnerRotation").finish(),
            Self::InboundBurnRecord {
                source_chain_id,
                burn_id,
                ..
            } => f
                .debug_struct("InboundBurnRecord")
                .field("source_chain_id", source_chain_id)
                .field("burn_id_hex", &hex::encode(burn_id))
                .finish(),
            Self::ObservedBurns { .. } => f.debug_struct("ObservedBurns").finish(),
            Self::StakedBreakdown { fid, .. } => {
                f.debug_struct("StakedBreakdown").field("fid", fid).finish()
            }
            Self::UnstakeQueueForFid { fid, .. } => f
                .debug_struct("UnstakeQueueForFid")
                .field("fid", fid)
                .finish(),
            Self::TrustScore { fid, .. } => f.debug_struct("TrustScore").field("fid", fid).finish(),
            Self::ValidatorCountForFid { fid, .. } => f
                .debug_struct("ValidatorCountForFid")
                .field("fid", fid)
                .finish(),
            Self::LastScoredEpoch { .. } => f.debug_struct("LastScoredEpoch").finish(),
            Self::CutoverStatus { .. } => f.debug_struct("CutoverStatus").finish(),
        }
    }
}

fn hex_prefix(bytes: &[u8]) -> String {
    let n = bytes.len().min(4);
    let mut s = String::with_capacity(n * 2);
    for b in &bytes[..n] {
        use std::fmt::Write as _;
        let _ = write!(s, "{:02x}", b);
    }
    s
}

impl std::fmt::Debug for HyperActorEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InboundMessage(_) => f.write_str("InboundMessage(..)"),
            Self::LocalSubmitMessage(_) => f.write_str("LocalSubmitMessage(..)"),
            Self::InboundBlock { block, .. } => f
                .debug_struct("InboundBlock")
                .field("height", &block.envelope.metadata.canonical_block_id)
                .finish(),
            Self::ProduceBlockDkls {
                height,
                snapchain_anchor_block,
                ..
            } => f
                .debug_struct("ProduceBlockDkls")
                .field("height", height)
                .field("snapchain_anchor_block", snapchain_anchor_block)
                .finish(),
            Self::InboundDkls { target_epoch, .. } => f
                .debug_struct("InboundDkls")
                .field("target_epoch", target_epoch)
                .finish(),
            Self::StartDkls { driver } => f
                .debug_struct("StartDkls")
                .field("target_epoch", &driver.target_epoch())
                .field("party_index", &driver.party_index())
                .finish(),
            Self::AdvanceDkls => f.write_str("AdvanceDkls"),
            Self::InboundDklsSign { epoch, .. } => f
                .debug_struct("InboundDklsSign")
                .field("epoch", epoch)
                .finish(),
            Self::StartDklsSign { driver } => f
                .debug_struct("StartDklsSign")
                .field("epoch", &driver.epoch())
                .field("party_index", &driver.party_index())
                .finish(),
            Self::AdvanceDklsSign => f.write_str("AdvanceDklsSign"),
            Self::EvaluateEpochDkls {
                epoch,
                anchor_block,
                anchor_timestamp,
            } => f
                .debug_struct("EvaluateEpochDkls")
                .field("epoch", epoch)
                .field("anchor_block", anchor_block)
                .field("anchor_timestamp", anchor_timestamp)
                .finish(),
            Self::InboundEvidence { block_a, block_b } => f
                .debug_struct("InboundEvidence")
                .field("height_a", &block_a.envelope.metadata.canonical_block_id)
                .field("height_b", &block_b.envelope.metadata.canonical_block_id)
                .finish(),
            Self::Query(q) => f.debug_tuple("Query").field(q).finish(),
            Self::Shutdown => f.write_str("Shutdown"),
        }
    }
}

/// Output emitted by the actor that the network layer should broadcast or
/// otherwise act on.
#[derive(Debug)]
pub enum HyperActorOutbound {
    /// A signed block ready for `TOPIC_HYPER_BLOCKS`.
    BroadcastBlock(HyperBlock),
    /// A locally-originated hyper message (lock/transfer/validator
    /// event/reward issuance) that should be gossiped on
    /// `TOPIC_HYPER_MESSAGES`. Emitted after a successful
    /// `LocalSubmitMessage`.
    BroadcastMessage(proto::HyperMessage),
    /// A DKLS23 ceremony round message ready for `TOPIC_HYPER_DKG`.
    /// Carries the target epoch so peers can route it to the right
    /// ceremony.
    ///
    /// `encoded` is the codec-wrapped wire payload (see
    /// [`crate::hyper::dkls_wire_codec`]): plaintext bincode for
    /// broadcast variants, transport-encrypted sealed-box for
    /// P2P variants. Receivers feed it through the codec to
    /// recover the typed message (or detect "not for me").
    BroadcastDkls { target_epoch: u64, encoded: Vec<u8> },
    /// A DKLS23 *signing* round message bound for the same gossip
    /// topic. `epoch` is the validator-set epoch the signing
    /// committee was drawn from; receivers route by epoch.
    ///
    /// `encoded` shape is the same as `BroadcastDkls.encoded`.
    BroadcastDklsSign { epoch: u64, encoded: Vec<u8> },
    /// A DKLS23 signing ceremony for `epoch` produced a finalized
    /// threshold ECDSA signature. The actor surfaces this so the
    /// caller (typically a block-producer or scoring driver) can
    /// attach the signature to the appropriate proto message and
    /// re-broadcast it.
    DklsSignFinalized {
        epoch: u64,
        digest: alloy_primitives::B256,
        signature: hypersnap_crypto::ecdsa::EcdsaSignature,
    },
    /// The DKG ceremony for `target_epoch` finalized; the actor has
    /// already installed the result into its runtime.
    DkgFinalized { target_epoch: u64 },
    /// Re-validated slashing evidence. The supervisor is expected to log,
    /// persist, and queue penalty enforcement at the next epoch boundary.
    EvidenceConfirmed(ConflictingBlocksEvidence),
    /// A non-fatal error processing an event. The network layer can decide
    /// whether to log, score the peer, or ignore.
    EventError(HyperActorError),
}

#[derive(thiserror::Error, Debug)]
pub enum HyperActorError {
    #[error("routing: {0}")]
    Routing(#[from] RoutingError),
    #[error("import: {0}")]
    Import(#[from] ImportError),
    #[error("produce: {0}")]
    Produce(#[from] RuntimeProduceError),
    #[error("builder: {0}")]
    Builder(#[from] BuilderError),
    #[error("dkls: {0}")]
    Dkls(#[from] crate::hyper::dkls_driver::DklsDriverError),
    #[error("dkls-sign: {0}")]
    DklsSign(#[from] crate::hyper::dkls_sign_driver::DklsSignDriverError),
    #[error("evidence: {0}")]
    Evidence(#[from] EvidenceError),
    #[error("no active DKG ceremony for epoch {0}")]
    NoActiveDkg(u64),
    #[error("scoring driver: {0}")]
    ScoringDriver(String),
    #[error("dkls wire codec: {0}")]
    DklsCodec(String),
}

/// Handles to talk to a running actor.
///
/// Cloning `inbound` is fine (mpsc Sender is multi-producer). The outbound
/// receiver is single-consumer — the network layer takes it once.
pub struct HyperActorHandles {
    pub inbound: mpsc::Sender<HyperActorEvent>,
    pub outbound: mpsc::Receiver<HyperActorOutbound>,
}

/// Read-only client view over a running actor. Cheaply cloneable. Hand
/// one of these to RPC/HTTP layers — they get state queries through the
/// same mpsc the gossip layer uses, so the actor remains the sole
/// runtime owner.
#[derive(Clone)]
pub struct HyperActorClient {
    inbound: mpsc::Sender<HyperActorEvent>,
}

#[derive(thiserror::Error, Debug)]
pub enum HyperActorClientError {
    #[error("actor inbound channel closed")]
    InboundClosed,
    #[error("actor dropped reply channel without responding")]
    ReplyDropped,
}

impl HyperActorClient {
    pub fn new(inbound: mpsc::Sender<HyperActorEvent>) -> Self {
        Self { inbound }
    }

    /// Raw access to the underlying inbound channel. The scheduler +
    /// DKG supervisor need this to fanout `ProduceBlockDkls` /
    /// `StartDkls` / `AdvanceDkls` events directly rather than going
    /// through the request-response `ask` API.
    pub fn inbound_sender(&self) -> &mpsc::Sender<HyperActorEvent> {
        &self.inbound
    }

    async fn ask<T: Send + 'static>(
        &self,
        build: impl FnOnce(oneshot::Sender<T>) -> HyperActorQuery,
    ) -> Result<T, HyperActorClientError> {
        let (tx, rx) = oneshot::channel();
        self.inbound
            .send(HyperActorEvent::Query(build(tx)))
            .await
            .map_err(|_| HyperActorClientError::InboundClosed)?;
        rx.await.map_err(|_| HyperActorClientError::ReplyDropped)
    }

    pub async fn last_block_height(&self) -> Result<Option<u64>, HyperActorClientError> {
        self.ask(|reply| HyperActorQuery::LastBlockHeight { reply })
            .await
    }

    pub async fn last_block_hash(&self) -> Result<Option<[u8; 32]>, HyperActorClientError> {
        self.ask(|reply| HyperActorQuery::LastBlockHash { reply })
            .await
    }

    pub async fn current_epoch(&self) -> Result<u64, HyperActorClientError> {
        self.ask(|reply| HyperActorQuery::CurrentEpoch { reply })
            .await
    }

    pub async fn get_block_by_height(
        &self,
        height: u64,
    ) -> Result<Option<proto::HyperBlock>, HyperActorClientError> {
        self.ask(move |reply| HyperActorQuery::GetBlockByHeight { height, reply })
            .await
    }

    pub async fn get_block_by_hash(
        &self,
        hash: [u8; 32],
    ) -> Result<Option<proto::HyperBlock>, HyperActorClientError> {
        self.ask(move |reply| HyperActorQuery::GetBlockByHash { hash, reply })
            .await
    }

    pub async fn is_nullifier_spent(
        &self,
        nullifier: [u8; 32],
    ) -> Result<bool, HyperActorClientError> {
        self.ask(move |reply| HyperActorQuery::IsNullifierSpent { nullifier, reply })
            .await
    }

    /// Bincode-serialized verkle inclusion proof; `Ok(None)` if the
    /// nullifier hasn't been recorded.
    pub async fn nullifier_inclusion_proof(
        &self,
        nullifier: [u8; 32],
    ) -> Result<Result<Option<Vec<u8>>, String>, HyperActorClientError> {
        self.ask(move |reply| HyperActorQuery::NullifierInclusionProof { nullifier, reply })
            .await
    }

    pub async fn note_commitment_inclusion_proof(
        &self,
        commitment: [u8; 56],
    ) -> Result<Result<Option<Vec<u8>>, String>, HyperActorClientError> {
        self.ask(move |reply| HyperActorQuery::NoteCommitmentInclusionProof { commitment, reply })
            .await
    }

    pub async fn pending_count(&self) -> Result<usize, HyperActorClientError> {
        self.ask(|reply| HyperActorQuery::PendingCount { reply })
            .await
    }

    pub async fn last_imported_at_unix_ms(&self) -> Result<Option<u64>, HyperActorClientError> {
        self.ask(|reply| HyperActorQuery::LastImportedAtUnixMs { reply })
            .await
    }

    pub async fn score_weights(
        &self,
    ) -> Result<crate::hyper::validator_score::ScoreWeights, HyperActorClientError> {
        self.ask(|reply| HyperActorQuery::ScoreWeights { reply })
            .await
    }

    pub async fn validator_score(
        &self,
        epoch: u64,
        validator_key: Vec<u8>,
    ) -> Result<Result<proto::ValidatorScoreRecord, String>, HyperActorClientError> {
        self.ask(move |reply| HyperActorQuery::ValidatorScore {
            epoch,
            validator_key,
            reply,
        })
        .await
    }

    pub async fn evidence_for_epoch(
        &self,
        epoch: u64,
    ) -> Result<Result<Vec<proto::HyperWireEvidence>, String>, HyperActorClientError> {
        self.ask(move |reply| HyperActorQuery::EvidenceForEpoch { epoch, reply })
            .await
    }

    pub async fn active_validators(
        &self,
        epoch: u64,
        enforced: bool,
    ) -> Result<
        Result<std::collections::BTreeMap<Vec<u8>, (Vec<u8>, Vec<u8>)>, String>,
        HyperActorClientError,
    > {
        self.ask(move |reply| HyperActorQuery::ActiveValidators {
            epoch,
            enforced,
            reply,
        })
        .await
    }

    pub async fn slashed_validators(
        &self,
        epoch: u64,
    ) -> Result<Result<std::collections::BTreeSet<Vec<u8>>, String>, HyperActorClientError> {
        self.ask(move |reply| HyperActorQuery::SlashedValidators { epoch, reply })
            .await
    }

    pub async fn validator_events(
        &self,
        validator_key: Vec<u8>,
        max_epoch: u64,
    ) -> Result<Result<Vec<proto::HyperValidatorEventBody>, String>, HyperActorClientError> {
        self.ask(move |reply| HyperActorQuery::ValidatorEvents {
            validator_key,
            max_epoch,
            reply,
        })
        .await
    }

    pub async fn reward_balance(
        &self,
        fid: u64,
    ) -> Result<Result<u64, String>, HyperActorClientError> {
        self.ask(move |reply| HyperActorQuery::RewardBalance { fid, reply })
            .await
    }

    pub async fn token_nonce(
        &self,
        fid: u64,
    ) -> Result<Result<u64, String>, HyperActorClientError> {
        self.ask(move |reply| HyperActorQuery::TokenNonce { fid, reply })
            .await
    }

    pub async fn token_lock_state(
        &self,
        fid: u64,
        lock_id: Vec<u8>,
    ) -> Result<Result<Option<crate::proto::TokenLockState>, String>, HyperActorClientError> {
        self.ask(move |reply| HyperActorQuery::TokenLockState {
            fid,
            lock_id,
            reply,
        })
        .await
    }

    pub async fn lock_merkle_root(
        &self,
    ) -> Result<Result<alloy_primitives::B256, String>, HyperActorClientError> {
        self.ask(|reply| HyperActorQuery::LockMerkleRoot { reply })
            .await
    }

    pub async fn lock_merkle_proof(
        &self,
        lock_id: Vec<u8>,
    ) -> Result<
        Result<Option<(alloy_primitives::B256, Vec<alloy_primitives::B256>)>, String>,
        HyperActorClientError,
    > {
        self.ask(move |reply| HyperActorQuery::LockMerkleProof { lock_id, reply })
            .await
    }

    pub async fn latest_signed_lock_merkle_root(
        &self,
    ) -> Result<
        Result<Option<crate::proto::HyperLockMerkleRootUpdate>, String>,
        HyperActorClientError,
    > {
        self.ask(|reply| HyperActorQuery::LatestSignedLockMerkleRoot { reply })
            .await
    }

    pub async fn latest_owner_rotation(
        &self,
    ) -> Result<Result<Option<crate::proto::HyperOwnerRotation>, String>, HyperActorClientError>
    {
        self.ask(|reply| HyperActorQuery::LatestOwnerRotation { reply })
            .await
    }

    pub async fn inbound_burn_record(
        &self,
        source_chain_id: u32,
        burn_id: Vec<u8>,
    ) -> Result<Result<Option<crate::proto::HyperInboundBurn>, String>, HyperActorClientError> {
        self.ask(move |reply| HyperActorQuery::InboundBurnRecord {
            source_chain_id,
            burn_id,
            reply,
        })
        .await
    }

    pub async fn observed_burns(
        &self,
    ) -> Result<Result<Vec<crate::proto::HyperObservedBurn>, String>, HyperActorClientError> {
        self.ask(|reply| HyperActorQuery::ObservedBurns { reply })
            .await
    }

    pub async fn staked_breakdown(
        &self,
        fid: u64,
    ) -> Result<Result<StakedBreakdownReply, String>, HyperActorClientError> {
        self.ask(move |reply| HyperActorQuery::StakedBreakdown { fid, reply })
            .await
    }

    pub async fn unstake_queue_for_fid(
        &self,
        fid: u64,
    ) -> Result<Result<Vec<UnstakeQueueEntry>, String>, HyperActorClientError> {
        self.ask(move |reply| HyperActorQuery::UnstakeQueueForFid { fid, reply })
            .await
    }

    pub async fn trust_score(
        &self,
        fid: u64,
    ) -> Result<Result<Option<f64>, String>, HyperActorClientError> {
        self.ask(move |reply| HyperActorQuery::TrustScore { fid, reply })
            .await
    }

    pub async fn validator_count_for_fid(
        &self,
        fid: u64,
    ) -> Result<Result<u32, String>, HyperActorClientError> {
        self.ask(move |reply| HyperActorQuery::ValidatorCountForFid { fid, reply })
            .await
    }

    pub async fn last_scored_epoch(&self) -> Result<Option<u64>, HyperActorClientError> {
        self.ask(|reply| HyperActorQuery::LastScoredEpoch { reply })
            .await
    }

    pub async fn cutover_status(&self) -> Result<CutoverStatusReply, HyperActorClientError> {
        self.ask(|reply| HyperActorQuery::CutoverStatus { reply })
            .await
    }
}

pub struct HyperActor {
    runtime: HyperRuntime,
    /// At most one DKLS23 DKG ceremony is in flight at a time.
    active_dkls: Option<ActiveDkls>,
    /// At most one DKLS23 signing ceremony at a time. Block
    /// production gates on prior completion. May relax to a small
    /// queue if signing rate becomes a bottleneck.
    active_dkls_sign: Option<crate::hyper::dkls_sign_driver::DklsSignDriver>,
    /// Unsigned blocks awaiting their DKLS23 signature. Keyed on
    /// the canonical signing-payload digest the ceremony is
    /// signing. On `AdvanceDklsSign` completion the actor consults
    /// this map; a hit drives "attach + import + broadcast".
    pending_dkls_blocks: std::collections::BTreeMap<alloy_primitives::B256, PendingDklsBlock>,
    /// Unsigned scoring-driver outputs (issuance or trust snapshot)
    /// awaiting their DKLS23 signature. Keyed on signing-payload
    /// digest. On `AdvanceDklsSign` completion the actor checks
    /// this map after the block map; a hit drives "attach + apply
    /// + broadcast as HyperMessage".
    pending_dkls_messages: std::collections::BTreeMap<alloy_primitives::B256, PendingDklsMessage>,
    /// FIFO queue of sign ceremonies waiting for `active_dkls_sign`
    /// to free up. Phase 5b multi-party scoring enqueues all four
    /// per-epoch outputs (3 issuances + 1 snapshot) here and pops
    /// one at a time. ProduceBlockDkls also uses this queue when a
    /// ceremony is already active.
    pending_sign_queue: std::collections::VecDeque<DklsSignTask>,
    inbound: mpsc::Receiver<HyperActorEvent>,
    outbound: mpsc::Sender<HyperActorOutbound>,
    statsd: Option<StatsdClientWrapper>,
    da_response_producer: Option<Arc<dyn crate::hyper::da_pow_driver::DaResponseProducer>>,
    last_da_responded_epoch: Option<u64>,
    last_da_seed_signed_for_epoch: Option<u64>,
    /// Bounded LRU of evidence frames already accepted this process
    /// lifetime, keyed on `(epoch, sorted block hashes)`. Short-
    /// circuits sig-verify on gossip replays.
    recent_evidence: std::collections::VecDeque<(u64, [u8; 32], [u8; 32])>,
}

const RECENT_EVIDENCE_CAP: usize = 256;

struct ActiveDkls {
    driver: crate::hyper::dkls_driver::DklsDriver,
}

struct PendingDklsBlock {
    block: HyperBlock,
    locks: Vec<proto::HyperLockEvent>,
    transfers: Vec<proto::HyperTransferTx>,
    /// 1-based committee party indices in canonical sorted order.
    /// Recorded so `attach_dkls_signature` can populate the
    /// `signer_indices` field.
    committee: Vec<u8>,
}

/// A scoring-driver output message awaiting its DKLS23 threshold
/// signature. Either an unsigned reward issuance, an unsigned
/// trust snapshot, or an unsigned lock-merkle-root update. Looked
/// up by the keccak256 digest of the canonical signing payload.
enum PendingDklsMessage {
    RewardIssuance(proto::HyperRewardIssuance),
    TrustSnapshot(proto::HyperTrustSnapshotUpdate),
    LockMerkleRoot(proto::HyperLockMerkleRootUpdate),
    InboundBurn(proto::HyperInboundBurn),
    DaEpochSeed(proto::DaEpochSeedBody),
}

/// A sign ceremony queued for execution. The actor processes one
/// at a time (because `active_dkls_sign` holds at most one driver);
/// when the active ceremony finalizes, the next task pops off the
/// queue and starts.
struct DklsSignTask {
    epoch: u64,
    digest: alloy_primitives::B256,
    /// Local DKLS share's `Party<Secp256k1>`. Cloned at enqueue
    /// time so a re-DKG between enqueue and start doesn't change
    /// what gets signed.
    party: hypersnap_crypto::dkls23::protocols::Party<hypersnap_crypto::k256::Secp256k1>,
    committee: Vec<u8>,
}

impl HyperActor {
    /// Spawn the actor as a tokio task. Returns the channel handles.
    ///
    /// `inbound_capacity` bounds the input queue — under back-pressure,
    /// gossip-layer senders will await capacity rather than dropping. Make
    /// it large enough to absorb gossip bursts but small enough to surface
    /// real congestion.
    pub fn spawn(runtime: HyperRuntime, inbound_capacity: usize) -> HyperActorHandles {
        Self::spawn_with_statsd(runtime, inbound_capacity, None)
    }

    /// Spawn variant that wires a statsd client into the actor for
    /// metrics emission.
    pub fn spawn_with_statsd(
        runtime: HyperRuntime,
        inbound_capacity: usize,
        statsd: Option<StatsdClientWrapper>,
    ) -> HyperActorHandles {
        Self::spawn_full(runtime, inbound_capacity, statsd, None)
    }

    /// Most-general spawn. Production wires `da_response_producer`
    /// here so the actor auto-emits DA-PoW challenge responses at
    /// every epoch boundary; legacy callers and tests pass `None`.
    pub fn spawn_full(
        runtime: HyperRuntime,
        inbound_capacity: usize,
        statsd: Option<StatsdClientWrapper>,
        da_response_producer: Option<Arc<dyn crate::hyper::da_pow_driver::DaResponseProducer>>,
    ) -> HyperActorHandles {
        let (in_tx, in_rx) = mpsc::channel(inbound_capacity);
        let (out_tx, out_rx) = mpsc::channel(inbound_capacity);
        let actor = HyperActor {
            runtime,
            active_dkls: None,
            active_dkls_sign: None,
            pending_dkls_blocks: std::collections::BTreeMap::new(),
            pending_dkls_messages: std::collections::BTreeMap::new(),
            pending_sign_queue: std::collections::VecDeque::new(),
            inbound: in_rx,
            outbound: out_tx,
            statsd,
            da_response_producer,
            last_da_responded_epoch: None,
            last_da_seed_signed_for_epoch: None,
            recent_evidence: std::collections::VecDeque::with_capacity(RECENT_EVIDENCE_CAP),
        };
        tokio::spawn(actor.run());
        HyperActorHandles {
            inbound: in_tx,
            outbound: out_rx,
        }
    }

    /// Drive the actor synchronously over a vector of events. Useful for
    /// testing and for embedding in a non-tokio harness.
    ///
    /// Returns the outbound items in order. Stops on `Shutdown` (which is
    /// appended automatically).
    pub async fn drive_events(
        runtime: HyperRuntime,
        events: Vec<HyperActorEvent>,
    ) -> Vec<HyperActorOutbound> {
        let cap = (events.len() + 1).max(4);
        let (in_tx, in_rx) = mpsc::channel(cap);
        let (out_tx, mut out_rx) = mpsc::channel(cap);
        let actor = HyperActor {
            runtime,
            active_dkls: None,
            active_dkls_sign: None,
            pending_dkls_blocks: std::collections::BTreeMap::new(),
            pending_dkls_messages: std::collections::BTreeMap::new(),
            pending_sign_queue: std::collections::VecDeque::new(),
            inbound: in_rx,
            outbound: out_tx,
            statsd: None,
            da_response_producer: None,
            last_da_responded_epoch: None,
            last_da_seed_signed_for_epoch: None,
            recent_evidence: std::collections::VecDeque::with_capacity(RECENT_EVIDENCE_CAP),
        };
        for ev in events {
            in_tx.send(ev).await.unwrap();
        }
        in_tx.send(HyperActorEvent::Shutdown).await.unwrap();
        drop(in_tx);
        actor.run().await;
        let mut out = Vec::new();
        while let Ok(item) = out_rx.try_recv() {
            out.push(item);
        }
        out
    }

    async fn run(mut self) {
        while let Some(event) = self.inbound.recv().await {
            if matches!(event, HyperActorEvent::Shutdown) {
                break;
            }
            self.handle_event(event).await;
        }
    }

    async fn handle_event(&mut self, event: HyperActorEvent) {
        let result = self.dispatch(event).await;
        if let Err(e) = result {
            // Errors are advisory — surface them to the network layer rather
            // than propagating, so a single bad gossip frame doesn't kill
            // the actor.
            let _ = self.outbound.send(HyperActorOutbound::EventError(e)).await;
        }
    }

    async fn dispatch(&mut self, event: HyperActorEvent) -> Result<(), HyperActorError> {
        match event {
            HyperActorEvent::InboundMessage(msg) => {
                self.observe_validator_event(&msg);
                self.observe_inbound_message_kind(&msg);
                let res = self.runtime.submit_message(msg);
                if let Err(e) = &res {
                    self.observe_routing_rejection(e);
                }
                res?;
                Ok(())
            }
            HyperActorEvent::LocalSubmitMessage(msg) => {
                // Process locally first so verification errors short-
                // circuit before we put broken messages on the wire.
                self.observe_validator_event(&msg);
                self.observe_inbound_message_kind(&msg);
                let res = self.runtime.submit_message(msg.clone());
                if let Err(e) = &res {
                    self.observe_routing_rejection(e);
                }
                res?;
                let _ = self
                    .outbound
                    .send(HyperActorOutbound::BroadcastMessage(msg))
                    .await;
                Ok(())
            }
            HyperActorEvent::InboundBlock {
                block,
                locks,
                transfers,
            } => {
                let anchor_block = block.envelope.metadata.snapchain_anchor_block;
                let anchor_ts = block.envelope.metadata.snapchain_anchor_timestamp;
                self.runtime.import_block(&block, &locks, &transfers)?;
                self.metric_count("hyper.blocks.imported", 1);
                self.maybe_trigger_scoring(anchor_block, anchor_ts).await;
                // Sign the seed before producing responses so the
                // batch picks up the new seed in the same block.
                self.maybe_sign_da_epoch_seed(anchor_block).await;
                self.maybe_trigger_da_responses(anchor_block).await;
                Ok(())
            }
            HyperActorEvent::ProduceBlockDkls {
                height,
                parent_hash,
                extra_rules_version,
                snapchain_anchor_block,
                snapchain_anchor_hash,
                snapchain_anchor_timestamp,
            } => {
                self.start_dkls_block_production(
                    height,
                    parent_hash,
                    extra_rules_version,
                    snapchain_anchor_block,
                    snapchain_anchor_hash,
                    snapchain_anchor_timestamp,
                )
                .await?;
                Ok(())
            }
            HyperActorEvent::EvaluateEpochDkls {
                epoch,
                anchor_block: _,
                anchor_timestamp,
            } => {
                if let Err(e) = self.runtime.apply_retro_vesting_tranche(epoch) {
                    tracing::warn!(epoch, error = %e, "retro vesting tranche failed");
                }

                let single_party = self
                    .runtime
                    .dkls_share_for_epoch(epoch)
                    .map(|s| {
                        s.party.parameters.threshold == 1 && s.party.parameters.share_count == 1
                    })
                    .unwrap_or(false);
                if single_party {
                    let output = self.run_scoring(epoch, anchor_timestamp)?;
                    self.apply_and_broadcast_scoring_output(output).await?;
                    if let Err(e) = self.refresh_signed_lock_merkle_root(epoch).await {
                        tracing::warn!(epoch, error = %e, "lock-root refresh failed");
                    }
                    if let Err(e) = self.refresh_inbound_burns(epoch).await {
                        tracing::warn!(epoch, error = %e, "inbound-burn refresh failed");
                    }
                    if let Err(e) = self.runtime.process_pending_custody_transfers() {
                        tracing::warn!(epoch, error = %e, "custody transfer processing failed");
                    }
                    if let Err(e) = self.runtime.process_unstake_queue(epoch) {
                        tracing::warn!(epoch, error = %e, "unstake queue drain failed");
                    }
                    return Ok(());
                }
                self.start_dkls_scoring_multi_party(epoch, anchor_timestamp)
                    .await?;
                self.start_dkls_lock_root_multi_party(epoch).await?;
                self.start_dkls_inbound_burns_multi_party(epoch).await?;
                if let Err(e) = self.runtime.process_pending_custody_transfers() {
                    tracing::warn!(epoch, error = %e, "custody transfer processing failed");
                }
                if let Err(e) = self.runtime.process_unstake_queue(epoch) {
                    tracing::warn!(epoch, error = %e, "unstake queue drain failed");
                }
                Ok(())
            }
            HyperActorEvent::InboundDkls {
                target_epoch,
                encoded,
            } => {
                let dkls = self
                    .active_dkls
                    .as_mut()
                    .filter(|d| d.driver.target_epoch() == target_epoch)
                    .ok_or(HyperActorError::NoActiveDkg(target_epoch))?;
                let local_party = dkls.driver.party_index();
                let opened = crate::hyper::dkls_wire_codec::open_dkls_round_message(
                    &encoded,
                    target_epoch,
                    &self.runtime.local_transport_secret,
                    local_party,
                )
                .map_err(|e| HyperActorError::DklsCodec(e.to_string()))?;
                use crate::hyper::dkls_wire_codec::OpenedDklsMessage;
                match opened {
                    OpenedDklsMessage::ForUs(message) | OpenedDklsMessage::Broadcast(message) => {
                        dkls.driver.submit(message)?;
                    }
                    OpenedDklsMessage::NotForUs { .. } => {
                        // Encrypted message sealed to a different
                        // party — skip silently. The intended
                        // receiver will pick it up off the same
                        // gossip topic with their own transport
                        // secret.
                    }
                }
                Ok(())
            }
            HyperActorEvent::StartDkls { driver } => {
                let mut driver = *driver;
                driver.start()?;
                self.flush_dkls_outbound(&mut driver).await;
                self.active_dkls = Some(ActiveDkls { driver });
                Ok(())
            }
            HyperActorEvent::AdvanceDkls => {
                let Some(mut active) = self.active_dkls.take() else {
                    return Ok(());
                };
                active.driver.try_advance()?;
                self.flush_dkls_outbound(&mut active.driver).await;
                if active.driver.is_completed() {
                    let target = active.driver.target_epoch();
                    active.driver.finalize_into_runtime(&mut self.runtime)?;
                    let _ = self
                        .outbound
                        .send(HyperActorOutbound::DkgFinalized {
                            target_epoch: target,
                        })
                        .await;
                } else {
                    self.active_dkls = Some(active);
                }
                Ok(())
            }
            HyperActorEvent::InboundDklsSign { epoch, encoded } => {
                let driver = self
                    .active_dkls_sign
                    .as_mut()
                    .filter(|d| d.epoch() == epoch)
                    .ok_or(HyperActorError::NoActiveDkg(epoch))?;
                let local_party = driver.party_index();
                let opened = crate::hyper::dkls_wire_codec::open_dkls_sign_round_message(
                    &encoded,
                    epoch,
                    &self.runtime.local_transport_secret,
                    local_party,
                )
                .map_err(|e| HyperActorError::DklsCodec(e.to_string()))?;
                use crate::hyper::dkls_wire_codec::OpenedDklsSignMessage;
                let message = match opened {
                    OpenedDklsSignMessage::ForUs(m) | OpenedDklsSignMessage::Broadcast(m) => m,
                    OpenedDklsSignMessage::NotForUs { .. } => return Ok(()),
                };
                driver.submit(message)?;
                Ok(())
            }
            HyperActorEvent::StartDklsSign { driver } => {
                let mut driver = *driver;
                driver.start()?;
                self.flush_dkls_sign_outbound(&mut driver).await;
                self.active_dkls_sign = Some(driver);
                Ok(())
            }
            HyperActorEvent::AdvanceDklsSign => {
                let Some(mut driver) = self.active_dkls_sign.take() else {
                    return Ok(());
                };
                driver.try_advance()?;
                self.flush_dkls_sign_outbound(&mut driver).await;
                if driver.is_completed() {
                    let signature = driver
                        .signature()
                        .expect("is_completed() ⇒ signature present")
                        .clone();
                    let digest = *driver.coordinator.digest();
                    let epoch = driver.epoch();
                    self.finalize_dkls_signature(epoch, digest, signature).await;
                } else {
                    self.active_dkls_sign = Some(driver);
                }
                Ok(())
            }
            HyperActorEvent::InboundEvidence { block_a, block_b } => {
                let evidence = detect_conflicting_blocks(&block_a, &block_b)?;
                let (lo, hi) = if evidence.block_a_hash <= evidence.block_b_hash {
                    (evidence.block_a_hash, evidence.block_b_hash)
                } else {
                    (evidence.block_b_hash, evidence.block_a_hash)
                };
                let dedupe_key = (evidence.epoch, lo, hi);
                if self.recent_evidence.contains(&dedupe_key) {
                    // Gossip replay — store + downstream readers
                    // already have this pair. Drop before sig-verify.
                    self.metric_count("hyper.evidence.dropped_replay", 1);
                    return Ok(());
                }
                // Authenticate both blocks under the conflict epoch's
                // group key before persisting. Without this, any peer
                // can submit two unsigned blocks naming arbitrary
                // `signer_indices` and slash arbitrary validators via
                // the next-epoch active-set filter.
                let group_address = self
                    .runtime
                    .dkls_group_address_for_epoch(evidence.epoch)
                    .ok_or(EvidenceError::UnknownEpochGroupKey {
                        epoch: evidence.epoch,
                    })?;
                verify_evidence_signatures(&evidence, &group_address)?;
                if let Err(e) = self.runtime.record_evidence(&evidence) {
                    tracing::warn!("failed to persist slashing evidence: {}", e);
                }
                if self.recent_evidence.len() >= RECENT_EVIDENCE_CAP {
                    self.recent_evidence.pop_front();
                }
                self.recent_evidence.push_back(dedupe_key);
                self.metric_count("hyper.evidence.confirmed", 1);
                let _ = self
                    .outbound
                    .send(HyperActorOutbound::EvidenceConfirmed(evidence))
                    .await;
                Ok(())
            }
            HyperActorEvent::Query(q) => {
                self.handle_query(q);
                Ok(())
            }
            HyperActorEvent::Shutdown => Ok(()),
        }
    }

    fn handle_query(&mut self, q: HyperActorQuery) {
        match q {
            HyperActorQuery::LastBlockHeight { reply } => {
                let _ = reply.send(self.runtime.last_block_height());
            }
            HyperActorQuery::LastBlockHash { reply } => {
                let _ = reply.send(self.runtime.last_block_hash());
            }
            HyperActorQuery::CurrentEpoch { reply } => {
                let _ = reply.send(self.runtime.current_epoch());
            }
            HyperActorQuery::GetBlockByHeight { height, reply } => {
                let r = self.runtime.get_block_by_height(height).ok().flatten();
                let _ = reply.send(r);
            }
            HyperActorQuery::GetBlockByHash { hash, reply } => {
                let r = self.runtime.get_block_by_hash(&hash).ok().flatten();
                let _ = reply.send(r);
            }
            HyperActorQuery::IsNullifierSpent { nullifier, reply } => {
                let _ = reply.send(self.runtime.is_nullifier_spent_in_tree(&nullifier));
            }
            HyperActorQuery::NullifierInclusionProof { nullifier, reply } => {
                let r = match self.runtime.prove_nullifier_inclusion(&nullifier) {
                    Ok(Some(p)) => Ok(Some(p.to_bytes())),
                    Ok(None) => Ok(None),
                    Err(e) => Err(format!("{}", e)),
                };
                let _ = reply.send(r);
            }
            HyperActorQuery::NoteCommitmentInclusionProof { commitment, reply } => {
                let r = match self.runtime.prove_note_commitment_inclusion(&commitment) {
                    Ok(Some(p)) => Ok(Some(p.to_bytes())),
                    Ok(None) => Ok(None),
                    Err(e) => Err(format!("{}", e)),
                };
                let _ = reply.send(r);
            }
            HyperActorQuery::PendingCount { reply } => {
                let _ = reply.send(self.runtime.pending_count());
            }
            HyperActorQuery::LastImportedAtUnixMs { reply } => {
                let _ = reply.send(self.runtime.last_imported_at_unix_ms());
            }
            HyperActorQuery::ScoreWeights { reply } => {
                let _ = reply.send(self.runtime.score_tracker.weights());
            }
            HyperActorQuery::ValidatorScore {
                epoch,
                validator_key,
                reply,
            } => {
                let r = self
                    .runtime
                    .get_validator_score(epoch, &validator_key)
                    .map_err(|e| e.to_string());
                let _ = reply.send(r);
            }
            HyperActorQuery::EvidenceForEpoch { epoch, reply } => {
                let r = self
                    .runtime
                    .evidence_for_epoch(epoch)
                    .map_err(|e| e.to_string());
                let _ = reply.send(r);
            }
            HyperActorQuery::ActiveValidators {
                epoch,
                enforced,
                reply,
            } => {
                let r = if enforced {
                    self.runtime
                        .active_validators_enforced(epoch)
                        .map_err(|e| e.to_string())
                } else {
                    self.runtime
                        .active_validators(epoch)
                        .map_err(|e| e.to_string())
                };
                let _ = reply.send(r);
            }
            HyperActorQuery::SlashedValidators { epoch, reply } => {
                let active = match self.runtime.active_validators(epoch) {
                    Ok(a) => a,
                    Err(e) => {
                        let _ = reply.send(Err(e.to_string()));
                        return;
                    }
                };
                let r = self
                    .runtime
                    .slashed_validators_for_epoch(epoch, &active)
                    .map_err(|e| e.to_string());
                let _ = reply.send(r);
            }
            HyperActorQuery::ValidatorEvents {
                validator_key,
                max_epoch,
                reply,
            } => {
                let r = self
                    .runtime
                    .validator_events(&validator_key, max_epoch)
                    .map_err(|e| e.to_string());
                let _ = reply.send(r);
            }
            HyperActorQuery::RewardBalance { fid, reply } => {
                let r = self
                    .runtime
                    .reward_store
                    .balance_of(fid)
                    .map_err(|e| e.to_string());
                let _ = reply.send(r);
            }
            HyperActorQuery::TokenNonce { fid, reply } => {
                let r = self
                    .runtime
                    .reward_store
                    .nonce_of(fid)
                    .map_err(|e| e.to_string());
                let _ = reply.send(r);
            }
            HyperActorQuery::TokenLockState {
                fid,
                lock_id,
                reply,
            } => {
                let r = self
                    .runtime
                    .reward_store
                    .lock_state(fid, &lock_id)
                    .map_err(|e| e.to_string());
                let _ = reply.send(r);
            }
            HyperActorQuery::LockMerkleRoot { reply } => {
                let r = self
                    .runtime
                    .build_lock_merkle_tree()
                    .map(|(t, _)| t.root)
                    .map_err(|e| e.to_string());
                let _ = reply.send(r);
            }
            HyperActorQuery::LockMerkleProof { lock_id, reply } => {
                let r = self
                    .runtime
                    .reward_store
                    .iter_all_locks()
                    .map_err(|e| e.to_string())
                    .map(|states| crate::hyper::lock_tree::build_proof_for(states, &lock_id));
                let _ = reply.send(r);
            }
            HyperActorQuery::LatestSignedLockMerkleRoot { reply } => {
                let r = self
                    .runtime
                    .latest_signed_lock_merkle_root()
                    .map_err(|e| e.to_string());
                let _ = reply.send(r);
            }
            HyperActorQuery::LatestOwnerRotation { reply } => {
                let r = self
                    .runtime
                    .latest_owner_rotation()
                    .map_err(|e| e.to_string());
                let _ = reply.send(r);
            }
            HyperActorQuery::InboundBurnRecord {
                source_chain_id,
                burn_id,
                reply,
            } => {
                let r = self
                    .runtime
                    .get_inbound_burn(source_chain_id, &burn_id)
                    .map_err(|e| e.to_string());
                let _ = reply.send(r);
            }
            HyperActorQuery::ObservedBurns { reply } => {
                let r = self
                    .runtime
                    .bridge_burn_store
                    .iter_all()
                    .map_err(|e| e.to_string());
                let _ = reply.send(r);
            }
            HyperActorQuery::StakedBreakdown { fid, reply } => {
                let r = (|| -> Result<StakedBreakdownReply, String> {
                    let validator_atoms = self
                        .runtime
                        .staked_of(fid, proto::StakeType::Validator as i32)
                        .map_err(|e| e.to_string())?;
                    let vouch_outgoing_atoms = self
                        .runtime
                        .total_vouch_outgoing(fid)
                        .map_err(|e| e.to_string())?;
                    let vouch_incoming_atoms = self
                        .runtime
                        .total_vouch_incoming(fid)
                        .map_err(|e| e.to_string())?;
                    let credibility_atoms = self
                        .runtime
                        .staked_of(fid, proto::StakeType::Credibility as i32)
                        .map_err(|e| e.to_string())?;
                    Ok(StakedBreakdownReply {
                        fid,
                        validator_atoms,
                        vouch_outgoing_atoms,
                        vouch_incoming_atoms,
                        credibility_atoms,
                    })
                })();
                let _ = reply.send(r);
            }
            HyperActorQuery::UnstakeQueueForFid { fid, reply } => {
                let r = self
                    .runtime
                    .unstake_queue_for_fid(fid)
                    .map(|entries| {
                        entries
                            .into_iter()
                            .map(|(maturation_epoch, stake_type, nonce, amount)| {
                                UnstakeQueueEntry {
                                    maturation_epoch,
                                    stake_type,
                                    nonce,
                                    amount,
                                }
                            })
                            .collect()
                    })
                    .map_err(|e| e.to_string());
                let _ = reply.send(r);
            }
            HyperActorQuery::TrustScore { fid, reply } => {
                let r = self.runtime.trust_store.get(fid).map_err(|e| e.to_string());
                let _ = reply.send(r);
            }
            HyperActorQuery::ValidatorCountForFid { fid, reply } => {
                let r = self
                    .runtime
                    .validator_registry
                    .count_active_validators_for_fid(fid)
                    .map_err(|e| e.to_string());
                let _ = reply.send(r);
            }
            HyperActorQuery::LastScoredEpoch { reply } => {
                let _ = reply.send(self.runtime.last_scored_epoch);
            }
            HyperActorQuery::CutoverStatus { reply } => {
                let _ = reply.send(CutoverStatusReply {
                    configured_block: self.runtime.cutover_snapchain_block,
                    is_post_cutover: self.runtime.is_post_cutover(),
                    min_validator_trust_score: self.runtime.min_validator_trust_score,
                    protocol_chain_id: crate::hyper::DEFAULT_PROTOCOL_CHAIN_ID,
                    seed_max_fid: self.runtime.seed_max_fid,
                });
            }
        }
    }

    fn metric_count(&self, key: &str, value: i64) {
        if let Some(c) = &self.statsd {
            c.count(key, value, vec![]);
        }
    }

    fn metric_gauge(&self, key: &str, value: u64) {
        if let Some(c) = &self.statsd {
            c.gauge(key, value, vec![]);
        }
    }

    fn metric_gauge_tagged(&self, key: &str, value: u64, tag_key: &str, tag_value: &str) {
        if let Some(c) = &self.statsd {
            c.gauge(key, value, vec![(tag_key, tag_value)]);
        }
    }

    fn metric_count_tagged(&self, key: &str, value: i64, tag_key: &str, tag_value: &str) {
        if let Some(c) = &self.statsd {
            c.count(key, value, vec![(tag_key, tag_value)]);
        }
    }

    /// Count validator-event attempts at the gossip-message boundary.
    /// Tagged by the inner `event_type` so register vs deregister is
    /// distinguishable.
    fn observe_validator_event(&self, msg: &proto::HyperMessage) {
        if let Some(proto::hyper_message::Body::ValidatorEvent(event)) = &msg.body {
            let event_type = event.event_type.to_string();
            self.metric_count_tagged(
                "hyper.validator.register_attempts",
                1,
                "event_type",
                &event_type,
            );
        }
    }

    /// Map registry-rejection reasons into their own counters so the
    /// supervisor can see at a glance whether rejections are coming
    /// from the per-FID cap, the trust gate, custody-sig mismatch, or
    /// pure structural validation. Anything that isn't a
    /// `RoutingError::Registry(...)` is ignored.
    fn observe_routing_rejection(&self, err: &RoutingError) {
        use crate::hyper::validator_registry::RegistryError;
        let reason = match err {
            RoutingError::Registry(re) => match re {
                RegistryError::PerFidQuotaExceeded { .. } => "quota_exceeded",
                RegistryError::TrustBelowFloor { .. } => "trust_below_floor",
                RegistryError::InvalidCustodySignature => "invalid_custody_sig",
                RegistryError::MissingCustodySignature => "missing_custody_sig",
                RegistryError::CustodyAddressUnknown { .. } => "custody_address_unknown",
                RegistryError::InvalidSignature => "invalid_validator_sig",
                RegistryError::MissingFid => "missing_fid",
                RegistryError::EpochMismatch { .. } => "epoch_mismatch",
                _ => "registry_other",
            },
            _ => return,
        };
        self.metric_count_tagged("hyper.validator.register_rejected", 1, "reason", reason);
    }

    fn observe_inbound_message_kind(&self, msg: &proto::HyperMessage) {
        use proto::hyper_message::Body;
        let kind = match &msg.body {
            Some(Body::Lock(_)) => "lock",
            Some(Body::Transfer(_)) => "transfer",
            Some(Body::ValidatorEvent(_)) => "validator_event",
            Some(Body::RewardIssuance(_)) => "reward_issuance",
            Some(Body::TrustSnapshotUpdate(_)) => "trust_snapshot_update",
            Some(Body::TokenTransfer(_)) => "token_transfer",
            Some(Body::TokenLock(_)) => "token_lock",
            Some(Body::LockMerkleRootUpdate(_)) => "lock_merkle_root_update",
            Some(Body::OwnerRotation(_)) => "owner_rotation",
            Some(Body::InboundBurn(_)) => "inbound_burn",
            Some(Body::TokenEscrowClaim(_)) => "token_escrow_claim",
            Some(Body::TokenEscrowBridge(_)) => "token_escrow_bridge",
            Some(Body::TokenStake(_)) => "token_stake",
            Some(Body::TokenUnstake(_)) => "token_unstake",
            Some(Body::NodeAttestation(_)) => "node_attestation",
            Some(Body::AppUsageReceipt(_)) => "app_usage_receipt",
            Some(Body::MiniappRegister(_)) => "miniapp_register",
            Some(Body::MiniappUnregister(_)) => "miniapp_unregister",
            Some(Body::MiniappUpdate(_)) => "miniapp_update",
            Some(Body::MiniappAdd(_)) => "miniapp_add",
            Some(Body::MiniappRemove(_)) => "miniapp_remove",
            Some(Body::DaChallengeResponse(_)) => "da_challenge_response",
            Some(Body::DaEpochSeed(_)) => "da_epoch_seed",
            Some(Body::FeeDeposit(_)) => "fee_deposit",
            None => "none",
        };
        self.metric_count_tagged("hyper.message.inbound", 1, "kind", kind);
    }

    /// Auto-trigger the in-protocol Proof-of-Quality scoring run when
    /// the imported block's snapchain anchor crosses an epoch boundary.
    ///
    /// Determinism: triggers on the FIRST hyperblock observed in
    /// `epoch_for(anchor_block)` — call this `current_epoch`. We score
    /// every epoch in `(last_scored, current)` (typically just one,
    /// but a long gap could span multiple). Each call to this method
    /// fires `EvaluateEpoch` events directly into the dispatch (in
    /// effect, recursive but bounded by the gap).
    ///
    /// The first block ever observed (no prior anchor) doesn't trigger
    /// scoring — there's no completed epoch to score. We just
    /// initialize `last_scored_epoch` to the current observed epoch.
    /// Run `evaluate_epoch` + DKLS23 1-of-1 inline signing.
    /// Multi-party shares enter via `start_dkls_scoring_multi_party`
    /// instead.
    fn run_scoring(
        &mut self,
        epoch: u64,
        anchor_timestamp: u64,
    ) -> Result<crate::hyper::scoring_driver::ScoringDriverOutput, HyperActorError> {
        let universe = self.runtime.fids_for_scoring();
        self.metric_gauge("hyper.scoring.fids_evaluated", universe.len() as u64);
        let seeds = self.runtime.seeds_for_scoring(&universe);
        // FIP §9: overlay per-epoch market budgets from the halving
        // curve. DA + App return 0 until those markets ship; Growth
        // gets its 20% slice of `emission_per_epoch(epoch)`.
        let mut params = self.runtime.scoring_params.clone();
        for &m in proof_of_quality::WorkMarket::ALL.iter() {
            let proto_market = crate::hyper::scoring_driver::poq_market_to_proto(m);
            params
                .market_budgets
                .insert(m, crate::emission::market_budget(epoch, proto_market));
        }
        let reader = crate::hyper::poq_reader::PoqReader::new(self.runtime.db_handle(), universe);
        let started = std::time::Instant::now();
        let output = crate::hyper::scoring_driver::run_epoch_dkls_local(
            &self.runtime,
            &reader,
            epoch,
            anchor_timestamp,
            &seeds,
            &params,
        )
        .map_err(|e| HyperActorError::ScoringDriver(e.to_string()))?;
        self.metric_gauge(
            "hyper.scoring.duration_ms",
            started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64,
        );
        Ok(output)
    }

    /// Apply each issuance + the trust snapshot to the local
    /// runtime, then broadcast each as a `HyperMessage`. The
    /// apply-then-broadcast order matches the `LocalSubmitMessage`
    /// pattern: a local verification failure short-circuits before
    /// the network sees a malformed message.
    async fn apply_and_broadcast_scoring_output(
        &mut self,
        output: crate::hyper::scoring_driver::ScoringDriverOutput,
    ) -> Result<(), HyperActorError> {
        const FILTER_NAMES: [&str; 7] = ["f0", "f1", "f2", "f3", "f4", "f5", "f6"];
        for (i, name) in FILTER_NAMES.iter().enumerate() {
            self.metric_gauge_tagged(
                "hyper.scoring.filter_pass_count",
                output.filter_pass_counts[i],
                "filter",
                name,
            );
        }
        for issuance in &output.issuances {
            let market_total: u64 = issuance
                .recipients
                .iter()
                .map(|r| r.amount)
                .fold(0u64, |a, b| a.saturating_add(b));
            let market_tag = issuance.market.to_string();
            self.metric_gauge_tagged(
                "hyper.scoring.market_total",
                market_total,
                "market",
                &market_tag,
            );
            self.metric_gauge_tagged(
                "hyper.scoring.market_recipients",
                issuance.recipients.len() as u64,
                "market",
                &market_tag,
            );
            if market_total > 0 {
                let top = issuance
                    .recipients
                    .iter()
                    .map(|r| r.amount)
                    .max()
                    .unwrap_or(0);
                let bps = (top as u128).saturating_mul(10_000) / market_total as u128;
                self.metric_gauge_tagged(
                    "hyper.scoring.market_top1_share_bps",
                    bps.try_into().unwrap_or(u64::MAX),
                    "market",
                    &market_tag,
                );
            }
            self.runtime.apply_reward_issuance(issuance).map_err(|e| {
                HyperActorError::Routing(RoutingError::RewardIssuance(e.to_string()))
            })?;
            let msg = proto::HyperMessage {
                message_type: proto::HyperMessageType::RewardIssuance as i32,
                body: Some(proto::hyper_message::Body::RewardIssuance(issuance.clone())),
            };
            let _ = self
                .outbound
                .send(HyperActorOutbound::BroadcastMessage(msg))
                .await;
        }
        self.metric_gauge(
            "hyper.trust.snapshot_size",
            output.trust_snapshot.entries.len() as u64,
        );
        if !output.trust_snapshot.entries.is_empty() {
            let mut scores: Vec<f64> = output
                .trust_snapshot
                .entries
                .iter()
                .map(|e| f64::from_bits(e.score_bits))
                .collect();
            // f64 NaN-safe sort. NaNs sort last (which is fine for
            // our percentile cuts — they never affect p50/p99
            // unless the whole snapshot is NaNs).
            scores.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
            let n = scores.len();
            let p50 = scores[n / 2];
            let p99 = scores[(n * 99).saturating_sub(1) / 100];
            let to_micros = |x: f64| (x.max(0.0) * 1_000_000.0).min(u64::MAX as f64) as u64;
            self.metric_gauge("hyper.trust.score_p50_micros", to_micros(p50));
            self.metric_gauge("hyper.trust.score_p99_micros", to_micros(p99));
        }
        self.runtime
            .apply_trust_snapshot_update(&output.trust_snapshot)
            .map_err(|e| {
                HyperActorError::Routing(RoutingError::TrustSnapshotUpdate(e.to_string()))
            })?;
        let snapshot_msg = proto::HyperMessage {
            message_type: proto::HyperMessageType::TrustSnapshotUpdate as i32,
            body: Some(proto::hyper_message::Body::TrustSnapshotUpdate(
                output.trust_snapshot,
            )),
        };
        let _ = self
            .outbound
            .send(HyperActorOutbound::BroadcastMessage(snapshot_msg))
            .await;
        self.metric_count("hyper.scoring.epochs", 1);
        Ok(())
    }

    /// FIP §13.5/§13.4: refresh the threshold-signed merkle root
    /// over unclaimed transparent locks. Called at each epoch
    /// boundary (1-of-1 single-validator path). Builds the tree,
    /// runs DKLS local sign over `merkle_root_update_signing_payload`,
    /// applies + broadcasts the resulting `HyperLockMerkleRootUpdate`.
    ///
    /// `block_number` for the signed payload is the hyper chain's
    /// current block height. The contract's `latestBlock`
    /// monotonicity check is satisfied because every epoch
    /// boundary post-dates a strictly-greater height than the
    /// prior one.
    async fn refresh_signed_lock_merkle_root(&mut self, epoch: u64) -> Result<(), HyperActorError> {
        // Skip on chains that haven't produced a block yet — there's
        // nothing to anchor against and nothing to sign over.
        let block_number = match self.runtime.last_block_height() {
            Some(h) => h,
            None => return Ok(()),
        };
        let update = match self
            .runtime
            .produce_signed_lock_merkle_root_local(epoch, block_number)
        {
            Ok(u) => u,
            Err(e) => {
                // Most common cause: this validator doesn't have a
                // 1-of-1 share for `epoch`. Treat as advisory; a
                // future multi-party path will sign through the
                // sign queue instead.
                tracing::debug!(epoch, error = %e, "signed-root produce skipped");
                return Ok(());
            }
        };
        if let Err(e) = self.runtime.apply_lock_merkle_root_update(&update) {
            tracing::warn!(epoch, error = %e, "signed-root apply failed");
            return Ok(());
        }
        let msg = proto::HyperMessage {
            message_type: proto::HyperMessageType::LockMerkleRootUpdate as i32,
            body: Some(proto::hyper_message::Body::LockMerkleRootUpdate(update)),
        };
        let _ = self
            .outbound
            .send(HyperActorOutbound::BroadcastMessage(msg))
            .await;
        Ok(())
    }

    async fn maybe_trigger_scoring(&mut self, anchor_block: u64, anchor_timestamp: u64) {
        use crate::hyper::epoch::epoch_for;
        let current_epoch = epoch_for(anchor_block);
        let last = self.runtime.last_scored_epoch;
        let next_to_score = match last {
            None => {
                // First block we've seen — initialize the watermark.
                self.runtime.last_scored_epoch = Some(current_epoch);
                return;
            }
            Some(prev) => prev + 1,
        };
        if current_epoch <= next_to_score {
            return; // still inside the same epoch (or earlier)
        }
        // Score every completed epoch in (last_scored, current_epoch).
        // The current_epoch itself is NOT scored — it's still in progress.
        // anchor_timestamp comes from the imported block's metadata,
        // which threshold-signed it on the proposer side, so every
        // validator agrees on the wall-clock value driving age_factor
        // and the 30-day cutoff inside `evaluate_epoch`.
        for ep in next_to_score..current_epoch {
            // Dispatch directly: re-entering `dispatch` from a tokio
            // task isn't allowed (no recursion through &mut self), so
            // we synthesize the inputs inline. This mirrors what
            // `EvaluateEpoch` does and keeps the auto-trigger
            // self-contained.
            let universe = self.runtime.fids_for_scoring();
            let seeds = self.runtime.seeds_for_scoring(&universe);
            let params = self.runtime.scoring_params.clone();
            let reader =
                crate::hyper::poq_reader::PoqReader::new(self.runtime.db_handle(), universe);
            let output = match crate::hyper::scoring_driver::run_epoch_dkls_local(
                &self.runtime,
                &reader,
                ep,
                anchor_timestamp,
                &seeds,
                &params,
            ) {
                Ok(o) => o,
                Err(e) => {
                    let _ = self
                        .outbound
                        .send(HyperActorOutbound::EventError(
                            HyperActorError::ScoringDriver(e.to_string()),
                        ))
                        .await;
                    continue;
                }
            };
            for issuance in &output.issuances {
                if let Err(e) = self.runtime.apply_reward_issuance(issuance) {
                    tracing::warn!(epoch = ep, market = ?issuance.market, "auto-scoring apply_reward_issuance failed: {}", e);
                    continue;
                }
                let msg = proto::HyperMessage {
                    message_type: proto::HyperMessageType::RewardIssuance as i32,
                    body: Some(proto::hyper_message::Body::RewardIssuance(issuance.clone())),
                };
                let _ = self
                    .outbound
                    .send(HyperActorOutbound::BroadcastMessage(msg))
                    .await;
            }
            if let Err(e) = self
                .runtime
                .apply_trust_snapshot_update(&output.trust_snapshot)
            {
                tracing::warn!(
                    epoch = ep,
                    "auto-scoring apply_trust_snapshot_update failed: {}",
                    e
                );
            } else {
                let snapshot_msg = proto::HyperMessage {
                    message_type: proto::HyperMessageType::TrustSnapshotUpdate as i32,
                    body: Some(proto::hyper_message::Body::TrustSnapshotUpdate(
                        output.trust_snapshot,
                    )),
                };
                let _ = self
                    .outbound
                    .send(HyperActorOutbound::BroadcastMessage(snapshot_msg))
                    .await;
            }
            self.runtime.last_scored_epoch = Some(ep);
            self.metric_count("hyper.scoring.epochs", 1);
        }
    }

    /// Sign + broadcast the DA seed for `current_epoch` using the
    /// share held for `current_epoch - 1`. 1-of-1 signs inline;
    /// ≥2-of-N enqueues via `start_dkls_da_epoch_seed_multi_party`.
    /// Idempotent on `last_da_seed_signed_for_epoch`.
    async fn maybe_sign_da_epoch_seed(&mut self, anchor_block: u64) {
        use crate::hyper::epoch::epoch_for;
        let current_epoch = epoch_for(anchor_block);
        if current_epoch == 0 {
            return;
        }
        if let Some(prev) = self.last_da_seed_signed_for_epoch {
            if prev >= current_epoch {
                return;
            }
        }
        if self
            .runtime
            .da_epoch_seed_for(current_epoch)
            .ok()
            .flatten()
            .is_some()
        {
            self.last_da_seed_signed_for_epoch = Some(current_epoch);
            return;
        }
        let signer_epoch = current_epoch - 1;
        let share = match self.runtime.dkls_share_for_epoch(signer_epoch) {
            Some(s) => s,
            None => return,
        };
        if share.party.parameters.threshold != 1 || share.party.parameters.share_count != 1 {
            if let Err(e) = self
                .start_dkls_da_epoch_seed_multi_party(current_epoch)
                .await
            {
                tracing::warn!(
                    target_epoch = current_epoch,
                    error = ?e,
                    "DA epoch seed multi-party trigger failed"
                );
            }
            return;
        }
        let payload = crate::hyper::rewards::da_epoch_seed_signing_payload(
            current_epoch,
            self.runtime.protocol_chain_id,
        );
        let digest = alloy_primitives::keccak256(&payload);
        let sig = match hypersnap_crypto::dkls_sign::run_local_dkls_sign(&share.party, digest) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(
                    epoch = current_epoch,
                    error = ?e,
                    "DA epoch seed: local DKLS sign failed"
                );
                return;
            }
        };
        let body = proto::DaEpochSeedBody {
            epoch: current_epoch,
            ecdsa_signature: sig.to_bytes().to_vec(),
        };
        let msg = proto::HyperMessage {
            message_type: proto::HyperMessageType::DaEpochSeed as i32,
            body: Some(proto::hyper_message::Body::DaEpochSeed(body)),
        };
        if let Err(e) = self.runtime.submit_message(msg.clone()) {
            tracing::warn!(
                epoch = current_epoch,
                error = %e,
                "DA epoch seed: local apply rejected"
            );
            return;
        }
        let _ = self
            .outbound
            .send(HyperActorOutbound::BroadcastMessage(msg))
            .await;
        self.last_da_seed_signed_for_epoch = Some(current_epoch);
        self.metric_count("hyper.da.seed_signed", 1);
    }

    /// Submit + broadcast this validator's batch of DA challenge
    /// responses for the current epoch. Idempotent per epoch via
    /// `last_da_responded_epoch`. No-op without a producer.
    async fn maybe_trigger_da_responses(&mut self, anchor_block: u64) {
        use crate::hyper::epoch::epoch_for;
        let producer = match self.da_response_producer.clone() {
            Some(p) => p,
            None => return,
        };
        let current_epoch = epoch_for(anchor_block);
        if current_epoch == 0 {
            return;
        }
        if let Some(prev) = self.last_da_responded_epoch {
            if prev >= current_epoch {
                return;
            }
        }
        // `None` → wait for `HyperDaEpochSeed` to land.
        let seed = match self.runtime.da_boundary_seed_for(current_epoch) {
            Ok(Some(s)) => s,
            Ok(None) => return,
            Err(e) => {
                tracing::warn!(
                    epoch = current_epoch,
                    error = %e,
                    "DA driver: boundary seed lookup failed"
                );
                return;
            }
        };

        let responses = producer.produce_for_epoch(current_epoch, &seed);
        let mut submitted = 0u64;
        for body in responses {
            let msg = proto::HyperMessage {
                message_type: proto::HyperMessageType::DaChallengeResponse as i32,
                body: Some(proto::hyper_message::Body::DaChallengeResponse(
                    body.clone(),
                )),
            };
            if let Err(e) = self.runtime.submit_message(msg.clone()) {
                // Submit-side rejection (e.g. duplicate, signer-not-
                // authorized) — log and skip; the producer never
                // emits the same (epoch, idx) twice within one
                // epoch, so duplicates here are downstream replays.
                tracing::debug!(
                    epoch = current_epoch,
                    challenge_index = body.challenge_index,
                    error = %e,
                    "DA driver: submit_message rejected response"
                );
                continue;
            }
            let _ = self
                .outbound
                .send(HyperActorOutbound::BroadcastMessage(msg))
                .await;
            submitted += 1;
        }
        self.last_da_responded_epoch = Some(current_epoch);
        self.metric_count("hyper.da.responses_submitted", submitted as i64);
    }

    async fn flush_dkls_outbound(&self, driver: &mut crate::hyper::dkls_driver::DklsDriver) {
        let target_epoch = driver.target_epoch();
        for msg in driver.drain_outbound() {
            // FIP §13.5 DKLS gossip E2EE: P2P-addressed messages
            // get sealed to the receiver's transport pubkey before
            // hitting the wire. Broadcast variants stay plaintext.
            let mut rng = rand::rngs::OsRng;
            let encoded = match crate::hyper::dkls_wire_codec::seal_dkls_round_message(
                &msg,
                target_epoch,
                |party_index| {
                    self.runtime
                        .transport_pubkey_for_party(target_epoch, party_index)
                },
                &mut rng,
            ) {
                Ok(bytes) => bytes,
                Err(e) => {
                    // The most common error here is
                    // `UnknownReceiverTransport` — the addressed
                    // party hasn't registered a transport pubkey.
                    // Skip the message rather than emitting it
                    // plaintext; the ceremony stalls until the
                    // receiver re-registers, which is the right
                    // failure mode (preferable to leaking shares).
                    tracing::warn!(
                        target_epoch,
                        error = %e,
                        "dropping DKLS round message — secret material would leak",
                    );
                    continue;
                }
            };
            let _ = self
                .outbound
                .send(HyperActorOutbound::BroadcastDkls {
                    target_epoch,
                    encoded,
                })
                .await;
        }
    }

    async fn flush_dkls_sign_outbound(
        &self,
        driver: &mut crate::hyper::dkls_sign_driver::DklsSignDriver,
    ) {
        let epoch = driver.epoch();
        for msg in driver.drain_outbound() {
            let mut rng = rand::rngs::OsRng;
            let encoded = match crate::hyper::dkls_wire_codec::seal_dkls_sign_round_message(
                &msg,
                epoch,
                |party_index| self.runtime.transport_pubkey_for_party(epoch, party_index),
                &mut rng,
            ) {
                Ok(bytes) => bytes,
                Err(e) => {
                    tracing::warn!(
                        epoch,
                        error = %e,
                        "dropping DKLS sign round message — secret material would leak",
                    );
                    continue;
                }
            };
            let _ = self
                .outbound
                .send(HyperActorOutbound::BroadcastDklsSign { epoch, encoded })
                .await;
        }
    }

    /// Common entry point for `ProduceBlockDkls` dispatch. Builds an
    /// unsigned block, picks the deterministic signing committee for
    /// `(epoch, keccak256(signing_payload))`, and — if the local
    /// node is in the committee — stashes the unsigned block in
    /// `pending_dkls_blocks` and starts a `DklsSignDriver` against
    /// the committee.
    ///
    /// Non-committee proposers no-op: the validator selected for
    /// the committee will produce + sign + broadcast independently.
    async fn start_dkls_block_production(
        &mut self,
        height: u64,
        parent_hash: Vec<u8>,
        extra_rules_version: u32,
        snapchain_anchor_block: u64,
        snapchain_anchor_hash: Vec<u8>,
        snapchain_anchor_timestamp: u64,
    ) -> Result<(), HyperActorError> {
        let (block, locks, transfers) = self.runtime.produce_unsigned_block_dkls(
            height,
            parent_hash,
            extra_rules_version,
            snapchain_anchor_block,
            snapchain_anchor_hash,
            snapchain_anchor_timestamp,
        )?;
        let epoch = block.signature.epoch;
        let payload = block.envelope.metadata.signing_payload(epoch);
        let digest = alloy_primitives::keccak256(&payload);

        // Resolve our local share to learn (party_index, threshold,
        // share_count).
        let Some(share) = self.runtime.dkls_share_for_epoch(epoch) else {
            // No local share — we can't sign; treat as no-op.
            return Ok(());
        };
        let threshold = share.party.parameters.threshold;
        let share_count = share.party.parameters.share_count;
        let local_party_index = share.party.party_index;
        let party = share.party.clone();

        let committee = crate::hyper::dkls_committee::select_signing_committee(
            epoch,
            &digest,
            share_count,
            threshold,
        )
        .map_err(|e| HyperActorError::Routing(RoutingError::RewardIssuance(e.to_string())))?;
        if !committee.contains(&local_party_index) {
            // Not in committee — nothing to do; the chosen
            // committee members will produce + sign + broadcast
            // independently.
            return Ok(());
        }

        let coordinator =
            hypersnap_crypto::dkls_sign::DklsSignCoordinator::new(party, committee.clone(), digest)
                .map_err(|e| {
                    HyperActorError::Routing(RoutingError::RewardIssuance(e.to_string()))
                })?;
        let mut driver = crate::hyper::dkls_sign_driver::DklsSignDriver::new(epoch, coordinator);
        driver.start()?;
        self.flush_dkls_sign_outbound(&mut driver).await;
        // Stash the unsigned block before installing the active
        // sign driver — keeps the invariant "if a driver is active,
        // its digest has a pending block to attach to".
        self.pending_dkls_blocks.insert(
            digest,
            PendingDklsBlock {
                block,
                locks,
                transfers,
                committee,
            },
        );
        // Single-party committees finish phase 1 → 2 → 3 → 4
        // entirely from drain+self-route; advance immediately so the
        // 1-of-1 case completes within a single tick.
        if driver.coordinator.signing_committee().len() == 1 {
            driver.try_advance()?;
        }
        if driver.is_completed() {
            // Already finalized — short-circuit straight to the
            // finalization path. Avoids needing an extra
            // `AdvanceDklsSign` event for 1-of-1 devnets.
            let signature = driver
                .signature()
                .expect("is_completed() ⇒ signature present")
                .clone();
            self.finalize_dkls_signature(epoch, digest, signature).await;
        } else {
            self.active_dkls_sign = Some(driver);
        }
        Ok(())
    }

    /// Dispatch a single completed DKLS signature. Consults the
    /// pending maps in priority order:
    ///  1. `pending_dkls_blocks` ⇒ attach + import + `BroadcastBlock`
    ///  2. `pending_dkls_messages` ⇒ attach + apply + `BroadcastMessage`
    ///  3. neither ⇒ emit a bare `DklsSignFinalized` for callers
    ///     subscribed to raw signature outputs.
    /// Does NOT pop the next queued ceremony — that's
    /// [`Self::finalize_dkls_signature`]'s job. Split this way to
    /// avoid async recursion when a 1-of-1 ceremony enqueued from
    /// the same `finalize_dkls_signature` call finalizes within
    /// `start_queued_sign`.
    async fn dispatch_dkls_signature(
        &mut self,
        epoch: u64,
        digest: alloy_primitives::B256,
        signature: hypersnap_crypto::ecdsa::EcdsaSignature,
    ) {
        if let Some(pending) = self.pending_dkls_blocks.remove(&digest) {
            let mut block = pending.block;
            crate::hyper::runtime::HyperRuntime::attach_dkls_signature(
                &mut block,
                &pending.committee,
                &signature,
            );
            let anchor_block = block.envelope.metadata.snapchain_anchor_block;
            let anchor_ts = block.envelope.metadata.snapchain_anchor_timestamp;
            let send_block = block.clone();
            if let Err(e) = self
                .runtime
                .import_block(&block, &pending.locks, &pending.transfers)
            {
                let _ = self
                    .outbound
                    .send(HyperActorOutbound::EventError(HyperActorError::Import(e)))
                    .await;
            } else {
                self.metric_count("hyper.blocks.produced", 1);
                let _ = self
                    .outbound
                    .send(HyperActorOutbound::BroadcastBlock(send_block))
                    .await;
                self.maybe_trigger_scoring(anchor_block, anchor_ts).await;
            }
        } else if let Some(pending) = self.pending_dkls_messages.remove(&digest) {
            match pending {
                PendingDklsMessage::RewardIssuance(mut iss) => {
                    iss.ecdsa_signature = signature.to_bytes().to_vec();
                    if let Err(e) = self.runtime.apply_reward_issuance(&iss) {
                        let _ = self
                            .outbound
                            .send(HyperActorOutbound::EventError(HyperActorError::Routing(
                                RoutingError::RewardIssuance(e.to_string()),
                            )))
                            .await;
                    } else {
                        let msg = proto::HyperMessage {
                            message_type: proto::HyperMessageType::RewardIssuance as i32,
                            body: Some(proto::hyper_message::Body::RewardIssuance(iss)),
                        };
                        let _ = self
                            .outbound
                            .send(HyperActorOutbound::BroadcastMessage(msg))
                            .await;
                    }
                }
                PendingDklsMessage::TrustSnapshot(mut snap) => {
                    snap.ecdsa_signature = signature.to_bytes().to_vec();
                    if let Err(e) = self.runtime.apply_trust_snapshot_update(&snap) {
                        let _ = self
                            .outbound
                            .send(HyperActorOutbound::EventError(HyperActorError::Routing(
                                RoutingError::TrustSnapshotUpdate(e.to_string()),
                            )))
                            .await;
                    } else {
                        let msg = proto::HyperMessage {
                            message_type: proto::HyperMessageType::TrustSnapshotUpdate as i32,
                            body: Some(proto::hyper_message::Body::TrustSnapshotUpdate(snap)),
                        };
                        let _ = self
                            .outbound
                            .send(HyperActorOutbound::BroadcastMessage(msg))
                            .await;
                    }
                }
                PendingDklsMessage::LockMerkleRoot(mut update) => {
                    update.ecdsa_signature = signature.to_bytes().to_vec();
                    if let Err(e) = self.runtime.apply_lock_merkle_root_update(&update) {
                        let _ = self
                            .outbound
                            .send(HyperActorOutbound::EventError(HyperActorError::Routing(
                                RoutingError::LockMerkleRootUpdate(e.to_string()),
                            )))
                            .await;
                    } else {
                        let msg = proto::HyperMessage {
                            message_type: proto::HyperMessageType::LockMerkleRootUpdate as i32,
                            body: Some(proto::hyper_message::Body::LockMerkleRootUpdate(update)),
                        };
                        let _ = self
                            .outbound
                            .send(HyperActorOutbound::BroadcastMessage(msg))
                            .await;
                    }
                }
                PendingDklsMessage::InboundBurn(mut burn) => {
                    burn.ecdsa_signature = signature.to_bytes().to_vec();
                    if let Err(e) = self.runtime.apply_inbound_burn(&burn) {
                        let _ = self
                            .outbound
                            .send(HyperActorOutbound::EventError(HyperActorError::Routing(
                                RoutingError::InboundBurn(e.to_string()),
                            )))
                            .await;
                    } else {
                        let msg = proto::HyperMessage {
                            message_type: proto::HyperMessageType::InboundBurn as i32,
                            body: Some(proto::hyper_message::Body::InboundBurn(burn)),
                        };
                        let _ = self
                            .outbound
                            .send(HyperActorOutbound::BroadcastMessage(msg))
                            .await;
                    }
                }
                PendingDklsMessage::DaEpochSeed(mut body) => {
                    body.ecdsa_signature = signature.to_bytes().to_vec();
                    if let Err(e) = self.runtime.apply_da_epoch_seed(&body) {
                        let _ = self
                            .outbound
                            .send(HyperActorOutbound::EventError(HyperActorError::Routing(
                                RoutingError::DaEpochSeed(e.to_string()),
                            )))
                            .await;
                    } else {
                        // Mark this validator as having committed for
                        // this target epoch so the idempotency check
                        // in `maybe_sign_da_epoch_seed` won't retry.
                        self.last_da_seed_signed_for_epoch = Some(
                            self.last_da_seed_signed_for_epoch
                                .map_or(body.epoch, |w| w.max(body.epoch)),
                        );
                        let msg = proto::HyperMessage {
                            message_type: proto::HyperMessageType::DaEpochSeed as i32,
                            body: Some(proto::hyper_message::Body::DaEpochSeed(body)),
                        };
                        let _ = self
                            .outbound
                            .send(HyperActorOutbound::BroadcastMessage(msg))
                            .await;
                        self.metric_count("hyper.da.seed_signed", 1);
                    }
                }
            }
        } else {
            let _ = self
                .outbound
                .send(HyperActorOutbound::DklsSignFinalized {
                    epoch,
                    digest,
                    signature,
                })
                .await;
        }
    }

    /// Top-level driver for "ceremony just finished, what's next?".
    /// Repeatedly:
    ///   1. dispatches the current finalized signature,
    ///   2. starts the next queued ceremony if any,
    ///   3. if the started ceremony finalizes synchronously (1-of-1),
    ///      keeps looping with the new (epoch, digest, signature).
    /// Avoids async recursion entirely; the loop terminates when
    /// either the queue empties or the started driver needs further
    /// `AdvanceDklsSign` ticks.
    async fn finalize_dkls_signature(
        &mut self,
        mut epoch: u64,
        mut digest: alloy_primitives::B256,
        mut signature: hypersnap_crypto::ecdsa::EcdsaSignature,
    ) {
        loop {
            self.dispatch_dkls_signature(epoch, digest, signature).await;
            // Pop next ceremony from the queue (only if no active
            // driver — block production may have already installed
            // one before EvaluateEpochDkls's queue ran).
            if self.active_dkls_sign.is_some() {
                break;
            }
            let Some(next) = self.pending_sign_queue.pop_front() else {
                break;
            };
            match self.start_queued_sign(next).await {
                Ok(Some((next_epoch, next_digest, next_sig))) => {
                    // 1-of-1 ceremony finalized synchronously —
                    // loop back and dispatch.
                    epoch = next_epoch;
                    digest = next_digest;
                    signature = next_sig;
                }
                Ok(None) => {
                    // Multi-party ceremony in flight; the next
                    // `AdvanceDklsSign` event will drive it.
                    break;
                }
                Err(e) => {
                    let _ = self.outbound.send(HyperActorOutbound::EventError(e)).await;
                    break;
                }
            }
        }
    }

    /// Build a `DklsSignCoordinator` for `task` and either:
    ///  - install it as `active_dkls_sign` (multi-party case;
    ///    returns `Ok(None)`), or
    ///  - finalize it synchronously and return the resulting
    ///    `(epoch, digest, signature)` for the caller to dispatch
    ///    (1-of-1 case; returns `Ok(Some(...))`).
    /// The caller is responsible for dispatching the synchronous
    /// finalize result — this fn deliberately doesn't recurse.
    async fn start_queued_sign(
        &mut self,
        task: DklsSignTask,
    ) -> Result<
        Option<(
            u64,
            alloy_primitives::B256,
            hypersnap_crypto::ecdsa::EcdsaSignature,
        )>,
        HyperActorError,
    > {
        let coordinator = hypersnap_crypto::dkls_sign::DklsSignCoordinator::new(
            task.party,
            task.committee,
            task.digest,
        )
        .map_err(|e| HyperActorError::Routing(RoutingError::RewardIssuance(e.to_string())))?;
        let mut driver =
            crate::hyper::dkls_sign_driver::DklsSignDriver::new(task.epoch, coordinator);
        driver.start()?;
        self.flush_dkls_sign_outbound(&mut driver).await;
        if driver.coordinator.signing_committee().len() == 1 {
            driver.try_advance()?;
            if driver.is_completed() {
                let signature = driver
                    .signature()
                    .expect("is_completed() ⇒ signature present")
                    .clone();
                let digest = *driver.coordinator.digest();
                let epoch = driver.epoch();
                return Ok(Some((epoch, digest, signature)));
            }
        }
        self.active_dkls_sign = Some(driver);
        Ok(None)
    }

    /// Multi-party EvaluateEpochDkls path: run scoring (no signing),
    /// for each output compute the canonical digest + committee,
    /// register pending unsigned messages, and enqueue sign tasks.
    /// Kicks off the first ceremony if no driver is currently
    /// active.
    async fn start_dkls_scoring_multi_party(
        &mut self,
        epoch: u64,
        anchor_timestamp: u64,
    ) -> Result<(), HyperActorError> {
        // Resolve the local share once.
        let Some(share_info) = self.runtime.dkls_share_for_epoch(epoch) else {
            // No local share — nothing to sign here. A peer will
            // produce + sign + broadcast independently.
            return Ok(());
        };
        let local_party_index = share_info.party.party_index;
        let party = share_info.party.clone();
        let parameters = share_info.party.parameters.clone();

        // Build the unsigned scoring output via the canonical
        // helper. This is byte-identical to what `run_epoch_*`
        // would emit for the same inputs except sig fields are
        // empty — guaranteeing every validator computes the same
        // digests over the same canonical payloads.
        let universe = self.runtime.fids_for_scoring();
        self.metric_gauge("hyper.scoring.fids_evaluated", universe.len() as u64);
        let seeds = self.runtime.seeds_for_scoring(&universe);
        let params = self.runtime.scoring_params.clone();
        let reader = crate::hyper::poq_reader::PoqReader::new(self.runtime.db_handle(), universe);
        let unsigned = crate::hyper::scoring_driver::run_epoch_unsigned(
            &reader,
            epoch,
            anchor_timestamp,
            &seeds,
            &params,
        )
        .map_err(|e| HyperActorError::ScoringDriver(e.to_string()))?;

        let mut tasks: Vec<DklsSignTask> = Vec::new();
        for iss in unsigned.issuances {
            let payload = crate::hyper::rewards::issuance_signing_payload(&iss);
            let digest = alloy_primitives::keccak256(&payload);
            let committee = crate::hyper::dkls_committee::select_signing_committee(
                epoch,
                &digest,
                parameters.share_count,
                parameters.threshold,
            )
            .map_err(|e| HyperActorError::Routing(RoutingError::RewardIssuance(e.to_string())))?;
            if !committee.contains(&local_party_index) {
                continue;
            }
            self.pending_dkls_messages
                .insert(digest, PendingDklsMessage::RewardIssuance(iss));
            tasks.push(DklsSignTask {
                epoch,
                digest,
                party: party.clone(),
                committee,
            });
        }

        // Trust snapshot.
        let snap = unsigned.trust_snapshot;
        let payload = crate::hyper::rewards::trust_snapshot_signing_payload(&snap);
        let digest = alloy_primitives::keccak256(&payload);
        let committee = crate::hyper::dkls_committee::select_signing_committee(
            epoch,
            &digest,
            parameters.share_count,
            parameters.threshold,
        )
        .map_err(|e| HyperActorError::Routing(RoutingError::TrustSnapshotUpdate(e.to_string())))?;
        if committee.contains(&local_party_index) {
            self.pending_dkls_messages
                .insert(digest, PendingDklsMessage::TrustSnapshot(snap));
            tasks.push(DklsSignTask {
                epoch,
                digest,
                party: party.clone(),
                committee,
            });
        }

        // Enqueue everything; start the first if no active driver.
        for t in tasks {
            self.pending_sign_queue.push_back(t);
        }
        if self.active_dkls_sign.is_none() {
            if let Some(next) = self.pending_sign_queue.pop_front() {
                self.start_queued_sign(next).await?;
            }
        }
        Ok(())
    }

    /// FIP §13.6 1-of-1 path: drain the local `BridgeBurnStore`,
    /// for each unprocessed observation produce a signed
    /// `HyperInboundBurn` via `produce_signed_inbound_burn_local`,
    /// apply locally + broadcast. Skips burns already credited
    /// (replay-protected via the `(source_chain_id, burn_id)`
    /// marker on the inbound-burn-processed prefix).
    ///
    /// Multi-party signing routes through `start_dkls_inbound_burns_multi_party`
    /// instead — same sign-queue plumbing as scoring + lock-root.
    async fn refresh_inbound_burns(&mut self, epoch: u64) -> Result<(), HyperActorError> {
        // No share for this epoch → nothing to sign locally.
        if self.runtime.dkls_share_for_epoch(epoch).is_none() {
            return Ok(());
        }
        let observed = match self.runtime.bridge_burn_store.iter_all() {
            Ok(o) => o,
            Err(e) => {
                tracing::warn!(epoch, error = %e, "bridge burn store iter failed");
                return Ok(());
            }
        };
        for obs in observed {
            // Skip already-processed (replay protection).
            match self
                .runtime
                .is_inbound_burn_processed(obs.source_chain_id, &obs.burn_id)
            {
                Ok(true) => continue,
                Ok(false) => {}
                Err(e) => {
                    tracing::warn!(error = %e, "inbound-burn processed check failed");
                    continue;
                }
            }
            let signed = match self.runtime.produce_signed_inbound_burn_local(epoch, &obs) {
                Ok(s) => s,
                Err(e) => {
                    tracing::debug!(epoch, error = %e, "inbound-burn local sign skipped");
                    continue;
                }
            };
            if let Err(e) = self.runtime.apply_inbound_burn(&signed) {
                tracing::warn!(epoch, error = %e, "inbound-burn apply failed");
                continue;
            }
            let msg = proto::HyperMessage {
                message_type: proto::HyperMessageType::InboundBurn as i32,
                body: Some(proto::hyper_message::Body::InboundBurn(signed)),
            };
            let _ = self
                .outbound
                .send(HyperActorOutbound::BroadcastMessage(msg))
                .await;
        }
        Ok(())
    }

    /// FIP §13.6 multi-party path: for each unprocessed observed
    /// burn, compute the canonical digest, pick a deterministic
    /// committee from `(epoch, digest)`, register the unsigned
    /// `HyperInboundBurn` in `pending_dkls_messages`, and enqueue
    /// a sign task. Mirrors `start_dkls_scoring_multi_party` and
    /// `start_dkls_lock_root_multi_party`.
    async fn start_dkls_inbound_burns_multi_party(
        &mut self,
        epoch: u64,
    ) -> Result<(), HyperActorError> {
        let Some(share_info) = self.runtime.dkls_share_for_epoch(epoch) else {
            return Ok(());
        };
        let local_party_index = share_info.party.party_index;
        let party = share_info.party.clone();
        let parameters = share_info.party.parameters.clone();

        let observed = self
            .runtime
            .bridge_burn_store
            .iter_all()
            .map_err(|e| HyperActorError::Routing(RoutingError::InboundBurn(e.to_string())))?;
        let mut tasks: Vec<DklsSignTask> = Vec::new();
        for obs in observed {
            // Skip already-processed.
            if self
                .runtime
                .is_inbound_burn_processed(obs.source_chain_id, &obs.burn_id)
                .unwrap_or(false)
            {
                continue;
            }
            let unsigned = proto::HyperInboundBurn {
                epoch,
                source_chain_id: obs.source_chain_id,
                burn_id: obs.burn_id.clone(),
                recipient_fid: obs.recipient_fid,
                amount: obs.amount,
                source_block_number: obs.source_block_number,
                source_tx_hash: obs.source_tx_hash.clone(),
                ecdsa_signature: Vec::new(),
            };
            let payload = crate::hyper::inbound_burn::inbound_burn_signing_payload(&unsigned);
            let digest = alloy_primitives::keccak256(&payload);
            let committee = crate::hyper::dkls_committee::select_signing_committee(
                epoch,
                &digest,
                parameters.share_count,
                parameters.threshold,
            )
            .map_err(|e| HyperActorError::Routing(RoutingError::InboundBurn(e.to_string())))?;
            if !committee.contains(&local_party_index) {
                continue;
            }
            self.pending_dkls_messages
                .insert(digest, PendingDklsMessage::InboundBurn(unsigned));
            tasks.push(DklsSignTask {
                epoch,
                digest,
                party: party.clone(),
                committee,
            });
        }
        for t in tasks {
            self.pending_sign_queue.push_back(t);
        }
        if self.active_dkls_sign.is_none() {
            if let Some(next) = self.pending_sign_queue.pop_front() {
                self.start_queued_sign(next).await?;
            }
        }
        Ok(())
    }

    /// FIP §13.5/§13.4 multi-party path: build the unsigned merkle-
    /// root update and enqueue a sign task for the committee
    /// deterministically picked from `(epoch, digest)`. Mirrors
    /// `start_dkls_scoring_multi_party` shape.
    ///
    /// Each validator independently observes the same canonical
    /// digest (built from the same canonical merkle tree) and so
    /// computes the same committee. Members of that committee
    /// drive a single DKLS sign ceremony; non-members no-op.
    async fn start_dkls_lock_root_multi_party(
        &mut self,
        epoch: u64,
    ) -> Result<(), HyperActorError> {
        let Some(share_info) = self.runtime.dkls_share_for_epoch(epoch) else {
            return Ok(());
        };
        let Some(block_number) = self.runtime.last_block_height() else {
            return Ok(());
        };
        let local_party_index = share_info.party.party_index;
        let party = share_info.party.clone();
        let parameters = share_info.party.parameters.clone();

        let (tree, _indexed) = match self.runtime.build_lock_merkle_tree() {
            Ok(t) => t,
            Err(e) => {
                tracing::warn!(epoch, error = %e, "lock-tree build for multi-party sign failed");
                return Ok(());
            }
        };
        let root = tree.root;
        let payload = hypersnap_crypto::bridge_payload::merkle_root_update_signing_payload(
            block_number,
            root,
        );
        let digest = alloy_primitives::keccak256(&payload);
        let committee = crate::hyper::dkls_committee::select_signing_committee(
            epoch,
            &digest,
            parameters.share_count,
            parameters.threshold,
        )
        .map_err(|e| HyperActorError::Routing(RoutingError::LockMerkleRootUpdate(e.to_string())))?;
        if !committee.contains(&local_party_index) {
            return Ok(());
        }
        let update = proto::HyperLockMerkleRootUpdate {
            epoch,
            block_number,
            root: root.as_slice().to_vec(),
            ecdsa_signature: Vec::new(),
        };
        self.pending_dkls_messages
            .insert(digest, PendingDklsMessage::LockMerkleRoot(update));
        let task = DklsSignTask {
            epoch,
            digest,
            party,
            committee,
        };
        self.pending_sign_queue.push_back(task);
        if self.active_dkls_sign.is_none() {
            if let Some(next) = self.pending_sign_queue.pop_front() {
                self.start_queued_sign(next).await?;
            }
        }
        Ok(())
    }

    /// Enqueue a committee DKLS sign ceremony for the
    /// `target_epoch` DA seed using the share for `target_epoch - 1`.
    /// Non-committee members no-op.
    async fn start_dkls_da_epoch_seed_multi_party(
        &mut self,
        target_epoch: u64,
    ) -> Result<(), HyperActorError> {
        if target_epoch == 0 {
            return Ok(());
        }
        // Already in the store (peer broadcast applied first) → bump
        // the watermark and return.
        if self
            .runtime
            .da_epoch_seed_for(target_epoch)
            .ok()
            .flatten()
            .is_some()
        {
            self.last_da_seed_signed_for_epoch = Some(
                self.last_da_seed_signed_for_epoch
                    .map_or(target_epoch, |w| w.max(target_epoch)),
            );
            return Ok(());
        }
        let signer_epoch = target_epoch - 1;
        let Some(share_info) = self.runtime.dkls_share_for_epoch(signer_epoch) else {
            return Ok(());
        };
        let local_party_index = share_info.party.party_index;
        let party = share_info.party.clone();
        let parameters = share_info.party.parameters.clone();

        let payload = crate::hyper::rewards::da_epoch_seed_signing_payload(
            target_epoch,
            self.runtime.protocol_chain_id,
        );
        let digest = alloy_primitives::keccak256(&payload);
        let committee = crate::hyper::dkls_committee::select_signing_committee(
            signer_epoch,
            &digest,
            parameters.share_count,
            parameters.threshold,
        )
        .map_err(|e| HyperActorError::Routing(RoutingError::DaEpochSeed(e.to_string())))?;
        if !committee.contains(&local_party_index) {
            return Ok(());
        }
        let body = proto::DaEpochSeedBody {
            epoch: target_epoch,
            ecdsa_signature: Vec::new(),
        };
        self.pending_dkls_messages
            .insert(digest, PendingDklsMessage::DaEpochSeed(body));
        let task = DklsSignTask {
            epoch: signer_epoch,
            digest,
            party,
            committee,
        };
        self.pending_sign_queue.push_back(task);
        if self.active_dkls_sign.is_none() {
            if let Some(next) = self.pending_sign_queue.pop_front() {
                self.start_queued_sign(next).await?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hyper::router::HyperRouter;
    use crate::hyper::runtime::{HyperRuntime, HyperRuntimeConfig};
    use crate::hyper::validator_score::ScoreWeights;
    use crate::storage::db::RocksDB;
    use hypersnap_crypto::kzg::KzgSrs;
    use hypersnap_crypto::kzg_lagrange::VERKLE_DOMAIN;
    use std::sync::Arc;
    use tempfile::TempDir;

    fn make_runtime_with_srs(srs: Arc<KzgSrs>) -> (HyperRuntime, TempDir) {
        let dir = TempDir::new().unwrap();
        let db = RocksDB::new(dir.path().to_str().unwrap());
        db.open().unwrap();
        let config = HyperRuntimeConfig {
            db: Arc::new(db),
            srs,
            mempool_capacity: 100,
            score_weights: ScoreWeights::default(),
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

    /// Install `parties` synthetic bootstrap validators (sorted
    /// validator_keys = `[1;32], [2;32], …`) with random transport
    /// pubkeys. Required by tests that exercise the DKLS multi-
    /// party path post-Phase-2f: the gossip layer encrypts P2P
    /// round messages to each receiver's transport pubkey, so the
    /// active set must have one registered for every party in the
    /// ceremony.
    fn install_test_active_set(runtime: &mut HyperRuntime, parties: u8) {
        let mut bootstrap = Vec::with_capacity(parties as usize);
        for i in 1..=parties {
            let validator_key = vec![i; 32];
            // Random transport pubkey. The seal path never derives
            // the secret half — for these tests the receiver never
            // actually attempts to open, so any 32 bytes that
            // X25519 accepts as a public point works (which is all
            // 32-byte values).
            let mut transport_pk = [0u8; 32];
            rand::Rng::fill(&mut OsRng, &mut transport_pk);
            bootstrap.push((validator_key, Vec::new(), transport_pk.to_vec()));
        }
        runtime.bootstrap_validators = bootstrap;
    }

    fn sample_lock(byte: u8) -> proto::HyperLockEvent {
        proto::HyperLockEvent {
            amount: 1_000_000,
            dest_chain_id: 1,
            dest_address: vec![0xab; 20],
            spend_pubkey: vec![0x02; 33],
            lock_id: vec![byte; 32],
            lock_height: 100,
            lock_timestamp: 1_700_000_000,
            lock_signature: vec![0u8; 64],
        }
    }

    fn install_single_validator(runtime: &mut HyperRuntime) {
        // 1-of-1 DKLS share for single-validator devnet test setups.
        // Pinned session_id so different tests using this helper still
        // get the SAME group address (handy when one test produces a
        // block another test reads back).
        let dkg =
            hypersnap_crypto::dkls_threshold::run_honest_dkg(1, 1, [0xc7; 32]).expect("1-of-1 dkg");
        runtime.install_local_dkls_share(0, 1, dkg.parties[0].clone(), dkg.group_address);
    }

    #[tokio::test]
    async fn inbound_message_lands_in_mempool() {
        let mut rng = OsRng;
        let srs = Arc::new(KzgSrs::random_unsafe(&mut rng, VERKLE_DOMAIN));
        let (runtime, _dir) = make_runtime_with_srs(srs);
        let outbound = HyperActor::drive_events(
            runtime,
            vec![HyperActorEvent::InboundMessage(HyperRouter::outbound_lock(
                sample_lock(1),
            ))],
        )
        .await;
        // No outbound; the message is just in the mempool.
        assert!(
            outbound
                .iter()
                .all(|o| !matches!(o, HyperActorOutbound::BroadcastBlock(_))),
            "should not have produced a block on a mere inbound message"
        );
    }

    #[tokio::test]
    async fn produce_block_emits_broadcast_and_advances_chain() {
        let mut rng = OsRng;
        let srs = Arc::new(KzgSrs::random_unsafe(&mut rng, VERKLE_DOMAIN));
        let (mut runtime, _dir) = make_runtime_with_srs(srs);
        install_single_validator(&mut runtime);

        let outbound = HyperActor::drive_events(
            runtime,
            vec![
                HyperActorEvent::InboundMessage(HyperRouter::outbound_lock(sample_lock(1))),
                HyperActorEvent::ProduceBlockDkls {
                    height: 0,
                    parent_hash: vec![],
                    extra_rules_version: 0,
                    snapchain_anchor_block: 0,
                    snapchain_anchor_hash: vec![],
                    snapchain_anchor_timestamp: 0,
                },
            ],
        )
        .await;

        let block_count = outbound
            .iter()
            .filter(|o| matches!(o, HyperActorOutbound::BroadcastBlock(_)))
            .count();
        assert_eq!(block_count, 1, "expected exactly one BroadcastBlock");

        let err_count = outbound
            .iter()
            .filter(|o| matches!(o, HyperActorOutbound::EventError(_)))
            .count();
        assert_eq!(err_count, 0, "no errors expected; got {:?}", outbound);
    }

    #[tokio::test]
    async fn produce_block_dkls_signs_and_broadcasts_with_one_of_one_share() {
        // Single-validator devnet path through the actor: install a
        // 1-of-1 DKLS share, fire ProduceBlockDkls, observe a
        // BroadcastBlock outbound carrying a DKLS-shape signature
        // that recovers to the installed group address.
        let mut rng = OsRng;
        let srs = Arc::new(KzgSrs::random_unsafe(&mut rng, VERKLE_DOMAIN));
        let (mut runtime, _dir) = make_runtime_with_srs(srs);
        let dkg =
            hypersnap_crypto::dkls_threshold::run_honest_dkg(1, 1, [0xa1; 32]).expect("1-of-1 dkg");
        runtime.install_local_dkls_share(0, 1, dkg.parties[0].clone(), dkg.group_address);

        let outbound = HyperActor::drive_events(
            runtime,
            vec![HyperActorEvent::ProduceBlockDkls {
                height: 0,
                parent_hash: vec![],
                extra_rules_version: 0,
                snapchain_anchor_block: 0,
                snapchain_anchor_hash: vec![],
                snapchain_anchor_timestamp: 0,
            }],
        )
        .await;

        let blocks: Vec<&HyperBlock> = outbound
            .iter()
            .filter_map(|o| match o {
                HyperActorOutbound::BroadcastBlock(b) => Some(b),
                _ => None,
            })
            .collect();
        assert_eq!(
            blocks.len(),
            1,
            "expected exactly one BroadcastBlock, got outbound={:?}",
            outbound
        );
        let block = blocks[0];
        // ECDSA-shape signature; legacy BLS fields empty.
        assert_eq!(block.signature.ecdsa_signature.len(), 65);
        assert_eq!(
            block.signature.group_address.as_slice(),
            dkg.group_address.as_slice()
        );
        assert_eq!(block.signature.signer_indices, vec![1u64]);

        // Verify via the same dispatch consensus runs on imports.
        let payload = block
            .envelope
            .metadata
            .signing_payload(block.signature.epoch);
        let group_addr = dkg.group_address;
        let expected = crate::hyper::sig_verify::ExpectedGroupKey::ecdsa_only(&group_addr);
        crate::hyper::sig_verify::verify_hyperblock_signature(
            &payload,
            &block.signature.ecdsa_signature,
            &block.signature.group_address,
            &expected,
        )
        .expect("verify");

        // No errors emitted.
        let err_count = outbound
            .iter()
            .filter(|o| matches!(o, HyperActorOutbound::EventError(_)))
            .count();
        assert_eq!(
            err_count, 0,
            "expected no errors; got outbound={:?}",
            outbound
        );
    }

    #[tokio::test]
    async fn evaluate_epoch_dkls_emits_signed_issuances_and_snapshot() {
        // Single-validator devnet: install 1-of-1 DKLS share for
        // epoch 0, fire EvaluateEpochDkls, expect ECDSA-signed
        // issuance + snapshot HyperMessages on the outbound channel.
        let mut rng = OsRng;
        let srs = Arc::new(KzgSrs::random_unsafe(&mut rng, VERKLE_DOMAIN));
        let (mut runtime, _dir) = make_runtime_with_srs(srs);
        let dkg =
            hypersnap_crypto::dkls_threshold::run_honest_dkg(1, 1, [0xc1; 32]).expect("1-of-1 dkg");
        runtime.install_local_dkls_share(0, 1, dkg.parties[0].clone(), dkg.group_address);

        let outbound = HyperActor::drive_events(
            runtime,
            vec![HyperActorEvent::EvaluateEpochDkls {
                epoch: 0,
                anchor_block: 0,
                anchor_timestamp: 1_700_000_000,
            }],
        )
        .await;

        // Three issuances (one per WorkMarket) + one trust snapshot
        // = four BroadcastMessage emissions.
        let messages: Vec<&proto::HyperMessage> = outbound
            .iter()
            .filter_map(|o| match o {
                HyperActorOutbound::BroadcastMessage(m) => Some(m),
                _ => None,
            })
            .collect();
        assert_eq!(
            messages.len(),
            4,
            "expected 3 issuances + 1 snapshot, got outbound={:?}",
            outbound
        );

        // All issuances carry an ECDSA-shape sig with the BLS field empty.
        let mut issuance_count = 0;
        let mut snapshot_count = 0;
        for m in &messages {
            match m.body.as_ref().expect("body") {
                proto::hyper_message::Body::RewardIssuance(iss) => {
                    issuance_count += 1;
                    assert_eq!(iss.ecdsa_signature.len(), 65);
                }
                proto::hyper_message::Body::TrustSnapshotUpdate(snap) => {
                    snapshot_count += 1;
                    assert_eq!(snap.ecdsa_signature.len(), 65);
                }
                other => panic!("unexpected body kind: {:?}", other),
            }
        }
        assert_eq!(issuance_count, 3);
        assert_eq!(snapshot_count, 1);

        let err_count = outbound
            .iter()
            .filter(|o| matches!(o, HyperActorOutbound::EventError(_)))
            .count();
        assert_eq!(err_count, 0, "no errors expected; got {:?}", outbound);
    }

    #[tokio::test]
    async fn evaluate_epoch_dkls_multi_party_enqueues_and_starts_first_ceremony() {
        // 2-of-3 DKLS share installed at party 1: EvaluateEpochDkls
        // takes the multi-party path. With 4 unsigned messages
        // (3 issuances + 1 snapshot) and party 1 in some subset of
        // the committees, we expect at least one BroadcastDklsSign
        // outbound (the first ceremony's phase-1 fragments to peers)
        // and zero finalized BroadcastMessage emissions (no peer
        // ever responds, so the ceremony can't complete).
        let mut rng = OsRng;
        let srs = Arc::new(KzgSrs::random_unsafe(&mut rng, VERKLE_DOMAIN));
        let (mut runtime, _dir) = make_runtime_with_srs(srs);
        // Post-Phase-2f: the multi-party sign flow encrypts P2P
        // round messages to each party's transport pubkey, so the
        // active set must have all three peers registered or the
        // outbound seal drops them as "would leak secret material".
        install_test_active_set(&mut runtime, 3);
        let dkg =
            hypersnap_crypto::dkls_threshold::run_honest_dkg(2, 3, [0xd1; 32]).expect("2-of-3 dkg");
        runtime.install_local_dkls_share(0, 1, dkg.parties[0].clone(), dkg.group_address);

        let outbound = HyperActor::drive_events(
            runtime,
            vec![HyperActorEvent::EvaluateEpochDkls {
                epoch: 0,
                anchor_block: 0,
                anchor_timestamp: 1_700_000_000,
            }],
        )
        .await;

        // No BroadcastMessage finalizations: peers haven't responded,
        // so no ceremony reached phase 4.
        let finalized: Vec<_> = outbound
            .iter()
            .filter_map(|o| match o {
                HyperActorOutbound::BroadcastMessage(m) => Some(m),
                _ => None,
            })
            .collect();
        assert!(
            finalized.is_empty(),
            "no peers ⇒ no finalized broadcasts; got {:?}",
            finalized.iter().map(|m| m.message_type).collect::<Vec<_>>()
        );

        // BUT there should be at least one DklsSign outbound — the
        // committee selection puts party 1 into at least one of the
        // four committees with overwhelming probability for the
        // pinned session_id (3-of-4 selection with 4 trials = ≥1 hit
        // at probability ≈ 0.96; the deterministic seed makes this
        // assertion stable).
        let sign_outbound: Vec<_> = outbound
            .iter()
            .filter(|o| matches!(o, HyperActorOutbound::BroadcastDklsSign { .. }))
            .collect();
        assert!(
            !sign_outbound.is_empty(),
            "expected at least one BroadcastDklsSign for the first ceremony; got {:?}",
            outbound
        );
    }

    /// FIP §13.6 1-of-1 end-to-end: a watcher-observed burn in the
    /// local `BridgeBurnStore` plus a 1-of-1 DKLS share leads to
    /// `EvaluateEpochDkls` signing the burn, applying it locally
    /// (recipient FID balance credited), and emitting an
    /// `InboundBurn` HyperMessage on the outbound channel.
    #[tokio::test]
    async fn evaluate_epoch_dkls_single_party_drains_inbound_burns() {
        let mut rng = OsRng;
        let srs = Arc::new(KzgSrs::random_unsafe(&mut rng, VERKLE_DOMAIN));
        let (mut runtime, _dir) = make_runtime_with_srs(srs);
        // 1-of-1 share so the fast inline path fires.
        let dkg = hypersnap_crypto::dkls_threshold::run_honest_dkg(1, 1, [0xab; 32]).unwrap();
        runtime.install_local_dkls_share(0, 1, dkg.parties[0].clone(), dkg.group_address);
        // Seed an observed burn.
        let observed = proto::HyperObservedBurn {
            source_chain_id: 10,
            burn_id: vec![0xab; 32],
            recipient_fid: 42,
            amount: 1_000_000,
            source_block_number: 12345,
            source_tx_hash: vec![0xcd; 32],
            observed_at_unix: 1_700_000_000,
        };
        runtime.bridge_burn_store.record(&observed).unwrap();

        let outbound = HyperActor::drive_events(
            runtime,
            vec![HyperActorEvent::EvaluateEpochDkls {
                epoch: 0,
                anchor_block: 0,
                anchor_timestamp: 1_700_000_000,
            }],
        )
        .await;

        // The single-party path runs scoring + lock-root + inbound
        // inline; the inbound-burn flow emits a BroadcastMessage of
        // type InboundBurn.
        let inbound_burns: Vec<_> = outbound
            .iter()
            .filter_map(|o| match o {
                HyperActorOutbound::BroadcastMessage(m)
                    if m.message_type == proto::HyperMessageType::InboundBurn as i32 =>
                {
                    Some(m)
                }
                _ => None,
            })
            .collect();
        assert_eq!(
            inbound_burns.len(),
            1,
            "expected exactly one InboundBurn broadcast; got {:?}",
            outbound
        );
        // The body carries the observed (source_chain_id, burn_id).
        let body = inbound_burns[0].body.as_ref().unwrap();
        if let proto::hyper_message::Body::InboundBurn(b) = body {
            assert_eq!(b.source_chain_id, 10);
            assert_eq!(b.burn_id, vec![0xab; 32]);
            assert_eq!(b.recipient_fid, 42);
            assert_eq!(b.amount, 1_000_000);
            assert_eq!(b.ecdsa_signature.len(), 65);
        } else {
            panic!("expected InboundBurn body");
        }
    }

    /// Already-processed burns are not re-signed at subsequent
    /// epoch boundaries.
    #[tokio::test]
    async fn evaluate_epoch_dkls_skips_processed_inbound_burns() {
        let mut rng = OsRng;
        let srs = Arc::new(KzgSrs::random_unsafe(&mut rng, VERKLE_DOMAIN));
        let (mut runtime, _dir) = make_runtime_with_srs(srs);
        let dkg = hypersnap_crypto::dkls_threshold::run_honest_dkg(1, 1, [0xab; 32]).unwrap();
        runtime.install_local_dkls_share(0, 1, dkg.parties[0].clone(), dkg.group_address);
        let observed = proto::HyperObservedBurn {
            source_chain_id: 10,
            burn_id: vec![0xab; 32],
            recipient_fid: 42,
            amount: 1_000_000,
            source_block_number: 12345,
            source_tx_hash: vec![0xcd; 32],
            observed_at_unix: 0,
        };
        runtime.bridge_burn_store.record(&observed).unwrap();
        // Pre-apply: produce + apply a signed burn so the
        // processed marker exists already.
        let signed = runtime
            .produce_signed_inbound_burn_local(0, &observed)
            .unwrap();
        runtime.apply_inbound_burn(&signed).unwrap();
        let balance_before = runtime.reward_store.balance_of(42).unwrap();

        let outbound = HyperActor::drive_events(
            runtime,
            vec![HyperActorEvent::EvaluateEpochDkls {
                epoch: 0,
                anchor_block: 0,
                anchor_timestamp: 1_700_000_000,
            }],
        )
        .await;
        // No additional InboundBurn broadcasts.
        let count = outbound
            .iter()
            .filter(|o| {
                matches!(
                    o,
                    HyperActorOutbound::BroadcastMessage(m)
                        if m.message_type == proto::HyperMessageType::InboundBurn as i32
                )
            })
            .count();
        assert_eq!(count, 0, "must not re-broadcast already-processed burns");
        assert_eq!(balance_before, 1_000_000);
    }

    #[tokio::test]
    async fn evaluate_epoch_dkls_multi_party_no_op_without_share() {
        // Without a DKLS share for the epoch, EvaluateEpochDkls
        // (multi-party flavor entered because 1-of-1 fast path
        // requires a share) is a silent no-op.
        let mut rng = OsRng;
        let srs = Arc::new(KzgSrs::random_unsafe(&mut rng, VERKLE_DOMAIN));
        let (runtime, _dir) = make_runtime_with_srs(srs);
        let outbound = HyperActor::drive_events(
            runtime,
            vec![HyperActorEvent::EvaluateEpochDkls {
                epoch: 0,
                anchor_block: 0,
                anchor_timestamp: 1_700_000_000,
            }],
        )
        .await;
        // Nothing should escape the actor.
        let any_dkls = outbound
            .iter()
            .any(|o| matches!(o, HyperActorOutbound::BroadcastDklsSign { .. }));
        let any_finalized = outbound
            .iter()
            .any(|o| matches!(o, HyperActorOutbound::BroadcastMessage(_)));
        assert!(!any_dkls);
        assert!(!any_finalized);
    }

    #[tokio::test]
    async fn produce_block_dkls_no_op_without_local_share() {
        // No DKLS share installed → ProduceBlockDkls is a silent
        // no-op (some other validator with a share will produce).
        let mut rng = OsRng;
        let srs = Arc::new(KzgSrs::random_unsafe(&mut rng, VERKLE_DOMAIN));
        let (runtime, _dir) = make_runtime_with_srs(srs);
        let outbound = HyperActor::drive_events(
            runtime,
            vec![HyperActorEvent::ProduceBlockDkls {
                height: 0,
                parent_hash: vec![],
                extra_rules_version: 0,
                snapchain_anchor_block: 0,
                snapchain_anchor_hash: vec![],
                snapchain_anchor_timestamp: 0,
            }],
        )
        .await;
        // Either an EventError carrying NoDklsShare, or a clean
        // no-op with no broadcasts. Both are acceptable; what
        // matters is that no malformed BroadcastBlock landed.
        let block_count = outbound
            .iter()
            .filter(|o| matches!(o, HyperActorOutbound::BroadcastBlock(_)))
            .count();
        assert_eq!(block_count, 0);
    }

    /// FIP §13.5/§13.4 multi-party lock-root signing. With a 2-of-3
    /// share installed and a non-empty lock set, EvaluateEpochDkls
    /// must enqueue the lock-root sign task into the same DKLS
    /// sign queue that scoring uses. Pin: at least one
    /// `BroadcastDklsSign` outbound (the first ceremony's
    /// fragments). We can't easily disambiguate scoring vs.
    /// lock-root in the outbound stream without inspecting actor
    /// internals, but the count uplift validates the wiring.
    #[tokio::test]
    async fn evaluate_epoch_dkls_multi_party_includes_lock_root_sign() {
        use ed25519_dalek::{Signer, SigningKey};
        let mut rng = OsRng;
        let srs = Arc::new(KzgSrs::random_unsafe(&mut rng, VERKLE_DOMAIN));
        let (mut runtime, _dir) = make_runtime_with_srs(srs);
        // Post-Phase-2f: transport pubkeys required for all peers.
        install_test_active_set(&mut runtime, 3);
        let dkg =
            hypersnap_crypto::dkls_threshold::run_honest_dkg(2, 3, [0xd2; 32]).expect("2-of-3 dkg");
        runtime.install_local_dkls_share(0, 1, dkg.parties[0].clone(), dkg.group_address);
        // Set a chain height so `last_block_height()` returns Some
        // — otherwise the lock-root path silently no-ops.
        runtime.chain = crate::hyper::chain::ChainTracker::from_state([0u8; 32], 100);

        // Seed an authorized signer + lock so the merkle tree is
        // non-empty (a zero-leaf tree would still sign, but a
        // realistic state pins behavior closer to production).
        let sk = SigningKey::from_bytes(&[3u8; 32]);
        {
            use crate::storage::store::account::{OnchainEventStore, StoreEventHandler};
            use crate::utils::factory::events_factory;
            let onchain =
                OnchainEventStore::new(runtime.db.clone(), StoreEventHandler::new_no_persist());
            let event = events_factory::create_signer_event(
                1,
                sk.clone(),
                proto::SignerEventType::Add,
                None,
                None,
            );
            let mut txn = crate::storage::db::RocksDbTransactionBatch::new();
            onchain.merge_onchain_event(event, &mut txn).unwrap();
            runtime.db.commit(txn).unwrap();
        }
        runtime
            .reward_store
            .credit_if_unissued(0, 1, proto::WorkMarket::Growth as i32, 5_000)
            .unwrap();
        let pk = sk.verifying_key();
        let mut body = proto::TokenLockBody {
            sender_fid: 1,
            amount: 1_000,
            nonce: 1,
            destination_chain_id: 10,
            destination_address: vec![0xab; 20],
            lock_id: vec![0xcc; 32],
            signer_pubkey: pk.to_bytes().to_vec(),
            signature: Vec::new(),
        };
        let payload = crate::hyper::token_lock::token_lock_signing_payload(&body);
        body.signature = sk.sign(&payload).to_bytes().to_vec();
        runtime
            .submit_message(proto::HyperMessage {
                message_type: proto::HyperMessageType::TokenLock as i32,
                body: Some(proto::hyper_message::Body::TokenLock(body)),
            })
            .unwrap();

        let outbound = HyperActor::drive_events(
            runtime,
            vec![HyperActorEvent::EvaluateEpochDkls {
                epoch: 0,
                anchor_block: 0,
                anchor_timestamp: 1_700_000_000,
            }],
        )
        .await;

        // No finalized broadcasts (no peers) but at least one
        // BroadcastDklsSign — the first ceremony in the queue.
        let sign_count = outbound
            .iter()
            .filter(|o| matches!(o, HyperActorOutbound::BroadcastDklsSign { .. }))
            .count();
        assert!(
            sign_count >= 1,
            "multi-party lock-root path should enqueue ≥ 1 ceremony; sign_count={}",
            sign_count
        );
        let finalized: Vec<_> = outbound
            .iter()
            .filter_map(|o| match o {
                HyperActorOutbound::BroadcastMessage(m) => Some(m.message_type),
                _ => None,
            })
            .collect();
        assert!(
            finalized.is_empty(),
            "no peers ⇒ no finalized broadcasts; got {:?}",
            finalized
        );
    }

    /// Two-actor end-to-end: proposer produces and broadcasts, importer
    /// consumes the broadcast and advances. This is the integration shape
    /// the gossip layer will adopt.
    #[tokio::test]
    async fn two_actors_proposer_importer_round_trip() {
        let mut rng = OsRng;
        let srs = Arc::new(KzgSrs::random_unsafe(&mut rng, VERKLE_DOMAIN));

        let (mut proposer, _pdir) = make_runtime_with_srs(srs.clone());
        let (importer, _idir) = make_runtime_with_srs(srs);

        // Both nodes share the same epoch's DKLS group address.
        // Proposer also has the local share for signing.
        let dkg =
            hypersnap_crypto::dkls_threshold::run_honest_dkg(1, 1, [0xd9; 32]).expect("1-of-1 dkg");
        proposer.install_local_dkls_share(0, 1, dkg.parties[0].clone(), dkg.group_address);
        let _ = &mut rng;

        // Submit a lock to the proposer.
        let lock = sample_lock(0xaa);
        proposer
            .submit_message(HyperRouter::outbound_lock(lock.clone()))
            .unwrap();

        // Drive the proposer to produce + broadcast a block.
        let proposer_out = HyperActor::drive_events(
            proposer,
            vec![HyperActorEvent::ProduceBlockDkls {
                height: 0,
                parent_hash: vec![],
                extra_rules_version: 0,
                snapchain_anchor_block: 0,
                snapchain_anchor_hash: vec![],
                snapchain_anchor_timestamp: 0,
            }],
        )
        .await;

        let block = proposer_out
            .into_iter()
            .find_map(|o| match o {
                HyperActorOutbound::BroadcastBlock(b) => Some(b),
                _ => None,
            })
            .expect("proposer should have broadcast a block");

        // The importer needs to know the same lock was in the payload.
        // (The gossip wire format will carry locks alongside the block.)
        let importer_out = HyperActor::drive_events(
            {
                let mut imp = importer;
                imp.install_dkls_group_address(0, dkg.group_address);
                imp
            },
            vec![HyperActorEvent::InboundBlock {
                block,
                locks: vec![lock],
                transfers: vec![],
            }],
        )
        .await;

        let err_count = importer_out
            .iter()
            .filter(|o| matches!(o, HyperActorOutbound::EventError(_)))
            .count();
        assert_eq!(
            err_count, 0,
            "import should have succeeded; got {:?}",
            importer_out
        );
    }

    #[tokio::test]
    async fn client_queries_round_trip_through_actor() {
        let mut rng = OsRng;
        let srs = Arc::new(KzgSrs::random_unsafe(&mut rng, VERKLE_DOMAIN));
        let (runtime, _dir) = make_runtime_with_srs(srs);
        let handles = HyperActor::spawn(runtime, 16);
        let client = HyperActorClient::new(handles.inbound.clone());

        // Pre-genesis: no head, no epoch yet.
        assert_eq!(client.last_block_height().await.unwrap(), None);
        assert_eq!(client.last_block_hash().await.unwrap(), None);
        assert_eq!(client.current_epoch().await.unwrap(), 0);
        assert_eq!(client.pending_count().await.unwrap(), 0);

        // Submit a message → mempool grows.
        handles
            .inbound
            .send(HyperActorEvent::InboundMessage(HyperRouter::outbound_lock(
                sample_lock(0xee),
            )))
            .await
            .unwrap();
        // Allow the actor to drain the inbound; await the count query as
        // a built-in synchronization point (the query runs after the
        // earlier event has been dispatched).
        assert_eq!(client.pending_count().await.unwrap(), 1);

        // Block lookup for an unknown height returns None.
        assert!(client.get_block_by_height(99).await.unwrap().is_none());
        assert!(client.get_block_by_hash([0u8; 32]).await.unwrap().is_none());

        // Cleanly shut down the actor.
        handles
            .inbound
            .send(HyperActorEvent::Shutdown)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn client_validator_score_and_evidence_round_trip() {
        let mut rng = OsRng;
        let srs = Arc::new(KzgSrs::random_unsafe(&mut rng, VERKLE_DOMAIN));
        let (mut runtime, _dir) = make_runtime_with_srs(srs);

        // Pre-populate state via the runtime (not via actor) so the
        // assertions are about the query path, not the recording path.
        let v = vec![0xa1u8; 32];
        runtime
            .score_tracker
            .record_successful_proposal(0, &v)
            .unwrap();

        // Persist evidence for epoch 4.
        use crate::hyper::slashing::ConflictingBlocksEvidence;
        use crate::hyper::{HyperBlockMetadata, HyperBlockSignature, HyperEnvelope};
        let mk = |state_root: u8| HyperBlock {
            envelope: HyperEnvelope {
                metadata: HyperBlockMetadata {
                    canonical_block_id: 1,
                    parent_hash: vec![0u8; 32],
                    hyper_state_root: vec![state_root; 48],
                    extra_rules_version: 0,
                    retained_message_count: 0,
                    missed_proposals: vec![],
                    snapchain_anchor_block: 0,
                    snapchain_anchor_hash: vec![],

                    snapchain_range_start_block: 0,

                    snapchain_range_root: vec![],
                    snapchain_anchor_timestamp: 0,
                },
                payload: vec![],
            },
            signature: HyperBlockSignature {
                epoch: 4,
                signer_indices: vec![1],
                group_address: Vec::new(),
                ecdsa_signature: Vec::new(),
            },
        };
        runtime
            .record_evidence(&ConflictingBlocksEvidence {
                epoch: 4,
                canonical_block_id: 1,
                block_a_hash: [0xaa; 32],
                block_b_hash: [0xbb; 32],
                block_a: Box::new(mk(0xaa)),
                block_b: Box::new(mk(0xbb)),
            })
            .unwrap();

        let handles = HyperActor::spawn(runtime, 16);
        let client = HyperActorClient::new(handles.inbound.clone());

        // Score query.
        let score = client.validator_score(0, v.clone()).await.unwrap().unwrap();
        assert_eq!(score.successful_proposals, 1);

        // Evidence query.
        let ev = client.evidence_for_epoch(4).await.unwrap().unwrap();
        assert_eq!(ev.len(), 1);

        // Empty epoch returns empty.
        let none = client.evidence_for_epoch(99).await.unwrap().unwrap();
        assert!(none.is_empty());

        handles
            .inbound
            .send(HyperActorEvent::Shutdown)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn client_active_validators_uses_runtime_bootstrap() {
        let mut rng = OsRng;
        let srs = Arc::new(KzgSrs::random_unsafe(&mut rng, VERKLE_DOMAIN));
        // Build a runtime with a non-empty bootstrap set.
        let dir = tempfile::TempDir::new().unwrap();
        let db = crate::storage::db::RocksDB::new(dir.path().to_str().unwrap());
        db.open().unwrap();
        let bootstrap: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> = (1u8..=3)
            .map(|i| (vec![i; 32], vec![i; 48], vec![i; 32]))
            .collect();
        let config = HyperRuntimeConfig {
            db: std::sync::Arc::new(db),
            srs,
            mempool_capacity: 100,
            score_weights: ScoreWeights::default(),
            bootstrap_validators: bootstrap.clone(),
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
        let runtime = HyperRuntime::new(config);

        let handles = HyperActor::spawn(runtime, 16);
        let client = HyperActorClient::new(handles.inbound.clone());

        // Raw active set — all 3 bootstrap validators.
        let raw = client.active_validators(0, false).await.unwrap().unwrap();
        assert_eq!(raw.len(), 3);
        assert!(raw.contains_key(&vec![1u8; 32]));

        // Enforced at epoch 0 — same (no prior epoch).
        let enf = client.active_validators(0, true).await.unwrap().unwrap();
        assert_eq!(enf.len(), 3);

        handles
            .inbound
            .send(HyperActorEvent::Shutdown)
            .await
            .unwrap();
        drop(dir);
    }

    #[tokio::test]
    async fn client_slashed_validators_round_trip() {
        use crate::hyper::slashing::ConflictingBlocksEvidence;
        use crate::hyper::{HyperBlockMetadata, HyperBlockSignature, HyperEnvelope};

        let mut rng = OsRng;
        let srs = Arc::new(KzgSrs::random_unsafe(&mut rng, VERKLE_DOMAIN));
        let dir = tempfile::TempDir::new().unwrap();
        let db = crate::storage::db::RocksDB::new(dir.path().to_str().unwrap());
        db.open().unwrap();
        // Bootstrap with 4 validators in deterministic key order.
        let bootstrap: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> = (1u8..=4)
            .map(|i| (vec![i; 32], vec![i; 48], vec![i; 32]))
            .collect();
        let config = HyperRuntimeConfig {
            db: std::sync::Arc::new(db),
            srs,
            mempool_capacity: 100,
            score_weights: ScoreWeights::default(),
            bootstrap_validators: bootstrap.clone(),
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
        let runtime = HyperRuntime::new(config);

        // Persist evidence at epoch 0 with signer indices [2, 4].
        // BTreeMap iteration order over keys = vk(1..=4) sorted →
        // index 2 is vk(2), index 4 is vk(4).
        let mk = |state_root: u8| HyperBlock {
            envelope: HyperEnvelope {
                metadata: HyperBlockMetadata {
                    canonical_block_id: 1,
                    parent_hash: vec![0u8; 32],
                    hyper_state_root: vec![state_root; 48],
                    extra_rules_version: 0,
                    retained_message_count: 0,
                    missed_proposals: vec![],
                    snapchain_anchor_block: 0,
                    snapchain_anchor_hash: vec![],

                    snapchain_range_start_block: 0,

                    snapchain_range_root: vec![],
                    snapchain_anchor_timestamp: 0,
                },
                payload: vec![],
            },
            signature: HyperBlockSignature {
                epoch: 0,
                signer_indices: vec![2, 4],
                group_address: Vec::new(),
                ecdsa_signature: Vec::new(),
            },
        };
        runtime
            .record_evidence(&ConflictingBlocksEvidence {
                epoch: 0,
                canonical_block_id: 1,
                block_a_hash: [0xaa; 32],
                block_b_hash: [0xbb; 32],
                block_a: Box::new(mk(0xaa)),
                block_b: Box::new(mk(0xbb)),
            })
            .unwrap();

        let handles = HyperActor::spawn(runtime, 16);
        let client = HyperActorClient::new(handles.inbound.clone());

        let slashed = client.slashed_validators(0).await.unwrap().unwrap();
        assert_eq!(slashed.len(), 2);
        assert!(slashed.contains(&vec![2u8; 32]));
        assert!(slashed.contains(&vec![4u8; 32]));
        assert!(!slashed.contains(&vec![1u8; 32]));
        assert!(!slashed.contains(&vec![3u8; 32]));

        // No evidence at epoch 1 → empty.
        let none = client.slashed_validators(1).await.unwrap().unwrap();
        assert!(none.is_empty());

        handles
            .inbound
            .send(HyperActorEvent::Shutdown)
            .await
            .unwrap();
        drop(dir);
    }

    #[tokio::test]
    async fn client_returns_inbound_closed_when_actor_gone() {
        let mut rng = OsRng;
        let srs = Arc::new(KzgSrs::random_unsafe(&mut rng, VERKLE_DOMAIN));
        let (runtime, _dir) = make_runtime_with_srs(srs);
        let handles = HyperActor::spawn(runtime, 4);
        let client = HyperActorClient::new(handles.inbound.clone());

        // Shut the actor down and drop the original sender.
        handles
            .inbound
            .send(HyperActorEvent::Shutdown)
            .await
            .unwrap();
        drop(handles.inbound);
        // Give the actor task a moment to exit.
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;

        // After the actor exits, sending on its receiver fails →
        // the client surfaces InboundClosed.
        let r = client.last_block_height().await;
        assert!(matches!(r, Err(HyperActorClientError::InboundClosed)));
    }

    #[tokio::test]
    async fn inbound_evidence_emits_evidence_confirmed_for_valid_conflict() {
        use crate::hyper::{HyperBlockMetadata, HyperBlockSignature, HyperEnvelope};
        use alloy_primitives::keccak256;

        let mut rng = OsRng;
        let srs = Arc::new(KzgSrs::random_unsafe(&mut rng, VERKLE_DOMAIN));
        let (mut runtime, _dir) = make_runtime_with_srs(srs);

        // Install a 1-of-1 DKG for the conflict epoch so the actor's
        // signature gate has a group key to verify against.
        let dkg =
            hypersnap_crypto::dkls_threshold::run_honest_dkg(1, 1, [0xee; 32]).expect("1-of-1 dkg");
        runtime.install_local_dkls_share(3, 1, dkg.parties[0].clone(), dkg.group_address);

        // Two blocks at same height + epoch, distinct state roots,
        // each properly signed under the epoch-3 group key.
        let mut make = |state_root: u8| {
            let mut block = HyperBlock {
                envelope: HyperEnvelope {
                    metadata: HyperBlockMetadata {
                        canonical_block_id: 7,
                        parent_hash: vec![0u8; 32],
                        hyper_state_root: vec![state_root; 48],
                        extra_rules_version: 0,
                        retained_message_count: 0,
                        missed_proposals: vec![],
                        snapchain_anchor_block: 0,
                        snapchain_anchor_hash: vec![],
                        snapchain_range_start_block: 0,
                        snapchain_range_root: vec![],
                        snapchain_anchor_timestamp: 0,
                    },
                    payload: vec![],
                },
                signature: HyperBlockSignature {
                    epoch: 3,
                    signer_indices: vec![1],
                    group_address: dkg.group_address.as_slice().to_vec(),
                    ecdsa_signature: Vec::new(),
                },
            };
            let payload = block
                .envelope
                .metadata
                .signing_payload(block.signature.epoch);
            let digest = keccak256(&payload);
            let sig = hypersnap_crypto::dkls_sign::run_local_dkls_sign(&dkg.parties[0], digest)
                .expect("local sign");
            block.signature.ecdsa_signature = sig.to_bytes().to_vec();
            block
        };

        let outbound = HyperActor::drive_events(
            runtime,
            vec![HyperActorEvent::InboundEvidence {
                block_a: make(0xaa),
                block_b: make(0xbb),
            }],
        )
        .await;

        let confirmed = outbound
            .iter()
            .filter(|o| matches!(o, HyperActorOutbound::EvidenceConfirmed(_)))
            .count();
        assert_eq!(
            confirmed, 1,
            "expected one EvidenceConfirmed; got {:?}",
            outbound
        );
    }

    /// Regression: unauthenticated InboundEvidence frames MUST be
    /// rejected before persistence. Without this gate, any gossip
    /// peer could publish two unsigned blocks naming arbitrary
    /// `signer_indices` and slash arbitrary validators at the next
    /// epoch boundary.
    #[tokio::test]
    async fn inbound_evidence_rejects_unsigned_blocks() {
        use crate::hyper::{HyperBlockMetadata, HyperBlockSignature, HyperEnvelope};

        let mut rng = OsRng;
        let srs = Arc::new(KzgSrs::random_unsafe(&mut rng, VERKLE_DOMAIN));
        let (mut runtime, _dir) = make_runtime_with_srs(srs);
        let dkg =
            hypersnap_crypto::dkls_threshold::run_honest_dkg(1, 1, [0xee; 32]).expect("1-of-1 dkg");
        runtime.install_local_dkls_share(3, 1, dkg.parties[0].clone(), dkg.group_address);

        let make = |state_root: u8| HyperBlock {
            envelope: HyperEnvelope {
                metadata: HyperBlockMetadata {
                    canonical_block_id: 7,
                    parent_hash: vec![0u8; 32],
                    hyper_state_root: vec![state_root; 48],
                    extra_rules_version: 0,
                    retained_message_count: 0,
                    missed_proposals: vec![],
                    snapchain_anchor_block: 0,
                    snapchain_anchor_hash: vec![],
                    snapchain_range_start_block: 0,
                    snapchain_range_root: vec![],
                    snapchain_anchor_timestamp: 0,
                },
                payload: vec![],
            },
            // Attacker-shaped signature: chosen signer_indices, no
            // ECDSA material. Pre-fix this was sufficient to slash
            // every named index.
            signature: HyperBlockSignature {
                epoch: 3,
                signer_indices: vec![1, 2, 3, 4, 5],
                group_address: Vec::new(),
                ecdsa_signature: Vec::new(),
            },
        };

        let outbound = HyperActor::drive_events(
            runtime,
            vec![HyperActorEvent::InboundEvidence {
                block_a: make(0xaa),
                block_b: make(0xbb),
            }],
        )
        .await;

        assert!(
            outbound
                .iter()
                .any(|o| matches!(o, HyperActorOutbound::EventError(_))),
            "expected EventError for unsigned evidence; got {:?}",
            outbound
        );
        assert!(
            !outbound
                .iter()
                .any(|o| matches!(o, HyperActorOutbound::EvidenceConfirmed(_))),
            "unsigned evidence must NOT be confirmed; got {:?}",
            outbound
        );
    }

    /// InboundEvidence for an epoch whose group key isn't yet known
    /// is rejected — prevents an attacker from front-running with
    /// evidence for a future epoch.
    #[tokio::test]
    async fn inbound_evidence_rejects_unknown_epoch_group_key() {
        use crate::hyper::{HyperBlockMetadata, HyperBlockSignature, HyperEnvelope};

        let mut rng = OsRng;
        let srs = Arc::new(KzgSrs::random_unsafe(&mut rng, VERKLE_DOMAIN));
        let (runtime, _dir) = make_runtime_with_srs(srs);
        // NB: no group address installed for epoch 99.

        let make = |state_root: u8| HyperBlock {
            envelope: HyperEnvelope {
                metadata: HyperBlockMetadata {
                    canonical_block_id: 7,
                    parent_hash: vec![0u8; 32],
                    hyper_state_root: vec![state_root; 48],
                    extra_rules_version: 0,
                    retained_message_count: 0,
                    missed_proposals: vec![],
                    snapchain_anchor_block: 0,
                    snapchain_anchor_hash: vec![],
                    snapchain_range_start_block: 0,
                    snapchain_range_root: vec![],
                    snapchain_anchor_timestamp: 0,
                },
                payload: vec![],
            },
            signature: HyperBlockSignature {
                epoch: 99,
                signer_indices: vec![1],
                group_address: Vec::new(),
                ecdsa_signature: vec![0xab; 65],
            },
        };

        let outbound = HyperActor::drive_events(
            runtime,
            vec![HyperActorEvent::InboundEvidence {
                block_a: make(0xaa),
                block_b: make(0xbb),
            }],
        )
        .await;

        assert!(outbound
            .iter()
            .any(|o| matches!(o, HyperActorOutbound::EventError(_))));
        assert!(!outbound
            .iter()
            .any(|o| matches!(o, HyperActorOutbound::EvidenceConfirmed(_))));
    }

    /// Replay of an already-confirmed evidence frame short-circuits
    /// before sig-verify and emits no second `EvidenceConfirmed`.
    #[tokio::test]
    async fn inbound_evidence_dedupes_replays() {
        use crate::hyper::{HyperBlockMetadata, HyperBlockSignature, HyperEnvelope};
        use alloy_primitives::keccak256;

        let mut rng = OsRng;
        let srs = Arc::new(KzgSrs::random_unsafe(&mut rng, VERKLE_DOMAIN));
        let (mut runtime, _dir) = make_runtime_with_srs(srs);
        let dkg =
            hypersnap_crypto::dkls_threshold::run_honest_dkg(1, 1, [0xee; 32]).expect("1-of-1 dkg");
        runtime.install_local_dkls_share(3, 1, dkg.parties[0].clone(), dkg.group_address);

        let make = |state_root: u8| {
            let mut block = HyperBlock {
                envelope: HyperEnvelope {
                    metadata: HyperBlockMetadata {
                        canonical_block_id: 7,
                        parent_hash: vec![0u8; 32],
                        hyper_state_root: vec![state_root; 48],
                        extra_rules_version: 0,
                        retained_message_count: 0,
                        missed_proposals: vec![],
                        snapchain_anchor_block: 0,
                        snapchain_anchor_hash: vec![],
                        snapchain_range_start_block: 0,
                        snapchain_range_root: vec![],
                        snapchain_anchor_timestamp: 0,
                    },
                    payload: vec![],
                },
                signature: HyperBlockSignature {
                    epoch: 3,
                    signer_indices: vec![1],
                    group_address: dkg.group_address.as_slice().to_vec(),
                    ecdsa_signature: Vec::new(),
                },
            };
            let payload = block
                .envelope
                .metadata
                .signing_payload(block.signature.epoch);
            let digest = keccak256(&payload);
            let sig = hypersnap_crypto::dkls_sign::run_local_dkls_sign(&dkg.parties[0], digest)
                .expect("local sign");
            block.signature.ecdsa_signature = sig.to_bytes().to_vec();
            block
        };

        let a = make(0xaa);
        let b = make(0xbb);
        let outbound = HyperActor::drive_events(
            runtime,
            vec![
                HyperActorEvent::InboundEvidence {
                    block_a: a.clone(),
                    block_b: b.clone(),
                },
                // Replay — should be deduped.
                HyperActorEvent::InboundEvidence {
                    block_a: a,
                    block_b: b,
                },
            ],
        )
        .await;

        let confirmed = outbound
            .iter()
            .filter(|o| matches!(o, HyperActorOutbound::EvidenceConfirmed(_)))
            .count();
        assert_eq!(
            confirmed, 1,
            "replay should not produce a second EvidenceConfirmed; got {:?}",
            outbound
        );
        // No EventError either — replay is a quiet drop.
        let errors = outbound
            .iter()
            .filter(|o| matches!(o, HyperActorOutbound::EventError(_)))
            .count();
        assert_eq!(errors, 0);
    }

    #[tokio::test]
    async fn inbound_evidence_with_different_heights_emits_event_error() {
        use crate::hyper::{HyperBlockMetadata, HyperBlockSignature, HyperEnvelope};

        let mut rng = OsRng;
        let srs = Arc::new(KzgSrs::random_unsafe(&mut rng, VERKLE_DOMAIN));
        let (runtime, _dir) = make_runtime_with_srs(srs);

        let make = |height: u64, state_root: u8| HyperBlock {
            envelope: HyperEnvelope {
                metadata: HyperBlockMetadata {
                    canonical_block_id: height,
                    parent_hash: vec![0u8; 32],
                    hyper_state_root: vec![state_root; 48],
                    extra_rules_version: 0,
                    retained_message_count: 0,
                    missed_proposals: vec![],
                    snapchain_anchor_block: 0,
                    snapchain_anchor_hash: vec![],

                    snapchain_range_start_block: 0,

                    snapchain_range_root: vec![],
                    snapchain_anchor_timestamp: 0,
                },
                payload: vec![],
            },
            signature: HyperBlockSignature {
                epoch: 3,
                signer_indices: vec![1],
                group_address: Vec::new(),
                ecdsa_signature: Vec::new(),
            },
        };

        let outbound = HyperActor::drive_events(
            runtime,
            vec![HyperActorEvent::InboundEvidence {
                block_a: make(7, 0xaa),
                block_b: make(8, 0xbb),
            }],
        )
        .await;
        assert!(outbound
            .iter()
            .any(|o| matches!(o, HyperActorOutbound::EventError(_))));
        assert!(!outbound
            .iter()
            .any(|o| matches!(o, HyperActorOutbound::EvidenceConfirmed(_))));
    }

    #[tokio::test]
    async fn local_submit_message_emits_broadcast() {
        let mut rng = OsRng;
        let srs = Arc::new(KzgSrs::random_unsafe(&mut rng, VERKLE_DOMAIN));
        let (runtime, _dir) = make_runtime_with_srs(srs);
        let outbound = HyperActor::drive_events(
            runtime,
            vec![HyperActorEvent::LocalSubmitMessage(
                HyperRouter::outbound_lock(sample_lock(0xab)),
            )],
        )
        .await;
        // Exactly one BroadcastMessage outbound, no errors.
        let broadcasts = outbound
            .iter()
            .filter(|o| matches!(o, HyperActorOutbound::BroadcastMessage(_)))
            .count();
        assert_eq!(broadcasts, 1);
        let errors = outbound
            .iter()
            .filter(|o| matches!(o, HyperActorOutbound::EventError(_)))
            .count();
        assert_eq!(errors, 0);
    }

    #[tokio::test]
    async fn local_submit_does_not_broadcast_on_failure() {
        let mut rng = OsRng;
        let srs = Arc::new(KzgSrs::random_unsafe(&mut rng, VERKLE_DOMAIN));
        let (runtime, _dir) = make_runtime_with_srs(srs);
        // RewardIssuance with no signature → submit_message rejects.
        let bad_msg = proto::HyperMessage {
            message_type: proto::HyperMessageType::RewardIssuance as i32,
            body: Some(proto::hyper_message::Body::RewardIssuance(
                proto::HyperRewardIssuance {
                    epoch: 99,
                    recipients: vec![proto::RewardEntry { fid: 1, amount: 1 }],
                    market: proto::WorkMarket::Growth as i32,
                    ..Default::default()
                },
            )),
        };
        let outbound =
            HyperActor::drive_events(runtime, vec![HyperActorEvent::LocalSubmitMessage(bad_msg)])
                .await;
        // No broadcast (verification fails), but an EventError surfaces.
        let broadcasts = outbound
            .iter()
            .filter(|o| matches!(o, HyperActorOutbound::BroadcastMessage(_)))
            .count();
        assert_eq!(broadcasts, 0);
        let errors = outbound
            .iter()
            .filter(|o| matches!(o, HyperActorOutbound::EventError(_)))
            .count();
        assert_eq!(errors, 1);
    }

    #[tokio::test]
    async fn shutdown_terminates_actor() {
        let mut rng = OsRng;
        let srs = Arc::new(KzgSrs::random_unsafe(&mut rng, VERKLE_DOMAIN));
        let (runtime, _dir) = make_runtime_with_srs(srs);
        let handles = HyperActor::spawn(runtime, 16);
        handles
            .inbound
            .send(HyperActorEvent::Shutdown)
            .await
            .unwrap();
        // Drop the sender so the actor's recv() returns None and the task ends.
        drop(handles.inbound);
        // If the actor task didn't terminate, the test would hang and time out.
    }

    #[tokio::test]
    async fn auto_trigger_fires_evaluate_epoch_on_boundary_crossing() {
        use crate::hyper::epoch::EPOCH_LENGTH;

        let mut rng = OsRng;
        let srs = Arc::new(KzgSrs::random_unsafe(&mut rng, VERKLE_DOMAIN));
        let (mut runtime, _dir) = make_runtime_with_srs(srs);
        // Install 1-of-1 DKLS share for epoch 1 (the one we'll score).
        let dkg =
            hypersnap_crypto::dkls_threshold::run_honest_dkg(1, 1, [0xe5; 32]).expect("1-of-1 dkg");
        runtime.install_local_dkls_share(1, 1, dkg.parties[0].clone(), dkg.group_address);
        let _ = &mut rng;

        let (in_tx, in_rx) = mpsc::channel(8);
        let (out_tx, mut out_rx) = mpsc::channel(16);
        let mut actor = HyperActor {
            runtime,
            active_dkls: None,
            active_dkls_sign: None,
            pending_dkls_blocks: std::collections::BTreeMap::new(),
            pending_dkls_messages: std::collections::BTreeMap::new(),
            pending_sign_queue: std::collections::VecDeque::new(),
            inbound: in_rx,
            outbound: out_tx,
            statsd: None,
            da_response_producer: None,
            last_da_responded_epoch: None,
            last_da_seed_signed_for_epoch: None,
            recent_evidence: std::collections::VecDeque::with_capacity(RECENT_EVIDENCE_CAP),
        };
        // First observation: anchor 0 (epoch 0) → just initialize.
        actor.maybe_trigger_scoring(0, 1_700_000_000).await;
        assert_eq!(actor.runtime.last_scored_epoch, Some(0));

        // Second observation: anchor in epoch 2 → score epoch 1.
        actor
            .maybe_trigger_scoring(EPOCH_LENGTH * 2, 1_705_000_000)
            .await;
        assert_eq!(actor.runtime.last_scored_epoch, Some(1));

        // Drain outbound. Expect 4 BroadcastMessage events for epoch
        // 1 (3 issuances + 1 trust snapshot).
        drop(in_tx);
        drop(actor);
        let mut received = Vec::new();
        while let Some(o) = out_rx.recv().await {
            received.push(o);
        }
        let broadcast_count = received
            .iter()
            .filter(|o| matches!(o, HyperActorOutbound::BroadcastMessage(_)))
            .count();
        assert_eq!(
            broadcast_count, 4,
            "expected 4 broadcasts (3 issuances + 1 trust snapshot), got {}: {:?}",
            broadcast_count, received
        );
    }

    #[tokio::test]
    async fn da_response_driver_fires_at_epoch_boundary() {
        use crate::hyper::da_pow_driver::DaResponseProducer;
        use crate::hyper::epoch::EPOCH_LENGTH;
        use std::sync::Mutex as StdMutex;

        /// Records each `produce_for_epoch` call. Returns one
        /// stub `DaChallengeResponseBody` per invocation so the
        /// actor exercises the broadcast loop (the body fails the
        /// runtime's validate-on-submit gate; that path logs +
        /// skips, which is what we want — keeps the test free of
        /// realistic signer registration plumbing).
        #[derive(Default)]
        struct RecordingProducer {
            calls: StdMutex<Vec<(u64, [u8; 32])>>,
        }
        impl DaResponseProducer for RecordingProducer {
            fn produce_for_epoch(
                &self,
                epoch: u64,
                seed: &[u8],
            ) -> Vec<proto::DaChallengeResponseBody> {
                let mut buf = [0u8; 32];
                let n = seed.len().min(32);
                buf[..n].copy_from_slice(&seed[..n]);
                self.calls.lock().unwrap().push((epoch, buf));
                vec![proto::DaChallengeResponseBody {
                    fid: 1,
                    validator_pubkey: vec![0u8; 32],
                    epoch,
                    challenge_index: 0,
                    served_key: vec![0u8; 32],
                    signer_pubkey: vec![0u8; 32],
                    signature: vec![0u8; 64],
                }]
            }
        }

        let mut rng = OsRng;
        let srs = Arc::new(KzgSrs::random_unsafe(&mut rng, VERKLE_DOMAIN));
        let (runtime, _dir) = make_runtime_with_srs(srs);
        let _ = &mut rng;

        let recording = Arc::new(RecordingProducer::default());
        let producer: Arc<dyn DaResponseProducer> = recording.clone();

        let (in_tx, in_rx) = mpsc::channel(8);
        let (out_tx, mut out_rx) = mpsc::channel(16);
        let mut actor = HyperActor {
            runtime,
            active_dkls: None,
            active_dkls_sign: None,
            pending_dkls_blocks: std::collections::BTreeMap::new(),
            pending_dkls_messages: std::collections::BTreeMap::new(),
            pending_sign_queue: std::collections::VecDeque::new(),
            inbound: in_rx,
            outbound: out_tx,
            statsd: None,
            da_response_producer: Some(producer),
            last_da_responded_epoch: None,
            last_da_seed_signed_for_epoch: None,
            recent_evidence: std::collections::VecDeque::with_capacity(RECENT_EVIDENCE_CAP),
        };

        // No seed for epoch 5 yet → skip silently, watermark unchanged.
        actor.maybe_trigger_da_responses(EPOCH_LENGTH * 5).await;
        assert_eq!(actor.last_da_responded_epoch, None);
        assert!(recording.calls.lock().unwrap().is_empty());

        // Install a committee-signed DaEpochSeed for epoch 5. The
        // helper signs via a deterministic 1-of-1 DKG at signer
        // epoch 4 and applies the resulting body to the runtime.
        let dkg_seed =
            hypersnap_crypto::dkls_threshold::run_honest_dkg(1, 1, [0xa1; 32]).expect("1-of-1 dkg");
        actor.runtime.install_local_dkls_share(
            4,
            1,
            dkg_seed.parties[0].clone(),
            dkg_seed.group_address,
        );
        let payload = crate::hyper::rewards::da_epoch_seed_signing_payload(
            5,
            actor.runtime.protocol_chain_id,
        );
        let digest = alloy_primitives::keccak256(&payload);
        let sig = hypersnap_crypto::dkls_sign::run_local_dkls_sign(&dkg_seed.parties[0], digest)
            .expect("local sign");
        let seed_body = proto::DaEpochSeedBody {
            epoch: 5,
            ecdsa_signature: sig.to_bytes().to_vec(),
        };
        actor
            .runtime
            .apply_da_epoch_seed(&seed_body)
            .expect("seed applied");

        // Now the trigger fires for epoch 5.
        actor.maybe_trigger_da_responses(EPOCH_LENGTH * 5).await;
        assert_eq!(actor.last_da_responded_epoch, Some(5));
        let calls = recording.calls.lock().unwrap().clone();
        assert_eq!(calls.len(), 1, "produce_for_epoch called exactly once");
        assert_eq!(calls[0].0, 5);

        // Same epoch again → idempotent no-op.
        actor
            .maybe_trigger_da_responses(EPOCH_LENGTH * 5 + 10)
            .await;
        assert_eq!(actor.last_da_responded_epoch, Some(5));
        assert_eq!(
            recording.calls.lock().unwrap().len(),
            1,
            "second call within same epoch is suppressed"
        );

        // Drop the channels so the test cleans up.
        drop(in_tx);
        drop(actor);
        // Drain any pending outbound (broadcast attempts for the
        // stub body — the submit_message gate rejects them, so we
        // expect zero BroadcastMessage events).
        let mut broadcasts = 0;
        while let Some(o) = out_rx.recv().await {
            if matches!(o, HyperActorOutbound::BroadcastMessage(_)) {
                broadcasts += 1;
            }
        }
        assert_eq!(
            broadcasts, 0,
            "stub response with empty signer fails validation; no broadcast expected"
        );
    }

    #[tokio::test]
    async fn da_epoch_seed_auto_sign_and_response_uses_v2_seed() {
        use crate::hyper::da_pow_driver::DaResponseProducer;
        use crate::hyper::epoch::EPOCH_LENGTH;
        use std::sync::Mutex as StdMutex;

        /// Stores the seed each `produce_for_epoch` call received
        /// so the test can assert v2 derivation.
        #[derive(Default)]
        struct SeedCapture {
            seeds: StdMutex<Vec<[u8; 32]>>,
        }
        impl DaResponseProducer for SeedCapture {
            fn produce_for_epoch(
                &self,
                _epoch: u64,
                seed: &[u8],
            ) -> Vec<proto::DaChallengeResponseBody> {
                let mut buf = [0u8; 32];
                let n = seed.len().min(32);
                buf[..n].copy_from_slice(&seed[..n]);
                self.seeds.lock().unwrap().push(buf);
                Vec::new()
            }
        }

        let mut rng = OsRng;
        let srs = Arc::new(KzgSrs::random_unsafe(&mut rng, VERKLE_DOMAIN));
        let (mut runtime, _dir) = make_runtime_with_srs(srs);
        // Install the share for epoch 4 (signer epoch for target 5).
        let dkg =
            hypersnap_crypto::dkls_threshold::run_honest_dkg(1, 1, [0xd2; 32]).expect("1-of-1 dkg");
        runtime.install_local_dkls_share(4, 1, dkg.parties[0].clone(), dkg.group_address);
        let _ = &mut rng;

        let capture = Arc::new(SeedCapture::default());
        let producer: Arc<dyn DaResponseProducer> = capture.clone();

        let (in_tx, in_rx) = mpsc::channel(8);
        let (out_tx, mut out_rx) = mpsc::channel(16);
        let mut actor = HyperActor {
            runtime,
            active_dkls: None,
            active_dkls_sign: None,
            pending_dkls_blocks: std::collections::BTreeMap::new(),
            pending_dkls_messages: std::collections::BTreeMap::new(),
            pending_sign_queue: std::collections::VecDeque::new(),
            inbound: in_rx,
            outbound: out_tx,
            statsd: None,
            da_response_producer: Some(producer),
            last_da_responded_epoch: None,
            last_da_seed_signed_for_epoch: None,
            recent_evidence: std::collections::VecDeque::with_capacity(RECENT_EVIDENCE_CAP),
        };

        // Sign + submit the seed for epoch 5.
        actor.maybe_sign_da_epoch_seed(EPOCH_LENGTH * 5).await;
        assert_eq!(actor.last_da_seed_signed_for_epoch, Some(5));
        // Runtime now has the seed.
        let stored = actor
            .runtime
            .da_epoch_seed_for(5)
            .unwrap()
            .expect("seed stored after auto-sign");
        assert_eq!(stored.len(), 65);

        // Compute the expected v2 boundary hash.
        let expected_v2_seed: [u8; 32] = {
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            h.update(b"FIP-PoW-da-seed-v1\x00\x00\x00\x00\x00\x00");
            h.update(&stored);
            h.finalize().into()
        };

        // Trigger the response producer; it should be invoked with
        // the v2-derived seed (not v1 fallback).
        actor.maybe_trigger_da_responses(EPOCH_LENGTH * 5).await;
        let seeds = capture.seeds.lock().unwrap().clone();
        assert_eq!(seeds.len(), 1, "produce_for_epoch invoked once");
        assert_eq!(
            seeds[0], expected_v2_seed,
            "response producer received v2 seed (committee-signed, not block-sig)"
        );

        // Idempotent re-entry — second call signs nothing new.
        actor.maybe_sign_da_epoch_seed(EPOCH_LENGTH * 5 + 100).await;
        assert_eq!(actor.last_da_seed_signed_for_epoch, Some(5));

        // Drain.
        drop(in_tx);
        drop(actor);
        let mut seed_broadcast_count = 0;
        while let Some(o) = out_rx.recv().await {
            if let HyperActorOutbound::BroadcastMessage(m) = o {
                if m.message_type == proto::HyperMessageType::DaEpochSeed as i32 {
                    seed_broadcast_count += 1;
                }
            }
        }
        assert_eq!(
            seed_broadcast_count, 1,
            "exactly one DaEpochSeed broadcast for the signed epoch"
        );
    }

    #[tokio::test]
    async fn da_epoch_seed_multi_party_path_enqueues_sign_task() {
        use crate::hyper::epoch::EPOCH_LENGTH;

        let mut rng = OsRng;
        let srs = Arc::new(KzgSrs::random_unsafe(&mut rng, VERKLE_DOMAIN));
        let (mut runtime, _dir) = make_runtime_with_srs(srs);
        // 2-of-3 DKG installed at signer epoch 4 (target = 5).
        let dkg =
            hypersnap_crypto::dkls_threshold::run_honest_dkg(2, 3, [0xe0; 32]).expect("2-of-3 dkg");
        // Install the party_index=1 share locally. The committee
        // picker is deterministic on `(signer_epoch=4, digest)`;
        // with 3 parties picking 2, party 1 has a 2/3 chance per
        // independent rank. To pin determinism for the test, we
        // install party 1 first AND if it isn't in the committee,
        // we install party 2 instead. Read the committee, then
        // pick a local share that's in it.
        let payload =
            crate::hyper::rewards::da_epoch_seed_signing_payload(5, runtime.protocol_chain_id);
        let digest = alloy_primitives::keccak256(&payload);
        let committee = crate::hyper::dkls_committee::select_signing_committee(4, &digest, 3, 2)
            .expect("committee");
        assert_eq!(committee.len(), 2);
        // Pick the lowest committee member as our local share.
        let local_index = committee[0] as usize - 1; // 1-based → 0-based
        runtime.install_local_dkls_share(
            4,
            2, // threshold
            dkg.parties[local_index].clone(),
            dkg.group_address,
        );
        let _ = &mut rng;

        let (in_tx, in_rx) = mpsc::channel(8);
        let (out_tx, _out_rx) = mpsc::channel(16);
        let mut actor = HyperActor {
            runtime,
            active_dkls: None,
            active_dkls_sign: None,
            pending_dkls_blocks: std::collections::BTreeMap::new(),
            pending_dkls_messages: std::collections::BTreeMap::new(),
            pending_sign_queue: std::collections::VecDeque::new(),
            inbound: in_rx,
            outbound: out_tx,
            statsd: None,
            da_response_producer: None,
            last_da_responded_epoch: None,
            last_da_seed_signed_for_epoch: None,
            recent_evidence: std::collections::VecDeque::with_capacity(RECENT_EVIDENCE_CAP),
        };

        // Multi-party trigger — should populate pending_dkls_messages
        // + sign queue, but NOT store the seed yet (signature isn't
        // produced until the ceremony completes).
        actor.maybe_sign_da_epoch_seed(EPOCH_LENGTH * 5).await;
        assert!(
            actor.pending_dkls_messages.contains_key(&digest),
            "DaEpochSeed enqueued in pending_dkls_messages map"
        );
        // The sign queue OR the active_dkls_sign holds the task —
        // start_queued_sign pops the front if the slot is free.
        let queued = !actor.pending_sign_queue.is_empty() || actor.active_dkls_sign.is_some();
        assert!(queued, "sign task queued or active");
        // Seed NOT yet in storage.
        assert!(
            actor.runtime.da_epoch_seed_for(5).unwrap().is_none(),
            "seed not stored before ceremony completes"
        );
        // Watermark stays unset for multi-party — the sign-completion
        // handler bumps it after applying the signed body.
        assert_eq!(actor.last_da_seed_signed_for_epoch, None);

        // Idempotent re-entry within the same epoch.
        let queue_len_before = actor.pending_sign_queue.len();
        let pending_len_before = actor.pending_dkls_messages.len();
        actor.maybe_sign_da_epoch_seed(EPOCH_LENGTH * 5 + 50).await;
        // Pending map still has exactly one DaEpochSeed entry; the
        // sign queue didn't double-enqueue.
        assert!(actor.pending_dkls_messages.contains_key(&digest));
        assert!(
            actor.pending_sign_queue.len() <= queue_len_before + 1,
            "re-entry must not duplicate sign tasks"
        );
        // No NEW DaEpochSeed pending entries (we re-keyed on the
        // same digest so insert is overwrite, not append).
        let da_seed_entries = actor
            .pending_dkls_messages
            .values()
            .filter(|m| matches!(m, PendingDklsMessage::DaEpochSeed(_)))
            .count();
        assert_eq!(
            da_seed_entries, 1,
            "exactly one DaEpochSeed pending entry; got {} (before: {})",
            da_seed_entries, pending_len_before
        );

        drop(in_tx);
        drop(actor);
    }

    #[tokio::test]
    async fn da_epoch_seed_multi_party_non_committee_member_no_ops() {
        use crate::hyper::epoch::EPOCH_LENGTH;

        let mut rng = OsRng;
        let srs = Arc::new(KzgSrs::random_unsafe(&mut rng, VERKLE_DOMAIN));
        let (mut runtime, _dir) = make_runtime_with_srs(srs);
        let dkg =
            hypersnap_crypto::dkls_threshold::run_honest_dkg(2, 3, [0xe1; 32]).expect("2-of-3 dkg");
        let payload =
            crate::hyper::rewards::da_epoch_seed_signing_payload(5, runtime.protocol_chain_id);
        let digest = alloy_primitives::keccak256(&payload);
        let committee = crate::hyper::dkls_committee::select_signing_committee(4, &digest, 3, 2)
            .expect("committee");
        // Pick the party_index NOT in the committee.
        let excluded = (1u8..=3)
            .find(|i| !committee.contains(i))
            .expect("one party excluded from any 2-of-3 committee");
        let local_index = excluded as usize - 1;
        runtime.install_local_dkls_share(4, 2, dkg.parties[local_index].clone(), dkg.group_address);
        let _ = &mut rng;

        let (in_tx, in_rx) = mpsc::channel(8);
        let (out_tx, _out_rx) = mpsc::channel(16);
        let mut actor = HyperActor {
            runtime,
            active_dkls: None,
            active_dkls_sign: None,
            pending_dkls_blocks: std::collections::BTreeMap::new(),
            pending_dkls_messages: std::collections::BTreeMap::new(),
            pending_sign_queue: std::collections::VecDeque::new(),
            inbound: in_rx,
            outbound: out_tx,
            statsd: None,
            da_response_producer: None,
            last_da_responded_epoch: None,
            last_da_seed_signed_for_epoch: None,
            recent_evidence: std::collections::VecDeque::with_capacity(RECENT_EVIDENCE_CAP),
        };

        actor.maybe_sign_da_epoch_seed(EPOCH_LENGTH * 5).await;
        // Non-committee → no enqueue, no watermark bump.
        assert!(actor.pending_dkls_messages.is_empty());
        assert!(actor.pending_sign_queue.is_empty());
        assert!(actor.active_dkls_sign.is_none());
        assert_eq!(actor.last_da_seed_signed_for_epoch, None);
        let _ = digest;
        drop(in_tx);
        drop(actor);
    }

    #[tokio::test]
    async fn evaluate_epoch_event_drives_scoring_and_emits_broadcasts() {
        let mut rng = OsRng;
        let srs = Arc::new(KzgSrs::random_unsafe(&mut rng, VERKLE_DOMAIN));
        let (mut runtime, _dir) = make_runtime_with_srs(srs);
        install_single_validator(&mut runtime);

        let outbound = HyperActor::drive_events(
            runtime,
            vec![HyperActorEvent::EvaluateEpochDkls {
                epoch: 0,
                anchor_block: 0,
                anchor_timestamp: 1_700_000_000,
            }],
        )
        .await;

        // Expect 3 BroadcastMessage events for the issuances + 1 for
        // the trust snapshot = 4 total.
        let broadcasts: Vec<_> = outbound
            .iter()
            .filter_map(|o| match o {
                HyperActorOutbound::BroadcastMessage(m) => Some(m),
                _ => None,
            })
            .collect();
        assert_eq!(
            broadcasts.len(),
            4,
            "expected 3 issuances + 1 trust snapshot, got {}: {:?}",
            broadcasts.len(),
            outbound
        );

        let issuance_count = broadcasts
            .iter()
            .filter(|m| matches!(&m.body, Some(proto::hyper_message::Body::RewardIssuance(_))))
            .count();
        let snapshot_count = broadcasts
            .iter()
            .filter(|m| {
                matches!(
                    &m.body,
                    Some(proto::hyper_message::Body::TrustSnapshotUpdate(_))
                )
            })
            .count();
        assert_eq!(issuance_count, 3, "expected 3 reward issuances");
        assert_eq!(snapshot_count, 1, "expected 1 trust snapshot update");

        // No errors emitted.
        let errors = outbound
            .iter()
            .filter(|o| matches!(o, HyperActorOutbound::EventError(_)))
            .count();
        assert_eq!(errors, 0, "scoring should have succeeded: {:?}", outbound);
    }
}
