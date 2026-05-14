//! Hyperblock import path.
//!
//! When a peer's signed `HyperBlock` arrives via gossip:
//!  1. Verify the threshold signature against the epoch's stored group pubkey.
//!  2. Apply the block's state transitions to the local verkle tree.
//!  3. Forget every message that was included from our local mempool.
//!
//! This is the receive-side counterpart to `HyperBlockBuilder` (which is
//! used by the local proposer). Both produce the same canonical state
//! after applying the same set of messages, by virtue of the verkle root
//! being signed and verified.

use crate::hyper::block_index::{HyperBlockIndex, IndexError};
use crate::hyper::builder::{HyperBlockBuilder, PendingMessage};
use crate::hyper::chain::{ChainError, ChainTracker};
use crate::hyper::mempool::HyperMempool;
use crate::hyper::validator_registry::{RegistryError, ValidatorRegistry};
use crate::hyper::validator_score::{ScoreError, ValidatorScoreTracker};
use crate::hyper::{HyperBlock, HyperBlockMetadata};
use crate::proto;
use hypersnap_crypto::kzg::KzgCommitment;
use hypersnap_crypto::verkle::VerkleTree;

#[derive(thiserror::Error, Debug)]
pub enum ImportError {
    #[error("block has no signature")]
    MissingSignature,
    #[error("block has no envelope")]
    MissingEnvelope,
    #[error("block has no envelope metadata")]
    MissingMetadata,
    #[error("group pubkey bytes are not a valid G1 point")]
    InvalidGroupPubkey,
    #[error("signature bytes are not a valid G2 point")]
    InvalidSignature,
    #[error("threshold signature verification failed")]
    SignatureVerificationFailed,
    #[error("state root in metadata does not match recomputed verkle root")]
    StateRootMismatch,
    #[error(transparent)]
    Lock(#[from] crate::hyper::lock_event::LockError),
    #[error(transparent)]
    Kzg(#[from] hypersnap_crypto::kzg::KzgError),
    #[error(transparent)]
    Registry(#[from] RegistryError),
    #[error(transparent)]
    Score(#[from] ScoreError),
    #[error(transparent)]
    Chain(#[from] ChainError),
    #[error(transparent)]
    Index(#[from] IndexError),
}

/// Apply each validator registration/deregistration event included in a block
/// to the local registry. Caller is responsible for passing only events whose
/// `registration_epoch` matches the block's epoch (sanity-checked here).
///
/// `custody_resolver`, when supplied, drives strict cross-sign +
/// per-FID-quota validation (`validate_and_check_quota`). When `None`
/// (test/migration paths), only the lenient `validate_event` runs —
/// signature verification still applies but FID binding and the 3-cap
/// are not enforced. Production callers should always pass a resolver.
pub fn apply_validator_events(
    registry: &ValidatorRegistry,
    block_epoch: u64,
    events: &[proto::HyperValidatorEventBody],
    custody_resolver: Option<&dyn crate::hyper::validator_registry::CustodyResolver>,
) -> Result<(), ImportError> {
    for event in events {
        match custody_resolver {
            Some(r) => registry.validate_and_check_quota(event, block_epoch, r)?,
            None => ValidatorRegistry::validate_event(event, block_epoch, None)?,
        }
        registry.record_event(event)?;
    }
    Ok(())
}

/// Update validator scores after a successful block import. Increments:
///  - The proposer's `successful_proposals` counter
///  - Each signer's (per `signer_indices`) `commit_signatures` counter,
///    where the index → validator_key mapping comes from the caller's
///    active set lookup.
pub fn update_scores_for_block(
    tracker: &ValidatorScoreTracker,
    block_epoch: u64,
    proposer_validator_key: &[u8],
    signer_validator_keys: &[Vec<u8>],
) -> Result<(), ScoreError> {
    tracker.record_successful_proposal(block_epoch, proposer_validator_key)?;
    for signer in signer_validator_keys {
        tracker.record_commit_signature(block_epoch, signer)?;
    }
    Ok(())
}

/// Apply FIP §5.1 missed-proposal entries from the imported block's
/// metadata to the score tracker. Each entry credits the named
/// validator with `record_missed_proposal` at the block's epoch.
pub fn update_scores_for_missed_proposals(
    tracker: &ValidatorScoreTracker,
    block_epoch: u64,
    missed: &[crate::hyper::MissedProposal],
) -> Result<(), ScoreError> {
    for mp in missed {
        tracker.record_missed_proposal(block_epoch, &mp.validator_key)?;
    }
    Ok(())
}

/// Validate chain continuity and import a block. The chain tracker is
/// advanced on success.
pub fn import_hyper_block_chain_aware(
    block: &HyperBlock,
    expected_dkls_group_address: &alloy_primitives::Address,
    tree: &mut VerkleTree,
    mempool: &mut HyperMempool,
    locks_in_block: &[proto::HyperLockEvent],
    transfers_in_block: &[proto::HyperTransferTx],
    chain: &mut ChainTracker,
) -> Result<(), ImportError> {
    // 0. Pre-import: chain continuity check (parent_hash + height).
    chain.validate(block)?;

    // 1-5. Standard import.
    import_hyper_block(
        block,
        expected_dkls_group_address,
        tree,
        mempool,
        locks_in_block,
        transfers_in_block,
    )?;

    // 6. Advance the chain tracker.
    chain.advance(block);
    Ok(())
}

/// Variant that also persists the imported block to the by-height + by-hash
/// indexes for future historical lookups.
#[allow(clippy::too_many_arguments)]
pub fn import_hyper_block_with_index(
    block: &HyperBlock,
    expected_dkls_group_address: &alloy_primitives::Address,
    tree: &mut VerkleTree,
    mempool: &mut HyperMempool,
    locks_in_block: &[proto::HyperLockEvent],
    transfers_in_block: &[proto::HyperTransferTx],
    chain: &mut ChainTracker,
    index: &HyperBlockIndex,
) -> Result<(), ImportError> {
    import_hyper_block_chain_aware(
        block,
        expected_dkls_group_address,
        tree,
        mempool,
        locks_in_block,
        transfers_in_block,
        chain,
    )?;
    index.record(block)?;
    // Persist the message payload alongside the block so the verkle
    // tree can be replayed at restart.
    index.record_messages(
        block.envelope.metadata.canonical_block_id,
        locks_in_block.to_vec(),
        transfers_in_block.to_vec(),
    )?;
    Ok(())
}

/// Variant of `import_hyper_block` that also updates validator scores after a
/// successful import. The active set's index→validator_key mapping is supplied
/// by the caller (typically via `ValidatorRegistry::compute_active_set`).
///
/// `proposer_index` is the 1-based position of the block proposer in the
/// active set. `signer_indices` come from `block.signature.signer_indices`
/// and identify which active-set members contributed to the threshold
/// ECDSA signing committee.
#[allow(clippy::too_many_arguments)]
pub fn import_hyper_block_with_scoring(
    block: &HyperBlock,
    expected_dkls_group_address: &alloy_primitives::Address,
    tree: &mut VerkleTree,
    mempool: &mut HyperMempool,
    locks_in_block: &[proto::HyperLockEvent],
    transfers_in_block: &[proto::HyperTransferTx],
    score_tracker: &ValidatorScoreTracker,
    active_validator_keys_by_index: &[Vec<u8>],
    proposer_index: u64,
) -> Result<(), ImportError> {
    import_hyper_block(
        block,
        expected_dkls_group_address,
        tree,
        mempool,
        locks_in_block,
        transfers_in_block,
    )?;

    // After successful import, credit proposer + signers.
    let proposer_key = active_validator_keys_by_index
        .get((proposer_index.saturating_sub(1)) as usize)
        .cloned()
        .unwrap_or_default();
    let signer_keys: Vec<Vec<u8>> = block
        .signature
        .signer_indices
        .iter()
        .filter_map(|idx| {
            active_validator_keys_by_index
                .get((*idx as usize).saturating_sub(1))
                .cloned()
        })
        .collect();
    update_scores_for_block(
        score_tracker,
        block.signature.epoch,
        &proposer_key,
        &signer_keys,
    )?;

    Ok(())
}

/// Verify and import a `HyperBlock`. `expected_dkls_group_address` is
/// the 20-byte secp256k1 address the verifier expects for
/// `block.signature.epoch`, recovered from
/// [`HyperRuntime::dkls_group_address_for_epoch`].
///
/// On success:
///  - All messages from the block are applied to `tree` via `HyperBlockBuilder`.
///  - The recomputed verkle root is checked against the metadata's state root.
///  - Included lock_ids and transfer first-nullifiers are removed from the mempool.
pub fn import_hyper_block(
    block: &HyperBlock,
    expected_dkls_group_address: &alloy_primitives::Address,
    tree: &mut VerkleTree,
    mempool: &mut HyperMempool,
    locks_in_block: &[proto::HyperLockEvent],
    transfers_in_block: &[proto::HyperTransferTx],
) -> Result<(), ImportError> {
    let payload = block
        .envelope
        .metadata
        .signing_payload(block.signature.epoch);
    let expected =
        crate::hyper::sig_verify::ExpectedGroupKey::ecdsa_only(expected_dkls_group_address);
    crate::hyper::sig_verify::verify_hyperblock_signature(
        &payload,
        &block.signature.ecdsa_signature,
        &block.signature.group_address,
        &expected,
    )
    .map_err(|_| ImportError::SignatureVerificationFailed)?;

    // 3. Apply ALL state transitions via the same builder the proposer used.
    let mut messages: Vec<PendingMessage> =
        Vec::with_capacity(locks_in_block.len() + transfers_in_block.len());
    for lock in locks_in_block {
        messages.push(PendingMessage::Lock(lock.clone()));
    }
    for tx in transfers_in_block {
        messages.push(PendingMessage::Transfer(tx.clone()));
    }
    let mut builder = HyperBlockBuilder::new(tree);
    for msg in &messages {
        builder.apply_message(msg).map_err(|e| match e {
            crate::hyper::builder::BuilderError::Lock(le) => ImportError::Lock(le),
            crate::hyper::builder::BuilderError::Kzg(ke) => ImportError::Kzg(ke),
            crate::hyper::builder::BuilderError::TransferCodec(_) => {
                ImportError::SignatureVerificationFailed
            }
            crate::hyper::builder::BuilderError::UnknownMessageType(_) => {
                ImportError::SignatureVerificationFailed
            }
            crate::hyper::builder::BuilderError::BlockTooLarge { .. } => {
                ImportError::SignatureVerificationFailed
            }
        })?;
    }
    let recomputed = tree.root_commitment()?;

    // 4. Compare the recomputed root against what the proposer signed.
    let stated = HyperBlockMetadata::decode_state_root(&block.envelope.metadata)
        .ok_or(ImportError::StateRootMismatch)?;
    if !commitments_eq(&recomputed, &stated) {
        return Err(ImportError::StateRootMismatch);
    }

    // 5. Forget mempool entries that were included.
    for lock in locks_in_block {
        mempool.forget_lock(&lock.lock_id);
    }
    for tx in transfers_in_block {
        if let Some(first_input) = tx.inputs.first() {
            mempool.forget_transfer(&first_input.nullifier);
        }
    }

    Ok(())
}

fn commitments_eq(a: &KzgCommitment, b: &KzgCommitment) -> bool {
    a.to_bytes() == b.to_bytes()
}
