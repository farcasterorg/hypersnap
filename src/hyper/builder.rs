//! Hyperblock construction.
//!
//! Builds a `HyperBlock` from pending hyper messages by:
//!  1. applying each message's state transition to the verkle tree,
//!  2. computing the new tree's root commitment,
//!  3. composing a `HyperBlockMetadata` with that root,
//!  4. wrapping in a `HyperEnvelope`.
//!
//! Signing happens externally because threshold sigs require partial sigs
//! from ≥t validators, gathered via gossip and combined per epoch by the
//! ceremony layer. The builder produces the canonical signing payload via
//! `HyperBlockMetadata::signing_payload(epoch)`.

use crate::hyper::lock_event::{insert_lock_into_tree, LockError};
use crate::hyper::transfer_codec::{tx_from_proto, TransferCodecError};
use crate::hyper::{HyperBlockMetadata, HyperEnvelope};
use crate::proto;
use hypersnap_crypto::kzg::KzgError;
use hypersnap_crypto::verkle::VerkleTree;

// Domain-separated key prefixes within the verkle tree so different message
// types' state lives in non-overlapping subtrees. Each prefix is the
// SHA-256 of a stable label, truncated to fit our 32-byte verkle keys.
//
// Lock leaves use the lock_id directly as the key (32 bytes). To prevent
// collision with nullifiers and note commitments, we prepend a 1-byte
// discriminator on each.

const KEY_DOMAIN_LOCK: u8 = 0x01;
const KEY_DOMAIN_NULLIFIER: u8 = 0x02;
const KEY_DOMAIN_NOTE_COMMITMENT: u8 = 0x03;

fn nullifier_verkle_key(nullifier_bytes: &[u8; 32]) -> Vec<u8> {
    let mut k = Vec::with_capacity(33);
    k.push(KEY_DOMAIN_NULLIFIER);
    k.extend_from_slice(nullifier_bytes);
    k
}

fn note_commitment_verkle_key(commitment_bytes: &[u8]) -> Vec<u8> {
    // Commitments are 56 bytes; we truncate to 32 to match the standard
    // verkle path depth, prepending the discriminator byte → 33B key.
    let mut k = Vec::with_capacity(33);
    k.push(KEY_DOMAIN_NOTE_COMMITMENT);
    k.extend_from_slice(&commitment_bytes[..commitment_bytes.len().min(32)]);
    while k.len() < 33 {
        k.push(0);
    }
    k
}

fn lock_verkle_key(lock_id: &[u8]) -> Vec<u8> {
    let mut k = Vec::with_capacity(33);
    k.push(KEY_DOMAIN_LOCK);
    k.extend_from_slice(lock_id);
    k
}

/// Default soft cap on messages per hyperblock. Block proposers respect this
/// to keep block-verification time bounded; importers reject any block
/// exceeding `MAX_MESSAGES_PER_BLOCK` regardless of signature validity.
pub const DEFAULT_MAX_MESSAGES_PER_BLOCK: usize = 5_000;

/// Hard ceiling that the protocol refuses to exceed. Beyond this, even
/// legitimately-signed blocks are rejected to prevent resource exhaustion.
pub const MAX_MESSAGES_PER_BLOCK: usize = 50_000;

#[derive(thiserror::Error, Debug)]
pub enum BuilderError {
    #[error("invalid lock event: {0}")]
    Lock(#[from] LockError),
    #[error("verkle commitment computation failed: {0}")]
    Kzg(#[from] KzgError),
    #[error("unknown hyper message type {0}")]
    UnknownMessageType(i32),
    #[error("transfer decode error: {0}")]
    TransferCodec(#[from] TransferCodecError),
    #[error("block exceeds max messages per block ({count} > {limit})")]
    BlockTooLarge { count: usize, limit: usize },
}

/// Pending message types the builder accepts. Mirrors `proto::hyper_message::Body`
/// but typed in Rust for handler dispatch.
#[derive(Clone, Debug)]
pub enum PendingMessage {
    Lock(proto::HyperLockEvent),
    // Transfers don't directly modify the verkle tree in the lock-only bridge
    // path — they update the note set + nullifier set in derived RocksDB
    // indices. They're included here for completeness but produce no verkle
    // state change.
    Transfer(proto::HyperTransferTx),
}

/// Build a `HyperBlock` payload by applying `messages` to `tree` and reading
/// the resulting state root.
///
/// `parent_hash` and `canonical_block_id` come from the snapchain anchor block
/// the hyperblock mirrors. `extra_rules_version` and `retained_message_count`
/// follow `HyperBlockMetadata` semantics.
pub struct HyperBlockBuilder<'a> {
    tree: &'a mut VerkleTree,
}

impl<'a> HyperBlockBuilder<'a> {
    pub fn new(tree: &'a mut VerkleTree) -> Self {
        Self { tree }
    }

    /// Apply one message to the underlying state. Idempotent only insofar as
    /// the underlying message handler is — locks with duplicate `lock_id`
    /// will overwrite (which the protocol-level mempool layer should prevent).
    pub fn apply_message(&mut self, msg: &PendingMessage) -> Result<(), BuilderError> {
        match msg {
            PendingMessage::Lock(event) => {
                insert_lock_into_tree(self.tree, event)?;
                Ok(())
            }
            PendingMessage::Transfer(tx_proto) => {
                // Decode and apply transfer state changes to the verkle tree.
                // For each input: insert its nullifier with value `[1]` so
                // double-spend can be proven via verkle inclusion.
                // For each output: insert its commitment so future spenders
                // can prove ownership of the note.
                let tx = tx_from_proto(tx_proto)?;
                for input in &tx.inputs {
                    self.tree.insert(
                        &nullifier_verkle_key(&input.nullifier.0),
                        vec![1u8], // presence marker
                    );
                }
                for output in &tx.outputs {
                    let commitment_bytes = output.commitment.to_bytes();
                    self.tree.insert(
                        &note_commitment_verkle_key(&commitment_bytes),
                        commitment_bytes.to_vec(),
                    );
                }
                Ok(())
            }
        }
    }

    /// Apply a batch of messages, then build the envelope. Returns the new
    /// envelope along with the recomputed root commitment.
    ///
    /// Equivalent to `build_envelope_with_anchor(.., 0, vec![])`. Pre-cutover
    /// blocks (or test fixtures that don't care about the anchor) use this.
    pub fn build_envelope(
        &mut self,
        messages: &[PendingMessage],
        canonical_block_id: u64,
        parent_hash: Vec<u8>,
        extra_rules_version: u32,
    ) -> Result<HyperEnvelope, BuilderError> {
        self.build_envelope_with_anchor(
            messages,
            canonical_block_id,
            parent_hash,
            extra_rules_version,
            0,
            vec![],
        )
    }

    /// Variant of `build_envelope` that pins the produced block to a specific
    /// snapchain anchor. Post-cutover blocks must carry the latest finalized
    /// snapchain block + hash so the threshold signature commits to the
    /// snapchain head observed at production time. Equivalent to
    /// `build_envelope_with_full_anchor` with timestamp = 0.
    pub fn build_envelope_with_anchor(
        &mut self,
        messages: &[PendingMessage],
        canonical_block_id: u64,
        parent_hash: Vec<u8>,
        extra_rules_version: u32,
        snapchain_anchor_block: u64,
        snapchain_anchor_hash: Vec<u8>,
    ) -> Result<HyperEnvelope, BuilderError> {
        self.build_envelope_with_full_anchor(
            messages,
            canonical_block_id,
            parent_hash,
            extra_rules_version,
            snapchain_anchor_block,
            snapchain_anchor_hash,
            0,
        )
    }

    /// Full anchor variant. Production proposers should use this so the
    /// threshold signature commits to the wall-clock timestamp of the
    /// snapchain anchor block — every importer (including the scoring
    /// auto-trigger) then sees the same `now_unix` deterministically.
    pub fn build_envelope_with_full_anchor(
        &mut self,
        messages: &[PendingMessage],
        canonical_block_id: u64,
        parent_hash: Vec<u8>,
        extra_rules_version: u32,
        snapchain_anchor_block: u64,
        snapchain_anchor_hash: Vec<u8>,
        snapchain_anchor_timestamp: u64,
    ) -> Result<HyperEnvelope, BuilderError> {
        if messages.len() > MAX_MESSAGES_PER_BLOCK {
            return Err(BuilderError::BlockTooLarge {
                count: messages.len(),
                limit: MAX_MESSAGES_PER_BLOCK,
            });
        }
        for msg in messages {
            self.apply_message(msg)?;
        }
        let root_commitment = self.tree.root_commitment()?;
        let metadata = HyperBlockMetadata {
            canonical_block_id,
            parent_hash,
            hyper_state_root: root_commitment.to_bytes().to_vec(),
            extra_rules_version,
            retained_message_count: messages.len() as u64,
            missed_proposals: vec![],
            snapchain_anchor_block,
            snapchain_anchor_hash,
            // The builder doesn't have visibility into the snapchain
            // range; callers (the proposer pipeline) populate the
            // start_block + Merkle root via a post-build step. Tests
            // and the legacy `build_envelope` path leave them empty.
            snapchain_range_start_block: 0,
            snapchain_range_root: vec![],
            snapchain_anchor_timestamp,
        };
        Ok(HyperEnvelope {
            metadata,
            payload: Vec::new(),
        })
    }
}

/// Validate that a block's message count is within the protocol's hard ceiling.
/// Importers call this before applying any state changes.
pub fn validate_block_size(message_count: usize) -> Result<(), BuilderError> {
    if message_count > MAX_MESSAGES_PER_BLOCK {
        Err(BuilderError::BlockTooLarge {
            count: message_count,
            limit: MAX_MESSAGES_PER_BLOCK,
        })
    } else {
        Ok(())
    }
}

/// Construct the verkle key under which a nullifier lives.
/// Mirrors the layout used by `apply_message(Transfer)`.
pub fn nullifier_verkle_key_public(nullifier_bytes: &[u8; 32]) -> Vec<u8> {
    nullifier_verkle_key(nullifier_bytes)
}

/// Construct the verkle key under which a note commitment lives.
pub fn note_commitment_verkle_key_public(commitment_bytes: &[u8]) -> Vec<u8> {
    note_commitment_verkle_key(commitment_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hypersnap_crypto::kzg::KzgSrs;
    use hypersnap_crypto::kzg_lagrange::VERKLE_DOMAIN;
    use hypersnap_crypto::verkle::{verify_inclusion, VerkleTree};
    use rand::rngs::OsRng;
    use std::sync::Arc;

    fn sample_lock(lock_id_byte: u8, amount: u64) -> proto::HyperLockEvent {
        proto::HyperLockEvent {
            amount,
            dest_chain_id: 1,
            dest_address: vec![0xab; 20],
            spend_pubkey: vec![0x02; 33],
            lock_id: vec![lock_id_byte; 32],
            lock_height: 100,
            lock_timestamp: 1_700_000_000,
            lock_signature: vec![0u8; 64],
        }
    }

    #[test]
    fn build_envelope_with_no_messages() {
        let mut rng = OsRng;
        let srs = Arc::new(KzgSrs::random_unsafe(&mut rng, VERKLE_DOMAIN));
        let mut tree = VerkleTree::new(srs);
        let mut builder = HyperBlockBuilder::new(&mut tree);
        let env = builder.build_envelope(&[], 100, vec![0u8; 32], 0).unwrap();
        assert_eq!(env.metadata.canonical_block_id, 100);
        assert_eq!(env.metadata.retained_message_count, 0);
        // The root commitment is 48 bytes (compressed G1).
        assert_eq!(env.metadata.hyper_state_root.len(), 48);
    }

    #[test]
    fn applying_locks_changes_state_root() {
        let mut rng = OsRng;
        let srs = Arc::new(KzgSrs::random_unsafe(&mut rng, VERKLE_DOMAIN));

        // Build empty envelope first to capture initial root.
        let initial_root = {
            let mut tree = VerkleTree::new(srs.clone());
            let mut b = HyperBlockBuilder::new(&mut tree);
            b.build_envelope(&[], 100, vec![0u8; 32], 0).unwrap()
        };

        // Now build with one lock applied.
        let mut tree = VerkleTree::new(srs);
        let mut b = HyperBlockBuilder::new(&mut tree);
        let env = b
            .build_envelope(
                &[PendingMessage::Lock(sample_lock(1, 1_000_000))],
                100,
                vec![0u8; 32],
                0,
            )
            .unwrap();

        assert_ne!(
            env.metadata.hyper_state_root,
            initial_root.metadata.hyper_state_root
        );
        assert_eq!(env.metadata.retained_message_count, 1);
    }

    #[test]
    fn built_envelope_proves_inclusion_for_each_lock() {
        let mut rng = OsRng;
        let srs = Arc::new(KzgSrs::random_unsafe(&mut rng, VERKLE_DOMAIN));
        let mut tree = VerkleTree::new(srs.clone());
        let mut b = HyperBlockBuilder::new(&mut tree);

        let locks = vec![
            sample_lock(1, 100_000),
            sample_lock(2, 200_000),
            sample_lock(3, 300_000),
        ];
        let messages: Vec<_> = locks.iter().cloned().map(PendingMessage::Lock).collect();
        let env = b.build_envelope(&messages, 200, vec![0xaa; 32], 0).unwrap();

        // The state root in metadata is the verkle root.
        assert_eq!(env.metadata.hyper_state_root.len(), 48);

        // Each lock's lock_id should produce a valid inclusion proof.
        let root = tree.root_commitment().unwrap();
        for lock in &locks {
            let proof = tree
                .prove_inclusion(&lock.lock_id)
                .unwrap()
                .expect("must have inclusion proof");
            assert!(verify_inclusion(&root, &lock.lock_id, &proof, &srs));
        }
    }

    #[test]
    fn deterministic_state_root_for_same_inputs() {
        let mut rng = OsRng;
        let srs = Arc::new(KzgSrs::random_unsafe(&mut rng, VERKLE_DOMAIN));

        let messages = vec![
            PendingMessage::Lock(sample_lock(1, 100)),
            PendingMessage::Lock(sample_lock(2, 200)),
        ];

        let root_a = {
            let mut tree = VerkleTree::new(srs.clone());
            let mut b = HyperBlockBuilder::new(&mut tree);
            b.build_envelope(&messages, 1, vec![0u8; 32], 0)
                .unwrap()
                .metadata
                .hyper_state_root
        };

        let root_b = {
            let mut tree = VerkleTree::new(srs);
            let mut b = HyperBlockBuilder::new(&mut tree);
            b.build_envelope(&messages, 1, vec![0u8; 32], 0)
                .unwrap()
                .metadata
                .hyper_state_root
        };

        assert_eq!(root_a, root_b);
    }

    #[test]
    fn order_independence_for_distinct_keys() {
        // Inserts at distinct lock_ids must produce the same root regardless of
        // application order — verifies the verkle tree's order-independence is
        // preserved through the builder.
        let mut rng = OsRng;
        let srs = Arc::new(KzgSrs::random_unsafe(&mut rng, VERKLE_DOMAIN));

        let l1 = PendingMessage::Lock(sample_lock(0xa1, 1));
        let l2 = PendingMessage::Lock(sample_lock(0xa2, 2));

        let root_forward = {
            let mut tree = VerkleTree::new(srs.clone());
            let mut b = HyperBlockBuilder::new(&mut tree);
            b.build_envelope(&[l1.clone(), l2.clone()], 0, vec![], 0)
                .unwrap()
                .metadata
                .hyper_state_root
        };
        let root_reverse = {
            let mut tree = VerkleTree::new(srs);
            let mut b = HyperBlockBuilder::new(&mut tree);
            b.build_envelope(&[l2, l1], 0, vec![], 0)
                .unwrap()
                .metadata
                .hyper_state_root
        };
        assert_eq!(root_forward, root_reverse);
    }

    #[test]
    fn rejects_invalid_lock_event() {
        let mut rng = OsRng;
        let srs = Arc::new(KzgSrs::random_unsafe(&mut rng, VERKLE_DOMAIN));
        let mut tree = VerkleTree::new(srs);
        let mut b = HyperBlockBuilder::new(&mut tree);

        let mut bad = sample_lock(1, 0); // amount = 0 → ZeroAmount
        bad.amount = 0;
        let result = b.build_envelope(&[PendingMessage::Lock(bad)], 0, vec![], 0);
        assert!(matches!(
            result,
            Err(BuilderError::Lock(LockError::ZeroAmount))
        ));
    }

    #[test]
    fn transfer_inserts_nullifier_and_commitment_into_tree() {
        use crate::hyper::transfer_codec::tx_to_proto;
        use hypersnap_crypto::bulletproofs::curve_adapter::Scalar;
        use hypersnap_crypto::tokens::{
            prove_value_range, schnorr_sign, Nullifier as Nf, PedersenCommitment as PC,
            SchnorrSignature, TransferInput, TransferOutput, TransferTx, DEFAULT_RANGE_BITS,
        };

        let mut rng = OsRng;
        let r_in = Scalar::random(&mut rng);
        let r_out = Scalar::random(&mut rng);
        let x = Scalar::random(&mut rng);

        let in_commitment = PC::commit(100, &r_in);
        let nullifier = Nf::derive(&x, &in_commitment);
        let spend_signature: SchnorrSignature = schnorr_sign(&x, &[0u8; 32], &mut rng);
        let out_commitment = PC::commit(100, &r_out);
        let (range_proof, _) =
            prove_value_range(100, &r_out, DEFAULT_RANGE_BITS, &mut rng).unwrap();

        let tx = TransferTx {
            inputs: vec![TransferInput {
                commitment: in_commitment,
                nullifier,
                spend_signature,
            }],
            outputs: vec![TransferOutput {
                commitment: out_commitment,
                range_proof,
            }],
            fee_atoms: 0,
        };
        let tx_proto = tx_to_proto(&tx);

        let srs = Arc::new(KzgSrs::random_unsafe(&mut rng, VERKLE_DOMAIN));
        let mut tree = VerkleTree::new(srs);
        let mut b = HyperBlockBuilder::new(&mut tree);
        let env = b
            .build_envelope(&[PendingMessage::Transfer(tx_proto.clone())], 0, vec![], 0)
            .unwrap();

        // The state root must reflect the transfer's insertions.
        assert_eq!(env.metadata.hyper_state_root.len(), 48);

        // Nullifier is present at its verkle path.
        let nf_key = nullifier_verkle_key(&nullifier.0);
        assert_eq!(tree.get(&nf_key), Some(&[1u8][..]));

        // Output commitment is present at its verkle path.
        let commitment_bytes = out_commitment.to_bytes();
        let comm_key = note_commitment_verkle_key(&commitment_bytes);
        assert!(tree.get(&comm_key).is_some());
    }

    #[test]
    fn locks_and_transfers_co_exist_in_tree() {
        use crate::hyper::transfer_codec::tx_to_proto;
        use hypersnap_crypto::bulletproofs::curve_adapter::Scalar;
        use hypersnap_crypto::tokens::{
            prove_value_range, schnorr_sign, Nullifier as Nf, PedersenCommitment as PC,
            SchnorrSignature, TransferInput, TransferOutput, TransferTx, DEFAULT_RANGE_BITS,
        };

        let mut rng = OsRng;
        let srs = Arc::new(KzgSrs::random_unsafe(&mut rng, VERKLE_DOMAIN));
        let mut tree = VerkleTree::new(srs);

        // Create a transfer.
        let r_in = Scalar::random(&mut rng);
        let r_out = Scalar::random(&mut rng);
        let x = Scalar::random(&mut rng);
        let in_commitment = PC::commit(50, &r_in);
        let nullifier = Nf::derive(&x, &in_commitment);
        let spend_signature: SchnorrSignature = schnorr_sign(&x, &[0u8; 32], &mut rng);
        let out_commitment = PC::commit(50, &r_out);
        let (range_proof, _) = prove_value_range(50, &r_out, DEFAULT_RANGE_BITS, &mut rng).unwrap();
        let tx_proto = tx_to_proto(&TransferTx {
            inputs: vec![TransferInput {
                commitment: in_commitment,
                nullifier,
                spend_signature,
            }],
            outputs: vec![TransferOutput {
                commitment: out_commitment,
                range_proof,
            }],
            fee_atoms: 0,
        });

        let mut b = HyperBlockBuilder::new(&mut tree);
        b.build_envelope(
            &[
                PendingMessage::Lock(sample_lock(0xa1, 1_000_000)),
                PendingMessage::Transfer(tx_proto),
            ],
            0,
            vec![],
            0,
        )
        .unwrap();

        // Lock is at lock_id (32B path).
        assert!(tree.get(&[0xa1; 32]).is_some());

        // Nullifier at 33B path with discriminator.
        let nf_key = nullifier_verkle_key(&nullifier.0);
        assert_eq!(tree.get(&nf_key), Some(&[1u8][..]));
    }

    #[test]
    fn build_rejects_block_exceeding_hard_limit() {
        let mut rng = OsRng;
        let srs = Arc::new(KzgSrs::random_unsafe(&mut rng, VERKLE_DOMAIN));
        let mut tree = VerkleTree::new(srs);
        let mut b = HyperBlockBuilder::new(&mut tree);
        let messages: Vec<PendingMessage> = (0..MAX_MESSAGES_PER_BLOCK + 1)
            .map(|i| PendingMessage::Lock(sample_lock((i % 256) as u8, 1)))
            .collect();
        let result = b.build_envelope(&messages, 0, vec![], 0);
        assert!(matches!(
            result,
            Err(BuilderError::BlockTooLarge {
                count: c,
                limit: MAX_MESSAGES_PER_BLOCK
            }) if c > MAX_MESSAGES_PER_BLOCK
        ));
    }

    #[test]
    fn validate_block_size_enforces_ceiling() {
        assert!(validate_block_size(0).is_ok());
        assert!(validate_block_size(1).is_ok());
        assert!(validate_block_size(MAX_MESSAGES_PER_BLOCK).is_ok());
        assert!(matches!(
            validate_block_size(MAX_MESSAGES_PER_BLOCK + 1),
            Err(BuilderError::BlockTooLarge { .. })
        ));
    }
}
