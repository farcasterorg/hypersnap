//! Higher-level proof helpers built on top of the verkle tree.
//!
//! These compose the raw `verkle::prove_inclusion` API with the verkle key
//! conventions established in `builder.rs` (domain-prefixed keys for locks,
//! nullifiers, and note commitments) so callers don't have to re-implement
//! the path encoding.

use crate::hyper::builder::{note_commitment_verkle_key_public, nullifier_verkle_key_public};
use hypersnap_crypto::kzg::KzgError;
use hypersnap_crypto::verkle::{VerkleProof, VerkleTree};

#[derive(thiserror::Error, Debug)]
pub enum ProofError {
    #[error("nullifier must be exactly 32 bytes")]
    BadNullifierLength,
    #[error("commitment bytes must be 56 bytes (got {0})")]
    BadCommitmentLength(usize),
    #[error(transparent)]
    Kzg(#[from] KzgError),
}

/// Generate a verkle inclusion proof for a spent nullifier.
/// Returns `None` if the nullifier has not been recorded as spent in `tree`.
pub fn prove_nullifier_spent(
    tree: &mut VerkleTree,
    nullifier: &[u8],
) -> Result<Option<VerkleProof>, ProofError> {
    if nullifier.len() != 32 {
        return Err(ProofError::BadNullifierLength);
    }
    let mut nf = [0u8; 32];
    nf.copy_from_slice(nullifier);
    let key = nullifier_verkle_key_public(&nf);
    Ok(tree.prove_inclusion(&key)?)
}

/// Generate a verkle inclusion proof for a known note commitment.
pub fn prove_note_commitment_present(
    tree: &mut VerkleTree,
    commitment_bytes: &[u8],
) -> Result<Option<VerkleProof>, ProofError> {
    if commitment_bytes.len() != 56 {
        return Err(ProofError::BadCommitmentLength(commitment_bytes.len()));
    }
    let key = note_commitment_verkle_key_public(commitment_bytes);
    Ok(tree.prove_inclusion(&key)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hyper::builder::{HyperBlockBuilder, PendingMessage};
    use crate::hyper::transfer_codec::tx_to_proto;
    use hypersnap_crypto::bulletproofs::curve_adapter::Scalar;
    use hypersnap_crypto::kzg::KzgSrs;
    use hypersnap_crypto::kzg_lagrange::VERKLE_DOMAIN;
    use hypersnap_crypto::tokens::{
        prove_value_range, schnorr_sign, Nullifier as Nf, PedersenCommitment as PC,
        SchnorrSignature, TransferInput, TransferOutput, TransferTx, DEFAULT_RANGE_BITS,
    };
    use rand::rngs::OsRng;
    use std::sync::Arc;

    fn build_transfer_into_tree() -> (VerkleTree, [u8; 32], [u8; 56], Arc<KzgSrs>) {
        let mut rng = OsRng;
        let srs = Arc::new(KzgSrs::random_unsafe(&mut rng, VERKLE_DOMAIN));
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
                commitment: out_commitment.clone(),
                range_proof,
            }],
            fee_atoms: 0,
        };

        let mut tree = VerkleTree::new(srs.clone());
        let mut b = HyperBlockBuilder::new(&mut tree);
        b.build_envelope(&[PendingMessage::Transfer(tx_to_proto(&tx))], 0, vec![], 0)
            .unwrap();

        (tree, nullifier.0, out_commitment.to_bytes(), srs)
    }

    #[test]
    fn nullifier_inclusion_proof_after_transfer() {
        let (mut tree, nullifier, _commitment, srs) = build_transfer_into_tree();
        let proof = prove_nullifier_spent(&mut tree, &nullifier)
            .unwrap()
            .expect("nullifier must have inclusion proof after transfer");

        // The proof's value field is the nullifier-presence marker [1].
        assert_eq!(proof.value, vec![1u8]);

        // The root commitment matches the tree's root.
        let root = tree.root_commitment().unwrap();
        let key = nullifier_verkle_key_public(&nullifier);
        assert!(hypersnap_crypto::verkle::verify_inclusion(
            &root, &key, &proof, &srs
        ));
    }

    #[test]
    fn nullifier_proof_returns_none_for_unspent() {
        let (mut tree, _nf, _commitment, _srs) = build_transfer_into_tree();
        let unspent = [0xff; 32];
        let proof = prove_nullifier_spent(&mut tree, &unspent).unwrap();
        assert!(proof.is_none());
    }

    #[test]
    fn nullifier_proof_rejects_short_input() {
        let mut rng = OsRng;
        let srs = Arc::new(KzgSrs::random_unsafe(&mut rng, VERKLE_DOMAIN));
        let mut tree = VerkleTree::new(srs);
        let result = prove_nullifier_spent(&mut tree, &[0u8; 16]);
        assert!(matches!(result, Err(ProofError::BadNullifierLength)));
    }

    #[test]
    fn note_commitment_inclusion_proof() {
        let (mut tree, _nullifier, commitment, srs) = build_transfer_into_tree();
        let proof = prove_note_commitment_present(&mut tree, &commitment)
            .unwrap()
            .expect("commitment must have inclusion proof");

        // Verify against the root.
        let root = tree.root_commitment().unwrap();
        let key = note_commitment_verkle_key_public(&commitment);
        assert!(hypersnap_crypto::verkle::verify_inclusion(
            &root, &key, &proof, &srs
        ));
    }

    #[test]
    fn note_commitment_proof_rejects_wrong_length() {
        let mut rng = OsRng;
        let srs = Arc::new(KzgSrs::random_unsafe(&mut rng, VERKLE_DOMAIN));
        let mut tree = VerkleTree::new(srs);
        let result = prove_note_commitment_present(&mut tree, &[0u8; 32]);
        assert!(matches!(result, Err(ProofError::BadCommitmentLength(32))));
    }
}
