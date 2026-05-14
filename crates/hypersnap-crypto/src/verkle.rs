//! 256-ary verkle tree with KZG commitments.
//!
//! Each internal node commits to a polynomial whose value at the root of unity
//! `ω_n^i` represents the contribution of child slot `i`. Children with no
//! entry contribute `Fr::ZERO`. Leaves contribute `H(value)` reduced into Fr.
//! Internal children contribute `H(commitment_bytes)` reduced into Fr.
//!
//! Keys must be a fixed length agreed by the caller; each byte selects a
//! child slot, so a `k`-byte key produces a tree of depth `k`. Inclusion
//! proofs (multipoint openings against intermediate node commitments) are
//! deferred to Step 13.

use crate::kzg::{self, KzgCommitment, KzgError, KzgProof, KzgSrs};
use crate::kzg_lagrange::{self, commit_evaluations, VERKLE_DOMAIN};
use bls12_381::Scalar as Fr;
use ff::Field;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::sync::Arc;

const INTERNAL_DOMAIN: &[u8] = b"hypersnap-verkle-internal-v1";
const LEAF_DOMAIN: &[u8] = b"hypersnap-verkle-leaf-v1";

/// Hash arbitrary bytes into Fr via SHA-256 + wide reduction.
fn hash_to_fr(domain: &[u8], bytes: &[u8]) -> Fr {
    let mut h = Sha256::new();
    h.update(domain);
    h.update(bytes);
    let digest: [u8; 32] = h.finalize().into();
    // Pad into a 64-byte buffer for from_bytes_wide so the reduction is well
    // defined even for digests that happen to exceed the Fr modulus.
    let mut wide = [0u8; 64];
    wide[..32].copy_from_slice(&digest);
    Fr::from_bytes_wide(&wide)
}

#[derive(Debug, Clone)]
pub enum VerkleNode {
    Internal {
        children: BTreeMap<u8, Box<VerkleNode>>,
        /// `None` after a descendant insert; `Some` once `compute_commitment` runs.
        commitment: Option<KzgCommitment>,
    },
    Leaf {
        value: Vec<u8>,
    },
}

impl VerkleNode {
    pub fn new_internal() -> Self {
        Self::Internal {
            children: BTreeMap::new(),
            commitment: None,
        }
    }

    /// The Fr value this node contributes to its parent's commitment polynomial.
    fn commitment_value(&self) -> Fr {
        match self {
            Self::Internal { commitment, .. } => {
                let c = commitment
                    .as_ref()
                    .expect("compute_commitment must run before commitment_value on Internal");
                hash_to_fr(INTERNAL_DOMAIN, &c.to_bytes())
            }
            Self::Leaf { value } => hash_to_fr(LEAF_DOMAIN, value),
        }
    }

    /// Recompute this node's commitment if missing. Children are computed first
    /// so the bottom-up dependency holds.
    fn compute_commitment(&mut self, srs: &KzgSrs) -> Result<(), KzgError> {
        if let Self::Internal {
            children,
            commitment,
        } = self
        {
            if commitment.is_some() {
                return Ok(());
            }
            for child in children.values_mut() {
                child.compute_commitment(srs)?;
            }
            let mut evals = vec![Fr::ZERO; VERKLE_DOMAIN];
            for (&slot, child) in children.iter() {
                evals[slot as usize] = child.commitment_value();
            }
            *commitment = Some(commit_evaluations(srs, &evals)?);
        }
        Ok(())
    }
}

pub struct VerkleTree {
    root: VerkleNode,
    srs: Arc<KzgSrs>,
}

impl VerkleTree {
    pub fn new(srs: Arc<KzgSrs>) -> Self {
        Self {
            root: VerkleNode::new_internal(),
            srs,
        }
    }

    pub fn insert(&mut self, key: &[u8], value: Vec<u8>) {
        assert!(!key.is_empty(), "verkle tree keys must be non-empty");
        Self::insert_recursive(&mut self.root, key, 0, value);
    }

    fn insert_recursive(node: &mut VerkleNode, key: &[u8], depth: usize, value: Vec<u8>) {
        if depth + 1 == key.len() {
            // Final byte — store leaf in slot key[depth].
            if let VerkleNode::Internal {
                children,
                commitment,
            } = node
            {
                *commitment = None;
                children.insert(key[depth], Box::new(VerkleNode::Leaf { value }));
            } else {
                panic!("verkle tree key length is inconsistent (parent is a leaf)");
            }
            return;
        }
        match node {
            VerkleNode::Internal {
                children,
                commitment,
            } => {
                *commitment = None;
                let slot = key[depth];
                let child = children
                    .entry(slot)
                    .or_insert_with(|| Box::new(VerkleNode::new_internal()));
                Self::insert_recursive(child, key, depth + 1, value);
            }
            VerkleNode::Leaf { .. } => {
                panic!("verkle tree key length is inconsistent (hit leaf at non-terminal depth)");
            }
        }
    }

    pub fn get(&self, key: &[u8]) -> Option<&[u8]> {
        Self::get_recursive(&self.root, key, 0)
    }

    fn get_recursive<'a>(node: &'a VerkleNode, key: &[u8], depth: usize) -> Option<&'a [u8]> {
        if depth + 1 == key.len() {
            if let VerkleNode::Internal { children, .. } = node {
                if let Some(child) = children.get(&key[depth]) {
                    if let VerkleNode::Leaf { value } = child.as_ref() {
                        return Some(value);
                    }
                }
            }
            return None;
        }
        match node {
            VerkleNode::Internal { children, .. } => children
                .get(&key[depth])
                .and_then(|c| Self::get_recursive(c, key, depth + 1)),
            VerkleNode::Leaf { .. } => None,
        }
    }

    /// Force computation of the root commitment. Returns the result.
    pub fn root_commitment(&mut self) -> Result<KzgCommitment, KzgError> {
        self.root.compute_commitment(&self.srs)?;
        match &self.root {
            VerkleNode::Internal { commitment, .. } => {
                Ok(commitment.clone().expect("just computed"))
            }
            VerkleNode::Leaf { .. } => panic!("verkle tree root must be Internal"),
        }
    }

    /// Produce an inclusion proof for `key`. Returns `None` if the key is not
    /// present. Side effect: ensures all path commitments are computed.
    pub fn prove_inclusion(&mut self, key: &[u8]) -> Result<Option<VerkleProof>, KzgError> {
        assert!(!key.is_empty(), "verkle tree keys must be non-empty");
        self.root_commitment()?;
        let mut steps = Vec::with_capacity(key.len());
        let value = Self::prove_recursive(&self.root, key, 0, &self.srs, &mut steps)?;
        Ok(value.map(|v| VerkleProof { steps, value: v }))
    }

    fn prove_recursive(
        node: &VerkleNode,
        key: &[u8],
        depth: usize,
        srs: &KzgSrs,
        steps: &mut Vec<ProofStep>,
    ) -> Result<Option<Vec<u8>>, KzgError> {
        let (children, commitment) = match node {
            VerkleNode::Internal {
                children,
                commitment,
            } => (children, commitment),
            VerkleNode::Leaf { .. } => return Ok(None),
        };
        let cmt = commitment
            .as_ref()
            .expect("commitments must be computed before proof generation")
            .clone();
        let slot = key[depth];

        // Build evaluation vector for this node and IFFT to coefficient form.
        let mut evals = vec![Fr::ZERO; VERKLE_DOMAIN];
        for (&s, child) in children.iter() {
            evals[s as usize] = child.commitment_value();
        }
        let mut coeffs = evals;
        kzg_lagrange::ifft(&mut coeffs);

        // Compute z = ω_n^slot.
        let z = omega_pow(slot);
        let (y, proof) = kzg::open(srs, &coeffs, z)?;
        steps.push(ProofStep {
            commitment: cmt,
            slot,
            evaluation: y,
            proof,
        });

        let child = match children.get(&slot) {
            Some(c) => c,
            None => return Ok(None),
        };

        if depth + 1 == key.len() {
            if let VerkleNode::Leaf { value } = child.as_ref() {
                Ok(Some(value.clone()))
            } else {
                Ok(None)
            }
        } else {
            Self::prove_recursive(child, key, depth + 1, srs, steps)
        }
    }
}

#[derive(Debug, Clone)]
pub struct VerkleProof {
    /// One step per byte of the key, walking from root to leaf.
    pub steps: Vec<ProofStep>,
    /// The leaf value at the end of the path.
    pub value: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct ProofStep {
    pub commitment: KzgCommitment,
    pub slot: u8,
    /// `f(ω^slot)` at this level — must equal the hash of the next level's
    /// commitment (or, at the final step, the hash of the leaf value).
    pub evaluation: Fr,
    pub proof: KzgProof,
}

/// Verify an inclusion proof against a claimed root commitment.
pub fn verify_inclusion(
    root_commitment: &KzgCommitment,
    key: &[u8],
    proof: &VerkleProof,
    srs: &KzgSrs,
) -> bool {
    if proof.steps.len() != key.len() || proof.steps.is_empty() {
        return false;
    }
    if &proof.steps[0].commitment != root_commitment {
        return false;
    }

    for (i, step) in proof.steps.iter().enumerate() {
        if step.slot != key[i] {
            return false;
        }
        let z = omega_pow(step.slot);
        if !kzg::verify(&step.commitment, z, step.evaluation, &step.proof, srs) {
            return false;
        }
        let expected = if i + 1 == proof.steps.len() {
            hash_to_fr(LEAF_DOMAIN, &proof.value)
        } else {
            hash_to_fr(INTERNAL_DOMAIN, &proof.steps[i + 1].commitment.to_bytes())
        };
        if step.evaluation != expected {
            return false;
        }
    }

    true
}

/// `ω_n^slot` for the verkle domain — repeated multiplication is fine since
/// slot ≤ 255.
fn omega_pow(slot: u8) -> Fr {
    let omega = kzg_lagrange::root_of_unity(VERKLE_DOMAIN);
    let mut acc = Fr::ONE;
    for _ in 0..slot {
        acc *= omega;
    }
    acc
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    fn make_tree() -> VerkleTree {
        let mut rng = OsRng;
        let srs = Arc::new(KzgSrs::random_unsafe(&mut rng, VERKLE_DOMAIN));
        VerkleTree::new(srs)
    }

    #[test]
    fn empty_tree_root_is_deterministic() {
        let mut t1 = make_tree();
        let mut t2 = make_tree();
        // Different SRS so commitments will differ — instead test self-consistency.
        let r1a = t1.root_commitment().unwrap();
        let r1b = t1.root_commitment().unwrap();
        assert_eq!(r1a, r1b);
        let _ = t2.root_commitment().unwrap();
    }

    #[test]
    fn insert_and_get() {
        let mut t = make_tree();
        t.insert(b"abcd", b"value1".to_vec());
        assert_eq!(t.get(b"abcd"), Some(&b"value1"[..]));
        assert_eq!(t.get(b"abce"), None);
    }

    #[test]
    fn multiple_inserts_and_gets() {
        let mut t = make_tree();
        let kvs = vec![
            (b"aaaa".to_vec(), b"v1".to_vec()),
            (b"aaab".to_vec(), b"v2".to_vec()),
            (b"aabb".to_vec(), b"v3".to_vec()),
            (b"bbbb".to_vec(), b"v4".to_vec()),
            (b"abcd".to_vec(), b"v5".to_vec()),
        ];
        for (k, v) in &kvs {
            t.insert(k, v.clone());
        }
        for (k, v) in &kvs {
            assert_eq!(t.get(k), Some(v.as_slice()));
        }
        assert_eq!(t.get(b"zzzz"), None);
    }

    #[test]
    fn updating_value_changes_root() {
        let mut t = make_tree();
        t.insert(b"abcd", b"first".to_vec());
        let r1 = t.root_commitment().unwrap();
        t.insert(b"abcd", b"second".to_vec());
        let r2 = t.root_commitment().unwrap();
        assert_ne!(r1, r2);
        assert_eq!(t.get(b"abcd"), Some(&b"second"[..]));
    }

    #[test]
    fn different_keys_produce_different_roots() {
        let mut t1 = make_tree();
        let mut t2 = make_tree();
        // Use the SAME SRS so the comparison is meaningful.
        t2.srs = t1.srs.clone();

        t1.insert(b"abcd", b"v1".to_vec());
        t2.insert(b"efgh", b"v1".to_vec());
        let r1 = t1.root_commitment().unwrap();
        let r2 = t2.root_commitment().unwrap();
        assert_ne!(r1, r2);
    }

    #[test]
    fn insert_order_independence() {
        let mut t1 = make_tree();
        let mut t2 = make_tree();
        t2.srs = t1.srs.clone();

        let kvs = vec![
            (b"aaaa".to_vec(), b"v1".to_vec()),
            (b"bbbb".to_vec(), b"v2".to_vec()),
            (b"cccc".to_vec(), b"v3".to_vec()),
            (b"dddd".to_vec(), b"v4".to_vec()),
        ];
        for (k, v) in kvs.iter() {
            t1.insert(k, v.clone());
        }
        for (k, v) in kvs.iter().rev() {
            t2.insert(k, v.clone());
        }
        assert_eq!(t1.root_commitment().unwrap(), t2.root_commitment().unwrap());
    }

    #[test]
    fn cache_invalidation_after_insert() {
        let mut t = make_tree();
        t.insert(b"abcd", b"v1".to_vec());
        let r1 = t.root_commitment().unwrap();
        // Insert a totally different key; the root must change because the
        // root commitment depends on all children.
        t.insert(b"wxyz", b"v2".to_vec());
        let r2 = t.root_commitment().unwrap();
        assert_ne!(r1, r2);
        // First key must still be retrievable.
        assert_eq!(t.get(b"abcd"), Some(&b"v1"[..]));
        assert_eq!(t.get(b"wxyz"), Some(&b"v2"[..]));
    }

    #[test]
    fn empty_tree_root_changes_after_first_insert() {
        let mut t = make_tree();
        let r0 = t.root_commitment().unwrap();
        t.insert(b"abcd", b"v1".to_vec());
        let r1 = t.root_commitment().unwrap();
        assert_ne!(r0, r1);
    }

    #[test]
    fn inclusion_proof_verifies_for_inserted_key() {
        let mut t = make_tree();
        t.insert(b"abcd", b"hello".to_vec());
        t.insert(b"abce", b"world".to_vec());
        t.insert(b"xyz0", b"!".to_vec());

        let root = t.root_commitment().unwrap();
        let proof = t
            .prove_inclusion(b"abcd")
            .unwrap()
            .expect("key present, proof must exist");
        assert_eq!(proof.value, b"hello");
        assert_eq!(proof.steps.len(), 4);

        assert!(verify_inclusion(&root, b"abcd", &proof, &t.srs));
    }

    #[test]
    fn inclusion_proof_verifies_for_each_inserted_key() {
        let mut t = make_tree();
        let kvs = vec![
            (b"aaaa".to_vec(), b"v1".to_vec()),
            (b"aaab".to_vec(), b"v2".to_vec()),
            (b"abcd".to_vec(), b"v3".to_vec()),
            (b"zzzz".to_vec(), b"v4".to_vec()),
        ];
        for (k, v) in &kvs {
            t.insert(k, v.clone());
        }
        let root = t.root_commitment().unwrap();
        for (k, v) in &kvs {
            let proof = t.prove_inclusion(k).unwrap().expect("must prove");
            assert_eq!(&proof.value, v);
            assert!(verify_inclusion(&root, k, &proof, &t.srs));
        }
    }

    #[test]
    fn missing_key_returns_no_proof() {
        let mut t = make_tree();
        t.insert(b"abcd", b"v".to_vec());
        assert!(t.prove_inclusion(b"abce").unwrap().is_none());
        assert!(t.prove_inclusion(b"xxxx").unwrap().is_none());
    }

    #[test]
    fn tampered_value_fails_verify() {
        let mut t = make_tree();
        t.insert(b"abcd", b"original".to_vec());
        let root = t.root_commitment().unwrap();
        let mut proof = t.prove_inclusion(b"abcd").unwrap().unwrap();
        proof.value = b"tampered".to_vec();
        assert!(!verify_inclusion(&root, b"abcd", &proof, &t.srs));
    }

    #[test]
    fn wrong_key_fails_verify() {
        let mut t = make_tree();
        t.insert(b"abcd", b"v".to_vec());
        let root = t.root_commitment().unwrap();
        let proof = t.prove_inclusion(b"abcd").unwrap().unwrap();
        // Verify against a different key — slots won't match.
        assert!(!verify_inclusion(&root, b"abce", &proof, &t.srs));
    }

    #[test]
    fn wrong_root_fails_verify() {
        let mut t1 = make_tree();
        let mut t2 = make_tree();
        t2.srs = t1.srs.clone();

        t1.insert(b"abcd", b"v".to_vec());
        t2.insert(b"efgh", b"v".to_vec());

        let proof = t1.prove_inclusion(b"abcd").unwrap().unwrap();
        let wrong_root = t2.root_commitment().unwrap();
        assert!(!verify_inclusion(&wrong_root, b"abcd", &proof, &t1.srs));
    }

    #[test]
    fn tampered_proof_step_fails_verify() {
        let mut t = make_tree();
        t.insert(b"abcd", b"v".to_vec());
        let root = t.root_commitment().unwrap();
        let mut proof = t.prove_inclusion(b"abcd").unwrap().unwrap();
        // Flip a bit in the second step's evaluation field.
        proof.steps[1].evaluation += Fr::ONE;
        assert!(!verify_inclusion(&root, b"abcd", &proof, &t.srs));
    }

    #[test]
    fn deep_subtree_isolation() {
        // Two trees that differ only in one deep leaf should produce different
        // root commitments, exercising the recursive bottom-up computation.
        let mut t1 = make_tree();
        let mut t2 = make_tree();
        t2.srs = t1.srs.clone();

        t1.insert(b"abcd", b"v1".to_vec());
        t1.insert(b"abce", b"v2".to_vec());
        t2.insert(b"abcd", b"v1".to_vec());
        t2.insert(b"abce", b"v3".to_vec()); // different value at deep leaf

        assert_ne!(t1.root_commitment().unwrap(), t2.root_commitment().unwrap());
    }
}
