//! Sorted-pair binary merkle tree matching OZ `MerkleProof.verifyCalldata`.
//!
//! At each level pairs of siblings are hashed `keccak256(min(a,b) || max(a,b))`
//! — commutative, so proof verification is order-independent. Odd lone leaves
//! at any level are promoted to the next level without re-hashing.
//!
//! The Hypersnap-side merkle root constructor must use this exact algorithm
//! and the same canonical leaf ordering (sort by leaf hash ascending) so every
//! validator agrees on the same root for the same set of leaves.

use alloy_primitives::{keccak256, B256};

/// `keccak256(min(a, b) || max(a, b))`. Bytes32 ordering is treated as the
/// big-endian uint256 ordering, which matches `bytes32 < bytes32` in Solidity.
pub fn commutative_keccak256(a: B256, b: B256) -> B256 {
    let mut buf = [0u8; 64];
    let (lo, hi) = if a < b { (a, b) } else { (b, a) };
    buf[..32].copy_from_slice(lo.as_slice());
    buf[32..].copy_from_slice(hi.as_slice());
    keccak256(&buf)
}

#[derive(Debug, Clone)]
pub struct Tree {
    pub root: B256,
    /// `layers[0]` = leaves; `layers.last()` = `[root]` (or empty for an empty
    /// tree). Each subsequent layer is half the previous layer's length,
    /// rounding up.
    pub layers: Vec<Vec<B256>>,
}

impl Tree {
    /// Build a tree from a list of leaf hashes. The caller is responsible for
    /// canonical ordering — typically sort the leaves ascending before
    /// passing them in. Two callers building from the same set must use the
    /// same order to produce the same root.
    pub fn build(leaves: Vec<B256>) -> Self {
        if leaves.is_empty() {
            return Self {
                root: B256::ZERO,
                layers: vec![vec![]],
            };
        }
        let mut layers = vec![leaves.clone()];
        let mut current = leaves;
        while current.len() > 1 {
            let mut next = Vec::with_capacity((current.len() + 1) / 2);
            for chunk in current.chunks(2) {
                if chunk.len() == 2 {
                    next.push(commutative_keccak256(chunk[0], chunk[1]));
                } else {
                    next.push(chunk[0]);
                }
            }
            current = next.clone();
            layers.push(next);
        }
        let root = current[0];
        Self { root, layers }
    }

    /// Sibling-only proof for the leaf at `leaf_index`. Verifies against
    /// `self.root` via [`verify`].
    pub fn proof_for(&self, leaf_index: usize) -> Vec<B256> {
        let mut proof = Vec::new();
        let mut idx = leaf_index;
        for layer in &self.layers[..self.layers.len() - 1] {
            let sibling_idx = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
            if sibling_idx < layer.len() {
                proof.push(layer[sibling_idx]);
            }
            // else: lone leaf at this level — promoted up without a sibling.
            idx /= 2;
        }
        proof
    }
}

/// Verify that hashing `leaf` with `proof` produces `root`. Mirrors OZ
/// `MerkleProof.verifyCalldata` exactly.
#[allow(dead_code)]
pub fn verify(leaf: B256, proof: &[B256], root: B256) -> bool {
    let mut computed = leaf;
    for sibling in proof {
        computed = commutative_keccak256(computed, *sibling);
    }
    computed == root
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b32(byte: u8) -> B256 {
        let mut a = [0u8; 32];
        a.fill(byte);
        B256::from(a)
    }

    #[test]
    fn single_leaf_tree_root_equals_leaf() {
        let leaf = b32(0xab);
        let t = Tree::build(vec![leaf]);
        assert_eq!(t.root, leaf);
        assert!(t.proof_for(0).is_empty());
        assert!(verify(leaf, &[], leaf));
    }

    #[test]
    fn two_leaf_tree() {
        let a = b32(0x01);
        let b = b32(0x02);
        let t = Tree::build(vec![a, b]);
        assert_eq!(t.root, commutative_keccak256(a, b));
        assert_eq!(t.proof_for(0), vec![b]);
        assert_eq!(t.proof_for(1), vec![a]);
        assert!(verify(a, &t.proof_for(0), t.root));
        assert!(verify(b, &t.proof_for(1), t.root));
    }

    #[test]
    fn three_leaf_tree_lone_leaf_promoted() {
        let a = b32(0x01);
        let b = b32(0x02);
        let c = b32(0x03);
        let t = Tree::build(vec![a, b, c]);
        // Layer 1: [H(a,b), c] (c promoted)
        // Root: H(H(a,b), c)
        let ab = commutative_keccak256(a, b);
        let expected_root = commutative_keccak256(ab, c);
        assert_eq!(t.root, expected_root);
        for (i, leaf) in [a, b, c].iter().enumerate() {
            assert!(verify(*leaf, &t.proof_for(i), t.root));
        }
    }

    #[test]
    fn five_leaf_tree() {
        let leaves: Vec<B256> = (1..=5).map(b32).collect();
        let t = Tree::build(leaves.clone());
        for (i, leaf) in leaves.iter().enumerate() {
            assert!(
                verify(*leaf, &t.proof_for(i), t.root),
                "leaf {i} failed to verify"
            );
        }
    }

    #[test]
    fn commutative_keccak_is_order_independent() {
        let a = b32(0x10);
        let b = b32(0x20);
        assert_eq!(commutative_keccak256(a, b), commutative_keccak256(b, a));
    }

    #[test]
    fn many_leaves_all_verify() {
        let leaves: Vec<B256> = (0..127).map(|i| b32(i as u8)).collect();
        let t = Tree::build(leaves.clone());
        for (i, leaf) in leaves.iter().enumerate() {
            assert!(verify(*leaf, &t.proof_for(i), t.root));
        }
    }
}
