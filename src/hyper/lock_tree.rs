//! FIP-proof-of-work-tokenization §13.5 outbound-bridge merkle
//! tree builder.
//!
//! Validators collect every persisted `TokenLockState` from the
//! `RewardStore` (across all FIDs), encode each as the canonical
//! EVM bridge leaf via
//! [`crate::hyper::token_lock::encode_token_lock_leaf`], sort the
//! leaves ascending, and build a sorted-pair keccak256 merkle tree
//! via [`hypersnap_crypto::merkle::Tree`]. The resulting root is
//! threshold-signed by the validator set and posted to
//! `HypersnapBridge.claim` as the new `latestRoot`.
//!
//! ## Canonical leaf ordering
//!
//! Leaves are sorted ascending by leaf hash before tree
//! construction. This is the same ordering the offline bridge
//! ceremony tool uses (`crates/hypersnap-bridge-ceremony`) and the
//! contract-side test helper (`MerkleHelper.sortAscending`). Same
//! lock-set in → same root out, byte-exact, regardless of
//! iteration order in the underlying store.
//!
//! ## Per-claim proof
//!
//! [`build_proof_for`] returns `(leaf_hash, sibling_path)` for a
//! specific `lock_id` against the same canonical tree. The
//! claimant submits this proof to `HypersnapBridge.claim` along
//! with the (lock_id, recipient, amount, chain_id) used to
//! recompute the leaf on-chain.

use crate::hyper::token_lock::encode_token_lock_leaf;
use crate::proto;
use alloy_primitives::B256;
use hypersnap_crypto::merkle::Tree;

/// A single lock with its canonical leaf hash. Returned by
/// [`build_lock_tree`] alongside the constructed tree so callers
/// can correlate state ↔ proof without recomputing leaves.
#[derive(Debug, Clone)]
pub struct IndexedLock {
    pub state: proto::TokenLockState,
    pub leaf: B256,
}

/// Build the canonical merkle tree over `states`. Leaves are sorted
/// ascending so the root is independent of input order.
///
/// Returns the constructed `Tree` and the per-lock list in canonical
/// (sorted) order — index `i` in the returned vec corresponds to
/// `tree.layers[0][i]`.
pub fn build_lock_tree(states: Vec<proto::TokenLockState>) -> (Tree, Vec<IndexedLock>) {
    let mut indexed: Vec<IndexedLock> = states
        .into_iter()
        .map(|state| {
            let leaf = encode_token_lock_leaf(&state);
            IndexedLock { state, leaf }
        })
        .collect();
    indexed.sort_by_key(|l| l.leaf);
    let leaves: Vec<B256> = indexed.iter().map(|l| l.leaf).collect();
    let tree = Tree::build(leaves);
    (tree, indexed)
}

/// Build a per-lock claim proof. Returns `(leaf, proof)` such that
/// [`hypersnap_crypto::merkle::verify`] (and OZ's
/// `MerkleProof.verifyCalldata`) accept `(leaf, proof, root)`.
/// Returns `None` if `target_lock_id` isn't present.
pub fn build_proof_for(
    states: Vec<proto::TokenLockState>,
    target_lock_id: &[u8],
) -> Option<(B256, Vec<B256>)> {
    let (tree, indexed) = build_lock_tree(states);
    let idx = indexed
        .iter()
        .position(|l| l.state.lock_id == target_lock_id)?;
    let proof = tree.proof_for(idx);
    Some((indexed[idx].leaf, proof))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::U256;
    use hypersnap_crypto::merkle::verify;

    fn lock(fid: u64, lock_id: u8, amount: u64, addr_byte: u8) -> proto::TokenLockState {
        proto::TokenLockState {
            sender_fid: fid,
            amount,
            destination_chain_id: 10,
            destination_address: vec![addr_byte; 20],
            lock_id: vec![lock_id; 32],
        }
    }

    #[test]
    fn empty_set_produces_zero_root() {
        let (tree, indexed) = build_lock_tree(vec![]);
        assert_eq!(tree.root, B256::ZERO);
        assert!(indexed.is_empty());
    }

    #[test]
    fn single_lock_root_equals_its_leaf() {
        let states = vec![lock(1, 0xaa, 100, 0xab)];
        let leaf = encode_token_lock_leaf(&states[0]);
        let (tree, indexed) = build_lock_tree(states);
        assert_eq!(tree.root, leaf);
        assert_eq!(indexed[0].leaf, leaf);
    }

    #[test]
    fn two_locks_form_simple_tree() {
        let states = vec![lock(1, 0xaa, 100, 0xab), lock(2, 0xbb, 200, 0xcd)];
        let (tree, indexed) = build_lock_tree(states);
        // Tree of 2 leaves: root = commutative_keccak256(l0, l1).
        assert_eq!(indexed.len(), 2);
        for entry in &indexed {
            let proof = tree.proof_for(indexed.iter().position(|l| l.leaf == entry.leaf).unwrap());
            assert!(verify(entry.leaf, &proof, tree.root));
        }
    }

    /// Tree root depends only on the leaf set (sorted), not on the
    /// order locks were added to the store. Pins the canonical
    /// ordering invariant — the bridge contract's `latestRoot`
    /// must converge regardless of which validator builds it.
    #[test]
    fn tree_root_is_input_order_independent() {
        let s1 = lock(1, 0x01, 100, 0xab);
        let s2 = lock(2, 0x02, 200, 0xcd);
        let s3 = lock(3, 0x03, 300, 0xef);
        let (t_a, _) = build_lock_tree(vec![s1.clone(), s2.clone(), s3.clone()]);
        let (t_b, _) = build_lock_tree(vec![s3.clone(), s1.clone(), s2.clone()]);
        let (t_c, _) = build_lock_tree(vec![s2, s3, s1]);
        assert_eq!(t_a.root, t_b.root);
        assert_eq!(t_a.root, t_c.root);
    }

    #[test]
    fn build_proof_for_returns_verifying_proof() {
        let states = (0..7u8)
            .map(|i| lock(i as u64 + 1, i, 100 + i as u64, 0xab))
            .collect::<Vec<_>>();
        let target = vec![3u8; 32];
        let (root, _) = {
            let (tree, _) = build_lock_tree(states.clone());
            (tree.root, tree)
        };
        let (leaf, proof) = build_proof_for(states, &target).unwrap();
        assert!(verify(leaf, &proof, root));
    }

    #[test]
    fn build_proof_for_returns_none_on_miss() {
        let states = vec![lock(1, 0xaa, 100, 0xab)];
        assert!(build_proof_for(states, &[0xff; 32]).is_none());
    }

    /// Pins the Phase 2a contract integration: the leaf encoder
    /// produces bytes the bridge contract accepts. Using the
    /// `lock_leaf_evm` cross-side pinned vector from
    /// `hypersnap_crypto::bridge_payload::tests::cross_side_pinned_vectors`,
    /// a single-lock tree's root must equal that exact value.
    #[test]
    fn single_lock_root_matches_cross_side_pinned_vector() {
        let lock_id = B256::from_slice(
            &hex::decode("deadbeefcafebabe1122334455667788deadbeefcafebabe1122334455667788")
                .unwrap(),
        );
        let recipient_bytes = hex::decode("0102030405060708090a0b0c0d0e0f1011121314").unwrap();
        let state = proto::TokenLockState {
            sender_fid: 99, // doesn't affect the leaf hash
            amount: 1_000_000,
            destination_chain_id: 1,
            destination_address: recipient_bytes,
            lock_id: lock_id.as_slice().to_vec(),
        };
        let (tree, _) = build_lock_tree(vec![state]);
        let expected = hypersnap_crypto::bridge_payload::lock_leaf_evm(
            lock_id,
            1,
            alloy_primitives::Address::from_slice(
                &hex::decode("0102030405060708090a0b0c0d0e0f1011121314").unwrap(),
            ),
            U256::from(1_000_000u64),
        );
        assert_eq!(tree.root, expected);
        // And the cross-side pinned vector itself.
        assert_eq!(
            tree.root,
            B256::from_slice(
                &hex::decode("946e398b9ac10b77850cfc5877dab9207e37c8622db8bbacecbbc1c997818996")
                    .unwrap()
            )
        );
    }
}
