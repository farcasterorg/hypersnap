//! Hypersnap-side bridge state and merkle root constructor.
//!
//! Validators run this at every epoch boundary to build the merkle root
//! they threshold-sign for the EVM/Solana/Quilibrium bridges. The output
//! is a [`BridgeRoot`] containing a single 32-byte root and per-leaf
//! proofs ready to hand to claim relayers.
//!
//! ## Carry-forward semantics
//!
//! [`BridgeRoot::build`] takes the full set of currently-outstanding locks
//! plus a set of `lockId`s that have already been claimed on their
//! destination chain. It excludes the claimed set from the new tree.
//!
//! **Validators MUST carry forward unclaimed leaves into successive roots.**
//! Once a new root is signed and advanced past on-chain, leaves only in
//! the previous root become unreachable — there's no on-chain memory of
//! prior roots. This module provides the mechanism (just feed it all
//! still-outstanding locks each epoch); the protocol-level discipline of
//! actually doing that lives in the validator daemon.
//!
//! ## Determinism
//!
//! Output is byte-deterministic across validators given identical input.
//! Leaves are sorted ascending by leaf hash before tree construction (the
//! same canonical ordering the ceremony CLI uses), so two validators with
//! the same `(locks, claimed)` set produce the same root.

use crate::bridge_payload::{lock_leaf_evm, lock_leaf_solana, FAMILY_EVM, FAMILY_SOLANA};
use crate::merkle::{self, Tree};
use alloy_primitives::{Address, B256, U256};
use std::collections::BTreeSet;

/// Discriminator for which destination-network family a lock targets.
/// Mirrors the family byte embedded in the leaf encoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NetworkFamily {
    Evm,
    Solana,
    Quilibrium,
}

impl NetworkFamily {
    pub fn as_byte(self) -> u8 {
        match self {
            NetworkFamily::Evm => FAMILY_EVM,
            NetworkFamily::Solana => FAMILY_SOLANA,
            NetworkFamily::Quilibrium => 2,
        }
    }
}

/// Family-specific destination encoding. The leaf hash function for each
/// family is fixed in [`crate::bridge_payload`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NetworkTarget {
    /// EVM-family target: a chainId + 20-byte recipient address.
    Evm { chain_id: u32, recipient: Address },
    /// Solana-family target: a 32-byte program-derived recipient pubkey.
    Solana { recipient_pubkey: [u8; 32] },
    /// Quilibrium target — encoding TBD, see FIP. Reserved for the future.
    Quilibrium,
}

impl NetworkTarget {
    pub fn family(&self) -> NetworkFamily {
        match self {
            NetworkTarget::Evm { .. } => NetworkFamily::Evm,
            NetworkTarget::Solana { .. } => NetworkFamily::Solana,
            NetworkTarget::Quilibrium => NetworkFamily::Quilibrium,
        }
    }
}

/// A single outstanding lock that has not yet been claimed on its
/// destination chain. Validator state stores these; each epoch's root is
/// the merkle tree over the (still-unclaimed) subset.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutstandingLock {
    /// Globally unique within Hypersnap; canonical identifier consumed by
    /// the destination chain's `claimed` nullifier set.
    pub lock_id: B256,
    pub target: NetworkTarget,
    /// Token amount in destination-chain units. The leaf encodes this as
    /// a 32-byte big-endian uint256.
    pub amount: U256,
    /// Hypersnap block number at which this lock was created. Not part of
    /// the leaf hash; useful for ordering, expiry, and observability.
    pub created_at_block: u64,
}

impl OutstandingLock {
    /// Compute the destination-side leaf hash. This is the value the
    /// destination chain's verifier reproduces from claim parameters; if
    /// the leaf hash matches a path in the signed root, the claim succeeds.
    pub fn leaf_hash(&self) -> Result<B256, BuildError> {
        match self.target {
            NetworkTarget::Evm {
                chain_id,
                recipient,
            } => Ok(lock_leaf_evm(
                self.lock_id,
                chain_id,
                recipient,
                self.amount,
            )),
            NetworkTarget::Solana { recipient_pubkey } => Ok(lock_leaf_solana(
                self.lock_id,
                recipient_pubkey,
                self.amount,
            )),
            NetworkTarget::Quilibrium => Err(BuildError::QuilibriumLeafEncodingNotFinalized),
        }
    }
}

#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum BuildError {
    #[error("empty locks set: cannot build a zero-leaf tree")]
    Empty,
    #[error("Quilibrium leaf encoding not finalized; refusing to include in tree")]
    QuilibriumLeafEncodingNotFinalized,
    #[error("duplicate lockId {0}")]
    DuplicateLockId(B256),
}

/// One entry in the published tree: the original lock plus its computed
/// leaf hash and merkle proof. Distributed to relayers so they can
/// build claim transactions.
#[derive(Clone, Debug)]
pub struct LeafEntry {
    pub lock: OutstandingLock,
    pub leaf_hash: B256,
    pub merkle_proof: Vec<B256>,
}

/// Output of [`BridgeRoot::build`]. The 32-byte `root` is what validators
/// threshold-sign and what every destination chain's bridge verifies
/// against. `entries` are sorted by `leaf_hash` ascending (canonical
/// ordering, matches the ceremony CLI).
#[derive(Clone, Debug)]
pub struct BridgeRoot {
    pub root: B256,
    pub entries: Vec<LeafEntry>,
}

impl BridgeRoot {
    /// Build a fresh root from the validator's view of outstanding locks,
    /// excluding any whose `lockId` has already been claimed on its
    /// destination chain.
    ///
    /// Validators run this at each epoch boundary, then threshold-sign
    /// `bridge_payload::merkle_root_update_digest(blockNumber, root)`.
    pub fn build(locks: &[OutstandingLock], claimed: &BTreeSet<B256>) -> Result<Self, BuildError> {
        // Filter out claimed leaves.
        let mut active: Vec<&OutstandingLock> = locks
            .iter()
            .filter(|l| !claimed.contains(&l.lock_id))
            .collect();

        if active.is_empty() {
            return Err(BuildError::Empty);
        }

        // Reject duplicate lock_ids — would silently exclude one and break
        // claim invariants.
        {
            let mut seen = BTreeSet::new();
            for l in &active {
                if !seen.insert(l.lock_id) {
                    return Err(BuildError::DuplicateLockId(l.lock_id));
                }
            }
        }

        // Compute leaf hashes. Pair each with its source lock so we can
        // emit per-entry proofs after sorting.
        let mut paired: Vec<(B256, &OutstandingLock)> = active
            .drain(..)
            .map(|l| Ok::<_, BuildError>((l.leaf_hash()?, l)))
            .collect::<Result<_, _>>()?;

        // Canonical ordering: ascending by leaf hash.
        paired.sort_by(|a, b| a.0.cmp(&b.0));

        let leaf_hashes: Vec<B256> = paired.iter().map(|(h, _)| *h).collect();
        let tree = Tree::build(leaf_hashes);

        let entries: Vec<LeafEntry> = paired
            .into_iter()
            .enumerate()
            .map(|(idx, (leaf_hash, lock))| LeafEntry {
                lock: lock.clone(),
                leaf_hash,
                merkle_proof: tree.proof_for(idx),
            })
            .collect();

        Ok(Self {
            root: tree.root,
            entries,
        })
    }

    /// Look up a single entry by `lockId`. Linear scan; entry count is
    /// expected small per epoch.
    pub fn entry_for(&self, lock_id: B256) -> Option<&LeafEntry> {
        self.entries.iter().find(|e| e.lock.lock_id == lock_id)
    }

    /// Verify a leaf+proof against this tree's root. Mirrors the EVM
    /// bridge's `MerkleProof.verifyCalldata` semantics.
    pub fn verify(&self, leaf: B256, proof: &[B256]) -> bool {
        merkle::verify(leaf, proof, self.root)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bridge_payload::{lock_leaf_evm, lock_leaf_solana};

    fn evm_lock(id_byte: u8, chain_id: u32, addr_byte: u8, amount: u64) -> OutstandingLock {
        let mut lock_id = [0u8; 32];
        lock_id[31] = id_byte;
        let mut addr = [0u8; 20];
        addr[19] = addr_byte;
        OutstandingLock {
            lock_id: B256::from(lock_id),
            target: NetworkTarget::Evm {
                chain_id,
                recipient: Address::from(addr),
            },
            amount: U256::from(amount),
            created_at_block: 1,
        }
    }

    fn solana_lock(id_byte: u8, key_byte: u8, amount: u64) -> OutstandingLock {
        let mut lock_id = [0u8; 32];
        lock_id[31] = id_byte;
        let mut key = [0u8; 32];
        key[31] = key_byte;
        OutstandingLock {
            lock_id: B256::from(lock_id),
            target: NetworkTarget::Solana {
                recipient_pubkey: key,
            },
            amount: U256::from(amount),
            created_at_block: 1,
        }
    }

    #[test]
    fn empty_locks_set_errors() {
        assert_eq!(
            BridgeRoot::build(&[], &BTreeSet::new()).unwrap_err(),
            BuildError::Empty
        );
    }

    #[test]
    fn all_claimed_errors() {
        let locks = vec![evm_lock(1, 1, 0xaa, 100)];
        let mut claimed = BTreeSet::new();
        claimed.insert(locks[0].lock_id);
        assert_eq!(
            BridgeRoot::build(&locks, &claimed).unwrap_err(),
            BuildError::Empty
        );
    }

    #[test]
    fn single_lock_root_equals_leaf() {
        let lock = evm_lock(1, 1, 0xaa, 100);
        let leaf = lock.leaf_hash().unwrap();
        let result = BridgeRoot::build(&[lock.clone()], &BTreeSet::new()).unwrap();
        assert_eq!(result.root, leaf);
        assert_eq!(result.entries.len(), 1);
        assert!(result.entries[0].merkle_proof.is_empty());
        assert!(result.verify(leaf, &[]));
    }

    #[test]
    fn duplicates_rejected() {
        let lock1 = evm_lock(1, 1, 0xaa, 100);
        let lock2 = evm_lock(1, 1, 0xbb, 200); // same lock_id, different other fields
        let err = BridgeRoot::build(&[lock1.clone(), lock2], &BTreeSet::new()).unwrap_err();
        assert!(matches!(err, BuildError::DuplicateLockId(_)));
    }

    #[test]
    fn claimed_set_excludes_leaves() {
        let lock1 = evm_lock(1, 1, 0xaa, 100);
        let lock2 = evm_lock(2, 1, 0xbb, 200);
        let lock3 = evm_lock(3, 1, 0xcc, 300);
        let mut claimed = BTreeSet::new();
        claimed.insert(lock2.lock_id);

        let result =
            BridgeRoot::build(&[lock1.clone(), lock2.clone(), lock3.clone()], &claimed).unwrap();
        assert_eq!(result.entries.len(), 2);
        assert!(result.entry_for(lock1.lock_id).is_some());
        assert!(result.entry_for(lock2.lock_id).is_none());
        assert!(result.entry_for(lock3.lock_id).is_some());
    }

    #[test]
    fn cross_family_tree() {
        // EVM + Solana leaves in the same tree.
        let evm = evm_lock(1, 1, 0xaa, 100);
        let sol = solana_lock(2, 0x42, 200);
        let result = BridgeRoot::build(&[evm.clone(), sol.clone()], &BTreeSet::new()).unwrap();
        assert_eq!(result.entries.len(), 2);

        let evm_entry = result.entry_for(evm.lock_id).unwrap();
        let sol_entry = result.entry_for(sol.lock_id).unwrap();
        assert!(result.verify(evm_entry.leaf_hash, &evm_entry.merkle_proof));
        assert!(result.verify(sol_entry.leaf_hash, &sol_entry.merkle_proof));
    }

    #[test]
    fn quilibrium_target_errors_until_finalized() {
        let lock = OutstandingLock {
            lock_id: B256::from([1u8; 32]),
            target: NetworkTarget::Quilibrium,
            amount: U256::from(100),
            created_at_block: 1,
        };
        assert!(matches!(
            BridgeRoot::build(&[lock], &BTreeSet::new()).unwrap_err(),
            BuildError::QuilibriumLeafEncodingNotFinalized
        ));
    }

    #[test]
    fn determinism_input_order_independent() {
        // Same set of locks in different input orders must produce the
        // same root (sorting by leaf hash is the canonical step).
        let locks_a = vec![
            evm_lock(1, 1, 0xaa, 100),
            evm_lock(2, 1, 0xbb, 200),
            evm_lock(3, 1, 0xcc, 300),
        ];
        let locks_b = vec![
            evm_lock(3, 1, 0xcc, 300),
            evm_lock(1, 1, 0xaa, 100),
            evm_lock(2, 1, 0xbb, 200),
        ];
        let r_a = BridgeRoot::build(&locks_a, &BTreeSet::new()).unwrap();
        let r_b = BridgeRoot::build(&locks_b, &BTreeSet::new()).unwrap();
        assert_eq!(r_a.root, r_b.root);
    }

    #[test]
    fn proofs_verify_against_root_for_every_leaf() {
        let locks: Vec<OutstandingLock> = (1..=11)
            .map(|i| evm_lock(i as u8, 1, i as u8, (i as u64) * 100))
            .collect();
        let r = BridgeRoot::build(&locks, &BTreeSet::new()).unwrap();
        for entry in &r.entries {
            assert!(
                r.verify(entry.leaf_hash, &entry.merkle_proof),
                "proof failed for lock {}",
                entry.lock.lock_id
            );
        }
    }

    /// Cross-side determinism: a tree built here from the same EVM-only
    /// fixture used by `bridge-ceremony build-tree` (and by the Foundry
    /// `MerkleHelperTest::test_crossCheckAgainstRustCeremonyTool`) produces
    /// the SAME root. Drift on any side fails.
    #[test]
    fn cross_check_against_ceremony_tool_5leaf() {
        // Fixture: 5 EVM locks with chainId 31337 (Anvil), sequential
        // recipients/amounts. Same input as the Solidity / CLI test.
        let mk = |id: u8, addr_byte: u8, amount: u64| {
            let mut lock_id = [0u8; 32];
            lock_id[31] = id;
            let mut addr = [0u8; 20];
            for b in addr.iter_mut() {
                *b = addr_byte;
            }
            OutstandingLock {
                lock_id: B256::from(lock_id),
                target: NetworkTarget::Evm {
                    chain_id: 31337,
                    recipient: Address::from(addr),
                },
                amount: U256::from(amount),
                created_at_block: 1,
            }
        };
        let locks = vec![
            mk(1, 0x11, 100),
            mk(2, 0x22, 200),
            mk(3, 0x33, 300),
            mk(4, 0x44, 400),
            mk(5, 0x55, 500),
        ];
        let r = BridgeRoot::build(&locks, &BTreeSet::new()).unwrap();
        let expected_root = B256::from_slice(
            &hex::decode("3d82cde960606e71ced9fefcc38e74c2f8d16aab2a54b2c3cc5394103107dd6a")
                .unwrap(),
        );
        assert_eq!(
            r.root, expected_root,
            "5-leaf root drift between bridge_state and ceremony CLI / Foundry tests"
        );
    }
}
