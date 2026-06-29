//! Hyper-side lock event handling.
//!
//! Locks are user-initiated events that move HYPER from the source-side balance
//! into a verkle-tree leaf, which the L1 bridge contract proves inclusion of
//! before minting wrapped tokens. The handler is responsible for:
//!
//!  1. Validating the lock signature.
//!  2. Computing the canonical leaf bytes the L1 bridge will decode.
//!  3. Inserting those bytes into the verkle tree at path `lock_id`.
//!
//! Burn semantics — actually decrementing the source-side balance — depend on
//! the UTXO + Pedersen + range-proof token primitives planned for Phase B-3.
//! Until those land, the handler accepts the lock event but does not enforce
//! source-side balance constraints. This is documented as a known gap.

use crate::proto;

/// Encode a lock event into the canonical leaf bytes consumed by the L1
/// bridge contract. Layout:
///
///   amount           (8B BE)
///   dest_chain_id    (8B BE)
///   dest_address_len (2B BE)
///   dest_address     (variable)
///   spend_pubkey_len (2B BE)
///   spend_pubkey     (variable)
pub fn encode_lock_leaf(event: &proto::HyperLockEvent) -> Vec<u8> {
    let mut buf =
        Vec::with_capacity(8 + 8 + 2 + event.dest_address.len() + 2 + event.spend_pubkey.len());
    buf.extend_from_slice(&event.amount.to_be_bytes());
    buf.extend_from_slice(&event.dest_chain_id.to_be_bytes());
    buf.extend_from_slice(&(event.dest_address.len() as u16).to_be_bytes());
    buf.extend_from_slice(&event.dest_address);
    buf.extend_from_slice(&(event.spend_pubkey.len() as u16).to_be_bytes());
    buf.extend_from_slice(&event.spend_pubkey);
    buf
}

/// Decoded view of a lock leaf.
#[derive(Debug, Clone, PartialEq)]
pub struct LockLeaf {
    pub amount: u64,
    pub dest_chain_id: u64,
    pub dest_address: Vec<u8>,
    pub spend_pubkey: Vec<u8>,
}

#[derive(thiserror::Error, Debug, PartialEq)]
pub enum DecodeError {
    #[error("leaf truncated: {what}")]
    Truncated { what: &'static str },
}

/// Decode the canonical lock leaf bytes back into its fields. Mirrors the
/// L1 bridge contract's parsing of the verkle leaf during claim verification.
pub fn decode_lock_leaf(bytes: &[u8]) -> Result<LockLeaf, DecodeError> {
    let mut cursor = 0usize;

    if bytes.len() < cursor + 8 {
        return Err(DecodeError::Truncated { what: "amount" });
    }
    let mut amount_bytes = [0u8; 8];
    amount_bytes.copy_from_slice(&bytes[cursor..cursor + 8]);
    let amount = u64::from_be_bytes(amount_bytes);
    cursor += 8;

    if bytes.len() < cursor + 8 {
        return Err(DecodeError::Truncated {
            what: "dest_chain_id",
        });
    }
    let mut chain_bytes = [0u8; 8];
    chain_bytes.copy_from_slice(&bytes[cursor..cursor + 8]);
    let dest_chain_id = u64::from_be_bytes(chain_bytes);
    cursor += 8;

    if bytes.len() < cursor + 2 {
        return Err(DecodeError::Truncated {
            what: "dest_address_len",
        });
    }
    let mut len_bytes = [0u8; 2];
    len_bytes.copy_from_slice(&bytes[cursor..cursor + 2]);
    let dest_addr_len = u16::from_be_bytes(len_bytes) as usize;
    cursor += 2;

    if bytes.len() < cursor + dest_addr_len {
        return Err(DecodeError::Truncated {
            what: "dest_address",
        });
    }
    let dest_address = bytes[cursor..cursor + dest_addr_len].to_vec();
    cursor += dest_addr_len;

    if bytes.len() < cursor + 2 {
        return Err(DecodeError::Truncated {
            what: "spend_pubkey_len",
        });
    }
    let mut len_bytes = [0u8; 2];
    len_bytes.copy_from_slice(&bytes[cursor..cursor + 2]);
    let spend_pk_len = u16::from_be_bytes(len_bytes) as usize;
    cursor += 2;

    if bytes.len() < cursor + spend_pk_len {
        return Err(DecodeError::Truncated {
            what: "spend_pubkey",
        });
    }
    let spend_pubkey = bytes[cursor..cursor + spend_pk_len].to_vec();

    Ok(LockLeaf {
        amount,
        dest_chain_id,
        dest_address,
        spend_pubkey,
    })
}

#[derive(thiserror::Error, Debug, PartialEq)]
pub enum LockError {
    #[error("amount must be non-zero")]
    ZeroAmount,
    #[error("lock_id must be exactly 32 bytes")]
    BadLockIdLength,
    #[error("dest_address must be non-empty")]
    EmptyDestAddress,
    #[error("spend_pubkey must be non-empty")]
    EmptySpendPubkey,
    #[error("EVM dest_address must be exactly 20 bytes (got {0})")]
    EvmDestAddressLength(usize),
    #[error(
        "EVM spend authority must be 20-byte address or 33-byte compressed secp256k1 (got {0})"
    )]
    EvmSpendPubkeyLength(usize),
    /// F035 fix: the transparent `HyperLockEvent` state-change path is
    /// disabled. Production bridge locks must flow through the
    /// confidential-lock pipeline (`apply_confidential_lock` →
    /// `validate_against_store`), which enforces Pedersen balance closure
    /// + Schnorr authorisation + nullifier double-spend checks. Any
    /// imported block carrying a transparent `HyperLockEvent` is
    /// rejected outright — without this gate, a malicious proposer could
    /// stuff arbitrary unbacked-mint leaves into the verkle root.
    #[error("transparent HyperLockEvent path disabled; use confidential locks")]
    TransparentLocksDisabled,
}

/// Validate the structural invariants of a lock event. Cryptographic
/// signature verification happens in a separate pass against the source-side
/// custody key.
pub fn validate_lock_event(event: &proto::HyperLockEvent) -> Result<(), LockError> {
    if event.amount == 0 {
        return Err(LockError::ZeroAmount);
    }
    if event.lock_id.len() != 32 {
        return Err(LockError::BadLockIdLength);
    }
    if event.dest_address.is_empty() {
        return Err(LockError::EmptyDestAddress);
    }
    if event.spend_pubkey.is_empty() {
        return Err(LockError::EmptySpendPubkey);
    }

    // EVM-specific enforcement: chain IDs that map to EVM chains must use
    // 20-byte addresses + 33-byte secp256k1 pubkeys. Non-EVM chains have
    // their own conventions enforced elsewhere.
    if is_evm_chain(event.dest_chain_id) {
        if event.dest_address.len() != 20 {
            return Err(LockError::EvmDestAddressLength(event.dest_address.len()));
        }
        // Spend authority can be either a 20-byte Ethereum address
        // (`ecrecover` directly) or a 33-byte compressed secp256k1 pubkey
        // (L1 derives the address itself before recovery).
        if event.spend_pubkey.len() != 20 && event.spend_pubkey.len() != 33 {
            return Err(LockError::EvmSpendPubkeyLength(event.spend_pubkey.len()));
        }
    }

    Ok(())
}

/// Common EVM chain ids that we recognize as EVM-formatted destinations.
/// Add to this list as we onboard new wrapped-token deployments.
fn is_evm_chain(chain_id: u64) -> bool {
    matches!(
        chain_id,
        1               // Ethereum mainnet
        | 8453          // Base
        | 10            // Optimism
        | 42161         // Arbitrum One
        | 137           // Polygon
        | 11155111 // Sepolia
    )
}

/// Insert a validated lock event into the verkle tree. The verkle key
/// is the `lock_id` prefixed with `KEY_DOMAIN_LOCK = 0x01` (see F117).
/// Without the discriminator a 32-byte lock_id can become a strict
/// path-prefix of a 33-byte nullifier or note-commitment key and
/// panic the recursive insert in `verkle::insert_recursive`.
pub fn insert_lock_into_tree(
    tree: &mut hypersnap_crypto::verkle::VerkleTree,
    event: &proto::HyperLockEvent,
) -> Result<(), LockError> {
    validate_lock_event(event)?;
    let leaf = encode_lock_leaf(event);
    let key = crate::hyper::builder::lock_verkle_key(&event.lock_id);
    tree.insert(&key, leaf);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hypersnap_crypto::kzg::KzgSrs;
    use hypersnap_crypto::kzg_lagrange::VERKLE_DOMAIN;
    use hypersnap_crypto::verkle::VerkleTree;
    use rand::rngs::OsRng;
    use std::sync::Arc;

    fn make_tree() -> VerkleTree {
        let mut rng = OsRng;
        VerkleTree::new(Arc::new(KzgSrs::random_unsafe(&mut rng, VERKLE_DOMAIN)))
    }

    fn sample_evm_event() -> proto::HyperLockEvent {
        proto::HyperLockEvent {
            amount: 1_000_000,
            dest_chain_id: 1,
            dest_address: vec![0xab; 20],
            spend_pubkey: vec![0x02; 33],
            lock_id: vec![0x01; 32],
            lock_height: 100,
            lock_timestamp: 1_700_000_000,
            lock_signature: vec![0u8; 64],
        }
    }

    #[test]
    fn validate_evm_event_accepts_correct_lengths() {
        let e = sample_evm_event();
        assert!(validate_lock_event(&e).is_ok());
    }

    #[test]
    fn validate_rejects_zero_amount() {
        let mut e = sample_evm_event();
        e.amount = 0;
        assert_eq!(validate_lock_event(&e), Err(LockError::ZeroAmount));
    }

    #[test]
    fn validate_rejects_short_lock_id() {
        let mut e = sample_evm_event();
        e.lock_id = vec![0u8; 16];
        assert_eq!(validate_lock_event(&e), Err(LockError::BadLockIdLength));
    }

    #[test]
    fn validate_rejects_evm_dest_address_with_wrong_length() {
        let mut e = sample_evm_event();
        e.dest_address = vec![0xab; 32];
        assert_eq!(
            validate_lock_event(&e),
            Err(LockError::EvmDestAddressLength(32))
        );
    }

    #[test]
    fn validate_rejects_evm_spend_pubkey_with_wrong_length() {
        let mut e = sample_evm_event();
        e.spend_pubkey = vec![0x02; 64];
        assert_eq!(
            validate_lock_event(&e),
            Err(LockError::EvmSpendPubkeyLength(64))
        );
    }

    #[test]
    fn encoded_leaf_has_expected_layout() {
        let e = sample_evm_event();
        let bytes = encode_lock_leaf(&e);
        // 8 (amount) + 8 (chain) + 2 (addr_len) + 20 (addr) + 2 (pk_len) + 33 (pk) = 73
        assert_eq!(bytes.len(), 73);
        assert_eq!(&bytes[0..8], &1_000_000u64.to_be_bytes());
        assert_eq!(&bytes[8..16], &1u64.to_be_bytes());
        assert_eq!(&bytes[16..18], &20u16.to_be_bytes());
        assert_eq!(&bytes[18..38], &[0xab; 20]);
        assert_eq!(&bytes[38..40], &33u16.to_be_bytes());
        assert_eq!(&bytes[40..73], &[0x02; 33]);
    }

    #[test]
    fn insert_lock_round_trips_through_tree() {
        let mut tree = make_tree();
        let e = sample_evm_event();
        insert_lock_into_tree(&mut tree, &e).unwrap();
        let key = crate::hyper::builder::lock_verkle_key(&e.lock_id);
        let stored = tree.get(&key).expect("lock must be retrievable");
        assert_eq!(stored, encode_lock_leaf(&e));
    }

    #[test]
    fn lock_leaf_decode_matches_event() {
        let e = sample_evm_event();
        let bytes = encode_lock_leaf(&e);
        let decoded = decode_lock_leaf(&bytes).unwrap();
        assert_eq!(decoded.amount, e.amount);
        assert_eq!(decoded.dest_chain_id, e.dest_chain_id);
        assert_eq!(decoded.dest_address, e.dest_address);
        assert_eq!(decoded.spend_pubkey, e.spend_pubkey);
    }

    #[test]
    fn lock_leaf_decode_rejects_truncated() {
        let e = sample_evm_event();
        let bytes = encode_lock_leaf(&e);
        for trunc in [0, 4, 7, 15, 17, 36] {
            assert!(
                decode_lock_leaf(&bytes[..trunc]).is_err(),
                "truncation at {} should fail",
                trunc
            );
        }
    }

    #[test]
    fn bridge_proof_pipeline_end_to_end() {
        // The full hypersnap-side bridge proof flow:
        // 1. Insert a lock event into the verkle tree.
        // 2. Compute the root commitment (this is what gets threshold-signed
        //    by the validator set and posted to L1 as the block's verkle_root).
        // 3. Generate an inclusion proof for the lock_id key.
        // 4. Verify the proof against the root (this is what the L1 bridge
        //    contract does during claim, via VerkleVerifier).
        // 5. Decode the leaf bytes back into its fields.
        // 6. Confirm the decoded fields match the original lock event.
        use hypersnap_crypto::kzg::KzgSrs;
        use hypersnap_crypto::kzg_lagrange::VERKLE_DOMAIN;
        use hypersnap_crypto::verkle::{verify_inclusion, VerkleTree};
        use rand::rngs::OsRng;
        use std::sync::Arc;

        let mut rng = OsRng;
        let srs = Arc::new(KzgSrs::random_unsafe(&mut rng, VERKLE_DOMAIN));
        let mut tree = VerkleTree::new(srs.clone());

        let event = sample_evm_event();
        insert_lock_into_tree(&mut tree, &event).unwrap();

        // Insert a few decoy locks so the proof exercises non-trivial path depth.
        let mut decoy = sample_evm_event();
        for i in 0u8..5 {
            decoy.lock_id = vec![0xa0 | i; 32];
            decoy.amount = 999_000 + i as u64;
            insert_lock_into_tree(&mut tree, &decoy).unwrap();
        }

        let root = tree.root_commitment().unwrap();
        let lock_key = crate::hyper::builder::lock_verkle_key(&event.lock_id);
        let proof = tree
            .prove_inclusion(&lock_key)
            .unwrap()
            .expect("lock must produce a valid inclusion proof");

        // L1-equivalent verification.
        assert!(verify_inclusion(&root, &lock_key, &proof, &srs));

        // Decode the leaf and confirm round-trip.
        let decoded = decode_lock_leaf(&proof.value).expect("leaf must decode");
        assert_eq!(decoded.amount, event.amount);
        assert_eq!(decoded.dest_chain_id, event.dest_chain_id);
        assert_eq!(decoded.dest_address, event.dest_address);
        assert_eq!(decoded.spend_pubkey, event.spend_pubkey);

        // Negative case: a wrong lock_id must produce a different (non-matching) proof.
        let wrong_key = crate::hyper::builder::lock_verkle_key(&vec![0xff; 32]);
        let wrong_proof = tree.prove_inclusion(&wrong_key).unwrap();
        assert!(wrong_proof.is_none(), "unknown lock_id has no proof");
    }

    #[test]
    fn distinct_lock_ids_produce_independent_entries() {
        let mut tree = make_tree();
        let mut e1 = sample_evm_event();
        e1.amount = 100;
        e1.lock_id = vec![0x01; 32];

        let mut e2 = sample_evm_event();
        e2.amount = 200;
        e2.lock_id = vec![0x02; 32];

        insert_lock_into_tree(&mut tree, &e1).unwrap();
        insert_lock_into_tree(&mut tree, &e2).unwrap();

        let k1 = crate::hyper::builder::lock_verkle_key(&e1.lock_id);
        let k2 = crate::hyper::builder::lock_verkle_key(&e2.lock_id);
        assert_eq!(tree.get(&k1).unwrap()[0..8], 100u64.to_be_bytes());
        assert_eq!(tree.get(&k2).unwrap()[0..8], 200u64.to_be_bytes());
    }

    /// F117: an attacker-chosen `lock_id` whose first byte equals the
    /// nullifier discriminator (0x02) used to be insertable into the
    /// same path-space, panicking the next nullifier insert. After
    /// the fix, lock keys are always 33 bytes with a leading 0x01,
    /// so no lock_id can be a prefix of a nullifier key.
    #[test]
    fn lock_with_attacker_chosen_nullifier_prefix_does_not_panic() {
        let mut tree = make_tree();
        let mut e = sample_evm_event();
        // Pick a lock_id that, before the fix, would have been a
        // strict 32-byte prefix of the 33-byte key
        // `[0x02, n_0, ..., n_31]` produced by `nullifier_verkle_key`.
        e.lock_id = vec![0x02u8; 32];
        insert_lock_into_tree(&mut tree, &e).unwrap();

        // Now drop a nullifier whose 32 inner bytes are identical to
        // the lock_id. With the fix, the lock landed at the 0x01
        // domain, so no path conflict — this insert must succeed.
        let nullifier = [0x02u8; 32];
        let nkey = crate::hyper::builder::nullifier_verkle_key_public(&nullifier);
        tree.insert(&nkey, b"sentinel".to_vec());
        assert!(tree.get(&nkey).is_some());
    }
}
