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
    #[error("lock signature must be exactly 112 bytes (got {0})")]
    BadSignatureLength(usize),
    #[error("invalid lock signature (R or s not canonical)")]
    BadSignature,
    #[error("locker pubkey must be exactly 56 bytes compressed Decaf448 (got {0})")]
    BadLockerPubkey(usize),
    #[error("lock signature does not verify under locker pubkey")]
    InvalidLockSignature,
}

/// Canonical signing payload for a lock event. The locker signs these bytes
/// to authorize the burn → bridge mint mapping. Domain-separated so it
/// cannot collide with any other Schnorr-signed payload in the protocol.
pub fn lock_signing_payload(event: &proto::HyperLockEvent) -> Vec<u8> {
    const DST: &[u8] = b"hypersnap-lock-event-v1";
    let mut buf = Vec::with_capacity(
        DST.len()
            + 8
            + 8
            + 2
            + event.dest_address.len()
            + 2
            + event.spend_pubkey.len()
            + 32
            + 8
            + 8,
    );
    buf.extend_from_slice(DST);
    buf.extend_from_slice(&event.amount.to_be_bytes());
    buf.extend_from_slice(&event.dest_chain_id.to_be_bytes());
    buf.extend_from_slice(&(event.dest_address.len() as u16).to_be_bytes());
    buf.extend_from_slice(&event.dest_address);
    buf.extend_from_slice(&(event.spend_pubkey.len() as u16).to_be_bytes());
    buf.extend_from_slice(&event.spend_pubkey);
    buf.extend_from_slice(&event.lock_id);
    buf.extend_from_slice(&event.lock_height.to_be_bytes());
    buf.extend_from_slice(&event.lock_timestamp.to_be_bytes());
    buf
}

/// Verify the lock event's Schnorr signature against `locker_pubkey`. The
/// locker pubkey is the spend pubkey of the burned note (or a one-time pubkey
/// derived during the burn). The caller is responsible for confirming the
/// pubkey matches whatever notes the locker claims to burn.
pub fn verify_lock_signature(
    event: &proto::HyperLockEvent,
    locker_pubkey_bytes: &[u8],
) -> Result<(), LockError> {
    use hypersnap_crypto::tokens::{point_from_compressed_bytes, schnorr_verify, SchnorrSignature};

    if locker_pubkey_bytes.len() != 56 {
        return Err(LockError::BadLockerPubkey(locker_pubkey_bytes.len()));
    }
    let mut pk_arr = [0u8; 56];
    pk_arr.copy_from_slice(locker_pubkey_bytes);
    let locker_pubkey =
        point_from_compressed_bytes(&pk_arr).ok_or(LockError::BadLockerPubkey(56))?;

    if event.lock_signature.len() != 112 {
        return Err(LockError::BadSignatureLength(event.lock_signature.len()));
    }
    let sig = SchnorrSignature::from_bytes(&event.lock_signature).ok_or(LockError::BadSignature)?;

    let payload = lock_signing_payload(event);
    if schnorr_verify(&locker_pubkey, &payload, &sig) {
        Ok(())
    } else {
        Err(LockError::InvalidLockSignature)
    }
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

/// Insert a validated lock event into the verkle tree. The verkle key is the
/// 32-byte `lock_id`; the value is the canonical leaf encoding.
pub fn insert_lock_into_tree(
    tree: &mut hypersnap_crypto::verkle::VerkleTree,
    event: &proto::HyperLockEvent,
) -> Result<(), LockError> {
    validate_lock_event(event)?;
    let leaf = encode_lock_leaf(event);
    tree.insert(&event.lock_id, leaf);
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
    fn lock_signing_payload_is_deterministic() {
        let e = sample_evm_event();
        let p1 = lock_signing_payload(&e);
        let p2 = lock_signing_payload(&e);
        assert_eq!(p1, p2);

        // Any field change → different payload.
        let mut e2 = e.clone();
        e2.amount += 1;
        assert_ne!(lock_signing_payload(&e), lock_signing_payload(&e2));

        let mut e3 = e.clone();
        e3.dest_chain_id = 999;
        assert_ne!(lock_signing_payload(&e), lock_signing_payload(&e3));

        let mut e4 = e.clone();
        e4.lock_id[0] ^= 0xff;
        assert_ne!(lock_signing_payload(&e), lock_signing_payload(&e4));
    }

    #[test]
    fn schnorr_signed_lock_verifies() {
        use hypersnap_crypto::bulletproofs::curve_adapter::Scalar;
        use hypersnap_crypto::tokens::{
            point_to_compressed_bytes, schnorr_sign, PedersenCommitment as PC,
        };
        use rand::rngs::OsRng;

        let mut rng = OsRng;
        let locker_secret = Scalar::random(&mut rng);
        // The locker's pubkey is locker_secret · B (using the Pedersen value
        // generator, the same one used for Schnorr signatures).
        let pc = hypersnap_crypto::bulletproofs::PedersenGens::default();
        let locker_pubkey = hypersnap_crypto::bulletproofs::curve_adapter::Point::multiscalar_mul(
            &[locker_secret],
            &[pc.B],
        );

        let mut e = sample_evm_event();
        let payload = lock_signing_payload(&e);
        let sig = schnorr_sign(&locker_secret, &payload, &mut rng);
        e.lock_signature = sig.to_bytes().to_vec();

        let pk_bytes = point_to_compressed_bytes(&locker_pubkey);
        verify_lock_signature(&e, &pk_bytes).unwrap();
    }

    #[test]
    fn schnorr_lock_rejects_wrong_locker() {
        use hypersnap_crypto::bulletproofs::curve_adapter::Scalar;
        use hypersnap_crypto::tokens::{point_to_compressed_bytes, schnorr_sign};
        use rand::rngs::OsRng;

        let mut rng = OsRng;
        let locker_secret = Scalar::random(&mut rng);
        let other_secret = Scalar::random(&mut rng);
        let pc = hypersnap_crypto::bulletproofs::PedersenGens::default();
        let other_pubkey = hypersnap_crypto::bulletproofs::curve_adapter::Point::multiscalar_mul(
            &[other_secret],
            &[pc.B],
        );

        let mut e = sample_evm_event();
        let payload = lock_signing_payload(&e);
        let sig = schnorr_sign(&locker_secret, &payload, &mut rng);
        e.lock_signature = sig.to_bytes().to_vec();

        let other_pk_bytes = point_to_compressed_bytes(&other_pubkey);
        assert!(matches!(
            verify_lock_signature(&e, &other_pk_bytes),
            Err(LockError::InvalidLockSignature)
        ));
    }

    #[test]
    fn schnorr_lock_rejects_tampered_amount() {
        use hypersnap_crypto::bulletproofs::curve_adapter::Scalar;
        use hypersnap_crypto::tokens::{point_to_compressed_bytes, schnorr_sign};
        use rand::rngs::OsRng;

        let mut rng = OsRng;
        let locker_secret = Scalar::random(&mut rng);
        let pc = hypersnap_crypto::bulletproofs::PedersenGens::default();
        let locker_pubkey = hypersnap_crypto::bulletproofs::curve_adapter::Point::multiscalar_mul(
            &[locker_secret],
            &[pc.B],
        );

        let mut e = sample_evm_event();
        let payload = lock_signing_payload(&e);
        let sig = schnorr_sign(&locker_secret, &payload, &mut rng);
        e.lock_signature = sig.to_bytes().to_vec();
        // Tamper with amount AFTER signing.
        e.amount += 1_000_000;

        let pk_bytes = point_to_compressed_bytes(&locker_pubkey);
        assert!(matches!(
            verify_lock_signature(&e, &pk_bytes),
            Err(LockError::InvalidLockSignature)
        ));
    }

    #[test]
    fn lock_signature_rejects_wrong_pubkey_length() {
        let e = sample_evm_event();
        assert!(matches!(
            verify_lock_signature(&e, &[0u8; 32]),
            Err(LockError::BadLockerPubkey(32))
        ));
    }

    #[test]
    fn lock_signature_rejects_wrong_signature_length() {
        let mut e = sample_evm_event();
        e.lock_signature = vec![0u8; 64];
        assert!(matches!(
            verify_lock_signature(&e, &[0u8; 56]),
            Err(LockError::BadLockerPubkey(_)) | Err(LockError::BadSignatureLength(_))
        ));
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
        let stored = tree.get(&e.lock_id).expect("lock must be retrievable");
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
        let proof = tree
            .prove_inclusion(&event.lock_id)
            .unwrap()
            .expect("lock must produce a valid inclusion proof");

        // L1-equivalent verification.
        assert!(verify_inclusion(&root, &event.lock_id, &proof, &srs));

        // Decode the leaf and confirm round-trip.
        let decoded = decode_lock_leaf(&proof.value).expect("leaf must decode");
        assert_eq!(decoded.amount, event.amount);
        assert_eq!(decoded.dest_chain_id, event.dest_chain_id);
        assert_eq!(decoded.dest_address, event.dest_address);
        assert_eq!(decoded.spend_pubkey, event.spend_pubkey);

        // Negative case: a wrong lock_id must produce a different (non-matching) proof.
        let wrong_key = vec![0xff; 32];
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

        assert_eq!(tree.get(&e1.lock_id).unwrap()[0..8], 100u64.to_be_bytes());
        assert_eq!(tree.get(&e2.lock_id).unwrap()[0..8], 200u64.to_be_bytes());
    }
}
