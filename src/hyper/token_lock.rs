//! FIP-proof-of-work-tokenization §13.5 transparent token lock.
//!
//! Locks decrement the sender's transparent balance and record a
//! `TokenLockState` keyed by `(sender_fid, lock_id)`. At root-
//! posting time, validators collect every unclaimed lock state
//! from the store, recompute each leaf hash via
//! [`hypersnap_crypto::bridge_payload::lock_leaf_evm`], build the
//! sorted-pair keccak256 merkle tree (matching OZ
//! `MerkleProof.verifyCalldata`), threshold-sign the root, and
//! post it to `HypersnapBridge.claim`. A user or relayer then
//! submits a single-leaf merkle proof against that root to mint
//! wrapped tokens.
//!
//! The leaf encoding is **byte-exact** with the on-chain
//! computation:
//!
//! ```text
//! keccak256(
//!     keccak256("HYPERSNAP_LOCK_LEAF_V1") ||
//!     lock_id (32 bytes) ||
//!     family (1 byte, EVM = 0x00) ||
//!     destination_chain_id (BE u32, 4 bytes) ||
//!     recipient (20 bytes) ||
//!     amount (BE u256, 32 bytes)
//! )
//! ```
//!
//! Phase 2a is EVM-only. Other network families plug in by
//! teaching the leaf encoder the appropriate
//! `lock_leaf_<family>` helper from `hypersnap_crypto::
//! bridge_payload`.

use crate::proto;
use alloy_primitives::{Address, B256, U256};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum LockValidationError {
    #[error("signer_pubkey must be 32 bytes (got {got})")]
    BadSignerPubkey { got: usize },
    #[error("signature must be 64 bytes (got {got})")]
    BadSignatureLen { got: usize },
    #[error("signer_pubkey did not parse as a valid Ed25519 key")]
    InvalidSignerPubkey,
    #[error("signature does not verify under the included signer_pubkey")]
    SignatureVerifyFailed,
    #[error("amount must be > 0")]
    ZeroAmount,
    #[error("sender_fid must be > 0")]
    BadSenderFid,
    #[error("destination_chain_id must be > 0")]
    BadDestinationChain,
    #[error("destination_address must be exactly 20 bytes for EVM family (got {got})")]
    BadDestinationAddressLen { got: usize },
    #[error("lock_id must be exactly 32 bytes (got {got})")]
    BadLockIdLen { got: usize },
}

/// Canonical signing payload for `TokenLockBody`. Independent of
/// the on-chain leaf encoding — this is what the user's Ed25519
/// signer commits to so the protocol knows the lock is authorized.
///
/// Format:
///
/// ```text
/// DST                             (29 bytes, includes \0 padding)
/// sender_fid           (BE u64)    ( 8 bytes)
/// amount               (BE u64)    ( 8 bytes)
/// nonce                (BE u64)    ( 8 bytes)
/// destination_chain_id (BE u32)    ( 4 bytes)
/// destination_address              (20 bytes, EVM)
/// lock_id                          (32 bytes)
/// signer_pubkey                    (32 bytes)
/// ```
///
/// The signer pubkey is part of the payload so a single signature
/// cannot be replayed across signer-key rotations.
pub fn token_lock_signing_payload(body: &proto::TokenLockBody) -> Vec<u8> {
    const DST: &[u8] = b"hypersnap-token-lock-v1\x00\x00\x00\x00\x00\x00";
    let mut buf = Vec::with_capacity(
        DST.len()
            + 8
            + 8
            + 8
            + 4
            + body.destination_address.len()
            + body.lock_id.len()
            + body.signer_pubkey.len(),
    );
    buf.extend_from_slice(DST);
    buf.extend_from_slice(&body.sender_fid.to_be_bytes());
    buf.extend_from_slice(&body.amount.to_be_bytes());
    buf.extend_from_slice(&body.nonce.to_be_bytes());
    buf.extend_from_slice(&body.destination_chain_id.to_be_bytes());
    buf.extend_from_slice(&body.destination_address);
    buf.extend_from_slice(&body.lock_id);
    buf.extend_from_slice(&body.signer_pubkey);
    buf
}

/// Compute the EVM-family merkle leaf hash for a lock. This is the
/// byte-exact value the on-chain `HypersnapBridge.claim` recomputes
/// from `(lock_id, destinationChainId, recipient, amount)` and
/// looks up in the merkle tree.
///
/// Delegates to [`hypersnap_crypto::bridge_payload::lock_leaf_evm`]
/// — the canonical encoder shared with the offline ceremony tool
/// (`crates/hypersnap-bridge-ceremony`) and the contract test
/// helper (`contracts/test/utils/MerkleHelper.sol`).
pub fn encode_token_lock_leaf(state: &proto::TokenLockState) -> B256 {
    let lock_id = B256::from_slice(&state.lock_id);
    let recipient = Address::from_slice(&state.destination_address);
    let amount = U256::from(state.amount);
    hypersnap_crypto::bridge_payload::lock_leaf_evm(
        lock_id,
        state.destination_chain_id,
        recipient,
        amount,
    )
}

/// Validate the structural + cryptographic shape of a lock body.
/// Pure-function; does not touch state. State checks (nonce,
/// balance, lock_id collision) live in `RewardStore::apply_lock`.
///
/// EVM-family validation: `destination_address.len() == 20`. Other
/// families would relax this but Phase 2a is EVM-only.
pub fn validate_token_lock(body: &proto::TokenLockBody) -> Result<(), LockValidationError> {
    if body.sender_fid == 0 {
        return Err(LockValidationError::BadSenderFid);
    }
    if body.amount == 0 {
        return Err(LockValidationError::ZeroAmount);
    }
    if body.destination_chain_id == 0 {
        return Err(LockValidationError::BadDestinationChain);
    }
    if body.destination_address.len() != 20 {
        return Err(LockValidationError::BadDestinationAddressLen {
            got: body.destination_address.len(),
        });
    }
    if body.lock_id.len() != 32 {
        return Err(LockValidationError::BadLockIdLen {
            got: body.lock_id.len(),
        });
    }
    if body.signer_pubkey.len() != 32 {
        return Err(LockValidationError::BadSignerPubkey {
            got: body.signer_pubkey.len(),
        });
    }
    if body.signature.len() != 64 {
        return Err(LockValidationError::BadSignatureLen {
            got: body.signature.len(),
        });
    }
    let pk_bytes: [u8; 32] = body.signer_pubkey.as_slice().try_into().expect("len 32");
    let pk = VerifyingKey::from_bytes(&pk_bytes)
        .map_err(|_| LockValidationError::InvalidSignerPubkey)?;
    let sig_bytes: [u8; 64] = body.signature.as_slice().try_into().expect("len 64");
    let sig = Signature::from_bytes(&sig_bytes);
    let payload = token_lock_signing_payload(body);
    pk.verify(&payload, &sig)
        .map_err(|_| LockValidationError::SignatureVerifyFailed)?;
    Ok(())
}

/// Convenience: derive the storage state from a body. The body
/// fields the bridge cares about are copied directly; nonce and
/// signature aren't part of the post-validation state.
pub fn state_from_body(body: &proto::TokenLockBody) -> proto::TokenLockState {
    proto::TokenLockState {
        sender_fid: body.sender_fid,
        amount: body.amount,
        destination_chain_id: body.destination_chain_id,
        destination_address: body.destination_address.clone(),
        lock_id: body.lock_id.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn make_signed_lock(
        sender_fid: u64,
        amount: u64,
        nonce: u64,
        lock_id: [u8; 32],
    ) -> (proto::TokenLockBody, SigningKey) {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let pk = sk.verifying_key();
        let mut body = proto::TokenLockBody {
            sender_fid,
            amount,
            nonce,
            destination_chain_id: 10,
            destination_address: vec![0xab; 20],
            lock_id: lock_id.to_vec(),
            signer_pubkey: pk.to_bytes().to_vec(),
            signature: Vec::new(),
        };
        let payload = token_lock_signing_payload(&body);
        body.signature = sk.sign(&payload).to_bytes().to_vec();
        (body, sk)
    }

    #[test]
    fn valid_signed_lock_validates() {
        let (body, _) = make_signed_lock(1, 100, 1, [0xaa; 32]);
        validate_token_lock(&body).unwrap();
    }

    #[test]
    fn rejects_zero_amount() {
        let (body, _) = make_signed_lock(1, 0, 1, [0xaa; 32]);
        assert_eq!(
            validate_token_lock(&body),
            Err(LockValidationError::ZeroAmount)
        );
    }

    #[test]
    fn rejects_zero_sender_fid() {
        let (body, _) = make_signed_lock(0, 100, 1, [0xaa; 32]);
        assert_eq!(
            validate_token_lock(&body),
            Err(LockValidationError::BadSenderFid)
        );
    }

    #[test]
    fn rejects_zero_destination_chain() {
        let (mut body, sk) = make_signed_lock(1, 100, 1, [0xaa; 32]);
        body.destination_chain_id = 0;
        let payload = token_lock_signing_payload(&body);
        body.signature = sk.sign(&payload).to_bytes().to_vec();
        assert_eq!(
            validate_token_lock(&body),
            Err(LockValidationError::BadDestinationChain)
        );
    }

    #[test]
    fn rejects_destination_address_not_20_bytes() {
        let (mut body, sk) = make_signed_lock(1, 100, 1, [0xaa; 32]);
        body.destination_address = vec![0u8; 32]; // Solana-shape, not EVM
        let payload = token_lock_signing_payload(&body);
        body.signature = sk.sign(&payload).to_bytes().to_vec();
        assert_eq!(
            validate_token_lock(&body),
            Err(LockValidationError::BadDestinationAddressLen { got: 32 })
        );
    }

    #[test]
    fn rejects_bad_lock_id_length() {
        let (mut body, sk) = make_signed_lock(1, 100, 1, [0xaa; 32]);
        body.lock_id = vec![0u8; 16];
        let payload = token_lock_signing_payload(&body);
        body.signature = sk.sign(&payload).to_bytes().to_vec();
        assert_eq!(
            validate_token_lock(&body),
            Err(LockValidationError::BadLockIdLen { got: 16 })
        );
    }

    #[test]
    fn rejects_signature_under_wrong_key() {
        let (mut body, _) = make_signed_lock(1, 100, 1, [0xaa; 32]);
        let other = SigningKey::from_bytes(&[9u8; 32]);
        body.signer_pubkey = other.verifying_key().to_bytes().to_vec();
        assert_eq!(
            validate_token_lock(&body),
            Err(LockValidationError::SignatureVerifyFailed)
        );
    }

    #[test]
    fn signing_payload_changes_with_amount() {
        let (mut body, _) = make_signed_lock(1, 100, 1, [0xaa; 32]);
        body.amount = 999;
        assert_eq!(
            validate_token_lock(&body),
            Err(LockValidationError::SignatureVerifyFailed)
        );
    }

    #[test]
    fn signing_payload_changes_with_destination_chain() {
        let (mut body, _) = make_signed_lock(1, 100, 1, [0xaa; 32]);
        body.destination_chain_id = 999;
        assert_eq!(
            validate_token_lock(&body),
            Err(LockValidationError::SignatureVerifyFailed)
        );
    }

    #[test]
    fn signing_payload_changes_with_lock_id() {
        let (mut body, _) = make_signed_lock(1, 100, 1, [0xaa; 32]);
        body.lock_id = vec![0xbb; 32];
        assert_eq!(
            validate_token_lock(&body),
            Err(LockValidationError::SignatureVerifyFailed)
        );
    }

    /// `encode_token_lock_leaf` matches the canonical leaf encoder
    /// in `hypersnap_crypto::bridge_payload`. Mismatch means the
    /// on-chain bridge contract would reject merkle proofs built
    /// from these leaves — fail loudly here.
    #[test]
    fn leaf_matches_canonical_bridge_encoder() {
        let lock_id_bytes = [0xaa; 32];
        // make_signed_lock seeds destination_address = [0xab; 20].
        let recipient_bytes = [0xab; 20];
        let (body, _) = make_signed_lock(1, 100, 1, lock_id_bytes);
        let state = state_from_body(&body);

        let leaf = encode_token_lock_leaf(&state);
        let expected = hypersnap_crypto::bridge_payload::lock_leaf_evm(
            B256::from(lock_id_bytes),
            10, // destination_chain_id from make_signed_lock
            Address::from(recipient_bytes),
            U256::from(100u64),
        );
        assert_eq!(leaf, expected);
    }

    #[test]
    fn leaf_changes_with_amount() {
        let (b1, _) = make_signed_lock(1, 100, 1, [0xaa; 32]);
        let (b2, _) = make_signed_lock(1, 200, 1, [0xaa; 32]);
        let l1 = encode_token_lock_leaf(&state_from_body(&b1));
        let l2 = encode_token_lock_leaf(&state_from_body(&b2));
        assert_ne!(l1, l2);
    }

    #[test]
    fn leaf_changes_with_destination_chain() {
        let (mut b1, _) = make_signed_lock(1, 100, 1, [0xaa; 32]);
        let (mut b2, _) = make_signed_lock(1, 100, 1, [0xaa; 32]);
        b1.destination_chain_id = 1;
        b2.destination_chain_id = 8453;
        let l1 = encode_token_lock_leaf(&state_from_body(&b1));
        let l2 = encode_token_lock_leaf(&state_from_body(&b2));
        assert_ne!(l1, l2);
    }

    /// `sender_fid` is intentionally NOT in the leaf — the bridge
    /// contract doesn't check it. Two locks with the same
    /// (lock_id, dest_chain, recipient, amount) but different
    /// senders produce identical leaves. The protocol enforces
    /// lock_id uniqueness on the storage side so this collision
    /// is impossible in practice.
    #[test]
    fn leaf_does_not_depend_on_sender_fid() {
        let lock_id = [0xaa; 32];
        let (mut b1, _) = make_signed_lock(1, 100, 1, lock_id);
        let (mut b2, _) = make_signed_lock(99, 100, 1, lock_id);
        // Force same body fields except sender_fid.
        b2.destination_chain_id = b1.destination_chain_id;
        b2.destination_address = b1.destination_address.clone();
        let s1 = state_from_body(&b1);
        let s2 = state_from_body(&b2);
        assert_eq!(encode_token_lock_leaf(&s1), encode_token_lock_leaf(&s2));
    }
}
