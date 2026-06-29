//! FIP-proof-of-work-tokenization §13.9 escrow-bridge validation.
//!
//! Mirrors `token_escrow_claim` but binds additional bridge-route
//! fields (chain id, destination address, lock id, amount) into
//! the EIP-712 hash. Same `HypersnapEscrow` domain, distinct
//! `primaryType` so a claim signature can't be replayed as a
//! bridge or vice versa.
//!
//! ## EIP-712 schema
//!
//! ```text
//! types.TokenEscrowBridge = [
//!     { name: "custody_address",     type: "address" },
//!     { name: "amount",              type: "uint256" },
//!     { name: "destination_chain_id", type: "uint256" },
//!     { name: "destination_address",  type: "bytes" },
//!     { name: "lock_id",              type: "bytes32" },
//!     { name: "nonce",                type: "uint256" }
//! ]
//! primaryType = "TokenEscrowBridge"
//! domain      = { name: "HypersnapEscrow", version: "1", chainId: 10 }
//! ```
//!
//! ## Why bind `amount` into the signature
//!
//! The apply path requires `current_escrow_balance == body.amount`
//! exactly (no partial bridges). If a transfer event accumulates
//! extra escrow between sign-time and broadcast-time, the user's
//! `amount` is wrong and the apply rejects — the user re-signs
//! with the new total. This protects users from bridging more
//! than they explicitly intended when their custody address has
//! racy inbound transfers.

use crate::proto;
use alloy_dyn_abi::TypedData;
use alloy_primitives::{Address, PrimitiveSignature};
use serde_json::{json, Value};

const ESCROW_EIP712_DOMAIN_NAME: &str = "HypersnapEscrow";
const ESCROW_EIP712_DOMAIN_VERSION: &str = "1";
const ESCROW_EIP712_CHAIN_ID: u64 = 10;

#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum EscrowBridgeValidationError {
    #[error("custody_address must be exactly 20 bytes (got {0})")]
    BadCustodyAddressLen(usize),
    #[error("destination_address must be exactly 20 bytes (EVM) (got {0})")]
    BadDestinationAddressLen(usize),
    #[error("lock_id must be exactly 32 bytes (got {0})")]
    BadLockIdLen(usize),
    #[error("amount must be > 0")]
    BadAmount,
    #[error("destination_chain_id must be > 0")]
    BadDestinationChain,
    #[error("nonce must be > 0")]
    BadNonce,
    #[error("eip712_signature must be exactly 65 bytes (got {0})")]
    BadSignatureLen(usize),
    #[error("EIP-712 typed-data construction failed: {0}")]
    TypedDataConstruction(String),
    #[error("EIP-712 prehash failed: {0}")]
    TypedDataPrehash(String),
    #[error("signature did not recover to custody_address")]
    SignatureMismatch,
}

fn escrow_bridge_eip712_types() -> Value {
    json!({
        "EIP712Domain": [
            {"name": "name", "type": "string"},
            {"name": "version", "type": "string"},
            {"name": "chainId", "type": "uint256"},
        ],
        "TokenEscrowBridge": [
            {"name": "custody_address", "type": "address"},
            {"name": "amount", "type": "uint256"},
            {"name": "destination_chain_id", "type": "uint256"},
            {"name": "destination_address", "type": "bytes"},
            {"name": "lock_id", "type": "bytes32"},
            {"name": "nonce", "type": "uint256"},
        ],
    })
}

fn escrow_bridge_eip712_domain() -> Value {
    json!({
        "name": ESCROW_EIP712_DOMAIN_NAME,
        "version": ESCROW_EIP712_DOMAIN_VERSION,
        "chainId": ESCROW_EIP712_CHAIN_ID,
    })
}

pub fn token_escrow_bridge_typed_data(body: &proto::TokenEscrowBridgeBody) -> Value {
    let mut custody_hex = String::with_capacity(2 + 40);
    custody_hex.push_str("0x");
    custody_hex.push_str(&hex::encode(&body.custody_address));

    let mut dest_addr_hex = String::with_capacity(2 + body.destination_address.len() * 2);
    dest_addr_hex.push_str("0x");
    dest_addr_hex.push_str(&hex::encode(&body.destination_address));

    let mut lock_id_hex = String::with_capacity(2 + 64);
    lock_id_hex.push_str("0x");
    lock_id_hex.push_str(&hex::encode(&body.lock_id));

    json!({
        "types": escrow_bridge_eip712_types(),
        "primaryType": "TokenEscrowBridge",
        "domain": escrow_bridge_eip712_domain(),
        "message": {
            "custody_address": custody_hex,
            "amount": body.amount.to_string(),
            "destination_chain_id": (body.destination_chain_id as u64).to_string(),
            "destination_address": dest_addr_hex,
            "lock_id": lock_id_hex,
            "nonce": body.nonce.to_string(),
        },
    })
}

pub fn validate_token_escrow_bridge(
    body: &proto::TokenEscrowBridgeBody,
) -> Result<(), EscrowBridgeValidationError> {
    if body.custody_address.len() != 20 {
        return Err(EscrowBridgeValidationError::BadCustodyAddressLen(
            body.custody_address.len(),
        ));
    }
    if body.destination_address.len() != 20 {
        return Err(EscrowBridgeValidationError::BadDestinationAddressLen(
            body.destination_address.len(),
        ));
    }
    if body.lock_id.len() != 32 {
        return Err(EscrowBridgeValidationError::BadLockIdLen(
            body.lock_id.len(),
        ));
    }
    if body.amount == 0 {
        return Err(EscrowBridgeValidationError::BadAmount);
    }
    if body.destination_chain_id == 0 {
        return Err(EscrowBridgeValidationError::BadDestinationChain);
    }
    if body.nonce == 0 {
        return Err(EscrowBridgeValidationError::BadNonce);
    }
    if body.eip712_signature.len() != 65 {
        return Err(EscrowBridgeValidationError::BadSignatureLen(
            body.eip712_signature.len(),
        ));
    }

    let json = token_escrow_bridge_typed_data(body);
    let typed: TypedData = serde_json::from_value(json)
        .map_err(|e| EscrowBridgeValidationError::TypedDataConstruction(e.to_string()))?;
    let prehash = typed
        .eip712_signing_hash()
        .map_err(|e| EscrowBridgeValidationError::TypedDataPrehash(e.to_string()))?;

    let v_byte = body.eip712_signature[64];
    let parity = v_byte != 0x1b && v_byte != 0x00;
    let sig = PrimitiveSignature::from_bytes_and_parity(&body.eip712_signature[0..64], parity);
    let recovered = sig
        .recover_address_from_prehash(&prehash)
        .map_err(|_| EscrowBridgeValidationError::SignatureMismatch)?;

    let mut expected_bytes = [0u8; 20];
    expected_bytes.copy_from_slice(&body.custody_address);
    let expected = Address::from(expected_bytes);
    if recovered != expected {
        return Err(EscrowBridgeValidationError::SignatureMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_signer::SignerSync;
    use alloy_signer_local::PrivateKeySigner;

    fn sign_bridge(
        signer: &PrivateKeySigner,
        amount: u64,
        nonce: u64,
    ) -> proto::TokenEscrowBridgeBody {
        let custody_address = signer.address().as_slice().to_vec();
        let mut body = proto::TokenEscrowBridgeBody {
            custody_address,
            amount,
            destination_chain_id: 10,
            destination_address: vec![0xab; 20],
            lock_id: vec![0xcd; 32],
            nonce,
            eip712_signature: Vec::new(),
        };
        let json = token_escrow_bridge_typed_data(&body);
        let typed: TypedData = serde_json::from_value(json).unwrap();
        let prehash = typed.eip712_signing_hash().unwrap();
        let sig = signer.sign_hash_sync(&prehash).unwrap();
        body.eip712_signature = sig.as_bytes().to_vec();
        body
    }

    #[test]
    fn valid_signed_bridge_validates() {
        let signer = PrivateKeySigner::random();
        let body = sign_bridge(&signer, 1_000, 1);
        validate_token_escrow_bridge(&body).unwrap();
    }

    #[test]
    fn rejects_zero_amount() {
        let signer = PrivateKeySigner::random();
        let body = sign_bridge(&signer, 0, 1);
        assert_eq!(
            validate_token_escrow_bridge(&body),
            Err(EscrowBridgeValidationError::BadAmount)
        );
    }

    #[test]
    fn rejects_bad_destination_address_length() {
        let signer = PrivateKeySigner::random();
        let mut body = sign_bridge(&signer, 1_000, 1);
        body.destination_address = vec![0xab; 32];
        assert_eq!(
            validate_token_escrow_bridge(&body),
            Err(EscrowBridgeValidationError::BadDestinationAddressLen(32))
        );
    }

    #[test]
    fn rejects_bad_lock_id_length() {
        let signer = PrivateKeySigner::random();
        let mut body = sign_bridge(&signer, 1_000, 1);
        body.lock_id = vec![0xab; 16];
        assert_eq!(
            validate_token_escrow_bridge(&body),
            Err(EscrowBridgeValidationError::BadLockIdLen(16))
        );
    }

    #[test]
    fn tampering_amount_after_sign_rejected() {
        let signer = PrivateKeySigner::random();
        let mut body = sign_bridge(&signer, 1_000, 1);
        body.amount = 999;
        assert_eq!(
            validate_token_escrow_bridge(&body),
            Err(EscrowBridgeValidationError::SignatureMismatch)
        );
    }

    #[test]
    fn tampering_destination_address_after_sign_rejected() {
        let signer = PrivateKeySigner::random();
        let mut body = sign_bridge(&signer, 1_000, 1);
        body.destination_address = vec![0xff; 20];
        assert_eq!(
            validate_token_escrow_bridge(&body),
            Err(EscrowBridgeValidationError::SignatureMismatch)
        );
    }

    /// Claim and bridge from the same custody at the same nonce
    /// produce DIFFERENT typed-data hashes — the `primaryType`
    /// differs ("TokenEscrowClaim" vs "TokenEscrowBridge"), and
    /// the bridge has additional fields. A claim sig can't be
    /// rebuilt into a bridge body and pass validation.
    #[test]
    fn claim_and_bridge_have_distinct_signature_domains() {
        let signer = PrivateKeySigner::random();
        // Build a CLAIM and sign it.
        let mut claim = proto::TokenEscrowClaimBody {
            custody_address: signer.address().as_slice().to_vec(),
            destination_fid: 42,
            nonce: 1,
            eip712_signature: Vec::new(),
        };
        let claim_json = crate::hyper::token_escrow_claim::token_escrow_claim_typed_data(&claim);
        let claim_typed: TypedData = serde_json::from_value(claim_json).unwrap();
        let claim_prehash = claim_typed.eip712_signing_hash().unwrap();
        claim.eip712_signature = signer
            .sign_hash_sync(&claim_prehash)
            .unwrap()
            .as_bytes()
            .to_vec();

        // Try to use the claim's signature on a bridge body.
        let bridge = proto::TokenEscrowBridgeBody {
            custody_address: claim.custody_address.clone(),
            amount: 1_000,
            destination_chain_id: 10,
            destination_address: vec![0xab; 20],
            lock_id: vec![0xcd; 32],
            nonce: 1,
            eip712_signature: claim.eip712_signature.clone(),
        };
        assert_eq!(
            validate_token_escrow_bridge(&bridge),
            Err(EscrowBridgeValidationError::SignatureMismatch)
        );
    }
}
