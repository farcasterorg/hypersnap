//! FIP-proof-of-work-tokenization §13.9 escrow claim validation.
//!
//! The previous custody address signs an EIP-712 typed data
//! payload to claim escrowed atoms into a destination FID. The
//! protocol-side verifier recovers the signer from the
//! signature and compares to the `custody_address` carried in
//! the body — a mismatch (or any tampering of the message
//! fields) fails the AEAD-like binding the typed-data hash
//! provides.
//!
//! ## EIP-712 schema
//!
//! ```json
//! types.TokenEscrowClaim = [
//!     { "name": "custody_address", "type": "address" },
//!     { "name": "destination_fid", "type": "uint256" },
//!     { "name": "nonce",           "type": "uint256" }
//! ]
//! primaryType = "TokenEscrowClaim"
//! domain = { "name": "HypersnapEscrow", "version": "1", "chainId": 10 }
//! ```
//!
//! Wallets that sign over this typed data produce a 65-byte
//! `(r || s || v)` signature recoverable to the
//! `custody_address`. Nonce advancement is monotonic per
//! custody address — replay of an older sig fails the apply
//! path's nonce check (separate from the cryptographic check).

use crate::proto;
use alloy_dyn_abi::TypedData;
use alloy_primitives::{Address, PrimitiveSignature};
use serde_json::{json, Value};

const ESCROW_EIP712_DOMAIN_NAME: &str = "HypersnapEscrow";
const ESCROW_EIP712_DOMAIN_VERSION: &str = "1";
/// OP Mainnet chain id, used as the EIP-712 domain separator —
/// no on-chain contract involved; we just want a stable domain.
const ESCROW_EIP712_CHAIN_ID: u64 = 10;

#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum EscrowClaimValidationError {
    #[error("custody_address must be exactly 20 bytes (got {0})")]
    BadCustodyAddressLen(usize),
    #[error("destination_fid must be > 0")]
    BadDestinationFid,
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

fn escrow_eip712_types() -> Value {
    json!({
        "EIP712Domain": [
            {"name": "name", "type": "string"},
            {"name": "version", "type": "string"},
            {"name": "chainId", "type": "uint256"},
        ],
        "TokenEscrowClaim": [
            {"name": "custody_address", "type": "address"},
            {"name": "destination_fid", "type": "uint256"},
            {"name": "nonce", "type": "uint256"},
        ],
    })
}

fn escrow_eip712_domain() -> Value {
    json!({
        "name": ESCROW_EIP712_DOMAIN_NAME,
        "version": ESCROW_EIP712_DOMAIN_VERSION,
        "chainId": ESCROW_EIP712_CHAIN_ID,
    })
}

/// Build the typed-data JSON for `body`. Wallets and protocol
/// verifiers must produce/consume this byte-identical shape.
pub fn token_escrow_claim_typed_data(body: &proto::TokenEscrowClaimBody) -> Value {
    let mut custody_hex = String::with_capacity(2 + 40);
    custody_hex.push_str("0x");
    custody_hex.push_str(&hex::encode(&body.custody_address));

    json!({
        "types": escrow_eip712_types(),
        "primaryType": "TokenEscrowClaim",
        "domain": escrow_eip712_domain(),
        "message": {
            "custody_address": custody_hex,
            "destination_fid": body.destination_fid.to_string(),
            "nonce": body.nonce.to_string(),
        },
    })
}

/// Validate the structural + cryptographic shape of a claim. Does
/// not touch state — nonce / escrow balance checks live in the
/// apply path.
pub fn validate_token_escrow_claim(
    body: &proto::TokenEscrowClaimBody,
) -> Result<(), EscrowClaimValidationError> {
    if body.custody_address.len() != 20 {
        return Err(EscrowClaimValidationError::BadCustodyAddressLen(
            body.custody_address.len(),
        ));
    }
    if body.destination_fid == 0 {
        return Err(EscrowClaimValidationError::BadDestinationFid);
    }
    if body.nonce == 0 {
        return Err(EscrowClaimValidationError::BadNonce);
    }
    if body.eip712_signature.len() != 65 {
        return Err(EscrowClaimValidationError::BadSignatureLen(
            body.eip712_signature.len(),
        ));
    }

    let json = token_escrow_claim_typed_data(body);
    let typed: TypedData = serde_json::from_value(json)
        .map_err(|e| EscrowClaimValidationError::TypedDataConstruction(e.to_string()))?;
    let prehash = typed
        .eip712_signing_hash()
        .map_err(|e| EscrowClaimValidationError::TypedDataPrehash(e.to_string()))?;

    let v_byte = body.eip712_signature[64];
    let parity = v_byte != 0x1b && v_byte != 0x00;
    let sig = PrimitiveSignature::from_bytes_and_parity(&body.eip712_signature[0..64], parity);
    let recovered = sig
        .recover_address_from_prehash(&prehash)
        .map_err(|_| EscrowClaimValidationError::SignatureMismatch)?;

    let mut expected_bytes = [0u8; 20];
    expected_bytes.copy_from_slice(&body.custody_address);
    let expected = Address::from(expected_bytes);
    if recovered != expected {
        return Err(EscrowClaimValidationError::SignatureMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_signer::SignerSync;
    use alloy_signer_local::PrivateKeySigner;

    fn sign_claim(
        signer: &PrivateKeySigner,
        destination_fid: u64,
        nonce: u64,
    ) -> proto::TokenEscrowClaimBody {
        let custody_address = signer.address().as_slice().to_vec();
        let mut body = proto::TokenEscrowClaimBody {
            custody_address,
            destination_fid,
            nonce,
            eip712_signature: Vec::new(),
        };
        let json = token_escrow_claim_typed_data(&body);
        let typed: TypedData = serde_json::from_value(json).unwrap();
        let prehash = typed.eip712_signing_hash().unwrap();
        let sig = signer.sign_hash_sync(&prehash).unwrap();
        body.eip712_signature = sig.as_bytes().to_vec();
        body
    }

    #[test]
    fn valid_signed_claim_validates() {
        let signer = PrivateKeySigner::random();
        let body = sign_claim(&signer, 42, 1);
        validate_token_escrow_claim(&body).unwrap();
    }

    #[test]
    fn rejects_bad_custody_address_length() {
        let signer = PrivateKeySigner::random();
        let mut body = sign_claim(&signer, 42, 1);
        body.custody_address = vec![0xab; 19];
        assert_eq!(
            validate_token_escrow_claim(&body),
            Err(EscrowClaimValidationError::BadCustodyAddressLen(19))
        );
    }

    #[test]
    fn rejects_zero_destination_fid() {
        let signer = PrivateKeySigner::random();
        let body = sign_claim(&signer, 0, 1);
        assert_eq!(
            validate_token_escrow_claim(&body),
            Err(EscrowClaimValidationError::BadDestinationFid)
        );
    }

    #[test]
    fn rejects_zero_nonce() {
        let signer = PrivateKeySigner::random();
        let body = sign_claim(&signer, 42, 0);
        assert_eq!(
            validate_token_escrow_claim(&body),
            Err(EscrowClaimValidationError::BadNonce)
        );
    }

    #[test]
    fn rejects_bad_signature_length() {
        let signer = PrivateKeySigner::random();
        let mut body = sign_claim(&signer, 42, 1);
        body.eip712_signature = vec![0u8; 64];
        assert_eq!(
            validate_token_escrow_claim(&body),
            Err(EscrowClaimValidationError::BadSignatureLen(64))
        );
    }

    /// Tampering: re-sign with one key, then claim a different
    /// custody address. Sig recovers to the signer (not the
    /// claimed address) so `SignatureMismatch` fires.
    #[test]
    fn rejects_custody_address_mismatch() {
        let signer = PrivateKeySigner::random();
        let mut body = sign_claim(&signer, 42, 1);
        // Replace custody_address with an unrelated 20-byte
        // address. The signature was over the original
        // (real-signer) address.
        body.custody_address = vec![0u8; 20];
        assert_eq!(
            validate_token_escrow_claim(&body),
            Err(EscrowClaimValidationError::SignatureMismatch)
        );
    }

    /// Field-tampering: change `destination_fid` after signing.
    /// The new typed-data hash no longer matches what the signer
    /// authorized; recovery yields a different address.
    #[test]
    fn rejects_field_tampering_after_signing() {
        let signer = PrivateKeySigner::random();
        let mut body = sign_claim(&signer, 42, 1);
        body.destination_fid = 99;
        assert_eq!(
            validate_token_escrow_claim(&body),
            Err(EscrowClaimValidationError::SignatureMismatch)
        );
    }

    #[test]
    fn signature_from_wrong_key_rejected() {
        let real_signer = PrivateKeySigner::random();
        let other_signer = PrivateKeySigner::random();
        let body = sign_claim(&real_signer, 42, 1);
        // Re-sign with a different key over the same body, then
        // replace the signature. Recovery yields `other_signer`
        // but the body claims `real_signer.address()` as the
        // custody — mismatch.
        let json = token_escrow_claim_typed_data(&body);
        let typed: TypedData = serde_json::from_value(json).unwrap();
        let prehash = typed.eip712_signing_hash().unwrap();
        let bad_sig = other_signer.sign_hash_sync(&prehash).unwrap();
        let mut bad_body = body.clone();
        bad_body.eip712_signature = bad_sig.as_bytes().to_vec();
        assert_eq!(
            validate_token_escrow_claim(&bad_body),
            Err(EscrowClaimValidationError::SignatureMismatch)
        );
    }
}
