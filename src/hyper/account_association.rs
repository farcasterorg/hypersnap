//! FIP-native-miniapp-index account-association verification.
//!
//! Standard Farcaster account-association proof: a JFS-style envelope
//! signed by an FID's custody Ethereum address proving the FID
//! controls a given domain. The shape mirrors the
//! `src/api/notifications/jfs.rs` verifier but:
//!
//! - This path is **sync** (called from the in-protocol apply layer).
//! - The signature is EIP-191 `personal_sign` over the JWS signing
//!   input (custody-key flow), not Ed25519 (app-key flow).
//! - The on-chain lookup is a custody-address lookup, not an
//!   active-signer lookup.
//!
//! Wire format (the proto stores the already-base64url-decoded
//! header + payload bytes, so we re-encode for the signing input):
//!
//! ```text
//! header JSON:    { "fid": 12345, "type": "custody", "key": "0x<20B hex>" }
//! payload JSON:   { "domain": "example.com" }
//! signing input:  BASE64URL_NOPAD(header_bytes) || "." || BASE64URL_NOPAD(payload_bytes)
//! signature:      EIP-191 personal_sign over signing input (65B: r||s||v)
//! ```
//!
//! `personal_sign` prepends `b"\x19Ethereum Signed Message:\n<len>"`
//! and keccak256s the result before ECDSA-secp256k1 signing. Standard
//! `alloy` machinery handles both sides.

use crate::core::error::HubError;
use crate::hyper::validator_registry::CustodyResolver;
use crate::proto;
use alloy_primitives::{keccak256, Address, PrimitiveSignature};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde::Deserialize;

#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum AccountAssociationError {
    #[error("proof missing field: {0}")]
    MissingField(&'static str),
    #[error("header JSON parse failed: {0}")]
    HeaderJson(String),
    #[error("payload JSON parse failed: {0}")]
    PayloadJson(String),
    #[error("unsupported account-association type: {0} (only 'custody' is supported)")]
    UnsupportedType(String),
    #[error("header.key must be a 0x-prefixed 20-byte hex Ethereum address")]
    BadKey,
    #[error("signature must be exactly 65 bytes (got {got})")]
    BadSignatureLen { got: usize },
    #[error("ECDSA recovery failed")]
    BadSignature,
    #[error("recovered signer address {recovered} does not match header.key {key}")]
    RecoveredMismatch { recovered: String, key: String },
    #[error("custody lookup error: {0}")]
    CustodyLookup(String),
    #[error("FID {fid} has no on-chain custody record")]
    UnknownFid { fid: u64 },
    #[error("header.key {key} does not match on-chain custody address {custody} for fid {fid}")]
    CustodyMismatch {
        fid: u64,
        key: String,
        custody: String,
    },
    #[error("header.fid {header_fid} does not match message fid {message_fid}")]
    FidMismatch { header_fid: u64, message_fid: u64 },
    #[error("payload.domain {payload_domain:?} does not match message domain {message_domain:?}")]
    DomainMismatch {
        payload_domain: String,
        message_domain: String,
    },
}

#[derive(Debug, Deserialize)]
struct AssociationHeader {
    fid: u64,
    #[serde(rename = "type")]
    key_type: String,
    key: String,
}

#[derive(Debug, Deserialize)]
struct AssociationPayload {
    domain: String,
}

fn parse_address(hex_str: &str) -> Result<Address, AccountAssociationError> {
    let stripped = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let bytes = hex::decode(stripped).map_err(|_| AccountAssociationError::BadKey)?;
    if bytes.len() != 20 {
        return Err(AccountAssociationError::BadKey);
    }
    let mut arr = [0u8; 20];
    arr.copy_from_slice(&bytes);
    Ok(Address::from(arr))
}

/// Compute the EIP-191 `personal_sign` digest of `msg`.
///
/// `keccak256(b"\x19Ethereum Signed Message:\n" || len_decimal_ascii(msg) || msg)`.
fn eip191_hash(msg: &[u8]) -> alloy_primitives::B256 {
    let mut buf = Vec::with_capacity(28 + msg.len());
    buf.extend_from_slice(b"\x19Ethereum Signed Message:\n");
    buf.extend_from_slice(msg.len().to_string().as_bytes());
    buf.extend_from_slice(msg);
    keccak256(buf)
}

/// Verified output. Returned on success so callers can use the
/// known-good `(fid, custody_address, domain)` triple without
/// re-parsing the proof.
#[derive(Debug, Clone)]
pub struct VerifiedAssociation {
    pub fid: u64,
    pub custody_address: [u8; 20],
    pub domain: String,
}

/// Verify a Farcaster account-association proof against an expected
/// `(fid, domain)` and the on-chain custody address for `fid`.
///
/// Returns `Ok(VerifiedAssociation)` only if every check passes:
/// 1. header + payload JSON parse cleanly
/// 2. `header.type == "custody"`
/// 3. `header.key` is a valid Ethereum address
/// 4. signature recovers to `header.key` (EIP-191 personal_sign over
///    `BASE64URL(header_bytes) || "." || BASE64URL(payload_bytes)`)
/// 5. `header.key` equals the on-chain custody address for `header.fid`
/// 6. `header.fid == expected_fid`
/// 7. `payload.domain == expected_domain`
pub fn verify_account_association(
    proof: &proto::AccountAssociationProof,
    expected_fid: u64,
    expected_domain: &str,
    custody: &dyn CustodyResolver,
) -> Result<VerifiedAssociation, AccountAssociationError> {
    if proof.header.is_empty() {
        return Err(AccountAssociationError::MissingField("header"));
    }
    if proof.payload.is_empty() {
        return Err(AccountAssociationError::MissingField("payload"));
    }
    if proof.signature.is_empty() {
        return Err(AccountAssociationError::MissingField("signature"));
    }
    if proof.signature.len() != 65 {
        return Err(AccountAssociationError::BadSignatureLen {
            got: proof.signature.len(),
        });
    }
    let header: AssociationHeader = serde_json::from_slice(&proof.header)
        .map_err(|e| AccountAssociationError::HeaderJson(e.to_string()))?;
    let payload: AssociationPayload = serde_json::from_slice(&proof.payload)
        .map_err(|e| AccountAssociationError::PayloadJson(e.to_string()))?;

    if header.key_type != "custody" {
        return Err(AccountAssociationError::UnsupportedType(header.key_type));
    }
    let header_key = parse_address(&header.key)?;

    // Build the signing input from the original bytes (base64url-encoded).
    let header_b64 = URL_SAFE_NO_PAD.encode(&proof.header);
    let payload_b64 = URL_SAFE_NO_PAD.encode(&proof.payload);
    let signing_input = format!("{}.{}", header_b64, payload_b64);

    // EIP-191 hash of the signing input.
    let digest = eip191_hash(signing_input.as_bytes());

    // Parse the 65-byte signature: r || s || v. `v` is either 0/1
    // (post-EIP-155 raw parity) or 27/28 (legacy). PrimitiveSignature
    // wants parity (bool) so map both forms.
    let parity_byte = proof.signature[64];
    let parity = match parity_byte {
        0 | 27 => false,
        1 | 28 => true,
        _ => return Err(AccountAssociationError::BadSignature),
    };
    let signature = PrimitiveSignature::from_bytes_and_parity(&proof.signature[..64], parity);
    let recovered = signature
        .recover_address_from_prehash(&digest)
        .map_err(|_| AccountAssociationError::BadSignature)?;

    if recovered != header_key {
        return Err(AccountAssociationError::RecoveredMismatch {
            recovered: format!("0x{}", hex::encode(recovered.as_slice())),
            key: format!("0x{}", hex::encode(header_key.as_slice())),
        });
    }

    // On-chain custody check.
    let onchain = custody
        .custody_address_for_fid(header.fid)
        .map_err(|e: HubError| AccountAssociationError::CustodyLookup(e.to_string()))?
        .ok_or(AccountAssociationError::UnknownFid { fid: header.fid })?;
    let header_key_bytes: [u8; 20] = header_key.into_array();
    if onchain != header_key_bytes {
        return Err(AccountAssociationError::CustodyMismatch {
            fid: header.fid,
            key: format!("0x{}", hex::encode(header_key.as_slice())),
            custody: format!("0x{}", hex::encode(onchain)),
        });
    }

    if header.fid != expected_fid {
        return Err(AccountAssociationError::FidMismatch {
            header_fid: header.fid,
            message_fid: expected_fid,
        });
    }
    if payload.domain != expected_domain {
        return Err(AccountAssociationError::DomainMismatch {
            payload_domain: payload.domain.clone(),
            message_domain: expected_domain.to_string(),
        });
    }

    Ok(VerifiedAssociation {
        fid: header.fid,
        custody_address: onchain,
        domain: payload.domain,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_signer::SignerSync;
    use alloy_signer_local::PrivateKeySigner;

    /// Static custody resolver for tests.
    struct FixedCustody(Vec<(u64, [u8; 20])>);
    impl CustodyResolver for FixedCustody {
        fn custody_address_for_fid(&self, fid: u64) -> Result<Option<[u8; 20]>, HubError> {
            Ok(self.0.iter().find(|(f, _)| *f == fid).map(|(_, a)| *a))
        }
    }

    fn make_proof(
        signer: &PrivateKeySigner,
        fid: u64,
        domain: &str,
    ) -> proto::AccountAssociationProof {
        let addr = signer.address();
        let header_json = format!(
            r#"{{"fid":{},"type":"custody","key":"0x{}"}}"#,
            fid,
            hex::encode(addr.as_slice())
        );
        let payload_json = format!(r#"{{"domain":"{}"}}"#, domain);
        let header_b64 = URL_SAFE_NO_PAD.encode(header_json.as_bytes());
        let payload_b64 = URL_SAFE_NO_PAD.encode(payload_json.as_bytes());
        let signing_input = format!("{}.{}", header_b64, payload_b64);
        // alloy_signer's `sign_message_sync` performs EIP-191 personal_sign.
        let sig = signer.sign_message_sync(signing_input.as_bytes()).unwrap();
        proto::AccountAssociationProof {
            header: header_json.into_bytes(),
            payload: payload_json.into_bytes(),
            signature: sig.as_bytes().to_vec(),
        }
    }

    #[test]
    fn happy_path_verifies() {
        let signer = PrivateKeySigner::from_bytes(&[7u8; 32].into()).unwrap();
        let addr_bytes: [u8; 20] = signer.address().into();
        let custody = FixedCustody(vec![(42, addr_bytes)]);
        let proof = make_proof(&signer, 42, "example.com");
        let v = verify_account_association(&proof, 42, "example.com", &custody).unwrap();
        assert_eq!(v.fid, 42);
        assert_eq!(v.custody_address, addr_bytes);
        assert_eq!(v.domain, "example.com");
    }

    #[test]
    fn wrong_signer_rejected() {
        let signer = PrivateKeySigner::from_bytes(&[7u8; 32].into()).unwrap();
        let attacker = PrivateKeySigner::from_bytes(&[8u8; 32].into()).unwrap();
        // Custody is the signer's address; attacker tries to forge.
        let real_addr: [u8; 20] = signer.address().into();
        let custody = FixedCustody(vec![(42, real_addr)]);
        // Attacker signs a proof claiming fid 42; the header.key in
        // the proof is the attacker's address.
        let proof = make_proof(&attacker, 42, "example.com");
        let err = verify_account_association(&proof, 42, "example.com", &custody).unwrap_err();
        // Recovered = attacker; header.key = attacker; recovered ==
        // key passes — but on-chain custody is the real signer, so
        // the CustodyMismatch fires.
        assert!(matches!(
            err,
            AccountAssociationError::CustodyMismatch { .. }
        ));
    }

    #[test]
    fn tampered_payload_breaks_signature() {
        let signer = PrivateKeySigner::from_bytes(&[7u8; 32].into()).unwrap();
        let addr_bytes: [u8; 20] = signer.address().into();
        let custody = FixedCustody(vec![(42, addr_bytes)]);
        let mut proof = make_proof(&signer, 42, "example.com");
        // Swap domain in the payload bytes (without re-signing).
        proof.payload = r#"{"domain":"evil.com"}"#.as_bytes().to_vec();
        let err = verify_account_association(&proof, 42, "example.com", &custody).unwrap_err();
        // The signature was over the original payload bytes — the
        // recovered address will not match header.key.
        assert!(matches!(
            err,
            AccountAssociationError::RecoveredMismatch { .. }
        ));
    }

    #[test]
    fn fid_mismatch_rejected() {
        let signer = PrivateKeySigner::from_bytes(&[7u8; 32].into()).unwrap();
        let addr_bytes: [u8; 20] = signer.address().into();
        let custody = FixedCustody(vec![(42, addr_bytes)]);
        let proof = make_proof(&signer, 42, "example.com");
        // Verifier expects FID 99 — header says 42.
        let err = verify_account_association(&proof, 99, "example.com", &custody).unwrap_err();
        assert!(matches!(
            err,
            AccountAssociationError::FidMismatch {
                header_fid: 42,
                message_fid: 99
            }
        ));
    }

    #[test]
    fn domain_mismatch_rejected() {
        let signer = PrivateKeySigner::from_bytes(&[7u8; 32].into()).unwrap();
        let addr_bytes: [u8; 20] = signer.address().into();
        let custody = FixedCustody(vec![(42, addr_bytes)]);
        let proof = make_proof(&signer, 42, "example.com");
        let err = verify_account_association(&proof, 42, "other.com", &custody).unwrap_err();
        assert!(matches!(
            err,
            AccountAssociationError::DomainMismatch { .. }
        ));
    }

    #[test]
    fn unknown_fid_rejected() {
        let signer = PrivateKeySigner::from_bytes(&[7u8; 32].into()).unwrap();
        let custody = FixedCustody(vec![]); // no entries
        let proof = make_proof(&signer, 42, "example.com");
        let err = verify_account_association(&proof, 42, "example.com", &custody).unwrap_err();
        assert!(matches!(
            err,
            AccountAssociationError::UnknownFid { fid: 42 }
        ));
    }

    #[test]
    fn unsupported_type_rejected() {
        let signer = PrivateKeySigner::from_bytes(&[7u8; 32].into()).unwrap();
        let addr_bytes: [u8; 20] = signer.address().into();
        let custody = FixedCustody(vec![(42, addr_bytes)]);
        let mut proof = make_proof(&signer, 42, "example.com");
        // Patch the header type to "app_key".
        let header_json = format!(
            r#"{{"fid":42,"type":"app_key","key":"0x{}"}}"#,
            hex::encode(addr_bytes)
        );
        proof.header = header_json.into_bytes();
        let err = verify_account_association(&proof, 42, "example.com", &custody).unwrap_err();
        assert!(matches!(err, AccountAssociationError::UnsupportedType(_)));
    }
}
