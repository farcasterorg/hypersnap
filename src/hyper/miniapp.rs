//! FIP-native-miniapp-index validation + canonical signing payloads.
//!
//! This module contains:
//!
//! - `miniapp_id_from_domain`: deterministic 16-byte identifier
//!   derived from the canonical domain string.
//! - `validate_metadata`: structural caps from FIP §9.
//! - `validate_register`: structural + account-association proof
//!   check (delegates to `account_association::verify_account_association`).
//! - `validate_*` for Unregister / Update / Add / Remove: structural
//!   checks + canonical Ed25519 signing-payload verification.
//!
//! The runtime apply layer adds DB-level gates (cap enforcement,
//! domain uniqueness, signer-authorization lookup, etc.) on top of
//! these structural checks.

use crate::proto;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

/// FIP-native-miniapp-index per-FID registration cap.
pub const MAX_REGISTRATIONS_PER_FID: usize = 10;
/// FIP-native-miniapp-index per-FID user-collection add cap.
pub const MAX_ADDS_PER_FID: usize = 100;

/// `miniapp_id = SHA256("farcaster-miniapp:" || domain)[0..16]`.
/// Deterministic so every validator computes the same identifier
/// from the same domain string.
pub fn miniapp_id_from_domain(domain: &str) -> [u8; 16] {
    let mut h = Sha256::new();
    h.update(b"farcaster-miniapp:");
    h.update(domain.as_bytes());
    let full = h.finalize();
    let mut out = [0u8; 16];
    out.copy_from_slice(&full[..16]);
    out
}

#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum MiniappValidationError {
    #[error("fid must be > 0")]
    BadFid,
    #[error("domain must be non-empty")]
    EmptyDomain,
    #[error("domain too long (got {got}, max {max})")]
    DomainTooLong { got: usize, max: usize },
    #[error("domain has invalid characters (scheme, path, port, or whitespace)")]
    InvalidDomain,
    #[error("name must be 1-32 chars (got {got})")]
    BadName { got: usize },
    #[error("description must be ≤ 256 chars (got {got})")]
    DescriptionTooLong { got: usize },
    #[error("tagline must be ≤ 64 chars (got {got})")]
    TaglineTooLong { got: usize },
    #[error("too many tags (got {got}, max 5)")]
    TooManyTags { got: usize },
    #[error("tag too long (got {got}, max 24)")]
    TagTooLong { got: usize },
    #[error("too many screenshots (got {got}, max 5)")]
    TooManyScreenshots { got: usize },
    #[error("home_url must start with https://")]
    BadHomeUrl,
    #[error("icon_url must start with https://")]
    BadIconUrl,
    #[error("signer_pubkey must be 32 bytes (got {got})")]
    BadSignerPubkey { got: usize },
    #[error("signer_pubkey did not parse as a valid Ed25519 key")]
    InvalidSignerPubkey,
    #[error("signature must be 64 bytes (got {got})")]
    BadSignatureLen { got: usize },
    #[error("signature does not verify under the included signer_pubkey")]
    SignatureVerifyFailed,
    #[error("metadata missing")]
    MissingMetadata,
    #[error("proof missing")]
    MissingProof,
}

/// Strict FIP §9 caps.
const MAX_DOMAIN_BYTES: usize = 253; // RFC 1035-style
const MAX_NAME_BYTES: usize = 32;
const MAX_DESCRIPTION_BYTES: usize = 256;
const MAX_TAGLINE_BYTES: usize = 64;
const MAX_TAGS: usize = 5;
const MAX_TAG_BYTES: usize = 24;
const MAX_SCREENSHOTS: usize = 5;

fn validate_domain(domain: &str) -> Result<(), MiniappValidationError> {
    if domain.is_empty() {
        return Err(MiniappValidationError::EmptyDomain);
    }
    if domain.len() > MAX_DOMAIN_BYTES {
        return Err(MiniappValidationError::DomainTooLong {
            got: domain.len(),
            max: MAX_DOMAIN_BYTES,
        });
    }
    // No scheme, no path, no port, no whitespace.
    if domain.contains("://")
        || domain.contains('/')
        || domain.contains(':')
        || domain.contains(' ')
        || domain.contains('\t')
        || domain.contains('\n')
    {
        return Err(MiniappValidationError::InvalidDomain);
    }
    Ok(())
}

fn validate_metadata(m: &proto::MiniappMetadata) -> Result<(), MiniappValidationError> {
    if m.name.is_empty() || m.name.as_bytes().len() > MAX_NAME_BYTES {
        return Err(MiniappValidationError::BadName {
            got: m.name.as_bytes().len(),
        });
    }
    if m.description.as_bytes().len() > MAX_DESCRIPTION_BYTES {
        return Err(MiniappValidationError::DescriptionTooLong {
            got: m.description.as_bytes().len(),
        });
    }
    if m.tagline.as_bytes().len() > MAX_TAGLINE_BYTES {
        return Err(MiniappValidationError::TaglineTooLong {
            got: m.tagline.as_bytes().len(),
        });
    }
    if m.tags.len() > MAX_TAGS {
        return Err(MiniappValidationError::TooManyTags { got: m.tags.len() });
    }
    for t in &m.tags {
        if t.as_bytes().len() > MAX_TAG_BYTES {
            return Err(MiniappValidationError::TagTooLong {
                got: t.as_bytes().len(),
            });
        }
    }
    if m.screenshot_urls.len() > MAX_SCREENSHOTS {
        return Err(MiniappValidationError::TooManyScreenshots {
            got: m.screenshot_urls.len(),
        });
    }
    if !m.home_url.starts_with("https://") {
        return Err(MiniappValidationError::BadHomeUrl);
    }
    if !m.icon_url.starts_with("https://") {
        return Err(MiniappValidationError::BadIconUrl);
    }
    Ok(())
}

// =========================================================================
// Register
// =========================================================================

/// Structural checks ONLY. The account-association proof is verified
/// at apply time by the runtime (needs `CustodyResolver` access).
pub fn validate_register_structure(
    body: &proto::MiniappRegisterBody,
) -> Result<(), MiniappValidationError> {
    if body.fid == 0 {
        return Err(MiniappValidationError::BadFid);
    }
    validate_domain(&body.domain)?;
    let metadata = body
        .metadata
        .as_ref()
        .ok_or(MiniappValidationError::MissingMetadata)?;
    validate_metadata(metadata)?;
    if body.proof.is_none() {
        return Err(MiniappValidationError::MissingProof);
    }
    Ok(())
}

// =========================================================================
// Unregister / Update / Add / Remove — Ed25519-signer-authorized
// =========================================================================
//
// Canonical signing payloads. Fixed-prefix DST + fixed-width integer
// fields + length-prefixed domain (and metadata for Update). Each
// operation has a distinct DST so a single signature is never valid
// across operations.

const UNREGISTER_DST: &[u8] = b"hypersnap-miniapp-unregister-v2\x00";
const UPDATE_DST: &[u8] = b"hypersnap-miniapp-update-v2\x00\x00\x00\x00\x00";
const ADD_DST: &[u8] = b"hypersnap-miniapp-add-v2\x00\x00\x00\x00\x00\x00\x00\x00";
const REMOVE_DST: &[u8] = b"hypersnap-miniapp-remove-v2\x00\x00\x00\x00\x00";

fn write_length_prefixed(buf: &mut Vec<u8>, bytes: &[u8]) {
    buf.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    buf.extend_from_slice(bytes);
}

/// Canonical signing payload for `MiniappUnregisterBody`.
pub fn unregister_signing_payload(body: &proto::MiniappUnregisterBody, chain_id: u64) -> Vec<u8> {
    let mut buf = Vec::with_capacity(UNREGISTER_DST.len() + 8 + 4 + body.domain.len() + 8 + 32);
    buf.extend_from_slice(UNREGISTER_DST);
    buf.extend_from_slice(&chain_id.to_be_bytes());
    buf.extend_from_slice(&body.fid.to_be_bytes());
    write_length_prefixed(&mut buf, body.domain.as_bytes());
    buf.extend_from_slice(&body.nonce.to_be_bytes());
    buf.extend_from_slice(&body.signer_pubkey);
    buf
}

/// Canonical signing payload for `MiniappUpdateBody`. Covers
/// metadata so an attacker cannot swap metadata after the FID
/// signs.
pub fn update_signing_payload(body: &proto::MiniappUpdateBody, chain_id: u64) -> Vec<u8> {
    use prost::Message;
    let metadata_bytes = body
        .metadata
        .as_ref()
        .map(|m| {
            let mut buf = Vec::with_capacity(m.encoded_len());
            m.encode(&mut buf).expect("infallible encode");
            buf
        })
        .unwrap_or_default();
    let mut buf = Vec::with_capacity(
        UPDATE_DST.len() + 8 + 4 + body.domain.len() + 4 + metadata_bytes.len() + 8 + 8 + 32,
    );
    buf.extend_from_slice(UPDATE_DST);
    buf.extend_from_slice(&chain_id.to_be_bytes());
    buf.extend_from_slice(&body.fid.to_be_bytes());
    write_length_prefixed(&mut buf, body.domain.as_bytes());
    write_length_prefixed(&mut buf, &metadata_bytes);
    buf.extend_from_slice(&body.timestamp.to_be_bytes());
    buf.extend_from_slice(&body.nonce.to_be_bytes());
    buf.extend_from_slice(&body.signer_pubkey);
    buf
}

/// Canonical signing payload for `MiniappAddBody`.
pub fn add_signing_payload(body: &proto::MiniappAddBody, chain_id: u64) -> Vec<u8> {
    let mut buf = Vec::with_capacity(ADD_DST.len() + 8 + 4 + body.domain.len() + 8 + 8 + 32);
    buf.extend_from_slice(ADD_DST);
    buf.extend_from_slice(&chain_id.to_be_bytes());
    buf.extend_from_slice(&body.fid.to_be_bytes());
    write_length_prefixed(&mut buf, body.domain.as_bytes());
    buf.extend_from_slice(&body.timestamp.to_be_bytes());
    buf.extend_from_slice(&body.nonce.to_be_bytes());
    buf.extend_from_slice(&body.signer_pubkey);
    buf
}

/// Canonical signing payload for `MiniappRemoveBody`.
pub fn remove_signing_payload(body: &proto::MiniappRemoveBody, chain_id: u64) -> Vec<u8> {
    let mut buf = Vec::with_capacity(REMOVE_DST.len() + 8 + 4 + body.domain.len() + 8 + 8 + 32);
    buf.extend_from_slice(REMOVE_DST);
    buf.extend_from_slice(&chain_id.to_be_bytes());
    buf.extend_from_slice(&body.fid.to_be_bytes());
    write_length_prefixed(&mut buf, body.domain.as_bytes());
    buf.extend_from_slice(&body.timestamp.to_be_bytes());
    buf.extend_from_slice(&body.nonce.to_be_bytes());
    buf.extend_from_slice(&body.signer_pubkey);
    buf
}

fn verify_sig(
    signer_pubkey: &[u8],
    signature: &[u8],
    payload: &[u8],
) -> Result<(), MiniappValidationError> {
    if signer_pubkey.len() != 32 {
        return Err(MiniappValidationError::BadSignerPubkey {
            got: signer_pubkey.len(),
        });
    }
    if signature.len() != 64 {
        return Err(MiniappValidationError::BadSignatureLen {
            got: signature.len(),
        });
    }
    let pk_bytes: [u8; 32] = signer_pubkey.try_into().expect("len 32");
    let pk = VerifyingKey::from_bytes(&pk_bytes)
        .map_err(|_| MiniappValidationError::InvalidSignerPubkey)?;
    let sig_bytes: [u8; 64] = signature.try_into().expect("len 64");
    pk.verify(payload, &Signature::from_bytes(&sig_bytes))
        .map_err(|_| MiniappValidationError::SignatureVerifyFailed)?;
    Ok(())
}

pub fn validate_unregister(
    body: &proto::MiniappUnregisterBody,
    chain_id: u64,
) -> Result<(), MiniappValidationError> {
    if body.fid == 0 {
        return Err(MiniappValidationError::BadFid);
    }
    validate_domain(&body.domain)?;
    verify_sig(
        &body.signer_pubkey,
        &body.signature,
        &unregister_signing_payload(body, chain_id),
    )
}

pub fn validate_update(
    body: &proto::MiniappUpdateBody,
    chain_id: u64,
) -> Result<(), MiniappValidationError> {
    if body.fid == 0 {
        return Err(MiniappValidationError::BadFid);
    }
    validate_domain(&body.domain)?;
    let metadata = body
        .metadata
        .as_ref()
        .ok_or(MiniappValidationError::MissingMetadata)?;
    validate_metadata(metadata)?;
    verify_sig(
        &body.signer_pubkey,
        &body.signature,
        &update_signing_payload(body, chain_id),
    )
}

pub fn validate_add(
    body: &proto::MiniappAddBody,
    chain_id: u64,
) -> Result<(), MiniappValidationError> {
    if body.fid == 0 {
        return Err(MiniappValidationError::BadFid);
    }
    validate_domain(&body.domain)?;
    verify_sig(
        &body.signer_pubkey,
        &body.signature,
        &add_signing_payload(body, chain_id),
    )
}

pub fn validate_remove(
    body: &proto::MiniappRemoveBody,
    chain_id: u64,
) -> Result<(), MiniappValidationError> {
    if body.fid == 0 {
        return Err(MiniappValidationError::BadFid);
    }
    validate_domain(&body.domain)?;
    verify_sig(
        &body.signer_pubkey,
        &body.signature,
        &remove_signing_payload(body, chain_id),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn good_metadata() -> proto::MiniappMetadata {
        proto::MiniappMetadata {
            name: "Example".to_string(),
            home_url: "https://example.com".to_string(),
            icon_url: "https://example.com/icon.png".to_string(),
            description: "An example miniapp".to_string(),
            image_url: String::new(),
            category: proto::MiniappCategory::Games as i32,
            tags: vec!["fun".to_string()],
            webhook_url: String::new(),
            screenshot_urls: vec![],
            tagline: "Play and earn".to_string(),
        }
    }

    #[test]
    fn miniapp_id_is_deterministic_and_16_bytes() {
        let id1 = miniapp_id_from_domain("example.com");
        let id2 = miniapp_id_from_domain("example.com");
        assert_eq!(id1, id2);
        assert_ne!(
            miniapp_id_from_domain("example.com"),
            miniapp_id_from_domain("other.com")
        );
        // Different DST behavior: same domain string but different
        // case yields a different id (case-sensitive).
        assert_ne!(
            miniapp_id_from_domain("Example.com"),
            miniapp_id_from_domain("example.com")
        );
    }

    #[test]
    fn register_structure_valid() {
        let body = proto::MiniappRegisterBody {
            fid: 42,
            domain: "example.com".to_string(),
            metadata: Some(good_metadata()),
            proof: Some(proto::AccountAssociationProof {
                header: vec![1],
                payload: vec![1],
                signature: vec![1; 65],
            }),
        };
        validate_register_structure(&body).unwrap();
    }

    #[test]
    fn register_rejects_scheme_in_domain() {
        let mut body = proto::MiniappRegisterBody {
            fid: 42,
            domain: "https://example.com".to_string(),
            metadata: Some(good_metadata()),
            proof: Some(proto::AccountAssociationProof {
                header: vec![1],
                payload: vec![1],
                signature: vec![1; 65],
            }),
        };
        assert!(matches!(
            validate_register_structure(&body),
            Err(MiniappValidationError::InvalidDomain)
        ));
        body.domain = "example.com:8080".to_string();
        assert!(matches!(
            validate_register_structure(&body),
            Err(MiniappValidationError::InvalidDomain)
        ));
        body.domain = "example.com/path".to_string();
        assert!(matches!(
            validate_register_structure(&body),
            Err(MiniappValidationError::InvalidDomain)
        ));
    }

    #[test]
    fn register_rejects_oversize_name() {
        let mut m = good_metadata();
        m.name = "x".repeat(33);
        let body = proto::MiniappRegisterBody {
            fid: 42,
            domain: "example.com".to_string(),
            metadata: Some(m),
            proof: Some(proto::AccountAssociationProof {
                header: vec![1],
                payload: vec![1],
                signature: vec![1; 65],
            }),
        };
        assert!(matches!(
            validate_register_structure(&body),
            Err(MiniappValidationError::BadName { got: 33 })
        ));
    }

    #[test]
    fn register_rejects_too_many_tags() {
        let mut m = good_metadata();
        m.tags = (0..6).map(|i| format!("tag{}", i)).collect();
        let body = proto::MiniappRegisterBody {
            fid: 42,
            domain: "example.com".to_string(),
            metadata: Some(m),
            proof: Some(proto::AccountAssociationProof {
                header: vec![1],
                payload: vec![1],
                signature: vec![1; 65],
            }),
        };
        assert!(matches!(
            validate_register_structure(&body),
            Err(MiniappValidationError::TooManyTags { got: 6 })
        ));
    }

    #[test]
    fn unregister_signs_and_verifies() {
        let sk = SigningKey::from_bytes(&[3u8; 32]);
        let pk = sk.verifying_key();
        let mut body = proto::MiniappUnregisterBody {
            fid: 42,
            domain: "example.com".to_string(),
            nonce: 1,
            signer_pubkey: pk.to_bytes().to_vec(),
            signature: Vec::new(),
        };
        body.signature = sk
            .sign(&unregister_signing_payload(
                &body,
                crate::hyper::DEFAULT_PROTOCOL_CHAIN_ID,
            ))
            .to_bytes()
            .to_vec();
        validate_unregister(&body, crate::hyper::DEFAULT_PROTOCOL_CHAIN_ID).unwrap();
    }

    #[test]
    fn unregister_dst_separation_from_remove() {
        let sk = SigningKey::from_bytes(&[3u8; 32]);
        let pk = sk.verifying_key();
        // Build a Remove body with the same logical fields, sign
        // it as Remove, then try to pass it to Unregister verifier.
        let mut remove = proto::MiniappRemoveBody {
            fid: 42,
            domain: "example.com".to_string(),
            timestamp: 0,
            nonce: 1,
            signer_pubkey: pk.to_bytes().to_vec(),
            signature: Vec::new(),
        };
        remove.signature = sk
            .sign(&remove_signing_payload(
                &remove,
                crate::hyper::DEFAULT_PROTOCOL_CHAIN_ID,
            ))
            .to_bytes()
            .to_vec();
        // Map Remove sig into an Unregister body — must fail.
        let unregister = proto::MiniappUnregisterBody {
            fid: 42,
            domain: "example.com".to_string(),
            nonce: 1,
            signer_pubkey: remove.signer_pubkey.clone(),
            signature: remove.signature.clone(),
        };
        assert_eq!(
            validate_unregister(&unregister, crate::hyper::DEFAULT_PROTOCOL_CHAIN_ID),
            Err(MiniappValidationError::SignatureVerifyFailed)
        );
    }

    #[test]
    fn add_tampering_after_sign_rejected() {
        let sk = SigningKey::from_bytes(&[3u8; 32]);
        let pk = sk.verifying_key();
        let mut body = proto::MiniappAddBody {
            fid: 42,
            domain: "example.com".to_string(),
            timestamp: 100,
            nonce: 1,
            signer_pubkey: pk.to_bytes().to_vec(),
            signature: Vec::new(),
        };
        body.signature = sk
            .sign(&add_signing_payload(
                &body,
                crate::hyper::DEFAULT_PROTOCOL_CHAIN_ID,
            ))
            .to_bytes()
            .to_vec();
        validate_add(&body, crate::hyper::DEFAULT_PROTOCOL_CHAIN_ID).unwrap();
        body.domain = "evil.com".to_string();
        assert_eq!(
            validate_add(&body, crate::hyper::DEFAULT_PROTOCOL_CHAIN_ID),
            Err(MiniappValidationError::SignatureVerifyFailed)
        );
    }

    #[test]
    fn update_metadata_tampering_rejected() {
        let sk = SigningKey::from_bytes(&[3u8; 32]);
        let pk = sk.verifying_key();
        let mut body = proto::MiniappUpdateBody {
            fid: 42,
            domain: "example.com".to_string(),
            metadata: Some(good_metadata()),
            timestamp: 100,
            nonce: 1,
            signer_pubkey: pk.to_bytes().to_vec(),
            signature: Vec::new(),
        };
        body.signature = sk
            .sign(&update_signing_payload(
                &body,
                crate::hyper::DEFAULT_PROTOCOL_CHAIN_ID,
            ))
            .to_bytes()
            .to_vec();
        validate_update(&body, crate::hyper::DEFAULT_PROTOCOL_CHAIN_ID).unwrap();
        // Mutate the metadata name; sig must no longer verify.
        if let Some(m) = body.metadata.as_mut() {
            m.name = "Hijacked".to_string();
        }
        assert_eq!(
            validate_update(&body, crate::hyper::DEFAULT_PROTOCOL_CHAIN_ID),
            Err(MiniappValidationError::SignatureVerifyFailed)
        );
    }
}
