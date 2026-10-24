//! FIP-native-miniapp-index structural rules: the miniapp ID of a domain,
//! and the caps of the domain and the metadata (FIP §9). Shard 0 applies
//! them to the miniapp messages (`chain::shard0::miniapp`).

use crate::proto;
use sha2::{Digest, Sha256};

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
}

/// Strict FIP §9 caps.
const MAX_DOMAIN_BYTES: usize = 253; // RFC 1035-style
const MAX_NAME_BYTES: usize = 32;
const MAX_DESCRIPTION_BYTES: usize = 256;
const MAX_TAGLINE_BYTES: usize = 64;
const MAX_TAGS: usize = 5;
const MAX_TAG_BYTES: usize = 24;
const MAX_SCREENSHOTS: usize = 5;

pub fn validate_domain(domain: &str) -> Result<(), MiniappValidationError> {
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

pub fn validate_metadata(m: &proto::MiniappMetadata) -> Result<(), MiniappValidationError> {
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

#[cfg(test)]
mod tests {
    use super::*;

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
        // The ID is case-sensitive.
        assert_ne!(
            miniapp_id_from_domain("Example.com"),
            miniapp_id_from_domain("example.com")
        );
    }

    #[test]
    fn a_domain_has_no_scheme_port_or_path() {
        validate_domain("example.com").unwrap();
        for d in [
            "https://example.com",
            "example.com:8080",
            "example.com/path",
        ] {
            assert_eq!(
                validate_domain(d),
                Err(MiniappValidationError::InvalidDomain)
            );
        }
        assert_eq!(
            validate_domain(""),
            Err(MiniappValidationError::EmptyDomain)
        );
    }

    #[test]
    fn metadata_caps() {
        validate_metadata(&good_metadata()).unwrap();
        let mut m = good_metadata();
        m.name = "x".repeat(33);
        assert_eq!(
            validate_metadata(&m),
            Err(MiniappValidationError::BadName { got: 33 })
        );
        let mut m = good_metadata();
        m.tags = (0..6).map(|i| format!("tag{}", i)).collect();
        assert_eq!(
            validate_metadata(&m),
            Err(MiniappValidationError::TooManyTags { got: 6 })
        );
        let mut m = good_metadata();
        m.home_url = "http://example.com".to_string();
        assert_eq!(
            validate_metadata(&m),
            Err(MiniappValidationError::BadHomeUrl)
        );
    }
}
