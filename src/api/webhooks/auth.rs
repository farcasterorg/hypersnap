//! EIP-712 ownership verification for webhook management requests.
//!
//! Wire format and verification rules are documented in
//! `src/api/webhooks/mod.rs`. This module is responsible only for taking
//! the parsed header values + raw request body and producing either a
//! verified `(fid, op)` tuple or an error.

use alloy_dyn_abi::TypedData;
use alloy_primitives::{keccak256, Address, PrimitiveSignature, B256};
use async_trait::async_trait;
use moka::sync::Cache;
use serde_json::json;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;

use crate::api::webhooks::types::WebhookOp;

/// Trait for resolving the current custody address of an FID.
///
/// Implemented for `crate::api::user_hydrator::HubUserHydrator` so the
/// auth verifier can reuse the same data path the user-hydrator already
/// hits, with no extra wiring.
#[async_trait]
pub trait CustodyAddressLookup: Send + Sync {
    async fn get_custody_address(&self, fid: u64) -> Option<Address>;
}

/// All the auth fields the client sends as `X-Hypersnap-*` headers,
/// pre-parsed by the HTTP layer.
#[derive(Debug, Clone)]
pub struct AuthHeaders {
    pub fid: u64,
    pub op: WebhookOp,
    pub signed_at: u64,
    pub nonce: B256,
    pub signature: [u8; 65],
}

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("missing or malformed header: {0}")]
    BadHeader(&'static str),
    #[error("clock skew too large (signed_at differs from server clock)")]
    ClockSkew,
    #[error("nonce already used")]
    NonceReplayed,
    #[error("could not build EIP-712 typed data: {0}")]
    TypedData(String),
    #[error("could not recover signer address")]
    BadSignature,
    #[error("FID has no on-chain custody address yet")]
    UnknownFid,
    #[error("recovered address does not match the FID's custody address")]
    NotCustody,
}

/// EIP-712 verifier with an in-memory nonce LRU.
///
/// Cloneable: clones share the same underlying nonce cache and lookup,
/// so the same instance can sit behind a `Clone` HTTP handler.
#[derive(Clone)]
pub struct WebhookAuthVerifier {
    custody_lookup: Arc<dyn CustodyAddressLookup>,
    nonce_cache: Cache<(u64, B256), ()>,
    /// Maximum acceptable skew (in either direction) between client `signed_at`
    /// and server clock.
    signed_at_window_secs: u64,
}

impl WebhookAuthVerifier {
    pub fn new(custody_lookup: Arc<dyn CustodyAddressLookup>, signed_at_window_secs: u64) -> Self {
        // Cache TTL is twice the signed_at window so a nonce can never be
        // replayed inside the window after it expires from the cache.
        let cache = Cache::builder()
            .time_to_live(Duration::from_secs(signed_at_window_secs.saturating_mul(2)))
            .max_capacity(100_000)
            .build();
        Self {
            custody_lookup,
            nonce_cache: cache,
            signed_at_window_secs,
        }
    }

    /// Verify a request and return the authenticated `(fid, op)` on success.
    ///
    /// `body_bytes` MUST be the literal HTTP body bytes that were signed.
    pub async fn verify(
        &self,
        headers: &AuthHeaders,
        body_bytes: &[u8],
    ) -> Result<(u64, WebhookOp), AuthError> {
        // 1. Clock skew.
        let now = current_unix_secs();
        let skew = now.abs_diff(headers.signed_at);
        if skew > self.signed_at_window_secs {
            return Err(AuthError::ClockSkew);
        }

        // 2. Nonce replay (also rejects same nonce sent twice within the window).
        let key = (headers.fid, headers.nonce);
        if self.nonce_cache.contains_key(&key) {
            return Err(AuthError::NonceReplayed);
        }

        // 3. Compute requestHash from body bytes.
        let request_hash = keccak256(body_bytes);

        // 4. Build the EIP-712 typed data and compute its signing hash.
        let typed_data_json = json!({
            "types": {
                "EIP712Domain": [
                    { "name": "name",    "type": "string"  },
                    { "name": "version", "type": "string"  },
                    { "name": "chainId", "type": "uint256" },
                ],
                "WebhookOperation": [
                    { "name": "op",          "type": "string"  },
                    { "name": "fid",         "type": "uint64"  },
                    { "name": "signedAt",    "type": "uint256" },
                    { "name": "nonce",       "type": "bytes32" },
                    { "name": "requestHash", "type": "bytes32" },
                ],
            },
            "primaryType": "WebhookOperation",
            "domain": {
                "name": "Hypersnap",
                "version": "1",
                "chainId": 10,
            },
            "message": {
                "op":          headers.op.as_str(),
                "fid":         headers.fid.to_string(),
                "signedAt":    headers.signed_at.to_string(),
                "nonce":       format!("0x{}", hex::encode(headers.nonce.as_slice())),
                "requestHash": format!("0x{}", hex::encode(request_hash.as_slice())),
            },
        });

        let typed_data: TypedData = serde_json::from_value(typed_data_json)
            .map_err(|e| AuthError::TypedData(e.to_string()))?;
        let signing_hash = typed_data
            .eip712_signing_hash()
            .map_err(|e| AuthError::TypedData(e.to_string()))?;

        // 5. Recover signer.
        let parity_byte = headers.signature[64];
        let parity = parity_byte != 0x1b && parity_byte != 0x00;
        let signature =
            PrimitiveSignature::from_bytes_and_parity(&headers.signature[0..64], parity);
        let recovered = signature
            .recover_address_from_prehash(&signing_hash)
            .map_err(|_| AuthError::BadSignature)?;

        // 6. Custody lookup.
        let custody = self
            .custody_lookup
            .get_custody_address(headers.fid)
            .await
            .ok_or(AuthError::UnknownFid)?;

        if recovered != custody {
            return Err(AuthError::NotCustody);
        }

        // 7. Mark nonce used. Done last so failed verifications don't
        //    permanently burn a nonce the caller might want to retry.
        self.nonce_cache.insert(key, ());

        Ok((headers.fid, headers.op))
    }
}

fn current_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_signer::SignerSync;
    use alloy_signer_local::PrivateKeySigner;

    /// In-memory custody lookup for tests: maps fid → address.
    struct MockLookup {
        addr: Address,
        fid: u64,
    }

    #[async_trait]
    impl CustodyAddressLookup for MockLookup {
        async fn get_custody_address(&self, fid: u64) -> Option<Address> {
            if fid == self.fid {
                Some(self.addr)
            } else {
                None
            }
        }
    }

    fn build_typed_data(
        op: WebhookOp,
        fid: u64,
        signed_at: u64,
        nonce: B256,
        body_bytes: &[u8],
    ) -> TypedData {
        let request_hash = keccak256(body_bytes);
        let json = json!({
            "types": {
                "EIP712Domain": [
                    { "name": "name",    "type": "string"  },
                    { "name": "version", "type": "string"  },
                    { "name": "chainId", "type": "uint256" },
                ],
                "WebhookOperation": [
                    { "name": "op",          "type": "string"  },
                    { "name": "fid",         "type": "uint64"  },
                    { "name": "signedAt",    "type": "uint256" },
                    { "name": "nonce",       "type": "bytes32" },
                    { "name": "requestHash", "type": "bytes32" },
                ],
            },
            "primaryType": "WebhookOperation",
            "domain": {
                "name": "Hypersnap",
                "version": "1",
                "chainId": 10,
            },
            "message": {
                "op":          op.as_str(),
                "fid":         fid.to_string(),
                "signedAt":    signed_at.to_string(),
                "nonce":       format!("0x{}", hex::encode(nonce.as_slice())),
                "requestHash": format!("0x{}", hex::encode(request_hash.as_slice())),
            },
        });
        serde_json::from_value(json).unwrap()
    }

    fn sign(signer: &PrivateKeySigner, data: &TypedData) -> [u8; 65] {
        let hash = data.eip712_signing_hash().unwrap();
        let sig = signer.sign_hash_sync(&hash).unwrap();
        let bytes = sig.as_bytes();
        let mut out = [0u8; 65];
        out.copy_from_slice(&bytes);
        out
    }

    #[tokio::test]
    async fn happy_path() {
        let signer = PrivateKeySigner::random();
        let addr = signer.address();
        let lookup = Arc::new(MockLookup { addr, fid: 7 });
        let verifier = WebhookAuthVerifier::new(lookup, 300);

        let body = br#"{"name":"my hook","url":"https://example.com/h"}"#;
        let signed_at = current_unix_secs();
        let nonce = B256::repeat_byte(0xab);
        let typed = build_typed_data(WebhookOp::Create, 7, signed_at, nonce, body);
        let signature = sign(&signer, &typed);

        let headers = AuthHeaders {
            fid: 7,
            op: WebhookOp::Create,
            signed_at,
            nonce,
            signature,
        };

        let (fid, op) = verifier.verify(&headers, body).await.unwrap();
        assert_eq!(fid, 7);
        assert_eq!(op, WebhookOp::Create);
    }

    #[tokio::test]
    async fn rejects_wrong_signer() {
        let real = PrivateKeySigner::random();
        let imposter = PrivateKeySigner::random();
        let lookup = Arc::new(MockLookup {
            addr: real.address(),
            fid: 7,
        });
        let verifier = WebhookAuthVerifier::new(lookup, 300);

        let body = b"{}";
        let signed_at = current_unix_secs();
        let nonce = B256::repeat_byte(0xcd);
        let typed = build_typed_data(WebhookOp::Create, 7, signed_at, nonce, body);
        let signature = sign(&imposter, &typed);

        let headers = AuthHeaders {
            fid: 7,
            op: WebhookOp::Create,
            signed_at,
            nonce,
            signature,
        };
        assert!(matches!(
            verifier.verify(&headers, body).await,
            Err(AuthError::NotCustody)
        ));
    }

    #[tokio::test]
    async fn rejects_replayed_nonce() {
        let signer = PrivateKeySigner::random();
        let lookup = Arc::new(MockLookup {
            addr: signer.address(),
            fid: 9,
        });
        let verifier = WebhookAuthVerifier::new(lookup, 300);

        let body = b"x";
        let signed_at = current_unix_secs();
        let nonce = B256::repeat_byte(0xee);
        let typed = build_typed_data(WebhookOp::Create, 9, signed_at, nonce, body);
        let signature = sign(&signer, &typed);

        let headers = AuthHeaders {
            fid: 9,
            op: WebhookOp::Create,
            signed_at,
            nonce,
            signature,
        };
        verifier.verify(&headers, body).await.unwrap();
        // Same nonce on second attempt → rejected.
        assert!(matches!(
            verifier.verify(&headers, body).await,
            Err(AuthError::NonceReplayed)
        ));
    }

    #[tokio::test]
    async fn rejects_clock_skew() {
        let signer = PrivateKeySigner::random();
        let lookup = Arc::new(MockLookup {
            addr: signer.address(),
            fid: 9,
        });
        let verifier = WebhookAuthVerifier::new(lookup, 60);

        let body = b"x";
        let signed_at = current_unix_secs() - 600;
        let nonce = B256::repeat_byte(0x11);
        let typed = build_typed_data(WebhookOp::Create, 9, signed_at, nonce, body);
        let signature = sign(&signer, &typed);

        let headers = AuthHeaders {
            fid: 9,
            op: WebhookOp::Create,
            signed_at,
            nonce,
            signature,
        };
        assert!(matches!(
            verifier.verify(&headers, body).await,
            Err(AuthError::ClockSkew)
        ));
    }

    #[tokio::test]
    async fn rejects_unknown_fid() {
        let signer = PrivateKeySigner::random();
        let lookup = Arc::new(MockLookup {
            addr: signer.address(),
            fid: 1,
        });
        let verifier = WebhookAuthVerifier::new(lookup, 300);

        let body = b"x";
        let signed_at = current_unix_secs();
        let nonce = B256::repeat_byte(0x22);
        let typed = build_typed_data(WebhookOp::Create, 999, signed_at, nonce, body);
        let signature = sign(&signer, &typed);

        let headers = AuthHeaders {
            fid: 999,
            op: WebhookOp::Create,
            signed_at,
            nonce,
            signature,
        };
        assert!(matches!(
            verifier.verify(&headers, body).await,
            Err(AuthError::UnknownFid)
        ));
    }

    #[tokio::test]
    async fn rejects_body_tamper() {
        let signer = PrivateKeySigner::random();
        let lookup = Arc::new(MockLookup {
            addr: signer.address(),
            fid: 5,
        });
        let verifier = WebhookAuthVerifier::new(lookup, 300);

        let body = b"original body";
        let signed_at = current_unix_secs();
        let nonce = B256::repeat_byte(0x33);
        let typed = build_typed_data(WebhookOp::Create, 5, signed_at, nonce, body);
        let signature = sign(&signer, &typed);

        // Send a tampered body to the verifier — same headers, different bytes.
        let headers = AuthHeaders {
            fid: 5,
            op: WebhookOp::Create,
            signed_at,
            nonce,
            signature,
        };
        let tampered = b"tampered body";
        // Tampering changes requestHash, which changes the signing hash, which
        // recovers a different (almost certainly non-matching) address, which
        // surfaces as NotCustody.
        assert!(matches!(
            verifier.verify(&headers, tampered).await,
            Err(AuthError::NotCustody) | Err(AuthError::BadSignature)
        ));
    }
}
