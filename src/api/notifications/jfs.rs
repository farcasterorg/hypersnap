//! JSON Farcaster Signature (JFS) verification.
//!
//! Spec: <https://github.com/farcasterxyz/protocol/discussions/208>
//!
//! Wire format (JSON form):
//!
//! ```json
//! {
//!   "header":    "<base64url JSON>",
//!   "payload":   "<base64url JSON>",
//!   "signature": "<base64url 64-byte ed25519 sig>"
//! }
//! ```
//!
//! Decoded header:
//!
//! ```json
//! { "fid": 12345, "type": "app_key", "key": "0x<32 bytes hex>" }
//! ```
//!
//! Signing input is `ASCII(BASE64URL(header) || '.' || BASE64URL(payload))`
//! — exactly the JWS compact serialization of the (header, payload) pair.
//! The signature is verified with the Ed25519 key from `header.key`, and
//! that key must currently be an active app key for `header.fid` per the
//! onchain or gasless signer state, including gasless key expiry.
//!
//! Only `type = "app_key"` is supported. Mini app webhook events are
//! always signed with the user's app key per spec; `custody` and `auth`
//! types are rejected with `JfsError::UnsupportedKeyType`.

use crate::core::util::FarcasterTime;
use crate::storage::db::RocksDbTransactionBatch;
use crate::storage::store::account::{
    get_active_key, get_last_used_at, ActiveKey, OnchainEventStore,
};
use async_trait::async_trait;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;

/// Pluggable lookup so the verifier doesn't have to know how the codebase
/// stores signer keys. Implemented by `OnchainSignerLookup` for live use
/// and by mocks in tests.
#[async_trait]
pub trait ActiveSignerLookup: Send + Sync {
    /// Return `true` if `signer_pubkey` (32 bytes) is currently an active
    /// app key for `fid`. Errors are mapped to `false` by the verifier.
    async fn is_active_signer(&self, fid: u64, signer_pubkey: &[u8]) -> bool;
}

/// Store-backed implementation for onchain and gasless keys. The historical
/// type name is retained for callers; both key indexes share this RocksDB.
pub struct OnchainSignerLookup {
    stores: HashMap<u32, OnchainEventStore>,
}

impl OnchainSignerLookup {
    pub fn new(store: OnchainEventStore) -> Self {
        Self {
            stores: [(1, store)].into(),
        }
    }

    pub fn for_shards(stores: HashMap<u32, OnchainEventStore>) -> Self {
        Self { stores }
    }
}

#[async_trait]
impl ActiveSignerLookup for OnchainSignerLookup {
    async fn is_active_signer(&self, fid: u64, signer_pubkey: &[u8]) -> bool {
        use crate::mempool::routing::MessageRouter;
        let store = if self.stores.len() == 1 {
            self.stores.values().next()
        } else {
            let shard = (crate::mempool::routing::ShardRouter {})
                .route_fid(fid, self.stores.len().max(1) as u32);
            self.stores.get(&shard)
        };
        let Some(store) = store else {
            return false;
        };
        let txn = RocksDbTransactionBatch::new();
        match get_active_key(store, &store.db, &txn, fid, signer_pubkey) {
            Ok(Some(ActiveKey::OnChain)) => true,
            Ok(Some(ActiveKey::Gasless { ttl_seconds, .. })) if ttl_seconds > 0 => {
                matches!(get_last_used_at(&store.db, &txn, fid, signer_pubkey),
                    Ok(Some(last)) if u64::from(last).saturating_add(u64::from(ttl_seconds)) >= FarcasterTime::current().to_u64())
            }
            _ => false,
        }
    }
}

#[derive(Debug, Error)]
pub enum JfsError {
    #[error("envelope missing field: {0}")]
    MissingField(&'static str),
    #[error("base64url decode failed for {field}: {reason}")]
    Base64 { field: &'static str, reason: String },
    #[error("header JSON parse failed: {0}")]
    HeaderJson(String),
    #[error("header.key is not a valid 0x-prefixed 32-byte hex string")]
    BadKey,
    #[error("header.type is not supported: {0}")]
    UnsupportedKeyType(String),
    #[error("ed25519 signature is the wrong length")]
    BadSignatureLength,
    #[error("ed25519 verification failed")]
    BadSignature,
    #[error("signer is not currently active for the FID")]
    SignerNotActive,
}

/// What `verify` returns to the webhook handler. The payload bytes are
/// the raw decoded `payload` JSON ready to be `serde_json::from_slice`'d
/// into a `MiniappEventPayload` (or whatever the caller expects).
#[derive(Debug, Clone)]
pub struct VerifiedJfs {
    pub fid: u64,
    pub signer_pubkey: [u8; 32],
    pub payload_bytes: Vec<u8>,
}

#[derive(Debug, Deserialize)]
struct JfsHeader {
    #[serde(with = "crate::native_registration::serde_fid")]
    fid: u64,
    #[serde(rename = "type")]
    key_type: String,
    key: String,
}

#[derive(Debug, Deserialize)]
struct JfsEnvelope {
    header: String,
    payload: String,
    signature: String,
}

/// Verify a JFS envelope and return the decoded payload.
///
/// Steps (in this order):
/// 1. Parse the outer envelope JSON to get the three base64url strings.
/// 2. Recompute the JWS signing input: `header_b64 || '.' || payload_b64`.
/// 3. Decode the header bytes and parse them as JSON to extract
///    `fid`, `type`, and `key`.
/// 4. Reject if `type != "app_key"`.
/// 5. Decode the 32-byte Ed25519 pubkey from `header.key` (with optional
///    `0x` prefix).
/// 6. Decode the 64-byte signature.
/// 7. Verify the signature with `verify_strict` (rejects malleable sigs).
/// 8. Confirm the signer is currently registered as an active app key
///    for `fid` via `ActiveSignerLookup`.
/// 9. Return the decoded payload bytes for the caller to parse.
pub async fn verify(
    envelope_bytes: &[u8],
    lookup: Arc<dyn ActiveSignerLookup>,
) -> Result<VerifiedJfs, JfsError> {
    let envelope: JfsEnvelope =
        serde_json::from_slice(envelope_bytes).map_err(|e| JfsError::HeaderJson(e.to_string()))?;

    if envelope.header.is_empty() {
        return Err(JfsError::MissingField("header"));
    }
    if envelope.payload.is_empty() {
        return Err(JfsError::MissingField("payload"));
    }
    if envelope.signature.is_empty() {
        return Err(JfsError::MissingField("signature"));
    }

    // 2. Reconstruct the signing input from the original base64url strings.
    let signing_input = format!("{}.{}", envelope.header, envelope.payload);

    // 3. Decode and parse the header.
    let header_bytes = URL_SAFE_NO_PAD
        .decode(envelope.header.as_bytes())
        .map_err(|e| JfsError::Base64 {
            field: "header",
            reason: e.to_string(),
        })?;
    let header: JfsHeader =
        serde_json::from_slice(&header_bytes).map_err(|e| JfsError::HeaderJson(e.to_string()))?;

    // 4. Only app_key is supported.
    if header.key_type != "app_key" {
        return Err(JfsError::UnsupportedKeyType(header.key_type));
    }

    // 5. Decode the pubkey.
    let pubkey_hex = header.key.strip_prefix("0x").unwrap_or(&header.key);
    let pubkey_vec = hex::decode(pubkey_hex).map_err(|_| JfsError::BadKey)?;
    if pubkey_vec.len() != 32 {
        return Err(JfsError::BadKey);
    }
    let mut pubkey_bytes = [0u8; 32];
    pubkey_bytes.copy_from_slice(&pubkey_vec);

    let verifying_key = VerifyingKey::from_bytes(&pubkey_bytes).map_err(|_| JfsError::BadKey)?;

    // 6. Decode the signature.
    let sig_vec = URL_SAFE_NO_PAD
        .decode(envelope.signature.as_bytes())
        .map_err(|e| JfsError::Base64 {
            field: "signature",
            reason: e.to_string(),
        })?;
    if sig_vec.len() != 64 {
        return Err(JfsError::BadSignatureLength);
    }
    let mut sig_bytes = [0u8; 64];
    sig_bytes.copy_from_slice(&sig_vec);
    let signature = Signature::from_bytes(&sig_bytes);

    // 7. Verify.
    verifying_key
        .verify_strict(signing_input.as_bytes(), &signature)
        .map_err(|_| JfsError::BadSignature)?;

    // 8. Active signer check.
    if !lookup.is_active_signer(header.fid, &pubkey_bytes).await {
        return Err(JfsError::SignerNotActive);
    }

    // 9. Decode the payload bytes for the caller.
    let payload_bytes = URL_SAFE_NO_PAD
        .decode(envelope.payload.as_bytes())
        .map_err(|e| JfsError::Base64 {
            field: "payload",
            reason: e.to_string(),
        })?;

    Ok(VerifiedJfs {
        fid: header.fid,
        signer_pubkey: pubkey_bytes,
        payload_bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;
    use serde_json::json;
    use std::sync::Mutex;

    #[derive(Default)]
    struct MockLookup {
        active: Mutex<Vec<(u64, [u8; 32])>>,
    }

    impl MockLookup {
        fn allow(&self, fid: u64, pubkey: [u8; 32]) {
            self.active.lock().unwrap().push((fid, pubkey));
        }
    }

    #[async_trait]
    impl ActiveSignerLookup for MockLookup {
        async fn is_active_signer(&self, fid: u64, signer_pubkey: &[u8]) -> bool {
            let pubkey: [u8; 32] = match signer_pubkey.try_into() {
                Ok(b) => b,
                Err(_) => return false,
            };
            self.active
                .lock()
                .unwrap()
                .iter()
                .any(|(f, k)| *f == fid && *k == pubkey)
        }
    }

    fn make_envelope(
        signing_key: &SigningKey,
        header: serde_json::Value,
        payload: serde_json::Value,
    ) -> Vec<u8> {
        let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
        let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap());
        let signing_input = format!("{}.{}", header_b64, payload_b64);
        let sig = signing_key.sign(signing_input.as_bytes());
        let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());

        serde_json::to_vec(&json!({
            "header": header_b64,
            "payload": payload_b64,
            "signature": sig_b64,
        }))
        .unwrap()
    }

    fn header_for(signing_key: &SigningKey, fid: u64, key_type: &str) -> serde_json::Value {
        let pubkey_hex = hex::encode(signing_key.verifying_key().to_bytes());
        json!({
            "fid": fid,
            "type": key_type,
            "key": format!("0x{}", pubkey_hex),
        })
    }

    #[tokio::test]
    async fn native_gasless_jfs_checks_expiry_revocation_and_fid() {
        use crate::proto::{self, message_data::Body};
        use crate::storage::store::account::{
            delete_gasless_key_record, init_last_used_at, put_gasless_key_record, GaslessKeyRecord,
        };
        let (engine, _dir) = crate::storage::store::test_helper::new_engine().await;
        let stores = engine.get_stores();
        let lookup = Arc::new(OnchainSignerLookup::new(stores.onchain_event_store.clone()));
        let fid = crate::native_registration::FIRST_NATIVE_FID;
        let key = SigningKey::generate(&mut OsRng);
        let public = key.verifying_key().to_bytes();
        let mut txn = RocksDbTransactionBatch::new();
        put_gasless_key_record(
            &stores.db,
            &mut txn,
            fid,
            &public,
            &GaslessKeyRecord {
                message: Some(proto::Message {
                    data: Some(proto::MessageData {
                        body: Some(Body::KeyAddBody(proto::KeyAddBody {
                            ttl: 3600,
                            scopes: vec![proto::MessageType::CastAdd as i32],
                            ..Default::default()
                        })),
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                request_fid: fid,
            },
        )
        .unwrap();
        init_last_used_at(
            &stores.db,
            &mut txn,
            fid,
            &public,
            FarcasterTime::current().to_u64() as u32,
        )
        .unwrap();
        stores.db.commit(txn).unwrap();
        let envelope = make_envelope(
            &key,
            json!({ "fid": fid.to_string(), "type": "app_key", "key": format!("0x{}", hex::encode(public)) }),
            json!({ "event": "miniapp_added" }),
        );
        assert_eq!(verify(&envelope, lookup.clone()).await.unwrap().fid, fid);
        let (other, _other_dir) = crate::storage::store::test_helper::new_engine().await;
        use crate::mempool::routing::MessageRouter;
        let owner = (crate::mempool::routing::ShardRouter {}).route_fid(fid, 2);
        let lookup = Arc::new(OnchainSignerLookup::for_shards(
            [
                (owner, stores.onchain_event_store.clone()),
                (3 - owner, other.get_stores().onchain_event_store),
            ]
            .into(),
        ));
        assert!(verify(&envelope, lookup.clone()).await.is_ok());
        assert!(!lookup.is_active_signer(fid + 1, &public).await);

        let mut txn = RocksDbTransactionBatch::new();
        init_last_used_at(&stores.db, &mut txn, fid, &public, 0).unwrap();
        stores.db.commit(txn).unwrap();
        assert!(matches!(
            verify(&envelope, lookup.clone()).await,
            Err(JfsError::SignerNotActive)
        ));

        let mut txn = RocksDbTransactionBatch::new();
        init_last_used_at(
            &stores.db,
            &mut txn,
            fid,
            &public,
            FarcasterTime::current().to_u64() as u32,
        )
        .unwrap();
        stores.db.commit(txn).unwrap();
        assert!(verify(&envelope, lookup.clone()).await.is_ok());
        let mut txn = RocksDbTransactionBatch::new();
        delete_gasless_key_record(&stores.db, &mut txn, fid, &public).unwrap();
        stores.db.commit(txn).unwrap();
        assert!(matches!(
            verify(&envelope, lookup).await,
            Err(JfsError::SignerNotActive)
        ));
    }

    #[tokio::test]
    async fn happy_path_app_key() {
        let key = SigningKey::generate(&mut OsRng);
        let pubkey = key.verifying_key().to_bytes();

        let lookup = Arc::new(MockLookup::default());
        lookup.allow(7, pubkey);

        let envelope = make_envelope(
            &key,
            header_for(&key, 7, "app_key"),
            json!({ "event": "miniapp_added" }),
        );

        let verified = verify(&envelope, lookup).await.unwrap();
        assert_eq!(verified.fid, 7);
        assert_eq!(verified.signer_pubkey, pubkey);
        let payload: serde_json::Value = serde_json::from_slice(&verified.payload_bytes).unwrap();
        assert_eq!(payload["event"], "miniapp_added");
    }

    #[tokio::test]
    async fn rejects_unsupported_key_type() {
        let key = SigningKey::generate(&mut OsRng);
        let lookup = Arc::new(MockLookup::default());
        let envelope = make_envelope(
            &key,
            header_for(&key, 7, "custody"),
            json!({ "event": "miniapp_added" }),
        );
        let err = verify(&envelope, lookup).await.unwrap_err();
        assert!(matches!(err, JfsError::UnsupportedKeyType(_)));
    }

    #[tokio::test]
    async fn rejects_bad_signature() {
        let key = SigningKey::generate(&mut OsRng);
        let imposter = SigningKey::generate(&mut OsRng);
        let lookup = Arc::new(MockLookup::default());
        lookup.allow(7, key.verifying_key().to_bytes());

        // Build an envelope where the header advertises `key`'s pubkey
        // but the signature is from `imposter`.
        let header = header_for(&key, 7, "app_key");
        let payload = json!({ "event": "miniapp_added" });
        let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
        let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap());
        let signing_input = format!("{}.{}", header_b64, payload_b64);
        let bad_sig = imposter.sign(signing_input.as_bytes());
        let envelope_bytes = serde_json::to_vec(&json!({
            "header": header_b64,
            "payload": payload_b64,
            "signature": URL_SAFE_NO_PAD.encode(bad_sig.to_bytes()),
        }))
        .unwrap();

        let err = verify(&envelope_bytes, lookup).await.unwrap_err();
        assert!(matches!(err, JfsError::BadSignature));
    }

    #[tokio::test]
    async fn rejects_inactive_signer() {
        let key = SigningKey::generate(&mut OsRng);
        let lookup = Arc::new(MockLookup::default()); // empty allow-list

        let envelope = make_envelope(
            &key,
            header_for(&key, 7, "app_key"),
            json!({ "event": "miniapp_added" }),
        );
        let err = verify(&envelope, lookup).await.unwrap_err();
        assert!(matches!(err, JfsError::SignerNotActive));
    }

    #[tokio::test]
    async fn rejects_wrong_pubkey_format() {
        let key = SigningKey::generate(&mut OsRng);
        let lookup = Arc::new(MockLookup::default());
        let header = json!({ "fid": 7, "type": "app_key", "key": "not-hex" });
        let payload = json!({ "event": "miniapp_added" });
        let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
        let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap());
        let signing_input = format!("{}.{}", header_b64, payload_b64);
        let sig = key.sign(signing_input.as_bytes());
        let envelope = serde_json::to_vec(&json!({
            "header": header_b64,
            "payload": payload_b64,
            "signature": URL_SAFE_NO_PAD.encode(sig.to_bytes()),
        }))
        .unwrap();

        let err = verify(&envelope, lookup).await.unwrap_err();
        assert!(matches!(err, JfsError::BadKey));
    }

    #[tokio::test]
    async fn rejects_tampered_payload() {
        let key = SigningKey::generate(&mut OsRng);
        let lookup = Arc::new(MockLookup::default());
        lookup.allow(7, key.verifying_key().to_bytes());

        // Build a valid envelope.
        let header = header_for(&key, 7, "app_key");
        let payload = json!({ "event": "miniapp_added" });
        let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
        let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap());
        let signing_input = format!("{}.{}", header_b64, payload_b64);
        let sig = key.sign(signing_input.as_bytes());

        // Now swap the payload to a *different* base64-encoded value but
        // keep the original signature. Verification must fail.
        let tampered_payload = json!({ "event": "miniapp_removed" });
        let tampered_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&tampered_payload).unwrap());
        let envelope = serde_json::to_vec(&json!({
            "header": header_b64,
            "payload": tampered_b64,
            "signature": URL_SAFE_NO_PAD.encode(sig.to_bytes()),
        }))
        .unwrap();

        let err = verify(&envelope, lookup).await.unwrap_err();
        assert!(matches!(err, JfsError::BadSignature));
    }
}
