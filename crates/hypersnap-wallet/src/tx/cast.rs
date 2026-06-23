//! Build + sign a snapchain `CastAdd` user message.
//!
//! Unlike the hyper transaction builders in this module, `CastAdd` is a
//! SNAPCHAIN message — it gets submitted via the snapchain HTTP API
//! (`POST /v1/submitMessage`) and committed in a snapchain shard chunk,
//! not a hyperblock. The signing flow matches `messages_factory` in
//! the main hypersnap crate:
//!
//!   1. Build `MessageData { fid, type=CastAdd, timestamp, network, body }`.
//!   2. `data_bytes = encode_to_vec(MessageData)`.
//!   3. `hash = blake3(data_bytes)[..20]`  (20-byte truncated hash).
//!   4. `signature = ed25519_sign(signing_key, hash)`.
//!   5. Wrap in `Message { data, hash_scheme=Blake3, hash, signature_scheme=Ed25519, signature, signer = pubkey }`.
//!
//! The `signer` field MUST be the public half of a key that's been
//! registered as a `SignerAdd` event for `fid` — otherwise the
//! snapchain admission path rejects the message with
//! `InvalidSigner`. For the local testnet, `setup_local_testnet
//! --seed-snapchain-state` writes `SignerAdd(fid, validator.key.pubkey)`,
//! so the same key the node uses for consensus also signs casts from
//! that FID.

use crate::error::WalletError;
use ed25519_dalek::{Signer, SigningKey};
use hypersnap_proto as proto;
use prost::Message as _;

/// Build a Cast-typed `CastAdd` message. `text` is the cast body; for
/// the local-testnet demo we leave embeds/mentions/parent empty.
///
/// `network` is the snapchain network the receiving node is running
/// in (Devnet for the local testnet). It's part of the signing
/// payload, so a Devnet-signed message will not verify on a Mainnet
/// node and vice-versa.
///
/// `timestamp` is Farcaster-epoch seconds (NOT Unix seconds). Callers
/// who don't have a Farcaster-epoch clock handy can call
/// `farcaster_now()` below.
pub fn build_cast_add(
    fid: u64,
    text: &str,
    timestamp: u32,
    network: proto::FarcasterNetwork,
    signing_key: &SigningKey,
) -> Result<proto::Message, WalletError> {
    let body = proto::CastAddBody {
        embeds_deprecated: vec![],
        mentions: vec![],
        parent: None,
        text: text.to_string(),
        mentions_positions: vec![],
        embeds: vec![],
        r#type: proto::CastType::Cast as i32,
    };
    let msg_data = proto::MessageData {
        fid,
        r#type: proto::MessageType::CastAdd as i32,
        timestamp,
        network: network as i32,
        body: Some(proto::message_data::Body::CastAddBody(body)),
    };
    let msg_data_bytes = msg_data.encode_to_vec();
    let hash = blake3::hash(&msg_data_bytes).as_bytes()[0..20].to_vec();
    let signature = signing_key.sign(&hash).to_bytes().to_vec();
    Ok(proto::Message {
        data: Some(msg_data),
        hash_scheme: proto::HashScheme::Blake3 as i32,
        hash,
        signature_scheme: proto::SignatureScheme::Ed25519 as i32,
        signature,
        signer: signing_key.verifying_key().to_bytes().to_vec(),
        data_bytes: None,
    })
}

/// Farcaster-epoch seconds — the timestamp domain snapchain messages
/// live in. Equal to `unix_seconds - FARCASTER_EPOCH/1000`.
pub fn farcaster_now() -> u32 {
    use std::time::{SystemTime, UNIX_EPOCH};
    const FARCASTER_EPOCH_MS: u64 = 1_609_459_200_000; // 2021-01-01 UTC
    let unix_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    (unix_secs - FARCASTER_EPOCH_MS / 1000) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Smoke: builds, signs, and parses back via prost. The hash
    /// should be exactly 20 bytes and recoverable from the signed
    /// data.
    #[test]
    fn build_cast_add_signs_and_round_trips() {
        let key = SigningKey::from_bytes(&[0x11u8; 32]);
        let msg = build_cast_add(
            42,
            "hello testnet",
            123_456,
            proto::FarcasterNetwork::Devnet,
            &key,
        )
        .unwrap();
        assert_eq!(msg.hash.len(), 20);
        assert_eq!(msg.signature.len(), 64);
        assert_eq!(msg.signer, key.verifying_key().to_bytes().to_vec());

        // Re-derive the hash from the embedded data and assert match.
        let data_bytes = msg.data.as_ref().unwrap().encode_to_vec();
        let expected_hash = blake3::hash(&data_bytes).as_bytes()[0..20].to_vec();
        assert_eq!(msg.hash, expected_hash);
    }
}
