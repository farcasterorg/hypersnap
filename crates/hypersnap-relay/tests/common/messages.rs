//! Message builders shared by the unit tests (through `#[path]` in lib.rs) and
//! the integration tests.
#![allow(dead_code)]

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use hypersnap_proto::{
    message_data, CastAddBody, FarcasterNetwork, HashScheme, HyperSignatureExtension, KeyAddBody,
    KeyRemoveBody, Message, MessageData, MessageType, SignatureScheme,
};
use prost::Message as _;

pub fn signing_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

pub fn cast_data(fid: u64, text: &str, network: FarcasterNetwork) -> MessageData {
    MessageData {
        r#type: MessageType::CastAdd as i32,
        fid,
        timestamp: 100_000_000,
        network: network as i32,
        body: Some(message_data::Body::CastAddBody(CastAddBody {
            text: text.to_string(),
            ..Default::default()
        })),
    }
}

pub fn key_add_data(fid: u64, body: KeyAddBody, network: FarcasterNetwork) -> MessageData {
    MessageData {
        r#type: MessageType::KeyAdd as i32,
        fid,
        timestamp: 100_000_000,
        network: network as i32,
        body: Some(message_data::Body::KeyAddBody(body)),
    }
}

pub fn key_remove_data(fid: u64, body: KeyRemoveBody, network: FarcasterNetwork) -> MessageData {
    MessageData {
        r#type: MessageType::KeyRemove as i32,
        fid,
        timestamp: 100_000_000,
        network: network as i32,
        body: Some(message_data::Body::KeyRemoveBody(body)),
    }
}

/// A Farcaster message: hash = BLAKE3(encode(data))[..20], Ed25519 over the hash.
pub fn ed25519_message(key: &SigningKey, data: MessageData) -> Message {
    let bytes = data.encode_to_vec();
    let hash = blake3::hash(&bytes).as_bytes()[..20].to_vec();
    let signature = key.sign(&hash).to_bytes().to_vec();
    Message {
        data: Some(data),
        hash,
        hash_scheme: HashScheme::Blake3 as i32,
        signature,
        signature_scheme: SignatureScheme::Ed25519 as i32,
        signer: key.verifying_key().to_bytes().to_vec(),
        data_bytes: None,
    }
}

/// The dual-signed form (FIP §16.8): Ed25519 signature || encode(extension).
pub fn add_extension(msg: &Message, ext: &HyperSignatureExtension) -> Message {
    let mut out = msg.clone();
    out.signature.extend_from_slice(&ext.encode_to_vec());
    out.signature_scheme = SignatureScheme::Ed25519Falcon512 as i32;
    out
}

pub fn dual_signed_message(
    key: &SigningKey,
    data: MessageData,
    ext: &HyperSignatureExtension,
) -> Message {
    add_extension(&ed25519_message(key, data), ext)
}

pub fn falcon_only_message(key: &SigningKey, data: MessageData) -> Message {
    let mut msg = ed25519_message(key, data);
    msg.signature = vec![0x5A; 666];
    msg.signer = vec![0x11; 32];
    msg.signature_scheme = SignatureScheme::Falcon512 as i32;
    msg
}

/// A message of a Hypersnap type (>= 100), for example TOKEN_TRANSFER (140).
pub fn hypersnap_type_message(
    key: &SigningKey,
    fid: u64,
    message_type: i32,
    network: FarcasterNetwork,
) -> Message {
    let data = MessageData {
        r#type: message_type,
        fid,
        timestamp: 100_000_000,
        network: network as i32,
        body: None,
    };
    ed25519_message(key, data)
}

pub fn verify_ed25519(msg: &Message) -> bool {
    let Ok(key_bytes) = <[u8; 32]>::try_from(msg.signer.as_slice()) else {
        return false;
    };
    let Ok(key) = VerifyingKey::from_bytes(&key_bytes) else {
        return false;
    };
    let Ok(sig) = ed25519_dalek::Signature::from_slice(&msg.signature) else {
        return false;
    };
    key.verify(&msg.hash, &sig).is_ok()
}
