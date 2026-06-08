//! Cross-implementation KEY_ADD compatibility test — GENERATED, do not hand-edit.
//!
//! Regenerate with (from the quorum-mobile repo root):
//!     node scripts/keyadd_golden_vector.cjs
//!
//! A KEY_ADD constructed + signed by the mobile client library
//! (`@quilibrium/quorum-shared`) MUST validate under this node's own validators.
//! If the client's protobuf serialization, EIP-712 digests, ABI metadata, or
//! signatures diverged from what the validator expects, the gateway would accept
//! the POST (envelope-level checks pass) but the forwarded message would be
//! silently dropped at `merge_key_add` time — the "client thinks it succeeded but
//! the signer never appears" symptom.
//!
//! Shared seed phrase on both sides:
//!   mnemonic "test test test test test test test test test test test junk"
//!   custody  m/44'/60'/0'/0/0  => 0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266
//!   signer   ed25519 priv = 0x11 * 32
//!   fid=1234 nonce=1700000000 deadline=1893456000 ttl=86400 ts=100000000 net=1
//!   scopes=[1, 2, 3, 4, 5, 6, 7, 8, 11, 12, 13, 14, 15]

use alloy_primitives::Address;
use prost::Message as _;

use crate::core::validations::key::{
    key_add_typed_data, recover_key_add_custody_address, validate_key_add_body,
    verify_signed_key_request_metadata, KeyAddPayload, ETH_MAINNET_CHAIN_ID,
};
use crate::core::validations::message::validate_message_hash;
use crate::proto::{
    self, message_data::Body, HashScheme, MessageData, MessageType, SignatureScheme,
};

const CUSTODY_ADDR: &str = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266";
const CUSTODY_PRIV: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const SIGNER_PUB_HEX: &str = "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737";
const ENVELOPE_HEX: &str = "0abb03081010d2091880c2d72f20019a01ab030a20d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c977873710011a41157967ee76b0ec7a2d89b8e60179ff18f0062eb2db3e712483c9134fc204fcdb551cecca0771767abcc03d8740caecda8145255ac23a1a4cff1f1a62c154cb141c2080b1ef86072880e2cfaa0632a002000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000004d2000000000000000000000000f39fd6e51aad88f6f4ce6ab8827279cfffb9226600000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000070dbd88000000000000000000000000000000000000000000000000000000000000000410a6804f0329c8440249bc310683b724b75fe645f3abd5205d7d6fc7676816fd75d97ac207b099d69d201b6d061332c874c6c0fc200a56b0b90267e246d2b18361c0000000000000000000000000000000000000000000000000000000000000038014a0d01020304050607080b0c0d0e0f5080a3051214163faebb7a12350f65a121558e920838884967a41801224033137cae5eff84a15ea8217406519717109bd24a22306b76d9d72f9d854870dae9ccc7ec5e56ef2d6d2b6b9c77ca1c992ad5d697231fc8161416197f9984930228013220d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c97787373abb03081010d2091880c2d72f20019a01ab030a20d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c977873710011a41157967ee76b0ec7a2d89b8e60179ff18f0062eb2db3e712483c9134fc204fcdb551cecca0771767abcc03d8740caecda8145255ac23a1a4cff1f1a62c154cb141c2080b1ef86072880e2cfaa0632a002000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000004d2000000000000000000000000f39fd6e51aad88f6f4ce6ab8827279cfffb9226600000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000070dbd88000000000000000000000000000000000000000000000000000000000000000410a6804f0329c8440249bc310683b724b75fe645f3abd5205d7d6fc7676816fd75d97ac207b099d69d201b6d061332c874c6c0fc200a56b0b90267e246d2b18361c0000000000000000000000000000000000000000000000000000000000000038014a0d01020304050607080b0c0d0e0f5080a305";
const DATA_BYTES_HEX: &str = "081010d2091880c2d72f20019a01ab030a20d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c977873710011a41157967ee76b0ec7a2d89b8e60179ff18f0062eb2db3e712483c9134fc204fcdb551cecca0771767abcc03d8740caecda8145255ac23a1a4cff1f1a62c154cb141c2080b1ef86072880e2cfaa0632a002000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000004d2000000000000000000000000f39fd6e51aad88f6f4ce6ab8827279cfffb9226600000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000070dbd88000000000000000000000000000000000000000000000000000000000000000410a6804f0329c8440249bc310683b724b75fe645f3abd5205d7d6fc7676816fd75d97ac207b099d69d201b6d061332c874c6c0fc200a56b0b90267e246d2b18361c0000000000000000000000000000000000000000000000000000000000000038014a0d01020304050607080b0c0d0e0f5080a305";
const KEY_ADD_DIGEST_HEX: &str = "3d889a493e157f2015a52d3e481d1502a2d40081bb388ea9914833a3fe70414d";

const FID: u64 = 1234;
const NONCE: u32 = 1700000000;
const DEADLINE: u32 = 1893456000;
const TTL: u32 = 86400;
const TIMESTAMP: u32 = 100000000;
const SCOPES: [i32; 13] = [1, 2, 3, 4, 5, 6, 7, 8, 11, 12, 13, 14, 15];

#[test]
fn quorum_shared_key_add_validates_on_node() {
    let custody: Address = CUSTODY_ADDR.parse().unwrap();
    let envelope = hex::decode(ENVELOPE_HEX).unwrap();
    let data_bytes_expected = hex::decode(DATA_BYTES_HEX).unwrap();
    let digest_expected = hex::decode(KEY_ADD_DIGEST_HEX).unwrap();
    let signer_pub = hex::decode(SIGNER_PUB_HEX).unwrap();

    // 1. Envelope decodes as proto::Message (protobuf serialization compatibility).
    let msg = proto::Message::decode(envelope.as_slice())
        .expect("quorum-shared envelope must decode as proto::Message");
    assert_eq!(msg.hash_scheme, HashScheme::Blake3 as i32);
    assert_eq!(msg.signature_scheme, SignatureScheme::Ed25519 as i32);
    assert_eq!(
        msg.signer, signer_pub,
        "envelope signer == ed25519 public key"
    );
    assert_eq!(msg.signature.len(), 64, "ed25519 signature is 64 bytes");
    let data_bytes = msg
        .data_bytes
        .clone()
        .expect("data_bytes present on envelope");
    assert_eq!(
        data_bytes, data_bytes_expected,
        "data_bytes byte-identical to golden"
    );

    // 2. blake3-20(data_bytes) == hash (hash-scheme compatibility).
    validate_message_hash(msg.hash_scheme, &data_bytes, &msg.hash)
        .expect("blake3_20(data_bytes) must equal the envelope hash");

    // 3. Envelope Ed25519 signature over the hash verifies.
    {
        use ed25519_dalek::{Signature, VerifyingKey};
        let vk = VerifyingKey::try_from(msg.signer.as_slice()).expect("valid ed25519 signer key");
        let sig = Signature::from_slice(&msg.signature).expect("valid ed25519 signature");
        vk.verify_strict(&msg.hash, &sig)
            .expect("envelope ed25519 signature over the hash must verify");
    }

    // 4. MessageData + KeyAddBody decode + static body validation.
    let md = MessageData::decode(data_bytes.as_slice()).expect("MessageData must decode");
    assert_eq!(
        md.r#type,
        MessageType::KeyAdd as i32,
        "message type is KEY_ADD"
    );
    assert_eq!(md.fid, FID);
    assert_eq!(md.timestamp, TIMESTAMP);
    let body = match md.body {
        Some(Body::KeyAddBody(b)) => b,
        _ => panic!("expected KeyAddBody in MessageData"),
    };
    assert_eq!(body.key, signer_pub, "KeyAddBody.key == signer public key");
    assert_eq!(body.key_type, 1);
    assert_eq!(body.nonce, NONCE);
    assert_eq!(body.ttl, TTL);
    assert_eq!(body.deadline, DEADLINE);
    assert_eq!(body.metadata_type, 1);
    assert_eq!(body.scopes, SCOPES.to_vec());
    validate_key_add_body(&body).expect("static KeyAddBody validation must pass");

    // 5. KeyAdd EIP-712 digest is byte-identical (typed-data construction compat).
    let payload = KeyAddPayload {
        fid: md.fid,
        key: &body.key,
        key_type: body.key_type,
        scopes: &body.scopes,
        ttl: body.ttl,
        nonce: body.nonce,
        deadline: body.deadline,
    };
    let digest = key_add_typed_data(&payload, ETH_MAINNET_CHAIN_ID)
        .unwrap()
        .eip712_signing_hash()
        .unwrap();
    assert_eq!(
        digest.as_slice(),
        digest_expected.as_slice(),
        "KeyAdd EIP-712 signing hash must match quorum-shared's keyAddDigest"
    );

    // 6. KeyAdd custody signature recovers the mnemonic's custody address.
    let recovered =
        recover_key_add_custody_address(&payload, &body.custody_signature, ETH_MAINNET_CHAIN_ID)
            .expect("custody signature must recover");
    assert_eq!(
        recovered, custody,
        "KeyAdd custody signature must recover the fid's custody address"
    );

    // 7. SignedKeyRequest metadata verifies; requestSigner == custody, requestFid == fid.
    //    current_timestamp mirrors merge_key_add: the message's own farcaster-epoch timestamp.
    let verified = verify_signed_key_request_metadata(
        body.metadata_type,
        &body.metadata,
        &body.key,
        TIMESTAMP as u64,
        ETH_MAINNET_CHAIN_ID,
    )
    .expect("SignedKeyRequest metadata must verify");
    assert_eq!(verified.request_fid, FID);
    assert_eq!(
        verified.request_signer, custody,
        "metadata requestSigner must equal the custody address"
    );

    // 8. The node can independently reproduce the SAME custody signature from the
    //    same custody key (deterministic RFC-6979 ECDSA): r||s must be byte-identical.
    {
        use alloy_signer::SignerSync;
        use alloy_signer_local::PrivateKeySigner;
        let signer: PrivateKeySigner = CUSTODY_PRIV.parse().expect("custody private key parses");
        assert_eq!(
            signer.address(),
            custody,
            "custody key derives the shared address"
        );
        let td = key_add_typed_data(&payload, ETH_MAINNET_CHAIN_ID).unwrap();
        let rust_sig: Vec<u8> = signer
            .sign_hash_sync(&td.eip712_signing_hash().unwrap())
            .unwrap()
            .into();
        assert_eq!(
            &rust_sig[0..64],
            &body.custody_signature[0..64],
            "node and quorum-shared must produce identical r||s for the KeyAdd custody signature"
        );
    }
}
