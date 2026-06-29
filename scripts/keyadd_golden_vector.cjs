/**
 * keyadd_golden_vector.cjs — cross-implementation KEY_ADD golden-vector generator.
 *
 * Drives the REAL @quilibrium/quorum-shared package (the mobile client lib) with
 * fixed inputs and emits a self-contained Rust test into the hypersnap repo that
 * runs quorum-shared's actual serialization + signatures through hypersnap's own
 * validators. If they ever diverge, the hub would 200 the POST but silently drop
 * the forwarded KEY_ADD at merge time — the "signer never shows up" bug.
 *
 * Run from the quorum-mobile repo root (so node resolves quorum-shared + @noble):
 *   node scripts/keyadd_golden_vector.cjs
 * Output Rust file (override with HYPERSNAP_DIR):
 *   $HYPERSNAP_DIR/src/core/validations/key_quorum_shared_compat_test.rs
 */
const fs = require('fs');
const path = require('path');
const Module = require('module');
const origLoad = Module._load;
const builtins = new Set(require('module').builtinModules);
function makeStub() {
  const f = function () { return makeStub(); };
  return new Proxy(f, { get: (_t, p) => (p === '__esModule' ? true : makeStub()), apply: () => makeStub(), construct: () => makeStub() });
}
// quorum-shared's CJS bundle eagerly imports UI/util deps (clsx, multiformats, …)
// at load time; none are on the KEY_ADD path. Allow the real crypto libs through,
// stub the rest so the package loads and the actual functions run untouched.
Module._load = function (request) {
  if (request.startsWith('@noble') || request.startsWith('@scure') || request.startsWith('.') ||
      request.startsWith('/') || builtins.has(request) || builtins.has(request.replace(/^node:/, ''))) {
    return origLoad.apply(this, arguments);
  }
  try { return origLoad.apply(this, arguments); }
  catch (e) { if (e && (e.code === 'MODULE_NOT_FOUND' || e.code === 'ERR_PACKAGE_PATH_NOT_EXPORTED')) return makeStub(); throw e; }
};

const qs = require('@quilibrium/quorum-shared');
const { ed25519 } = require('@noble/curves/ed25519.js');
const { secp256k1 } = require('@noble/curves/secp256k1.js');
const { HDKey } = require('@scure/bip32');
const bip39 = require('@scure/bip39');
const { keccak_256 } = require('@noble/hashes/sha3.js');

const hex = (u8) => Buffer.from(u8).toString('hex');
const fromHex = (h) => Uint8Array.from(Buffer.from(h.replace(/^0x/, ''), 'hex'));

// ---- shared seed phrase + custody key (Foundry's well-known test mnemonic) ----
const MNEMONIC = 'test test test test test test test test test test test junk';
const CUSTODY_PRIV_HEX = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80';
const seed = bip39.mnemonicToSeedSync(MNEMONIC);
const custodyPriv = HDKey.fromMasterSeed(seed).derive("m/44'/60'/0'/0/0").privateKey;
if (hex(custodyPriv) !== CUSTODY_PRIV_HEX.slice(2)) throw new Error('custody derivation drift: ' + hex(custodyPriv));
const custodyAddress = '0x' + hex(keccak_256(secp256k1.getPublicKey(custodyPriv, false).slice(1)).slice(12));

// ---- fixed signer + params ----
const signerPriv = fromHex('1111111111111111111111111111111111111111111111111111111111111111');
const signerPub = ed25519.getPublicKey(signerPriv);
const FID = 1234, NONCE = 1700000000, DEADLINE = 1893456000, TTL = 86400, TIMESTAMP = 100000000, NETWORK = 1;
const SCOPES = [1, 2, 3, 4, 5, 6, 7, 8, 11, 12, 13, 14, 15];

// ---- build via the real package, mirroring submitKeyAdd() ----
const { metadata } = qs.buildSignedKeyRequestMetadata({ requestFid: FID, signerPublicKey: signerPub, deadline: DEADLINE, custodyPrivateKey: custodyPriv });
const keyAddDigest = qs.keyAddDigest({ fid: FID, key: signerPub, keyType: 1, scopes: SCOPES, ttl: TTL, nonce: NONCE, deadline: DEADLINE });
const custodySignature = qs.signEip712Digest(keyAddDigest, custodyPriv);
const dataBytes = qs.encodeMessageData({ type: 16, fid: FID, timestamp: TIMESTAMP, network: NETWORK,
  body: { keyAddBody: { key: signerPub, keyType: 1, custodySignature, deadline: DEADLINE, nonce: NONCE, metadata, metadataType: 1, scopes: SCOPES, ttl: TTL } } });
const msgHash = qs.blake3_20(dataBytes);
const envSignature = ed25519.sign(msgHash, signerPriv);
const envelope = qs.encodeMessageEnvelope({ dataBytes, hash: msgHash, signature: envSignature, signatureScheme: 1, signer: signerPub });

const rust = `//! Cross-implementation KEY_ADD compatibility test — GENERATED, do not hand-edit.
//!
//! Regenerate with (from the quorum-mobile repo root):
//!     node scripts/keyadd_golden_vector.cjs
//!
//! A KEY_ADD constructed + signed by the mobile client library
//! (\`@quilibrium/quorum-shared\`) MUST validate under this node's own validators.
//! If the client's protobuf serialization, EIP-712 digests, ABI metadata, or
//! signatures diverged from what the validator expects, the gateway would accept
//! the POST (envelope-level checks pass) but the forwarded message would be
//! silently dropped at \`merge_key_add\` time — the "client thinks it succeeded but
//! the signer never appears" symptom.
//!
//! Shared seed phrase on both sides:
//!   mnemonic "${MNEMONIC}"
//!   custody  m/44'/60'/0'/0/0  => ${custodyAddress}
//!   signer   ed25519 priv = 0x11 * 32
//!   fid=${FID} nonce=${NONCE} deadline=${DEADLINE} ttl=${TTL} ts=${TIMESTAMP} net=${NETWORK}
//!   scopes=[${SCOPES.join(', ')}]

use alloy_primitives::Address;
use prost::Message as _;

use crate::core::validations::key::{
    key_add_typed_data, recover_key_add_custody_address, validate_key_add_body,
    verify_signed_key_request_metadata, KeyAddPayload, ETH_MAINNET_CHAIN_ID,
};
use crate::core::validations::message::validate_message_hash;
use crate::proto::{self, message_data::Body, HashScheme, MessageData, MessageType, SignatureScheme};

const CUSTODY_ADDR: &str = "${custodyAddress}";
const CUSTODY_PRIV: &str = "${CUSTODY_PRIV_HEX}";
const SIGNER_PUB_HEX: &str = "${hex(signerPub)}";
const ENVELOPE_HEX: &str = "${hex(envelope)}";
const DATA_BYTES_HEX: &str = "${hex(dataBytes)}";
const KEY_ADD_DIGEST_HEX: &str = "${hex(keyAddDigest)}";

const FID: u64 = ${FID};
const NONCE: u32 = ${NONCE};
const DEADLINE: u32 = ${DEADLINE};
const TTL: u32 = ${TTL};
const TIMESTAMP: u32 = ${TIMESTAMP};
const SCOPES: [i32; ${SCOPES.length}] = [${SCOPES.join(', ')}];

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
    assert_eq!(msg.signer, signer_pub, "envelope signer == ed25519 public key");
    assert_eq!(msg.signature.len(), 64, "ed25519 signature is 64 bytes");
    let data_bytes = msg.data_bytes.clone().expect("data_bytes present on envelope");
    assert_eq!(data_bytes, data_bytes_expected, "data_bytes byte-identical to golden");

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
    assert_eq!(md.r#type, MessageType::KeyAdd as i32, "message type is KEY_ADD");
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
        assert_eq!(signer.address(), custody, "custody key derives the shared address");
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
`;

const outDir = path.join(process.env.HYPERSNAP_DIR || path.join(process.env.HOME, 'src/hypersnap'), 'src/core/validations');
const outFile = path.join(outDir, 'key_quorum_shared_compat_test.rs');
fs.writeFileSync(outFile, rust);
console.log('custodyAddress =', custodyAddress);
console.log('wrote', outFile, '(' + rust.length + ' bytes)');
