use crate::error::WalletError;
use alloy_dyn_abi::TypedData;
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use ed25519_dalek::{Signer, SigningKey};
use hypersnap_proto as proto;
use serde_json::{json, Value};

const DST: &[u8] = b"hypersnap-validator-event-v4";

// EIP-712 domain — must match `crate::hyper::validator_registry`'s constants
// byte-for-byte, otherwise the prehash diverges and the on-node verifier
// rejects the signature.
const VALIDATOR_AUTH_EIP712_DOMAIN_NAME: &str = "Hypersnap";
const VALIDATOR_AUTH_EIP712_DOMAIN_VERSION: &str = "1";
const VALIDATOR_AUTH_EIP712_CHAIN_ID: u64 = 10;

pub fn build_validator_register(
    validator_key: &SigningKey,
    transport_pubkey: [u8; 32],
    validator_address: [u8; 20],
    fid: u64,
    registration_epoch: u64,
    custody_signature: Vec<u8>,
    libp2p_peer_id: Vec<u8>,
    operator_address: Vec<u8>,
) -> Result<proto::HyperMessage, WalletError> {
    let vk = validator_key.verifying_key().to_bytes().to_vec();
    let mut body = proto::HyperValidatorEventBody {
        event_type: proto::HyperValidatorEventType::Register as i32,
        validator_key: vk,
        transport_pubkey: transport_pubkey.to_vec(),
        registration_epoch,
        operator_address,
        signature: Vec::new(),
        fid,
        custody_signature,
        validator_address: validator_address.to_vec(),
        libp2p_peer_id,
    };
    let payload = validator_event_signing_payload(&body);
    body.signature = validator_key.sign(&payload).to_bytes().to_vec();

    Ok(proto::HyperMessage {
        message_type: proto::HyperMessageType::ValidatorRegister as i32,
        body: Some(proto::hyper_message::Body::ValidatorEvent(body)),
    })
}

pub fn build_validator_deregister(
    validator_key: &SigningKey,
    fid: u64,
    registration_epoch: u64,
) -> Result<proto::HyperMessage, WalletError> {
    let vk = validator_key.verifying_key().to_bytes().to_vec();
    let mut body = proto::HyperValidatorEventBody {
        event_type: proto::HyperValidatorEventType::Deregister as i32,
        validator_key: vk,
        transport_pubkey: Vec::new(),
        registration_epoch,
        operator_address: Vec::new(),
        signature: Vec::new(),
        fid,
        custody_signature: Vec::new(),
        validator_address: Vec::new(),
        libp2p_peer_id: Vec::new(),
    };
    let payload = validator_event_signing_payload(&body);
    body.signature = validator_key.sign(&payload).to_bytes().to_vec();

    Ok(proto::HyperMessage {
        message_type: proto::HyperMessageType::ValidatorDeregister as i32,
        body: Some(proto::hyper_message::Body::ValidatorEvent(body)),
    })
}

/// Build the EIP-712 typed data for the validator-authorization payload,
/// matching `validator_authorization_typed_data` in
/// `src/hyper/validator_registry.rs` byte-for-byte.
fn validator_authorization_typed_data_json(event: &proto::HyperValidatorEventBody) -> Value {
    let mut validator_key_hex = String::with_capacity(2 + 64);
    validator_key_hex.push_str("0x");
    validator_key_hex.push_str(&hex::encode(&event.validator_key));

    let mut transport_hex = String::with_capacity(2 + 64);
    transport_hex.push_str("0x");
    transport_hex.push_str(&hex::encode(&event.transport_pubkey));

    let mut validator_address_hex = String::with_capacity(2 + event.validator_address.len() * 2);
    validator_address_hex.push_str("0x");
    validator_address_hex.push_str(&hex::encode(&event.validator_address));

    json!({
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"},
            ],
            "ValidatorAuthorization": [
                {"name": "fid", "type": "uint256"},
                {"name": "validator_key", "type": "bytes32"},
                {"name": "transport_pubkey", "type": "bytes32"},
                {"name": "event_type", "type": "uint8"},
                {"name": "registration_epoch", "type": "uint256"},
                {"name": "validator_address", "type": "bytes"},
            ],
        },
        "primaryType": "ValidatorAuthorization",
        "domain": {
            "name": VALIDATOR_AUTH_EIP712_DOMAIN_NAME,
            "version": VALIDATOR_AUTH_EIP712_DOMAIN_VERSION,
            "chainId": VALIDATOR_AUTH_EIP712_CHAIN_ID,
        },
        "message": {
            "fid": event.fid.to_string(),
            "validator_key": validator_key_hex,
            "transport_pubkey": transport_hex,
            "event_type": event.event_type as u32,
            "registration_epoch": event.registration_epoch.to_string(),
            "validator_address": validator_address_hex,
        },
    })
}

/// Build a ValidatorRegister hyper message and auto-sign its EIP-712
/// custody payload with the supplied secp256k1 private key. Returned
/// message is identical to what `build_validator_register` produces,
/// but the caller does not have to precompute the 65-byte custody
/// signature out-of-band.
///
/// `custody_secret_bytes` is the raw 32-byte secp256k1 private key
/// (e.g. the contents of `nodes/{i}/custody.key` produced by
/// `setup_local_testnet --seed-validator-fids`).
pub fn build_validator_register_with_custody(
    validator_key: &SigningKey,
    transport_pubkey: [u8; 32],
    validator_address: [u8; 20],
    fid: u64,
    registration_epoch: u64,
    custody_secret_bytes: &[u8; 32],
    libp2p_peer_id: Vec<u8>,
    operator_address: Vec<u8>,
) -> Result<proto::HyperMessage, WalletError> {
    let signer = PrivateKeySigner::from_slice(custody_secret_bytes)
        .map_err(|e| WalletError::InvalidKey(e.to_string()))?;

    // Build the unsigned event so we can hash its EIP-712 prehash.
    // `signature` and `custody_signature` are filled in after.
    let vk = validator_key.verifying_key().to_bytes().to_vec();
    let unsigned = proto::HyperValidatorEventBody {
        event_type: proto::HyperValidatorEventType::Register as i32,
        validator_key: vk.clone(),
        transport_pubkey: transport_pubkey.to_vec(),
        registration_epoch,
        operator_address: operator_address.clone(),
        signature: Vec::new(),
        fid,
        custody_signature: Vec::new(),
        validator_address: validator_address.to_vec(),
        libp2p_peer_id: libp2p_peer_id.clone(),
    };

    let typed_json = validator_authorization_typed_data_json(&unsigned);
    let typed: TypedData = serde_json::from_value(typed_json)
        .map_err(|e| WalletError::InvalidKey(format!("typed-data parse: {e}")))?;
    let prehash = typed
        .eip712_signing_hash()
        .map_err(|e| WalletError::InvalidKey(format!("eip712 prehash: {e}")))?;
    let sig = signer
        .sign_hash_sync(&prehash)
        .map_err(|e| WalletError::InvalidKey(format!("custody sign: {e}")))?;
    let custody_signature: Vec<u8> = sig.into();

    build_validator_register(
        validator_key,
        transport_pubkey,
        validator_address,
        fid,
        registration_epoch,
        custody_signature,
        libp2p_peer_id,
        operator_address,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_signer_local::PrivateKeySigner;

    /// Production-grade transport-pubkey derivation: the X25519 public
    /// half computed from a 32-byte secret must match what the node's
    /// `TransportSecretKey::from_bytes(...).public_bytes()` produces
    /// from the same secret. This is the contract the wallet's
    /// `--transport-secret-file` path relies on — both sides read the
    /// same bytes off disk and must agree on the announced pubkey.
    #[test]
    fn transport_pubkey_derivation_matches_node_side() {
        use hypersnap_crypto::transport_encrypt::TransportSecretKey;
        let secret: [u8; 32] = [0x42; 32];
        let pubkey = TransportSecretKey::from_bytes(secret).public_bytes();
        // Reference value via direct x25519_dalek::PublicKey::from(secret_bytes).
        // We re-derive it independently here so any drift between the
        // crypto-crate helper and the canonical x25519 derivation is
        // visible.
        let reference =
            x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(secret)).to_bytes();
        assert_eq!(pubkey, reference);
    }

    /// Round-trip: build a register message with a freshly-generated
    /// secp256k1 custody key, then independently re-derive the EIP-712
    /// prehash and recover the signer address from the embedded
    /// 65-byte custody signature. The recovered address must equal
    /// `signer.address()` — which is what the on-node
    /// `verify_custody_signature` checks against the resolver-supplied
    /// custody address.
    #[test]
    fn build_validator_register_with_custody_recovers_signer_address() {
        let validator_sk = ed25519_dalek::SigningKey::from_bytes(&[0x11; 32]);
        let custody = PrivateKeySigner::random();
        let custody_secret_arr: [u8; 32] = custody.to_bytes().into();
        let expected_addr: alloy_primitives::Address = custody.address();

        let transport_pk = [0x22u8; 32];
        let validator_addr = [0x33u8; 20];
        let fid = 7;
        let epoch = 4;

        let msg = build_validator_register_with_custody(
            &validator_sk,
            transport_pk,
            validator_addr,
            fid,
            epoch,
            &custody_secret_arr,
            Vec::new(),
            Vec::new(),
        )
        .expect("build_validator_register_with_custody");
        let body = match msg.body {
            Some(proto::hyper_message::Body::ValidatorEvent(b)) => b,
            _ => panic!("expected ValidatorEvent body"),
        };

        assert_eq!(body.custody_signature.len(), 65);

        // Reconstruct typed-data prehash + recover.
        let typed_json = validator_authorization_typed_data_json(&body);
        let typed: TypedData = serde_json::from_value(typed_json).unwrap();
        let prehash = typed.eip712_signing_hash().unwrap();

        let v_byte = body.custody_signature[64];
        let parity = v_byte != 0x1b && v_byte != 0x00;
        let sig = alloy_primitives::PrimitiveSignature::from_bytes_and_parity(
            &body.custody_signature[0..64],
            parity,
        );
        let recovered = sig.recover_address_from_prehash(&prehash).expect("recover");
        assert_eq!(recovered, expected_addr);
    }
}

fn validator_event_signing_payload(event: &proto::HyperValidatorEventBody) -> Vec<u8> {
    let mut buf = Vec::with_capacity(
        DST.len()
            + 4
            + event.validator_key.len()
            + 2
            + event.transport_pubkey.len()
            + 8
            + 2
            + event.operator_address.len()
            + 8
            + 2
            + event.validator_address.len()
            + 2
            + event.libp2p_peer_id.len(),
    );
    buf.extend_from_slice(DST);
    buf.extend_from_slice(&event.event_type.to_be_bytes());
    buf.extend_from_slice(&event.validator_key);
    buf.extend_from_slice(&(event.transport_pubkey.len() as u16).to_be_bytes());
    buf.extend_from_slice(&event.transport_pubkey);
    buf.extend_from_slice(&event.registration_epoch.to_be_bytes());
    buf.extend_from_slice(&(event.operator_address.len() as u16).to_be_bytes());
    buf.extend_from_slice(&event.operator_address);
    buf.extend_from_slice(&event.fid.to_be_bytes());
    buf.extend_from_slice(&(event.validator_address.len() as u16).to_be_bytes());
    buf.extend_from_slice(&event.validator_address);
    buf.extend_from_slice(&(event.libp2p_peer_id.len() as u16).to_be_bytes());
    buf.extend_from_slice(&event.libp2p_peer_id);
    buf
}
