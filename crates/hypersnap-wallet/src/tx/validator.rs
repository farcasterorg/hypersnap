use crate::error::WalletError;
use ed25519_dalek::{Signer, SigningKey};
use hypersnap_proto as proto;

const DST: &[u8] = b"hypersnap-validator-event-v4";

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
