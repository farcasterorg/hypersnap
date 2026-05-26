use crate::error::WalletError;
use ed25519_dalek::{Signer, SigningKey};
use hypersnap_proto as proto;

const DST: &[u8] = b"hypersnap-app-receipt-v2\x00\x00\x00\x00\x00\x00\x00\x00\x00";

pub fn build_app_receipt(
    miniapp_id: [u8; 16],
    user_fid: u64,
    app_owner_fid: u64,
    action_type: &str,
    timestamp: u64,
    nonce: u64,
    epoch: u64,
    user_signer: &SigningKey,
    chain_id: u64,
) -> Result<proto::HyperMessage, WalletError> {
    let pubkey = user_signer.verifying_key().to_bytes().to_vec();
    let action_bytes = action_type.as_bytes();
    let mut body = proto::AppUsageReceiptBody {
        miniapp_id: miniapp_id.to_vec(),
        user_fid,
        app_owner_fid,
        action_type: action_type.to_string(),
        timestamp,
        nonce,
        epoch,
        user_signer_pubkey: pubkey.clone(),
        user_signature: Vec::new(),
    };
    let payload = app_receipt_signing_payload(&body, chain_id);
    body.user_signature = user_signer.sign(&payload).to_bytes().to_vec();

    Ok(proto::HyperMessage {
        message_type: proto::HyperMessageType::AppUsageReceipt as i32,
        body: Some(proto::hyper_message::Body::AppUsageReceipt(body)),
    })
}

fn app_receipt_signing_payload(body: &proto::AppUsageReceiptBody, chain_id: u64) -> Vec<u8> {
    let action_bytes = body.action_type.as_bytes();
    let mut buf =
        Vec::with_capacity(DST.len() + 8 + 16 + 8 + 8 + 8 + 8 + 8 + 2 + action_bytes.len() + 32);
    buf.extend_from_slice(DST);
    buf.extend_from_slice(&chain_id.to_be_bytes());
    buf.extend_from_slice(&body.miniapp_id);
    buf.extend_from_slice(&body.user_fid.to_be_bytes());
    buf.extend_from_slice(&body.app_owner_fid.to_be_bytes());
    buf.extend_from_slice(&body.timestamp.to_be_bytes());
    buf.extend_from_slice(&body.nonce.to_be_bytes());
    buf.extend_from_slice(&body.epoch.to_be_bytes());
    buf.extend_from_slice(&(action_bytes.len() as u16).to_be_bytes());
    buf.extend_from_slice(action_bytes);
    buf.extend_from_slice(&body.user_signer_pubkey);
    buf
}
