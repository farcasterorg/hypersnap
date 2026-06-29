use crate::error::WalletError;
use ed25519_dalek::{Signer, SigningKey};
use hypersnap_proto as proto;

pub fn build_token_transfer(
    sender_fid: u64,
    recipient_fid: u64,
    amount: u64,
    nonce: u64,
    memo: Vec<u8>,
    signer: &SigningKey,
    chain_id: u64,
) -> Result<proto::HyperMessage, WalletError> {
    let pubkey = signer.verifying_key().to_bytes().to_vec();
    let mut body = proto::TokenTransferBody {
        sender_fid,
        recipient_fid,
        amount,
        nonce,
        signer_pubkey: pubkey,
        signature: Vec::new(),
        memo,
    };
    let payload = token_transfer_signing_payload(&body, chain_id);
    body.signature = signer.sign(&payload).to_bytes().to_vec();
    Ok(proto::HyperMessage {
        message_type: proto::HyperMessageType::TokenTransfer as i32,
        body: Some(proto::hyper_message::Body::TokenTransfer(body)),
    })
}

fn token_transfer_signing_payload(body: &proto::TokenTransferBody, chain_id: u64) -> Vec<u8> {
    const DST: &[u8] = b"hypersnap-token-transfer-v1";
    let mut buf =
        Vec::with_capacity(DST.len() + 8 * 5 + 2 + body.signer_pubkey.len() + 2 + body.memo.len());
    buf.extend_from_slice(DST);
    buf.extend_from_slice(&chain_id.to_be_bytes());
    buf.extend_from_slice(&body.sender_fid.to_be_bytes());
    buf.extend_from_slice(&body.recipient_fid.to_be_bytes());
    buf.extend_from_slice(&body.amount.to_be_bytes());
    buf.extend_from_slice(&body.nonce.to_be_bytes());
    buf.extend_from_slice(&(body.signer_pubkey.len() as u16).to_be_bytes());
    buf.extend_from_slice(&body.signer_pubkey);
    buf.extend_from_slice(&(body.memo.len() as u16).to_be_bytes());
    buf.extend_from_slice(&body.memo);
    buf
}
