use crate::error::WalletError;
use ed25519_dalek::{Signer, SigningKey};
use hypersnap_proto as proto;

pub fn build_fee_deposit(
    sender_fid: u64,
    amount: u64,
    nonce: u64,
    signer: &SigningKey,
    chain_id: u64,
) -> Result<proto::HyperMessage, WalletError> {
    let pubkey = signer.verifying_key().to_bytes().to_vec();
    let mut body = proto::FeeDepositBody {
        sender_fid,
        amount,
        nonce,
        signer_pubkey: pubkey,
        signature: Vec::new(),
    };
    let payload = fee_deposit_signing_payload(&body, chain_id);
    body.signature = signer.sign(&payload).to_bytes().to_vec();
    Ok(proto::HyperMessage {
        message_type: proto::HyperMessageType::FeeDeposit as i32,
        body: Some(proto::hyper_message::Body::FeeDeposit(body)),
    })
}

fn fee_deposit_signing_payload(body: &proto::FeeDepositBody, chain_id: u64) -> Vec<u8> {
    const DST: &[u8] = b"hypersnap-fee-deposit-v1";
    let mut buf = Vec::with_capacity(DST.len() + 8 * 4 + 2 + body.signer_pubkey.len());
    buf.extend_from_slice(DST);
    buf.extend_from_slice(&chain_id.to_be_bytes());
    buf.extend_from_slice(&body.sender_fid.to_be_bytes());
    buf.extend_from_slice(&body.amount.to_be_bytes());
    buf.extend_from_slice(&body.nonce.to_be_bytes());
    buf.extend_from_slice(&(body.signer_pubkey.len() as u16).to_be_bytes());
    buf.extend_from_slice(&body.signer_pubkey);
    buf
}
