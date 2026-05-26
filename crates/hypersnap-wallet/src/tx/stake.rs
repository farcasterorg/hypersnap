use crate::error::WalletError;
use ed25519_dalek::{Signer, SigningKey};
use hypersnap_proto as proto;

const STAKE_DST: &[u8] = b"hypersnap-token-stake-v2\x00\x00\x00\x00\x00";
const UNSTAKE_DST: &[u8] = b"hypersnap-token-unstake-v2\x00\x00\x00";

pub fn build_token_stake(
    fid: u64,
    amount: u64,
    stake_type: i32,
    nonce: u64,
    vouchee_fid: u64,
    signer: &SigningKey,
    chain_id: u64,
) -> Result<proto::HyperMessage, WalletError> {
    let pubkey = signer.verifying_key().to_bytes().to_vec();
    let mut body = proto::TokenStakeBody {
        fid,
        amount,
        stake_type,
        nonce,
        vouchee_fid,
        signer_pubkey: pubkey,
        signature: Vec::new(),
    };
    let payload = token_stake_signing_payload(&body, chain_id);
    body.signature = signer.sign(&payload).to_bytes().to_vec();
    Ok(proto::HyperMessage {
        message_type: proto::HyperMessageType::TokenStake as i32,
        body: Some(proto::hyper_message::Body::TokenStake(body)),
    })
}

pub fn build_token_unstake(
    fid: u64,
    amount: u64,
    stake_type: i32,
    nonce: u64,
    vouchee_fid: u64,
    signer: &SigningKey,
    chain_id: u64,
) -> Result<proto::HyperMessage, WalletError> {
    let pubkey = signer.verifying_key().to_bytes().to_vec();
    let mut body = proto::TokenUnstakeBody {
        fid,
        amount,
        stake_type,
        nonce,
        vouchee_fid,
        signer_pubkey: pubkey,
        signature: Vec::new(),
    };
    let payload = token_unstake_signing_payload(&body, chain_id);
    body.signature = signer.sign(&payload).to_bytes().to_vec();
    Ok(proto::HyperMessage {
        message_type: proto::HyperMessageType::TokenUnstake as i32,
        body: Some(proto::hyper_message::Body::TokenUnstake(body)),
    })
}

fn token_stake_signing_payload(body: &proto::TokenStakeBody, chain_id: u64) -> Vec<u8> {
    let mut buf =
        Vec::with_capacity(STAKE_DST.len() + 8 + 8 + 8 + 1 + 8 + 8 + body.signer_pubkey.len());
    buf.extend_from_slice(STAKE_DST);
    buf.extend_from_slice(&chain_id.to_be_bytes());
    buf.extend_from_slice(&body.fid.to_be_bytes());
    buf.extend_from_slice(&body.amount.to_be_bytes());
    buf.push(body.stake_type as u8);
    buf.extend_from_slice(&body.nonce.to_be_bytes());
    buf.extend_from_slice(&body.vouchee_fid.to_be_bytes());
    buf.extend_from_slice(&body.signer_pubkey);
    buf
}

fn token_unstake_signing_payload(body: &proto::TokenUnstakeBody, chain_id: u64) -> Vec<u8> {
    let mut buf =
        Vec::with_capacity(UNSTAKE_DST.len() + 8 + 8 + 8 + 1 + 8 + 8 + body.signer_pubkey.len());
    buf.extend_from_slice(UNSTAKE_DST);
    buf.extend_from_slice(&chain_id.to_be_bytes());
    buf.extend_from_slice(&body.fid.to_be_bytes());
    buf.extend_from_slice(&body.amount.to_be_bytes());
    buf.push(body.stake_type as u8);
    buf.extend_from_slice(&body.nonce.to_be_bytes());
    buf.extend_from_slice(&body.vouchee_fid.to_be_bytes());
    buf.extend_from_slice(&body.signer_pubkey);
    buf
}
