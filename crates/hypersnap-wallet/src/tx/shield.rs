use crate::error::WalletError;
use ed25519_dalek::{Signer, SigningKey};
use hypersnap_crypto::bulletproofs::curve_adapter::Scalar;
use hypersnap_crypto::tokens::{
    create_stealth_output, point_to_compressed_bytes, PedersenCommitment, StealthPublicAddress,
};
use hypersnap_proto as proto;
use rand::rngs::OsRng;

const SHIELD_DST: &[u8] = b"hypersnap-shield-v1\x00\x00\x00\x00\x00";

pub fn build_shield(
    sender_fid: u64,
    amount: u64,
    nonce: u64,
    signer: &SigningKey,
    recipient: &StealthPublicAddress,
    chain_id: u64,
) -> Result<proto::HyperMessage, WalletError> {
    let mut rng = OsRng;
    let blinding = Scalar::random(&mut rng);
    let commitment = PedersenCommitment::commit(amount, &blinding);
    let stealth_out = create_stealth_output(recipient, &mut rng);
    let commitment_bytes = commitment.to_bytes();
    let otp_bytes = point_to_compressed_bytes(&stealth_out.one_time_pubkey);
    let blinding_bytes = blinding.to_bytes();

    let output = proto::HyperTransferOutput {
        commitment: commitment_bytes.to_vec(),
        one_time_pubkey: otp_bytes.to_vec(),
        range_proof: blinding_bytes.to_vec(),
    };
    let pubkey = signer.verifying_key().to_bytes().to_vec();
    let mut body = proto::ShieldBody {
        sender_fid,
        amount,
        nonce,
        signer_pubkey: pubkey,
        signature: Vec::new(),
        output: Some(output),
    };
    let payload = shield_signing_payload(&body, chain_id);
    body.signature = signer.sign(&payload).to_bytes().to_vec();

    Ok(proto::HyperMessage {
        message_type: proto::HyperMessageType::Shield as i32,
        body: Some(proto::hyper_message::Body::Shield(body)),
    })
}

fn shield_signing_payload(body: &proto::ShieldBody, chain_id: u64) -> Vec<u8> {
    let mut buf = Vec::with_capacity(SHIELD_DST.len() + 8 * 4 + 2 + 32 + 56 * 3);
    buf.extend_from_slice(SHIELD_DST);
    buf.extend_from_slice(&chain_id.to_be_bytes());
    buf.extend_from_slice(&body.sender_fid.to_be_bytes());
    buf.extend_from_slice(&body.amount.to_be_bytes());
    buf.extend_from_slice(&body.nonce.to_be_bytes());
    buf.extend_from_slice(&(body.signer_pubkey.len() as u16).to_be_bytes());
    buf.extend_from_slice(&body.signer_pubkey);
    if let Some(ref out) = body.output {
        buf.extend_from_slice(&out.commitment);
        buf.extend_from_slice(&out.one_time_pubkey);
        buf.extend_from_slice(&out.range_proof);
    }
    buf
}
