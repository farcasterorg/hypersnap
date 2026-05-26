use crate::error::WalletError;
use hypersnap_crypto::bulletproofs::curve_adapter::Scalar;
use hypersnap_crypto::tokens::{schnorr_sign, Nullifier, PedersenCommitment};
use hypersnap_proto as proto;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

const LOCK_DST: &[u8] = b"hypersnap-conf-lock-v1";

pub fn derive_lock_id(nullifier: &[u8; 32]) -> [u8; 32] {
    let hash =
        alloy_primitives::keccak256([b"hypersnap-conf-lock-v1:" as &[u8], nullifier].concat());
    hash.0
}

pub fn build_confidential_lock(
    input_commitment: PedersenCommitment,
    input_blinding: Scalar,
    spend_secret: Scalar,
    amount: u64,
    fee_atoms: u64,
    destination_chain_id: u32,
    destination_address: Vec<u8>,
    chain_id: u64,
) -> Result<proto::HyperMessage, WalletError> {
    let mut rng = OsRng;
    let nullifier = Nullifier::derive(&spend_secret, &input_commitment);
    let lock_id = derive_lock_id(&nullifier.0);

    let output_blinding = Scalar::random(&mut rng);
    let output_commitment = PedersenCommitment::commit(amount + fee_atoms, &output_blinding);
    let blinding_diff = input_blinding - output_blinding;

    let input = proto::HyperTransferInput {
        commitment: input_commitment.to_bytes().to_vec(),
        nullifier: nullifier.0.to_vec(),
        spend_signature: Vec::new(),
    };
    let mut body = proto::ConfidentialLockBody {
        input: Some(input),
        amount,
        destination_chain_id,
        destination_address,
        blinding_diff_scalar: blinding_diff.to_bytes().to_vec(),
        range_proof: Vec::new(),
        fee_atoms,
    };

    let payload = confidential_lock_signing_payload(&body, chain_id);
    let payload_hash = {
        let mut h = Sha256::new();
        h.update(&payload);
        let digest = h.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        out
    };
    if let Some(ref mut inp) = body.input {
        inp.spend_signature = schnorr_sign(&spend_secret, &payload_hash, &mut rng)
            .to_bytes()
            .to_vec();
    }

    Ok(proto::HyperMessage {
        message_type: proto::HyperMessageType::ConfidentialLock as i32,
        body: Some(proto::hyper_message::Body::ConfidentialLock(body)),
    })
}

fn confidential_lock_signing_payload(body: &proto::ConfidentialLockBody, chain_id: u64) -> Vec<u8> {
    let mut buf = Vec::with_capacity(128);
    buf.extend_from_slice(LOCK_DST);
    buf.extend_from_slice(&chain_id.to_be_bytes());
    buf.extend_from_slice(&body.amount.to_be_bytes());
    buf.extend_from_slice(&body.destination_chain_id.to_be_bytes());
    buf.extend_from_slice(&(body.destination_address.len() as u32).to_be_bytes());
    buf.extend_from_slice(&body.destination_address);
    buf.extend_from_slice(&body.fee_atoms.to_be_bytes());
    if let Some(ref inp) = body.input {
        buf.extend_from_slice(&(inp.commitment.len() as u32).to_be_bytes());
        buf.extend_from_slice(&inp.commitment);
        buf.extend_from_slice(&(inp.nullifier.len() as u32).to_be_bytes());
        buf.extend_from_slice(&inp.nullifier);
    }
    buf
}
