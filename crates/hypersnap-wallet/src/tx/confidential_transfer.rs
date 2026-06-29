use crate::error::WalletError;
use hypersnap_crypto::bulletproofs::curve_adapter::Scalar;
use hypersnap_crypto::tokens::{
    create_stealth_output, prove_value_range, schnorr_sign, Nullifier, PedersenCommitment,
    StealthPublicAddress, TransferInput, TransferOutput, TransferTx, DEFAULT_RANGE_BITS,
};
use hypersnap_proto as proto;
use prost::Message;
use rand::rngs::OsRng;

pub struct ConfidentialInput {
    pub commitment: PedersenCommitment,
    pub blinding: Scalar,
    pub value: u64,
    pub spend_secret: Scalar,
}

pub struct ConfidentialOutput {
    pub value: u64,
    pub recipient: StealthPublicAddress,
}

pub fn build_confidential_transfer(
    inputs: Vec<ConfidentialInput>,
    outputs: Vec<ConfidentialOutput>,
    fee_atoms: u64,
) -> Result<proto::HyperMessage, WalletError> {
    let mut rng = OsRng;
    let mut tx_inputs = Vec::with_capacity(inputs.len());
    let mut input_blindings_sum = Scalar::zero();
    for inp in &inputs {
        let nullifier = Nullifier::derive(&inp.spend_secret, &inp.commitment);
        let payload = [0u8; 32]; // signing payload placeholder — will be replaced
        let sig = schnorr_sign(&inp.spend_secret, &payload, &mut rng);
        input_blindings_sum = input_blindings_sum + inp.blinding;
        tx_inputs.push(TransferInput {
            commitment: inp.commitment,
            nullifier,
            spend_signature: sig,
        });
    }

    let mut tx_outputs = Vec::with_capacity(outputs.len());
    let mut output_pubkeys = Vec::with_capacity(outputs.len());
    let mut output_blindings_sum = Scalar::zero();
    for out in &outputs {
        let blinding = Scalar::random(&mut rng);
        let commitment = PedersenCommitment::commit(out.value, &blinding);
        let (range_proof, _) =
            prove_value_range(out.value, &blinding, DEFAULT_RANGE_BITS, &mut rng)
                .map_err(|e| WalletError::Crypto(format!("range proof: {e}")))?;
        output_blindings_sum = output_blindings_sum + blinding;
        let stealth = create_stealth_output(&out.recipient, &mut rng);
        output_pubkeys.push(stealth.one_time_pubkey);
        tx_outputs.push(TransferOutput {
            commitment,
            range_proof,
        });
    }

    let blinding_diff = input_blindings_sum - output_blindings_sum;
    let tx = TransferTx {
        inputs: tx_inputs,
        outputs: tx_outputs,
        fee_atoms,
    };

    // Re-sign inputs with the real signing payload
    let payload = tx.signing_payload();
    let mut tx_resigned = tx;
    for (i, inp) in inputs.iter().enumerate() {
        tx_resigned.inputs[i].spend_signature = schnorr_sign(&inp.spend_secret, &payload, &mut rng);
    }

    let tx_proto = tx_to_proto(&tx_resigned, &blinding_diff, &output_pubkeys);
    Ok(proto::HyperMessage {
        message_type: proto::HyperMessageType::Transfer as i32,
        body: Some(proto::hyper_message::Body::Transfer(tx_proto)),
    })
}

fn tx_to_proto(
    tx: &TransferTx,
    blinding_diff: &Scalar,
    output_pubkeys: &[hypersnap_crypto::bulletproofs::curve_adapter::Point],
) -> proto::HyperTransferTx {
    use hypersnap_crypto::tokens::point_to_compressed_bytes;
    let inputs = tx
        .inputs
        .iter()
        .map(|inp| proto::HyperTransferInput {
            commitment: inp.commitment.to_bytes().to_vec(),
            nullifier: inp.nullifier.0.to_vec(),
            spend_signature: inp.spend_signature.to_bytes().to_vec(),
        })
        .collect();
    let outputs = tx
        .outputs
        .iter()
        .enumerate()
        .map(|(i, out)| {
            let mut proto_out = proto::HyperTransferOutput {
                commitment: out.commitment.to_bytes().to_vec(),
                range_proof: out.range_proof.clone(),
                one_time_pubkey: Vec::new(),
            };
            if let Some(pk) = output_pubkeys.get(i) {
                proto_out.one_time_pubkey = point_to_compressed_bytes(pk).to_vec();
            }
            proto_out
        })
        .collect();
    proto::HyperTransferTx {
        inputs,
        outputs,
        fee_atoms: tx.fee_atoms,
        blinding_diff_scalar: blinding_diff.to_bytes().to_vec(),
    }
}
