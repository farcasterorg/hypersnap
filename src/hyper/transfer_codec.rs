//! Wire-format conversions between `proto::HyperTransfer*` and the
//! `hypersnap_crypto::tokens` Rust types.
//!
//! Lives in the snapchain crate (not hypersnap-crypto) so the crypto crate
//! stays free of proto/snapchain dependencies. The orphan rule prevents
//! `impl From` between two foreign types, so these are free functions; the
//! ergonomics are essentially the same.

use crate::proto;
use hypersnap_crypto::tokens::{
    Nullifier, PedersenCommitment, SchnorrSignature, TransferInput, TransferOutput, TransferTx,
};

#[derive(thiserror::Error, Debug, PartialEq)]
pub enum TransferCodecError {
    #[error("invalid commitment bytes (must be 56-byte canonical Decaf448)")]
    BadCommitment,
    #[error("nullifier must be exactly 32 bytes (got {0})")]
    BadNullifierLength(usize),
    #[error("spend signature bytes must be exactly 112 (got {0})")]
    BadSignatureLength(usize),
    #[error("invalid spend signature (R or s not canonical)")]
    BadSignature,
}

pub fn input_to_proto(t: &TransferInput) -> proto::HyperTransferInput {
    proto::HyperTransferInput {
        commitment: t.commitment.to_bytes().to_vec(),
        nullifier: t.nullifier.0.to_vec(),
        spend_signature: t.spend_signature.to_bytes().to_vec(),
    }
}

pub fn input_from_proto(
    p: &proto::HyperTransferInput,
) -> Result<TransferInput, TransferCodecError> {
    let commitment =
        PedersenCommitment::from_bytes(&p.commitment).ok_or(TransferCodecError::BadCommitment)?;
    if p.nullifier.len() != 32 {
        return Err(TransferCodecError::BadNullifierLength(p.nullifier.len()));
    }
    let mut nf = [0u8; 32];
    nf.copy_from_slice(&p.nullifier);

    if p.spend_signature.len() != 112 {
        return Err(TransferCodecError::BadSignatureLength(
            p.spend_signature.len(),
        ));
    }
    let spend_signature =
        SchnorrSignature::from_bytes(&p.spend_signature).ok_or(TransferCodecError::BadSignature)?;

    Ok(TransferInput {
        commitment,
        nullifier: Nullifier(nf),
        spend_signature,
    })
}

pub fn output_to_proto(t: &TransferOutput) -> proto::HyperTransferOutput {
    proto::HyperTransferOutput {
        commitment: t.commitment.to_bytes().to_vec(),
        range_proof: t.range_proof.clone(),
    }
}

pub fn output_from_proto(
    p: &proto::HyperTransferOutput,
) -> Result<TransferOutput, TransferCodecError> {
    let commitment =
        PedersenCommitment::from_bytes(&p.commitment).ok_or(TransferCodecError::BadCommitment)?;
    Ok(TransferOutput {
        commitment,
        range_proof: p.range_proof.clone(),
    })
}

pub fn tx_to_proto(t: &TransferTx) -> proto::HyperTransferTx {
    proto::HyperTransferTx {
        inputs: t.inputs.iter().map(input_to_proto).collect(),
        outputs: t.outputs.iter().map(output_to_proto).collect(),
        fee_atoms: t.fee_atoms,
    }
}

pub fn tx_from_proto(p: &proto::HyperTransferTx) -> Result<TransferTx, TransferCodecError> {
    let mut inputs = Vec::with_capacity(p.inputs.len());
    for i in &p.inputs {
        inputs.push(input_from_proto(i)?);
    }
    let mut outputs = Vec::with_capacity(p.outputs.len());
    for o in &p.outputs {
        outputs.push(output_from_proto(o)?);
    }
    Ok(TransferTx {
        inputs,
        outputs,
        fee_atoms: p.fee_atoms,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use hypersnap_crypto::bulletproofs::curve_adapter::Scalar;
    use hypersnap_crypto::tokens::{prove_value_range, schnorr_sign, DEFAULT_RANGE_BITS};
    use prost::Message;
    use rand::rngs::OsRng;

    fn make_test_transfer() -> TransferTx {
        let mut rng = OsRng;
        let r_in = Scalar::random(&mut rng);
        let r_out = Scalar::random(&mut rng);
        let x = Scalar::random(&mut rng);

        let in_commitment = PedersenCommitment::commit(100, &r_in);
        let nullifier = Nullifier::derive(&x, &in_commitment);
        let spend_signature = schnorr_sign(&x, &[0u8; 32], &mut rng);

        let out_commitment = PedersenCommitment::commit(100, &r_out);
        let (range_proof, _) =
            prove_value_range(100, &r_out, DEFAULT_RANGE_BITS, &mut rng).unwrap();

        TransferTx {
            inputs: vec![TransferInput {
                commitment: in_commitment,
                nullifier,
                spend_signature,
            }],
            outputs: vec![TransferOutput {
                commitment: out_commitment,
                range_proof,
            }],
            fee_atoms: 7,
        }
    }

    #[test]
    fn input_round_trip() {
        let original = make_test_transfer().inputs.into_iter().next().unwrap();
        let encoded = input_to_proto(&original);
        let decoded = input_from_proto(&encoded).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn output_round_trip() {
        let original = make_test_transfer().outputs.into_iter().next().unwrap();
        let encoded = output_to_proto(&original);
        let decoded = output_from_proto(&encoded).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn tx_round_trip() {
        let original = make_test_transfer();
        let encoded = tx_to_proto(&original);
        let decoded = tx_from_proto(&encoded).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn tx_round_trip_through_proto_bytes() {
        // On-the-wire scenario: encode, transmit, decode, validate.
        let original = make_test_transfer();
        let encoded = tx_to_proto(&original);
        let wire_bytes = encoded.encode_to_vec();

        let recovered_proto = proto::HyperTransferTx::decode(wire_bytes.as_slice()).unwrap();
        let recovered = tx_from_proto(&recovered_proto).unwrap();

        assert_eq!(recovered, original);
        // The recovered transfer is structurally valid (range proofs verify).
        assert!(recovered.validate().is_ok());
    }

    #[test]
    fn input_rejects_short_nullifier() {
        let mut p = input_to_proto(&make_test_transfer().inputs.remove(0));
        p.nullifier.truncate(16);
        assert_eq!(
            input_from_proto(&p),
            Err(TransferCodecError::BadNullifierLength(16))
        );
    }

    #[test]
    fn input_rejects_short_signature() {
        let mut p = input_to_proto(&make_test_transfer().inputs.remove(0));
        p.spend_signature.truncate(64);
        assert_eq!(
            input_from_proto(&p),
            Err(TransferCodecError::BadSignatureLength(64))
        );
    }

    #[test]
    fn input_rejects_invalid_commitment() {
        let mut p = input_to_proto(&make_test_transfer().inputs.remove(0));
        p.commitment = vec![0xff; 56];
        assert_eq!(input_from_proto(&p), Err(TransferCodecError::BadCommitment));
    }

    #[test]
    fn output_rejects_invalid_commitment() {
        let mut p = output_to_proto(&make_test_transfer().outputs.remove(0));
        p.commitment = vec![0u8; 32];
        assert_eq!(
            output_from_proto(&p),
            Err(TransferCodecError::BadCommitment)
        );
    }
}
