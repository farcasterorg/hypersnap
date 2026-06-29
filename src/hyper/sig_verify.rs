//! Threshold-signature verification for hyperblocks, reward
//! issuances, and trust snapshots.
//!
//! The hyper layer signs every consensus payload with DKLS23
//! threshold ECDSA over secp256k1. A 32-byte keccak256 prehash of
//! the canonical signing payload is recovered against the per-epoch
//! group address; mismatch fails closed.

use crate::proto;
use alloy_primitives::{keccak256, Address};
use hypersnap_crypto::ecdsa::EcdsaSignature;

#[derive(thiserror::Error, Debug)]
pub enum SigVerifyError {
    #[error("ECDSA signature is missing or empty")]
    NoSignatureMaterial,
    #[error("ECDSA signature is the wrong length: expected 65, got {0}")]
    BadEcdsaLength(usize),
    #[error("declared group_address ({declared:?}) does not match expected ({expected:?})")]
    GroupAddressMismatch {
        declared: Address,
        expected: Address,
    },
    #[error("ECDSA verification failed: {0}")]
    EcdsaVerificationFailed(#[from] hypersnap_crypto::ecdsa::EcdsaError),
}

/// Per-epoch DKLS23 group address the verifier expects. Borrowed
/// from the runtime's `dkls_group_addresses` registry.
pub struct ExpectedGroupKey<'a> {
    pub ecdsa: &'a Address,
}

impl<'a> ExpectedGroupKey<'a> {
    pub fn ecdsa_only(ecdsa: &'a Address) -> Self {
        Self { ecdsa }
    }
}

/// Internal: verify a 65-byte threshold ECDSA signature against the
/// expected group address. `declared_group_address` is the
/// self-attested identity bytes the producer embeds alongside the
/// signature; when non-empty it must match the expected address.
/// Mismatch is a hard rejection — we don't trust attacker-controlled
/// bytes to identify whose signature this should be.
fn dispatch(
    payload: &[u8],
    ecdsa_sig_bytes: &[u8],
    declared_group_address: &[u8],
    expected: &ExpectedGroupKey<'_>,
) -> Result<(), SigVerifyError> {
    if ecdsa_sig_bytes.is_empty() {
        return Err(SigVerifyError::NoSignatureMaterial);
    }
    if ecdsa_sig_bytes.len() != 65 {
        return Err(SigVerifyError::BadEcdsaLength(ecdsa_sig_bytes.len()));
    }
    let expected_addr = *expected.ecdsa;
    if !declared_group_address.is_empty() {
        if declared_group_address.len() != 20 {
            return Err(SigVerifyError::GroupAddressMismatch {
                declared: Address::ZERO,
                expected: expected_addr,
            });
        }
        let declared = Address::from_slice(declared_group_address);
        if declared != expected_addr {
            return Err(SigVerifyError::GroupAddressMismatch {
                declared,
                expected: expected_addr,
            });
        }
    }
    let digest = keccak256(payload);
    let sig = EcdsaSignature::from_bytes(ecdsa_sig_bytes)?;
    sig.verify_against_address(&digest, expected_addr)?;
    Ok(())
}

/// Verify a hyperblock's threshold signature. Takes byte slices so
/// the same helper serves callers holding either the proto
/// `HyperBlockSignature` or its Rust mirror in
/// [`crate::hyper::HyperBlockSignature`].
pub fn verify_hyperblock_signature(
    payload: &[u8],
    ecdsa_sig: &[u8],
    declared_group_address: &[u8],
    expected: &ExpectedGroupKey<'_>,
) -> Result<(), SigVerifyError> {
    dispatch(payload, ecdsa_sig, declared_group_address, expected)
}

/// Verify a `HyperRewardIssuance`'s threshold signature. The
/// canonical signing payload comes from
/// [`crate::hyper::rewards::issuance_signing_payload`].
///
/// `HyperRewardIssuance` carries no `group_address` self-identifier;
/// the runtime resolves the expected address out of band from
/// `dkls_group_address_for_epoch(iss.epoch)`.
pub fn verify_reward_issuance_signature(
    payload: &[u8],
    iss: &proto::HyperRewardIssuance,
    expected: &ExpectedGroupKey<'_>,
) -> Result<(), SigVerifyError> {
    dispatch(payload, &iss.ecdsa_signature, &[], expected)
}

/// Verify a `HyperTrustSnapshotUpdate`'s threshold signature.
pub fn verify_trust_snapshot_signature(
    payload: &[u8],
    update: &proto::HyperTrustSnapshotUpdate,
    expected: &ExpectedGroupKey<'_>,
) -> Result<(), SigVerifyError> {
    dispatch(payload, &update.ecdsa_signature, &[], expected)
}

/// Verify a `DaEpochSeedBody` threshold signature. `expected` is
/// the group address of epoch `body.epoch - 1`.
pub fn verify_da_epoch_seed_signature(
    payload: &[u8],
    body: &proto::DaEpochSeedBody,
    expected: &ExpectedGroupKey<'_>,
) -> Result<(), SigVerifyError> {
    dispatch(payload, &body.ecdsa_signature, &[], expected)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto;
    use hypersnap_crypto::dkls_threshold::{run_honest_dkg, run_honest_sign};

    fn ecdsa_signed_block_sig(payload: &[u8]) -> (proto::HyperBlockSignature, Address) {
        let dkg = run_honest_dkg(2, 3, [0xab; 32]).expect("dkg");
        let digest = keccak256(payload);
        let sig = run_honest_sign(&dkg, &digest, &[1, 2]).expect("sign");
        let proto = proto::HyperBlockSignature {
            epoch: 0,
            signer_indices: vec![1, 2],
            group_address: dkg.group_address.as_slice().to_vec(),
            ecdsa_signature: sig.to_bytes().to_vec(),
        };
        (proto, dkg.group_address)
    }

    #[test]
    fn ecdsa_path_verifies() {
        let payload = b"phase6-ecdsa";
        let (sig_proto, group_addr) = ecdsa_signed_block_sig(payload);
        let expected = ExpectedGroupKey::ecdsa_only(&group_addr);
        verify_hyperblock_signature(
            payload,
            &sig_proto.ecdsa_signature,
            &sig_proto.group_address,
            &expected,
        )
        .expect("verify");
    }

    #[test]
    fn missing_signature_material_errors() {
        let payload = b"phase6-missing";
        let any_addr = Address::ZERO;
        let expected = ExpectedGroupKey::ecdsa_only(&any_addr);
        let r = verify_hyperblock_signature(payload, &[], &[], &expected);
        assert!(matches!(r, Err(SigVerifyError::NoSignatureMaterial)));
    }

    #[test]
    fn wrong_ecdsa_length_rejected() {
        let payload = b"phase6-bad-ecdsa-len";
        let any_addr = Address::ZERO;
        let expected = ExpectedGroupKey::ecdsa_only(&any_addr);
        let r = verify_hyperblock_signature(payload, &vec![0u8; 64], &[0u8; 20], &expected);
        assert!(matches!(r, Err(SigVerifyError::BadEcdsaLength(64))));
    }

    #[test]
    fn declared_group_address_mismatch_rejected() {
        // ECDSA dispatch fails closed when the message's claimed
        // group_address differs from what the verifier expected.
        // Otherwise an attacker could attach a real ECDSA sig from
        // group A and a fake `group_address` for group B and the
        // verifier might think group B signed.
        let payload = b"phase6-claim-mismatch";
        let (mut sig_proto, _real_addr) = ecdsa_signed_block_sig(payload);
        let other = Address::repeat_byte(0xff);
        let expected = ExpectedGroupKey::ecdsa_only(&other);
        let r = verify_hyperblock_signature(
            payload,
            &sig_proto.ecdsa_signature,
            &sig_proto.group_address,
            &expected,
        );
        assert!(matches!(
            r,
            Err(SigVerifyError::GroupAddressMismatch { .. })
        ));
        // Now set declared to match expected; sig still doesn't
        // recover to it (it was produced for the real group).
        sig_proto.group_address = other.as_slice().to_vec();
        let r = verify_hyperblock_signature(
            payload,
            &sig_proto.ecdsa_signature,
            &sig_proto.group_address,
            &expected,
        );
        assert!(matches!(r, Err(SigVerifyError::EcdsaVerificationFailed(_))));
    }

    #[test]
    fn tampered_payload_fails_verification() {
        let payload = b"phase6-original";
        let (sig_proto, group_addr) = ecdsa_signed_block_sig(payload);
        let expected = ExpectedGroupKey::ecdsa_only(&group_addr);
        let r = verify_hyperblock_signature(
            b"tampered",
            &sig_proto.ecdsa_signature,
            &sig_proto.group_address,
            &expected,
        );
        assert!(matches!(r, Err(SigVerifyError::EcdsaVerificationFailed(_))));
    }
}
