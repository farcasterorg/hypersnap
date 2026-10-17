//! Commit certificates in the bundled form (FIP §16.5).
//!
//! A certificate holds one Falcon-512 precommit signature (666 bytes) for
//! each signer, in the order of `signer_bitmap`. Bit `i` (most significant
//! bit of byte 0 first) is member `i` of `set(epoch)`, in
//! `consensus_key_hash` order. The signed bytes are those of the consensus
//! precommit vote for `ShardHash { shard_index, hash: block_hash }`, so a
//! certificate is the Malachite commit certificate written against the epoch
//! member list.

use super::validator_sets::EpochSet;
use crate::core::consensus_keys::{ConsensusDomain, ConsensusPublicKey};
use crate::core::types::{Address, SnapchainValidatorContext};
use crate::proto::{self, BundledSignatures, CommitCertificate};
use informalsystems_malachitebft_core_types as malachite;
use std::collections::BTreeMap;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CertificateError {
    #[error("certificate is for epoch {got}, the set is epoch {expected}")]
    WrongEpoch { got: u64, expected: u64 },
    #[error("signer bitmap has {got} bytes, expected {expected}")]
    BadBitmap { got: usize, expected: usize },
    #[error("certificate has {signatures} signatures for {signers} signers")]
    SignatureCount { signatures: usize, signers: usize },
    #[error("signers have weight {weight} of {total}; more than 2/3 is needed")]
    NoQuorum { weight: u64, total: u64 },
    #[error("signature of member {0} does not verify")]
    BadSignature(usize),
    #[error("signer {0} is not a member of the set")]
    UnknownSigner(String),
    #[error("certificate has no bundled signatures")]
    NotBundled,
}

fn bitmap_len(members: usize) -> usize {
    members.div_ceil(8)
}

fn bit(bitmap: &[u8], i: usize) -> bool {
    bitmap[i / 8] & (0x80 >> (i % 8)) != 0
}

/// What a certificate signature covers: the commit digest
/// `d = keccak256("hypersnap-commit-v1" || u32 shard || u64 height || u32 round || block_hash)`
/// (FIP §16.5), signed with the Falcon-512 domain `CONSENSUS_VOTE`. The
/// CERT-STARK verifier and the bridge contract take `d` as the payload
/// digest.
pub fn precommit_sign_bytes(
    shard_id: u32,
    height: u64,
    round: u32,
    block_hash: &[u8],
    _voter: &Address,
) -> Vec<u8> {
    crate::core::consensus_keys::vote_digest(true, shard_id, height, round, Some(block_hash))
        .to_vec()
}

/// Bundled certificate from signatures keyed by validator address.
/// Addresses that are not members are an error.
pub fn build(
    set: &EpochSet,
    shard_id: u32,
    height: u64,
    round: u32,
    block_hash: &[u8],
    signatures: &BTreeMap<Address, Vec<u8>>,
) -> Result<CommitCertificate, CertificateError> {
    let members = &set.record.members;
    let index: BTreeMap<Address, usize> = members
        .iter()
        .enumerate()
        .map(|(i, m)| (Address::from_vec(m.consensus_key_hash.clone()), i))
        .collect();
    let mut bitmap = vec![0u8; bitmap_len(members.len())];
    let mut ordered: Vec<(usize, Vec<u8>)> = Vec::with_capacity(signatures.len());
    for (address, sig) in signatures {
        let i = *index
            .get(address)
            .ok_or_else(|| CertificateError::UnknownSigner(address.to_hex()))?;
        bitmap[i / 8] |= 0x80 >> (i % 8);
        ordered.push((i, sig.clone()));
    }
    ordered.sort_by_key(|(i, _)| *i);
    Ok(CommitCertificate {
        shard_id,
        height,
        round,
        block_hash: block_hash.to_vec(),
        epoch: set.epoch(),
        signer_bitmap: bitmap,
        form: Some(proto::commit_certificate::Form::Bundled(
            BundledSignatures {
                signatures: ordered.into_iter().map(|(_, s)| s).collect(),
            },
        )),
    })
}

/// Bundled certificate from a Malachite commit certificate.
pub fn from_malachite(
    set: &EpochSet,
    certificate: &malachite::CommitCertificate<SnapchainValidatorContext>,
) -> Result<CommitCertificate, CertificateError> {
    let signatures: BTreeMap<Address, Vec<u8>> = certificate
        .aggregated_signature
        .signatures
        .iter()
        .map(|s| (s.address.clone(), s.signature.0.clone()))
        .collect();
    build(
        set,
        certificate.height.shard_index,
        certificate.height.block_number,
        certificate.round.as_i64() as u32,
        &certificate.value_id.hash,
        &signatures,
    )
}

/// Check a bundled certificate against the set of its epoch (FIP §16.5).
pub fn verify(set: &EpochSet, cert: &CommitCertificate) -> Result<(), CertificateError> {
    if cert.epoch != set.epoch() {
        return Err(CertificateError::WrongEpoch {
            got: cert.epoch,
            expected: set.epoch(),
        });
    }
    let members = &set.record.members;
    let expected_len = bitmap_len(members.len());
    if cert.signer_bitmap.len() != expected_len {
        return Err(CertificateError::BadBitmap {
            got: cert.signer_bitmap.len(),
            expected: expected_len,
        });
    }
    // Padding bits after the last member must be zero (canonical form).
    for i in members.len()..expected_len * 8 {
        if bit(&cert.signer_bitmap, i) {
            return Err(CertificateError::BadBitmap {
                got: cert.signer_bitmap.len(),
                expected: expected_len,
            });
        }
    }
    let signatures = match &cert.form {
        Some(proto::commit_certificate::Form::Bundled(b)) => &b.signatures,
        _ => return Err(CertificateError::NotBundled),
    };
    let signers: Vec<usize> = (0..members.len())
        .filter(|&i| bit(&cert.signer_bitmap, i))
        .collect();
    if signers.len() != signatures.len() {
        return Err(CertificateError::SignatureCount {
            signatures: signatures.len(),
            signers: signers.len(),
        });
    }
    let weight: u64 = signers.iter().map(|&i| members[i].weight).sum();
    if !set.is_quorum(weight) {
        return Err(CertificateError::NoQuorum {
            weight,
            total: set.record.total_weight,
        });
    }
    let vset = set.validator_set(cert.shard_id);
    let keys: BTreeMap<&Address, &ConsensusPublicKey> = vset
        .validators
        .iter()
        .map(|v| (&v.address, &v.public_key))
        .collect();
    for (&i, sig) in signers.iter().zip(signatures) {
        let address = Address::from_vec(members[i].consensus_key_hash.clone());
        let key = keys
            .get(&address)
            .ok_or_else(|| CertificateError::UnknownSigner(address.to_hex()))?;
        let bytes = precommit_sign_bytes(
            cert.shard_id,
            cert.height,
            cert.round,
            &cert.block_hash,
            &address,
        );
        if !key.verify(ConsensusDomain::Vote, &bytes, sig) {
            return Err(CertificateError::BadSignature(i));
        }
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod test_support {
    //! A Falcon-512 validator set for tests.
    use super::*;
    use crate::chain::validator_sets::build_record;
    use crate::core::consensus_keys::{test_key, ConsensusPrivateKey};
    use crate::proto::HyperValidatorSetMember;

    pub struct TestValidators {
        pub keys: Vec<ConsensusPrivateKey>,
        pub set: EpochSet,
    }

    pub fn test_validators(n: u8, epoch: u64) -> TestValidators {
        let mut keys = Vec::new();
        let mut publics = Vec::new();
        let mut members = Vec::new();
        for s in 1..=n {
            let key = test_key(s);
            let ConsensusPrivateKey::Falcon { public, .. } = &key else {
                unreachable!()
            };
            members.push(HyperValidatorSetMember {
                consensus_key_hash: public.key_id().to_vec(),
                weight: 1,
                node_key_hash: vec![s; 32],
                fid: 1_000 + s as u64,
            });
            publics.push(public.clone());
            keys.push(key);
        }
        let record = build_record(epoch, members);
        let set = EpochSet::new(record, [epoch as u8; 32], publics).unwrap();
        TestValidators { keys, set }
    }

    impl TestValidators {
        /// Precommit signatures of the first `count` keys.
        pub fn sign(
            &self,
            count: usize,
            shard_id: u32,
            height: u64,
            round: u32,
            block_hash: &[u8],
        ) -> BTreeMap<Address, Vec<u8>> {
            self.keys
                .iter()
                .take(count)
                .map(|k| {
                    let address = k.public_key().address();
                    let bytes = precommit_sign_bytes(shard_id, height, round, block_hash, &address);
                    (address, k.sign(ConsensusDomain::Vote, &bytes))
                })
                .collect()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::test_validators;
    use super::*;

    #[test]
    fn build_and_verify() {
        let v = test_validators(4, 1);
        let hash = [7u8; 32];
        let sigs = v.sign(3, 1, 10, 0, &hash);
        let cert = build(&v.set, 1, 10, 0, &hash, &sigs).unwrap();
        assert_eq!(cert.signer_bitmap.len(), 1);
        assert_eq!(cert.signer_bitmap[0].count_ones(), 3);
        verify(&v.set, &cert).unwrap();

        // 2 of 4 is not more than 2/3.
        let two = build(&v.set, 1, 10, 0, &hash, &v.sign(2, 1, 10, 0, &hash)).unwrap();
        assert!(matches!(
            verify(&v.set, &two),
            Err(CertificateError::NoQuorum { .. })
        ));

        // Another block hash, height or shard fails.
        let mut other = cert.clone();
        other.block_hash = vec![8u8; 32];
        assert!(matches!(
            verify(&v.set, &other),
            Err(CertificateError::BadSignature(_))
        ));
        let mut other = cert.clone();
        other.height = 11;
        assert!(verify(&v.set, &other).is_err());
        let mut other = cert.clone();
        other.shard_id = 2;
        assert!(verify(&v.set, &other).is_err());

        // A wrong epoch, a padding bit, or a missing signature fails.
        let mut other = cert.clone();
        other.epoch = 2;
        assert!(matches!(
            verify(&v.set, &other),
            Err(CertificateError::WrongEpoch { .. })
        ));
        let mut other = cert.clone();
        other.signer_bitmap[0] |= 0x01;
        assert!(verify(&v.set, &other).is_err());
        let mut other = cert;
        if let Some(proto::commit_certificate::Form::Bundled(b)) = &mut other.form {
            b.signatures.pop();
        }
        assert!(matches!(
            verify(&v.set, &other),
            Err(CertificateError::SignatureCount { .. })
        ));
    }
}
