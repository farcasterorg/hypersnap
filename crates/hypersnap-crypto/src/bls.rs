//! BLS12-381 signatures over blst.
//!
//! Convention matches Ethereum consensus: G1 public keys (48 bytes compressed),
//! G2 signatures (96 bytes compressed). Hash-to-curve uses RFC 9380
//! `BLS12381G2_XMD:SHA-256_SSWU_RO_` with a hypersnap-specific suffix so the
//! DST cannot collide with any other BLS deployment.

use blst::min_pk::{AggregatePublicKey, AggregateSignature, PublicKey, SecretKey, Signature};
use blst::BLST_ERROR;
use rand::{CryptoRng, RngCore};

pub const DST: &[u8] = b"HYPERSNAP_BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_V1_";

#[derive(thiserror::Error, Debug)]
pub enum BlsError {
    #[error("invalid private key bytes")]
    InvalidPrivateKey,
    #[error("invalid public key bytes")]
    InvalidPublicKey,
    #[error("invalid signature bytes")]
    InvalidSignature,
    #[error("aggregation input must be non-empty")]
    EmptyAggregation,
    #[error("aggregation failed")]
    AggregationFailed,
}

#[derive(Clone)]
pub struct BlsPrivateKey(SecretKey);

impl std::fmt::Debug for BlsPrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BlsPrivateKey(<redacted>)")
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlsPublicKey(PublicKey);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlsSignature(Signature);

impl BlsPrivateKey {
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut ikm = [0u8; 32];
        rng.fill_bytes(&mut ikm);
        let sk = SecretKey::key_gen(&ikm, &[]).expect("32 bytes is always valid IKM");
        Self(sk)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, BlsError> {
        SecretKey::from_bytes(bytes)
            .map(Self)
            .map_err(|_| BlsError::InvalidPrivateKey)
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    pub fn public_key(&self) -> BlsPublicKey {
        BlsPublicKey(self.0.sk_to_pk())
    }

    pub fn sign(&self, msg: &[u8]) -> BlsSignature {
        BlsSignature(self.0.sign(msg, DST, &[]))
    }
}

impl BlsPublicKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, BlsError> {
        PublicKey::uncompress(bytes)
            .map(Self)
            .map_err(|_| BlsError::InvalidPublicKey)
    }

    pub fn to_bytes(&self) -> [u8; 48] {
        self.0.compress()
    }
}

impl BlsSignature {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, BlsError> {
        Signature::uncompress(bytes)
            .map(Self)
            .map_err(|_| BlsError::InvalidSignature)
    }

    pub fn to_bytes(&self) -> [u8; 96] {
        self.0.compress()
    }

    pub fn verify(&self, msg: &[u8], pk: &BlsPublicKey) -> bool {
        self.0.verify(true, msg, DST, &[], &pk.0, true) == BLST_ERROR::BLST_SUCCESS
    }
}

pub fn aggregate_signatures(sigs: &[&BlsSignature]) -> Result<BlsSignature, BlsError> {
    if sigs.is_empty() {
        return Err(BlsError::EmptyAggregation);
    }
    let inner: Vec<&Signature> = sigs.iter().map(|s| &s.0).collect();
    let agg =
        AggregateSignature::aggregate(&inner, true).map_err(|_| BlsError::AggregationFailed)?;
    Ok(BlsSignature(agg.to_signature()))
}

pub fn aggregate_public_keys(pks: &[&BlsPublicKey]) -> Result<BlsPublicKey, BlsError> {
    if pks.is_empty() {
        return Err(BlsError::EmptyAggregation);
    }
    let inner: Vec<&PublicKey> = pks.iter().map(|p| &p.0).collect();
    let agg =
        AggregatePublicKey::aggregate(&inner, true).map_err(|_| BlsError::AggregationFailed)?;
    Ok(BlsPublicKey(agg.to_public_key()))
}

/// Verify an aggregate signature where every signer signed the same message.
pub fn fast_aggregate_verify(pks: &[&BlsPublicKey], msg: &[u8], sig: &BlsSignature) -> bool {
    if pks.is_empty() {
        return false;
    }
    let inner: Vec<&PublicKey> = pks.iter().map(|p| &p.0).collect();
    sig.0.fast_aggregate_verify(true, msg, DST, &inner) == BLST_ERROR::BLST_SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn sign_verify_roundtrip() {
        let mut rng = OsRng;
        let sk = BlsPrivateKey::generate(&mut rng);
        let pk = sk.public_key();
        let msg = b"hypersnap test message";
        let sig = sk.sign(msg);
        assert!(sig.verify(msg, &pk));
    }

    #[test]
    fn wrong_message_fails() {
        let mut rng = OsRng;
        let sk = BlsPrivateKey::generate(&mut rng);
        let pk = sk.public_key();
        let sig = sk.sign(b"original");
        assert!(!sig.verify(b"tampered", &pk));
    }

    #[test]
    fn wrong_key_fails() {
        let mut rng = OsRng;
        let sk1 = BlsPrivateKey::generate(&mut rng);
        let sk2 = BlsPrivateKey::generate(&mut rng);
        let msg = b"msg";
        let sig = sk1.sign(msg);
        assert!(!sig.verify(msg, &sk2.public_key()));
    }

    #[test]
    fn aggregate_same_message() {
        let mut rng = OsRng;
        let signers: Vec<_> = (0..5).map(|_| BlsPrivateKey::generate(&mut rng)).collect();
        let msg = b"committee message";

        let sigs: Vec<_> = signers.iter().map(|sk| sk.sign(msg)).collect();
        let sig_refs: Vec<_> = sigs.iter().collect();
        let agg_sig = aggregate_signatures(&sig_refs).unwrap();

        let pks: Vec<_> = signers.iter().map(|sk| sk.public_key()).collect();
        let pk_refs: Vec<_> = pks.iter().collect();

        assert!(fast_aggregate_verify(&pk_refs, msg, &agg_sig));
    }

    #[test]
    fn aggregate_pubkey_then_verify() {
        let mut rng = OsRng;
        let signers: Vec<_> = (0..5).map(|_| BlsPrivateKey::generate(&mut rng)).collect();
        let msg = b"committee message";

        let sigs: Vec<_> = signers.iter().map(|sk| sk.sign(msg)).collect();
        let sig_refs: Vec<_> = sigs.iter().collect();
        let agg_sig = aggregate_signatures(&sig_refs).unwrap();

        let pks: Vec<_> = signers.iter().map(|sk| sk.public_key()).collect();
        let pk_refs: Vec<_> = pks.iter().collect();
        let agg_pk = aggregate_public_keys(&pk_refs).unwrap();

        assert!(agg_sig.verify(msg, &agg_pk));
    }

    #[test]
    fn missing_signer_breaks_aggregate() {
        let mut rng = OsRng;
        let signers: Vec<_> = (0..5).map(|_| BlsPrivateKey::generate(&mut rng)).collect();
        let msg = b"committee message";

        let sigs: Vec<_> = signers.iter().take(4).map(|sk| sk.sign(msg)).collect();
        let sig_refs: Vec<_> = sigs.iter().collect();
        let agg_sig = aggregate_signatures(&sig_refs).unwrap();

        // Verifier expects all 5 — should fail because only 4 actually signed.
        let pks: Vec<_> = signers.iter().map(|sk| sk.public_key()).collect();
        let pk_refs: Vec<_> = pks.iter().collect();

        assert!(!fast_aggregate_verify(&pk_refs, msg, &agg_sig));
    }

    #[test]
    fn private_key_serde_roundtrip() {
        let mut rng = OsRng;
        let sk = BlsPrivateKey::generate(&mut rng);
        let bytes = sk.to_bytes();
        let sk2 = BlsPrivateKey::from_bytes(&bytes).unwrap();
        assert_eq!(sk.public_key().to_bytes(), sk2.public_key().to_bytes());
    }

    #[test]
    fn public_key_serde_roundtrip() {
        let mut rng = OsRng;
        let pk = BlsPrivateKey::generate(&mut rng).public_key();
        let bytes = pk.to_bytes();
        let pk2 = BlsPublicKey::from_bytes(&bytes).unwrap();
        assert_eq!(pk, pk2);
    }

    #[test]
    fn signature_serde_roundtrip() {
        let mut rng = OsRng;
        let sk = BlsPrivateKey::generate(&mut rng);
        let sig = sk.sign(b"msg");
        let bytes = sig.to_bytes();
        let sig2 = BlsSignature::from_bytes(&bytes).unwrap();
        assert_eq!(sig, sig2);
    }

    #[test]
    fn empty_aggregation_errors() {
        let sigs: Vec<&BlsSignature> = Vec::new();
        assert!(matches!(
            aggregate_signatures(&sigs),
            Err(BlsError::EmptyAggregation)
        ));
        let pks: Vec<&BlsPublicKey> = Vec::new();
        assert!(matches!(
            aggregate_public_keys(&pks),
            Err(BlsError::EmptyAggregation)
        ));
    }
}
