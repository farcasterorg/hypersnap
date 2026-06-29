//! KZG polynomial commitments over BLS12-381.
//!
//! Given a structured reference string (SRS) of the form
//!   `(g, g^τ, g^τ², …, g^τⁿ)` in G1 and `g²^τ` in G2,
//! a polynomial `f(x) = a₀ + a₁x + ⋯ + aₙxⁿ` commits to `C = g^{f(τ)}`.
//! An opening at point `z` is a proof `π = g^{q(τ)}` where
//! `q(x) = (f(x) − f(z)) / (x − z)`. Verification checks
//!   `e(π, g²^τ − g²^z) ≟ e(C − g^{f(z)}, g²)`.
//!
//! For unit tests we synthesize τ from a CSPRNG. Production code must derive
//! the SRS from a real multi-party trusted-setup ceremony — Ethereum's
//! KZG ceremony output (used by EIP-4844) is the intended source.

use bls12_381::{pairing, G1Affine, G1Projective, G2Affine, G2Projective, Scalar as Fr};
use ff::Field;
use rand::{CryptoRng, RngCore};

/// Structured Reference String for KZG commitments.
#[derive(Clone)]
pub struct KzgSrs {
    /// `g^{τ^0}, g^{τ^1}, ..., g^{τ^{max_degree}}` in G1.
    pub g1_powers: Vec<G1Affine>,
    /// `g²^τ` in G2 — the only G2 element needed for verifier-side pairings.
    pub g2_tau: G2Affine,
}

impl KzgSrs {
    pub fn max_degree(&self) -> usize {
        self.g1_powers.len() - 1
    }

    /// Generate an SRS from a known τ. **Test-only** — exposing τ defeats the
    /// security of any commitment under this SRS.
    #[doc(hidden)]
    pub fn from_tau_unsafe(tau: Fr, max_degree: usize) -> Self {
        let mut g1_powers = Vec::with_capacity(max_degree + 1);
        let mut tau_pow = Fr::ONE;
        for _ in 0..=max_degree {
            let p = G1Projective::generator() * tau_pow;
            g1_powers.push(G1Affine::from(p));
            tau_pow *= tau;
        }
        let g2_tau = G2Affine::from(G2Projective::generator() * tau);
        Self { g1_powers, g2_tau }
    }

    /// Sample an SRS using a fresh random τ. **Test-only** — no toxic-waste
    /// destruction, the τ is in process memory and may leak.
    #[doc(hidden)]
    pub fn random_unsafe<R: RngCore + CryptoRng>(rng: &mut R, max_degree: usize) -> Self {
        let tau = Fr::random(rng);
        Self::from_tau_unsafe(tau, max_degree)
    }

    /// Construct an SRS from compressed G1 and G2 points produced by a
    /// trusted-setup ceremony. Each `g1_powers_compressed[i]` must be the
    /// canonical 48-byte compressed encoding of `g^{τ^i}`. `g2_tau_compressed`
    /// is the 96-byte compressed encoding of `g²^τ`.
    pub fn from_compressed(
        g1_powers_compressed: &[[u8; 48]],
        g2_tau_compressed: &[u8; 96],
    ) -> Result<Self, KzgError> {
        if g1_powers_compressed.len() < 2 {
            return Err(KzgError::SrsTooSmall);
        }
        let mut g1_powers = Vec::with_capacity(g1_powers_compressed.len());
        for (i, bytes) in g1_powers_compressed.iter().enumerate() {
            let point: Option<G1Affine> = G1Affine::from_compressed(bytes).into();
            g1_powers.push(point.ok_or(KzgError::InvalidG1Point(i))?);
        }
        let g2_tau: Option<G2Affine> = G2Affine::from_compressed(g2_tau_compressed).into();
        let g2_tau = g2_tau.ok_or(KzgError::InvalidG2Point)?;
        Ok(Self { g1_powers, g2_tau })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KzgCommitment(pub G1Projective);

impl KzgCommitment {
    pub fn to_bytes(&self) -> [u8; 48] {
        G1Affine::from(self.0).to_compressed()
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 48 {
            return None;
        }
        let mut arr = [0u8; 48];
        arr.copy_from_slice(bytes);
        Option::<G1Affine>::from(G1Affine::from_compressed(&arr)).map(|p| Self(p.into()))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KzgProof(pub G1Projective);

impl KzgProof {
    pub fn to_bytes(&self) -> [u8; 48] {
        G1Affine::from(self.0).to_compressed()
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 48 {
            return None;
        }
        let mut arr = [0u8; 48];
        arr.copy_from_slice(bytes);
        Option::<G1Affine>::from(G1Affine::from_compressed(&arr)).map(|p| Self(p.into()))
    }
}

#[derive(thiserror::Error, Debug)]
pub enum KzgError {
    #[error("polynomial degree {polynomial} exceeds SRS max degree {srs_max}")]
    DegreeExceeded { polynomial: usize, srs_max: usize },
    #[error("g1_powers must contain at least 2 points")]
    SrsTooSmall,
    #[error("invalid compressed G1 point at index {0}")]
    InvalidG1Point(usize),
    #[error("invalid compressed G2 point")]
    InvalidG2Point,
}

/// Commit to a polynomial given its coefficients in ascending degree order.
pub fn commit(srs: &KzgSrs, coeffs: &[Fr]) -> Result<KzgCommitment, KzgError> {
    if !coeffs.is_empty() && coeffs.len() > srs.g1_powers.len() {
        return Err(KzgError::DegreeExceeded {
            polynomial: coeffs.len() - 1,
            srs_max: srs.max_degree(),
        });
    }
    let mut c = G1Projective::identity();
    for (i, a_i) in coeffs.iter().enumerate() {
        c += srs.g1_powers[i] * a_i;
    }
    Ok(KzgCommitment(c))
}

/// Open the commitment at point `z`. Returns `(f(z), proof)`.
pub fn open(srs: &KzgSrs, coeffs: &[Fr], z: Fr) -> Result<(Fr, KzgProof), KzgError> {
    let y = horner_eval(coeffs, z);
    let q_coeffs = quotient_polynomial(coeffs, z, y);
    let pi = commit(srs, &q_coeffs)?;
    Ok((y, KzgProof(pi.0)))
}

/// Verify an opening: `e(π, g²^τ - g²^z) == e(C - g^y, g²)`.
pub fn verify(commitment: &KzgCommitment, z: Fr, y: Fr, proof: &KzgProof, srs: &KzgSrs) -> bool {
    let g1 = G1Projective::generator();
    let g2 = G2Projective::generator();

    let lhs_g2 = G2Projective::from(srs.g2_tau) - g2 * z;
    let lhs = pairing(&G1Affine::from(proof.0), &G2Affine::from(lhs_g2));

    let rhs_g1 = commitment.0 - g1 * y;
    let rhs = pairing(&G1Affine::from(rhs_g1), &G2Affine::from(g2));

    lhs == rhs
}

fn horner_eval(coeffs: &[Fr], x: Fr) -> Fr {
    let mut acc = Fr::ZERO;
    for c in coeffs.iter().rev() {
        acc = acc * x + c;
    }
    acc
}

/// Compute the coefficients of `q(x) = (f(x) - y) / (x - z)` via synthetic
/// division. Returns an empty vec for constant or zero polynomials.
fn quotient_polynomial(coeffs: &[Fr], z: Fr, y: Fr) -> Vec<Fr> {
    if coeffs.len() < 2 {
        return Vec::new();
    }
    let mut shifted = coeffs.to_vec();
    shifted[0] -= y;

    let n = shifted.len();
    let mut q = vec![Fr::ZERO; n - 1];
    q[n - 2] = shifted[n - 1];
    for i in (0..n - 2).rev() {
        q[i] = shifted[i + 1] + q[i + 1] * z;
    }
    q
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    fn random_polynomial<R: RngCore + CryptoRng>(rng: &mut R, degree: usize) -> Vec<Fr> {
        (0..=degree).map(|_| Fr::random(&mut *rng)).collect()
    }

    #[test]
    fn commit_open_verify_roundtrip() {
        let mut rng = OsRng;
        let srs = KzgSrs::random_unsafe(&mut rng, 32);
        let coeffs = random_polynomial(&mut rng, 32);
        let z = Fr::random(&mut rng);

        let commitment = commit(&srs, &coeffs).unwrap();
        let (y, proof) = open(&srs, &coeffs, z).unwrap();
        assert!(verify(&commitment, z, y, &proof, &srs));
    }

    #[test]
    fn open_at_multiple_points_verifies() {
        let mut rng = OsRng;
        let srs = KzgSrs::random_unsafe(&mut rng, 16);
        let coeffs = random_polynomial(&mut rng, 16);
        let commitment = commit(&srs, &coeffs).unwrap();

        for _ in 0..5 {
            let z = Fr::random(&mut rng);
            let (y, proof) = open(&srs, &coeffs, z).unwrap();
            assert!(verify(&commitment, z, y, &proof, &srs));
        }
    }

    #[test]
    fn wrong_y_fails_verify() {
        let mut rng = OsRng;
        let srs = KzgSrs::random_unsafe(&mut rng, 8);
        let coeffs = random_polynomial(&mut rng, 8);
        let z = Fr::random(&mut rng);

        let commitment = commit(&srs, &coeffs).unwrap();
        let (y, proof) = open(&srs, &coeffs, z).unwrap();
        let bad_y = y + Fr::ONE;
        assert!(!verify(&commitment, z, bad_y, &proof, &srs));
    }

    #[test]
    fn wrong_z_fails_verify() {
        let mut rng = OsRng;
        let srs = KzgSrs::random_unsafe(&mut rng, 8);
        let coeffs = random_polynomial(&mut rng, 8);
        let z = Fr::random(&mut rng);

        let commitment = commit(&srs, &coeffs).unwrap();
        let (y, proof) = open(&srs, &coeffs, z).unwrap();
        let bad_z = z + Fr::ONE;
        assert!(!verify(&commitment, bad_z, y, &proof, &srs));
    }

    #[test]
    fn wrong_proof_fails_verify() {
        let mut rng = OsRng;
        let srs = KzgSrs::random_unsafe(&mut rng, 8);
        let coeffs = random_polynomial(&mut rng, 8);
        let z = Fr::random(&mut rng);

        let commitment = commit(&srs, &coeffs).unwrap();
        let (y, _proof) = open(&srs, &coeffs, z).unwrap();

        // Open a different polynomial at the same z and use that proof.
        let other_coeffs = random_polynomial(&mut rng, 8);
        let (_, bad_proof) = open(&srs, &other_coeffs, z).unwrap();

        assert!(!verify(&commitment, z, y, &bad_proof, &srs));
    }

    #[test]
    fn wrong_commitment_fails_verify() {
        let mut rng = OsRng;
        let srs = KzgSrs::random_unsafe(&mut rng, 8);
        let coeffs1 = random_polynomial(&mut rng, 8);
        let coeffs2 = random_polynomial(&mut rng, 8);
        let z = Fr::random(&mut rng);

        let commitment2 = commit(&srs, &coeffs2).unwrap();
        let (y, proof) = open(&srs, &coeffs1, z).unwrap();
        assert!(!verify(&commitment2, z, y, &proof, &srs));
    }

    #[test]
    fn constant_polynomial_works() {
        let mut rng = OsRng;
        let srs = KzgSrs::random_unsafe(&mut rng, 4);
        let c = Fr::random(&mut rng);
        let coeffs = vec![c];
        let z = Fr::random(&mut rng);

        let commitment = commit(&srs, &coeffs).unwrap();
        let (y, proof) = open(&srs, &coeffs, z).unwrap();
        assert_eq!(y, c, "f(z) of a constant polynomial is the constant");
        assert!(verify(&commitment, z, y, &proof, &srs));
    }

    #[test]
    fn degree_exceeded_returns_error() {
        let mut rng = OsRng;
        let srs = KzgSrs::random_unsafe(&mut rng, 4);
        let too_many = vec![Fr::ONE; 6];
        match commit(&srs, &too_many) {
            Err(KzgError::DegreeExceeded {
                polynomial,
                srs_max,
            }) => {
                assert_eq!(polynomial, 5);
                assert_eq!(srs_max, 4);
            }
            other => panic!("expected DegreeExceeded, got {:?}", other.is_ok()),
        }
    }

    #[test]
    fn commitment_serialization_roundtrip() {
        let mut rng = OsRng;
        let srs = KzgSrs::random_unsafe(&mut rng, 4);
        let coeffs = random_polynomial(&mut rng, 4);
        let c = commit(&srs, &coeffs).unwrap();

        let bytes = c.to_bytes();
        let c2 = KzgCommitment::from_bytes(&bytes).unwrap();
        assert_eq!(c, c2);
    }

    #[test]
    fn proof_serialization_roundtrip() {
        let mut rng = OsRng;
        let srs = KzgSrs::random_unsafe(&mut rng, 4);
        let coeffs = random_polynomial(&mut rng, 4);
        let z = Fr::random(&mut rng);
        let (_, p) = open(&srs, &coeffs, z).unwrap();

        let bytes = p.to_bytes();
        let p2 = KzgProof::from_bytes(&bytes).unwrap();
        assert_eq!(p, p2);
    }

    #[test]
    fn from_compressed_round_trip_through_random_srs() {
        let mut rng = OsRng;
        let original = KzgSrs::random_unsafe(&mut rng, 16);

        // Encode the original SRS into compressed bytes (mimicking a real
        // ceremony output), then reconstruct via from_compressed.
        let g1_bytes: Vec<[u8; 48]> = original
            .g1_powers
            .iter()
            .map(|p| p.to_compressed())
            .collect();
        let g2_bytes: [u8; 96] = original.g2_tau.to_compressed();

        let reconstructed = KzgSrs::from_compressed(&g1_bytes, &g2_bytes).unwrap();
        assert_eq!(reconstructed.max_degree(), original.max_degree());

        // Commit + verify round-trip should produce identical results under both.
        let coeffs: Vec<Fr> = (0..=16).map(|_| Fr::random(&mut rng)).collect();
        let z = Fr::random(&mut rng);

        let c_orig = commit(&original, &coeffs).unwrap();
        let c_recon = commit(&reconstructed, &coeffs).unwrap();
        assert_eq!(c_orig, c_recon);

        let (y, proof) = open(&original, &coeffs, z).unwrap();
        assert!(verify(&c_orig, z, y, &proof, &reconstructed));
    }

    #[test]
    fn from_compressed_rejects_invalid_g1() {
        let bad_g1 = vec![[0xffu8; 48]; 4];
        let mut rng = OsRng;
        let srs = KzgSrs::random_unsafe(&mut rng, 4);
        let g2 = srs.g2_tau.to_compressed();
        match KzgSrs::from_compressed(&bad_g1, &g2) {
            Err(KzgError::InvalidG1Point(0)) => {}
            other => panic!("expected InvalidG1Point(0), got {:?}", other.is_ok()),
        }
    }

    #[test]
    fn from_compressed_rejects_too_small_srs() {
        let one_point = vec![[0u8; 48]; 1];
        let g2 = [0u8; 96];
        match KzgSrs::from_compressed(&one_point, &g2) {
            Err(KzgError::SrsTooSmall) => {}
            other => panic!("expected SrsTooSmall, got {:?}", other.is_ok()),
        }
    }

    #[test]
    fn quotient_polynomial_correctness() {
        // Spot-check the synthetic division: q(x) such that (x-z)q(x) + (a0 - y) = f(x) - y.
        // For f(x) = 2 + 3x + x^2 at z=1: y = 6, q(x) should satisfy
        //   (x-1)q(x) = (1)x^2 + 3x + 2 - 6 = x^2 + 3x - 4 = (x-1)(x+4)
        // So q(x) = x + 4, i.e. q_coeffs = [4, 1].
        let coeffs = vec![Fr::from(2), Fr::from(3), Fr::from(1)];
        let z = Fr::from(1);
        let y = Fr::from(6);
        let q = quotient_polynomial(&coeffs, z, y);
        assert_eq!(q.len(), 2);
        assert_eq!(q[0], Fr::from(4));
        assert_eq!(q[1], Fr::from(1));
    }
}
