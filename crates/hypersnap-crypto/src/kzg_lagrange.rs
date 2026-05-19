//! Evaluation-form KZG support.
//!
//! A 256-ary verkle node commits to a polynomial whose value at each of the
//! n = 256 roots of unity is the corresponding child slot's contribution.
//! This module provides:
//!
//! 1. `root_of_unity(n)` — returns ω_n in Fr where ω_n^n = 1 and ω_n is primitive
//! 2. `ifft(evals)` — radix-2 Cooley-Tukey inverse FFT, in place
//! 3. `commit_evaluations(srs, &evals)` — IFFT then standard `kzg::commit`
//!
//! Step 13 will add evaluation-form opening proofs at `ω_n^i`.

use crate::kzg::{commit, KzgCommitment, KzgError, KzgSrs};
use bls12_381::Scalar as Fr;
use ff::{Field, PrimeField};

/// Domain size for verkle tree commitments.
pub const VERKLE_DOMAIN: usize = 256;

/// Primitive n-th root of unity in Fr. `n` must be a power of two and at
/// most 2^32 (the 2-adic order of the BLS12-381 scalar field).
pub fn root_of_unity(n: usize) -> Fr {
    assert!(n.is_power_of_two(), "n must be a power of two");
    let log_n = n.trailing_zeros();
    assert!(
        log_n <= Fr::S,
        "n = 2^{} exceeds Fr's 2-adic order 2^{}",
        log_n,
        Fr::S
    );

    // ROOT_OF_UNITY is a primitive 2^S root of unity. Squaring it (S - log_n)
    // times yields a primitive 2^log_n = n root of unity.
    let mut w = Fr::ROOT_OF_UNITY;
    for _ in 0..(Fr::S - log_n) {
        w = w.square();
    }
    w
}

/// Bit-reverse permutation of a slice with `len = 2^log_n`.
fn bit_reverse_permute<T>(values: &mut [T]) {
    let n = values.len();
    if n <= 1 {
        return;
    }
    let log_n = n.trailing_zeros();
    for i in 0..n {
        let j = bit_reverse(i, log_n);
        if i < j {
            values.swap(i, j);
        }
    }
}

fn bit_reverse(mut x: usize, log_n: u32) -> usize {
    let mut r = 0usize;
    for _ in 0..log_n {
        r = (r << 1) | (x & 1);
        x >>= 1;
    }
    r
}

/// Radix-2 Cooley-Tukey IFFT, in place. `evals.len()` must be a power of two.
pub fn ifft(evals: &mut [Fr]) {
    let n = evals.len();
    assert!(n.is_power_of_two(), "FFT length must be a power of two");
    if n <= 1 {
        return;
    }

    bit_reverse_permute(evals);

    let omega_n_inv = root_of_unity(n).invert().unwrap();

    // Butterfly stages: m doubles each round (2, 4, 8, ..., n).
    let log_n = n.trailing_zeros();
    let mut m = 2usize;
    let mut stage = 1u32;
    while m <= n {
        // omega for this stage = omega_n_inv^(n/m) = omega_n_inv^{2^(log_n - stage)}
        let mut omega_m = omega_n_inv;
        for _ in 0..(log_n - stage) {
            omega_m = omega_m.square();
        }

        let half = m / 2;
        let mut block_start = 0usize;
        while block_start < n {
            let mut twiddle = Fr::ONE;
            for j in 0..half {
                let upper = evals[block_start + j + half] * twiddle;
                let lower = evals[block_start + j];
                evals[block_start + j] = lower + upper;
                evals[block_start + j + half] = lower - upper;
                twiddle *= omega_m;
            }
            block_start += m;
        }

        m *= 2;
        stage += 1;
    }

    // Scale by 1/n.
    let n_inv = Fr::from(n as u64).invert().unwrap();
    for v in evals.iter_mut() {
        *v *= n_inv;
    }
}

/// KZG-commit to a polynomial in evaluation form. The input is the polynomial's
/// values at `(ω_n^0, ω_n^1, …, ω_n^{n−1})` for n = `evals.len()`. Internally
/// converts to coefficient form via `ifft` and forwards to `commit`.
pub fn commit_evaluations(srs: &KzgSrs, evals: &[Fr]) -> Result<KzgCommitment, KzgError> {
    let mut coeffs = evals.to_vec();
    ifft(&mut coeffs);
    commit(srs, &coeffs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn root_of_unity_is_correct_order() {
        for &n in &[2usize, 4, 8, 16, 256, 1024] {
            let w = root_of_unity(n);
            // w^n == 1
            let mut acc = Fr::ONE;
            for _ in 0..n {
                acc *= w;
            }
            assert_eq!(acc, Fr::ONE, "ω_{}^{} should be 1", n, n);

            // w^(n/2) == -1 (primitive)
            let mut half = Fr::ONE;
            for _ in 0..(n / 2) {
                half *= w;
            }
            assert_eq!(half, -Fr::ONE, "ω_{} should be primitive", n);
        }
    }

    #[test]
    fn ifft_inverts_evaluation() {
        // f(x) = 1 + 2x at n = 2. f(1) = 3, f(-1) = -1.
        let mut evals = vec![Fr::from(3), -Fr::ONE];
        ifft(&mut evals);
        assert_eq!(evals, vec![Fr::ONE, Fr::from(2)]);
    }

    #[test]
    fn ifft_then_commit_matches_coefficient_commit() {
        let mut rng = OsRng;
        let srs = KzgSrs::random_unsafe(&mut rng, 256);
        let n = 256;
        let omega = root_of_unity(n);

        // Pick random coefficients, evaluate at all ω^i, run through commit_evaluations,
        // compare against committing the original coefficients directly.
        let coeffs: Vec<Fr> = (0..n).map(|_| Fr::random(&mut rng)).collect();
        let mut evals = vec![Fr::ZERO; n];
        let mut x = Fr::ONE;
        for i in 0..n {
            // evals[i] = f(ω^i) via Horner's rule
            let mut acc = Fr::ZERO;
            for c in coeffs.iter().rev() {
                acc = acc * x + c;
            }
            evals[i] = acc;
            x *= omega;
        }

        let c_via_coeffs = commit(&srs, &coeffs).unwrap();
        let c_via_evals = commit_evaluations(&srs, &evals).unwrap();
        assert_eq!(c_via_coeffs, c_via_evals);
    }

    #[test]
    fn small_domain_ifft_matches_naive() {
        let mut rng = OsRng;
        let n = 8;
        let omega = root_of_unity(n);

        let coeffs: Vec<Fr> = (0..n).map(|_| Fr::random(&mut rng)).collect();
        let mut evals = vec![Fr::ZERO; n];
        let mut x = Fr::ONE;
        for i in 0..n {
            let mut acc = Fr::ZERO;
            for c in coeffs.iter().rev() {
                acc = acc * x + c;
            }
            evals[i] = acc;
            x *= omega;
        }

        let mut recovered = evals.clone();
        ifft(&mut recovered);
        assert_eq!(recovered, coeffs);
    }
}
