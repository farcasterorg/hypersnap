//! Hash functions and domain separators.
//!
//! Every SHAKE256 call absorbs `len(ds) as u8 || ds` first, where `ds` is
//! one of the constants below, so no two uses of the hash share an input.

use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{Digest, Keccak256, Shake256, Shake256Reader};

/// ExpandA seed prefix (FIP §16.4): `SHAKE128("hypersnap-lwe-A-v1" || id_be32)`.
pub const DS_EXPAND_A: &[u8] = b"hypersnap-lwe-A-v1";
/// Seed expansion in key generation.
pub(crate) const DS_KEYGEN: &[u8] = b"hypersnap-lwe-fsa-v1/keygen";
/// Sampling of `S`.
pub(crate) const DS_S: &[u8] = b"hypersnap-lwe-fsa-v1/S";
/// Sampling of `E`.
pub(crate) const DS_E: &[u8] = b"hypersnap-lwe-fsa-v1/E";
/// `tr = H(encoded public key)`.
pub(crate) const DS_TR: &[u8] = b"hypersnap-lwe-fsa-v1/tr";
/// Message representative `μ̂ = H(tr, ctx, msg)`.
pub(crate) const DS_MU: &[u8] = b"hypersnap-lwe-fsa-v1/mu";
/// Per-signature mask seed `ρ' = PRF(K, rnd, μ̂)`.
pub(crate) const DS_RHO: &[u8] = b"hypersnap-lwe-fsa-v1/rho";
/// `ExpandMask(ρ', attempt)`.
pub(crate) const DS_MASK: &[u8] = b"hypersnap-lwe-fsa-v1/mask";
/// `H_c`: challenge seed `c̃ = H(μ̂, HighBits(w))`.
pub(crate) const DS_CHAL: &[u8] = b"hypersnap-lwe-fsa-v1/chal";
/// `SampleInBall(c̃)`.
pub(crate) const DS_BALL: &[u8] = b"hypersnap-lwe-fsa-v1/ball";

/// SHAKE256 with a length-prefixed domain separator already absorbed.
pub(crate) fn shake256(ds: &[u8]) -> Shake256 {
    debug_assert!(ds.len() < 256);
    let mut h = Shake256::default();
    h.update(&[ds.len() as u8]);
    h.update(ds);
    h
}

pub(crate) fn finish<const N: usize>(h: Shake256) -> [u8; N] {
    let mut out = [0u8; N];
    h.finalize_xof().read(&mut out);
    out
}

/// Buffered XOF reader, so byte-at-a-time sampling stays cheap.
pub(crate) struct Xof<R: XofReader> {
    reader: R,
    buf: [u8; 1088],
    pos: usize,
}

impl<R: XofReader> Xof<R> {
    pub(crate) fn new(reader: R) -> Self {
        Xof {
            reader,
            buf: [0u8; 1088],
            pos: 1088,
        }
    }

    #[inline]
    pub(crate) fn byte(&mut self) -> u8 {
        if self.pos == self.buf.len() {
            self.reader.read(&mut self.buf);
            self.pos = 0;
        }
        let b = self.buf[self.pos];
        self.pos += 1;
        b
    }

    /// `nbytes` bytes, little-endian.
    #[inline]
    pub(crate) fn le(&mut self, nbytes: u32) -> u32 {
        let mut v = 0u32;
        for i in 0..nbytes {
            v |= (self.byte() as u32) << (8 * i);
        }
        v
    }

    pub(crate) fn fill(&mut self, out: &mut [u8]) {
        for b in out.iter_mut() {
            *b = self.byte();
        }
    }
}

impl<R: XofReader> Drop for Xof<R> {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.buf);
    }
}

pub(crate) fn xof256(h: Shake256) -> Xof<Shake256Reader> {
    Xof::new(h.finalize_xof())
}

/// `tr = SHAKE256(DS_TR || encoded_pk)`, 64 bytes.
pub(crate) fn tr(pk_bytes: &[u8]) -> [u8; 64] {
    let mut h = shake256(DS_TR);
    h.update(pk_bytes);
    finish(h)
}

/// `μ̂ = SHAKE256(DS_MU || tr || len(ctx) as u8 || ctx || msg)`, 64 bytes.
pub(crate) fn mu_hat(tr: &[u8; 64], ctx: &[u8], msg: &[u8]) -> [u8; 64] {
    debug_assert!(ctx.len() < 256);
    let mut h = shake256(DS_MU);
    h.update(tr);
    h.update(&[ctx.len() as u8]);
    h.update(ctx);
    h.update(msg);
    finish(h)
}

/// `ρ' = SHAKE256(DS_RHO || K || rnd || μ̂)`, 64 bytes.
pub(crate) fn rho_prime(key: &[u8; 32], rnd: &[u8; 32], mu: &[u8; 64]) -> [u8; 64] {
    let mut h = shake256(DS_RHO);
    h.update(key);
    h.update(rnd);
    h.update(mu);
    finish(h)
}

/// `c̃ = SHAKE256(DS_CHAL || μ̂ || pack(HighBits(w)))`, 32 bytes.
pub(crate) fn challenge_seed(mu: &[u8; 64], w1_packed: &[u8]) -> [u8; 32] {
    let mut h = shake256(DS_CHAL);
    h.update(mu);
    h.update(w1_packed);
    finish(h)
}

/// Ethereum Keccak-256 (not SHA3-256).
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    Keccak256::digest(data).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keccak256_is_ethereum_keccak() {
        // keccak256("") = c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
        let h = keccak256(b"");
        assert_eq!(h[..4], [0xc5, 0xd2, 0x46, 0x01]);
        assert_eq!(h[28..], [0x5d, 0x85, 0xa4, 0x70]);
    }

    #[test]
    fn domain_separators_are_distinct() {
        let all = [
            DS_EXPAND_A,
            DS_KEYGEN,
            DS_S,
            DS_E,
            DS_TR,
            DS_MU,
            DS_RHO,
            DS_MASK,
            DS_CHAL,
            DS_BALL,
        ];
        for (i, a) in all.iter().enumerate() {
            for b in &all[i + 1..] {
                assert_ne!(a, b);
            }
        }
    }
}
