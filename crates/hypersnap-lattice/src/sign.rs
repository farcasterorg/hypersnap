//! Signing, verification, and proof of possession.

use rand_core::{CryptoRng, RngCore};
use zeroize::{Zeroize, Zeroizing};

use crate::hash;
use crate::keys::{PublicKey, SecretKey};
use crate::matrix::expand_a;
use crate::packing::{check_len, BitReader, BitWriter};
use crate::params::ParamSet;
use crate::rounding::decompose;
use crate::sampling::{expand_mask, sample_in_ball, Challenge};
use crate::Error;

/// Context string of the proof of possession (FIP §4.5, §16.4). Reserved:
/// [`SecretKey::sign`] and [`PublicKey::verify`] refuse it.
pub const POP_CONTEXT: &[u8] = b"hypersnap-validator-lwe-pop-v1";

/// Longest context string.
pub const MAX_CONTEXT_LEN: usize = 255;

/// Signing gives up after this many attempts. With the provisional set
/// (≈2.4 expected attempts) the chance of reaching it is below 2^-500.
pub const MAX_SIGN_ATTEMPTS: u32 = 1000;

/// An LWE-FSA signature `(c̃, z)`.
///
/// `c̃` is the 32-byte challenge seed, `c = SampleInBall(c̃)`. FIP §16.4
/// writes the signature as `(c, z)`; the seed is the canonical, compact
/// representation of `c`.
///
/// Encoding ([`Signature::to_bytes`]):
///
/// ```text
/// c̃   32 bytes
/// z   m coefficients, each stored as z_j + B ∈ [0, 2B] in bitlen(2B) bits,
///     packed little-endian, zero-padded to a byte
/// ```
///
/// There is no parameter-set header: a signature is always decoded against
/// the parameter set of the key that must verify it.
#[derive(Clone, PartialEq, Eq)]
pub struct Signature {
    params: &'static ParamSet,
    c_tilde: [u8; 32],
    z: Vec<i32>,
}

impl std::fmt::Debug for Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Signature")
            .field("params", &self.params.id)
            .field("c_tilde", &crate::hex(&self.c_tilde))
            .finish_non_exhaustive()
    }
}

impl Signature {
    /// The parameter set of this signature.
    pub fn params(&self) -> &'static ParamSet {
        self.params
    }

    /// The challenge seed `c̃`.
    pub fn c_tilde(&self) -> &[u8; 32] {
        &self.c_tilde
    }

    /// The response `z`, `||z||∞ ≤ B`.
    pub fn z(&self) -> &[i32] {
        &self.z
    }

    /// The challenge `c = SampleInBall(c̃)`.
    pub fn challenge(&self) -> Challenge {
        sample_in_ball(self.params, &self.c_tilde)
    }

    /// Canonical encoding (see the type documentation).
    pub fn to_bytes(&self) -> Vec<u8> {
        let p = self.params;
        let b = p.z_bound() as i32;
        let bits = p.z_bits();
        let mut w = BitWriter::with_capacity(p.signature_bytes());
        w.bytes(&self.c_tilde);
        for &zj in &self.z {
            w.write((zj + b) as u32, bits);
        }
        let out = w.finish();
        debug_assert_eq!(out.len(), p.signature_bytes());
        out
    }

    /// Strict decoding: exact length, every `|z_j| ≤ B`, zero padding.
    pub fn from_bytes(params: &'static ParamSet, bytes: &[u8]) -> Result<Signature, Error> {
        check_len(bytes, params.signature_bytes())?;
        let mut r = BitReader::new(bytes);
        let c_tilde = r.bytes::<32>();
        let b = params.z_bound();
        let bits = params.z_bits();
        let mut z = Vec::with_capacity(params.m);
        for _ in 0..params.m {
            let v = r.read(bits);
            if v > 2 * b {
                return Err(Error::CoefficientOutOfRange);
            }
            z.push(v as i32 - b as i32);
        }
        r.finish()?;
        Ok(Signature { params, c_tilde, z })
    }
}

fn check_context(ctx: &[u8]) -> Result<(), Error> {
    if ctx.is_empty() {
        return Err(Error::EmptyContext);
    }
    if ctx.len() > MAX_CONTEXT_LEN {
        return Err(Error::ContextTooLong);
    }
    if ctx == POP_CONTEXT {
        return Err(Error::ReservedContext);
    }
    Ok(())
}

/// Packs `HighBits(w)` for the challenge hash.
fn pack_w1(p: &ParamSet, w: &[u32], out: &mut Vec<u8>) {
    let bits = p.w1_bits();
    let mut wr = BitWriter::with_capacity((p.n * bits as usize).div_ceil(8));
    for &wi in w {
        wr.write(decompose(wi, p.q, p.gamma2).0, bits);
    }
    *out = wr.finish();
}

impl SecretKey {
    /// Deterministic signature on `msg` under the context string `ctx`.
    ///
    /// `ctx` is the per-use domain separator of FIP §16.4 ("H_c uses SHAKE256
    /// with a domain separator for each use"): give each message type its own
    /// non-empty `ctx` of at most 255 bytes. [`POP_CONTEXT`] is reserved.
    ///
    /// The masking vectors come from `ρ' = PRF(K, 0^32, μ̂)`, so the same
    /// `(key, ctx, msg)` always gives the same signature. This needs no RNG at
    /// signing time and cannot fail from a bad RNG. See
    /// [`SecretKey::sign_hedged`] for the randomized variant.
    pub fn sign(&self, ctx: &[u8], msg: &[u8]) -> Result<Signature, Error> {
        check_context(ctx)?;
        Ok(sign_internal(self, ctx, msg, &[0u8; 32])?.0)
    }

    /// Hedged signature: as [`SecretKey::sign`], but 32 fresh bytes from
    /// `rng` also enter `ρ'`. Signatures are then randomized, which adds
    /// protection against fault attacks and some side channels; a broken RNG
    /// degrades this to the deterministic case, not worse.
    pub fn sign_hedged<R: RngCore + CryptoRng>(
        &self,
        ctx: &[u8],
        msg: &[u8],
        rng: &mut R,
    ) -> Result<Signature, Error> {
        check_context(ctx)?;
        let mut rnd = Zeroizing::new([0u8; 32]);
        rng.fill_bytes(&mut rnd[..]);
        Ok(sign_internal(self, ctx, msg, &rnd)?.0)
    }

    /// Diagnostic variant of signing with explicit randomness `rnd` (all-zero
    /// for the deterministic signature). Also returns the number of attempts
    /// (1 + the number of aborts). Use it to measure the abort rate.
    pub fn sign_with_attempts(
        &self,
        ctx: &[u8],
        msg: &[u8],
        rnd: &[u8; 32],
    ) -> Result<(Signature, u32), Error> {
        check_context(ctx)?;
        sign_internal(self, ctx, msg, rnd)
    }
}

/// FIP §16.4 signing loop.
///
/// ```text
/// μ̂  = SHAKE256(DS_MU || tr || len(ctx) || ctx || msg)          64 bytes
/// ρ'  = SHAKE256(DS_RHO || K || rnd || μ̂)                        64 bytes
/// for attempt = 0, 1, …:
///     y  = ExpandMask(ρ', attempt)              ∈ [-γ1+1, γ1]^m
///     w  = A·y mod q
///     c̃  = SHAKE256(DS_CHAL || μ̂ || pack(HighBits(w)))           32 bytes
///     c  = SampleInBall(c̃)
///     z  = y + S·c;   abort if ||z||∞ > B
///     r0 = LowBits(w - E·c);  abort if ||r0||∞ ≥ γ2 - β
///     return (c̃, z)
/// ```
fn sign_internal(
    sk: &SecretKey,
    ctx: &[u8],
    msg: &[u8],
    rnd: &[u8; 32],
) -> Result<(Signature, u32), Error> {
    let p = sk.params;
    let a = expand_a(p);
    let mu = hash::mu_hat(&sk.tr, ctx, msg);
    let rho = Zeroizing::new(hash::rho_prime(&sk.key, rnd, &mu));
    let b = p.z_bound() as i32;
    let low = p.low_bound();

    let mut y = Zeroizing::new(vec![0i32; p.m]);
    let mut sc = Zeroizing::new(vec![0i32; p.m]);
    let mut ec = Zeroizing::new(vec![0i32; p.n]);
    let mut w = Zeroizing::new(vec![0u32; p.n]);
    let mut scratch = Zeroizing::new(Vec::new());
    let mut w1 = Zeroizing::new(Vec::new());

    for attempt in 0..MAX_SIGN_ATTEMPTS {
        expand_mask(p, &rho, attempt, &mut y, &mut scratch);
        a.mul_vec_mod(p.q, &y, None, &mut w);
        pack_w1(p, &w, &mut w1);
        let c_tilde = hash::challenge_seed(&mu, &w1);
        let c = sample_in_ball(p, &c_tilde);

        // z = y + S·c, computed in place over y.
        sk.s_times(&c, &mut sc);
        let mut z_ok = true;
        for (yj, &scj) in y.iter_mut().zip(sc.iter()) {
            *yj += scj;
            z_ok &= yj.abs() <= b;
        }
        if !z_ok {
            continue;
        }

        // LowBits(w - E·c).
        sk.e_times(&c, &mut ec);
        let mut r_ok = true;
        for (&wi, &eci) in w.iter().zip(ec.iter()) {
            let r = (wi as i64 - eci as i64).rem_euclid(p.q as i64) as u32;
            r_ok &= decompose(r, p.q, p.gamma2).1.unsigned_abs() < low;
        }
        if !r_ok {
            continue;
        }

        let z = y.to_vec();
        y.zeroize();
        return Ok((
            Signature {
                params: p,
                c_tilde,
                z,
            },
            attempt + 1,
        ));
    }
    Err(Error::SigningFailed)
}

impl PublicKey {
    /// Verifies `sig` on `msg` under the context string `ctx`.
    ///
    /// ```text
    /// accept iff ||z||∞ ≤ B  and
    ///            c̃ == SHAKE256(DS_CHAL || μ̂ || pack(HighBits(A·z - T·c mod q)))
    /// ```
    ///
    /// Not constant-time; it handles public data only.
    pub fn verify(&self, ctx: &[u8], msg: &[u8], sig: &Signature) -> Result<(), Error> {
        check_context(ctx)?;
        verify_internal(self, ctx, msg, sig)
    }

    /// Decodes `sig` strictly and verifies it.
    pub fn verify_bytes(&self, ctx: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), Error> {
        check_context(ctx)?;
        let sig = Signature::from_bytes(self.params, sig)?;
        verify_internal(self, ctx, msg, &sig)
    }
}

fn verify_internal(pk: &PublicKey, ctx: &[u8], msg: &[u8], sig: &Signature) -> Result<(), Error> {
    let p = pk.params;
    if sig.params != p {
        return Err(Error::ParamSetMismatch {
            expected: p.id,
            actual: sig.params.id,
        });
    }
    let b = p.z_bound() as i32;
    if sig.z.len() != p.m || sig.z.iter().any(|zj| zj.abs() > b) {
        return Err(Error::InvalidSignature);
    }
    let a = expand_a(p);
    let c = sample_in_ball(p, &sig.c_tilde);
    let mut tc = vec![0i64; p.n];
    pk.neg_t_times(&c, &mut tc);
    let tc: Vec<i32> = tc
        .iter()
        .map(|&v| v.rem_euclid(p.q as i64) as i32)
        .collect();
    let mut w = vec![0u32; p.n];
    a.mul_vec_mod(p.q, &sig.z, Some(&tc), &mut w);
    let mut w1 = Vec::new();
    pack_w1(p, &w, &mut w1);
    let mu = hash::mu_hat(&pk.tr, ctx, msg);
    if hash::challenge_seed(&mu, &w1) == sig.c_tilde {
        Ok(())
    } else {
        Err(Error::InvalidSignature)
    }
}

/// Proof of possession of a new validator key (FIP §4.5, §16.4): an LWE-FSA
/// signature by the key over the registration payload, under the reserved
/// context [`POP_CONTEXT`]. It prevents rogue-key attacks on the plain key
/// sum of LWE-MS2 (§16.5).
pub fn prove_possession(sk: &SecretKey, registration_payload: &[u8]) -> Result<Signature, Error> {
    Ok(sign_internal(sk, POP_CONTEXT, registration_payload, &[0u8; 32])?.0)
}

/// Verifies a proof of possession made by [`prove_possession`].
pub fn verify_possession(
    pk: &PublicKey,
    registration_payload: &[u8],
    sig: &Signature,
) -> Result<(), Error> {
    verify_internal(pk, POP_CONTEXT, registration_payload, sig)
}
