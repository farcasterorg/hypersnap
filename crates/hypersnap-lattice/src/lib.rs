//! # LWE-FSA: validator consensus signatures over unstructured lattices
//!
//! This crate implements LWE-FSA, the validator signature of FIP
//! proof-of-work tokenization §16.4: a stateless Fiat–Shamir signature with
//! aborts over **unstructured** LWE/SIS, after Lyubashevsky (EUROCRYPT 2012)
//! and Bai–Galbraith (CT-RSA 2014). The rounding of the commitment is
//! Dilithium's `Decompose`, applied coefficient-wise over `Z_q`.
//!
//! > **Status: PROVISIONAL.** The only production-candidate parameter set,
//! > [`params::PROVISIONAL_V1`] (`LWE_PARAM_SET_ID = 1`), is not frozen. A
//! > release freezes it after external review of the lattice-estimator
//! > output in `params/`. The [`params::TEST`] set is insecure.
//!
//! ## Scheme
//!
//! ```text
//! A  = ExpandA(SHAKE128("hypersnap-lwe-A-v1" || LWE_PARAM_SET_ID be32))  ∈ Z_q^{n×m}
//! sk = (S ∈ [-η,η]^{m×k}, E ∈ [-η,η]^{n×k}, K)          pk = T = A·S + E mod q
//!
//! Sign(sk, ctx, μ):                                       Verify(pk, ctx, μ, (c̃, z)):
//!   y ← ExpandMask(ρ', attempt) ∈ [-γ1+1, γ1]^m            ||z||∞ ≤ B
//!   w = A·y mod q                                          c  = SampleInBall(c̃)
//!   c̃ = H_c(μ̂, HighBits(w));  c = SampleInBall(c̃)          w' = A·z - T·c mod q
//!   z = y + S·c                                            c̃ == H_c(μ̂, HighBits(w'))
//!   abort if ||z||∞ > B or ||LowBits(w - E·c)||∞ ≥ γ2 - β
//! ```
//!
//! with `μ̂ = H(tr, ctx, μ)`, `tr = H(encoded pk)`, `β = κ·η`,
//! `B = γ1 - β - 1`. Since `w' = w - E·c` and `||E·c||∞ ≤ β`, the low-bits
//! check makes `HighBits(w') = HighBits(w)`, so honest signatures verify.
//!
//! ## Byte-level specification
//!
//! Integers in hash inputs are big-endian. `H(ds; x)` is
//! `SHAKE256(len(ds) as u8 || ds || x)`; every `ds` below starts with
//! `hypersnap-lwe-fsa-v1/`. Bit packing is little-endian, least-significant
//! bit first.
//!
//! ```text
//! ExpandA      XOF = SHAKE128("hypersnap-lwe-A-v1" || id_be32)   (no length prefix)
//!              A row-major; each entry: next ⌈bitlen(q-1)/8⌉ bytes LE, masked
//!              to bitlen(q-1) bits, rejected unless < q
//! KeyGen       (σ_S, σ_E, K) = H(keygen; id_be32 || seed)[0..96]
//!              S = SampleShort(H(S; σ_S)), m·k coefficients, column-major
//!              E = SampleShort(H(E; σ_E)), n·k coefficients, column-major
//! SampleShort  b = bitlen(2η); each XOF byte yields ⌊8/b⌋ b-bit candidates,
//!              low bits first; candidate v ≤ 2η gives η - v, others are skipped
//! tr           H(tr; encoded pk)[0..64]
//! μ̂            H(mu; tr || len(ctx) as u8 || ctx || msg)[0..64]
//! ρ'           H(rho; K || rnd || μ̂)[0..64]     rnd = 0^32 (deterministic) or RNG
//! ExpandMask   H(mask; ρ' || attempt_be32)[0..⌈m·b/8⌉], b = log2(γ1) + 1,
//!              y_j = γ1 - (j-th b-bit value)
//! w1           pack(HighBits(w_0), …, HighBits(w_{n-1})), bitlen(M-1) bits each
//! c̃            H(chal; μ̂ || w1)[0..32]
//! SampleInBall XOF = H(ball; c̃): ⌈κ/8⌉ sign bytes, then index candidates of
//!              ⌈bitlen(k-1)/8⌉ bytes LE masked to bitlen(k-1) bits (see
//!              [`Signature::challenge`])
//! ```
//!
//! The encodings of keys and signatures are documented on [`PublicKey`],
//! [`SecretKey`] and [`Signature`].
//!
//! ## Domain separation ("context")
//!
//! FIP §16.4 requires a domain separator for each use of `H_c`. Every
//! signature therefore takes a non-empty context string `ctx` (≤ 255 bytes)
//! that is hashed into `μ̂`. Use one context per message type (vote,
//! proposal, commit, …). The proof of possession uses the reserved
//! [`POP_CONTEXT`] through [`prove_possession`] / [`verify_possession`]
//! only.
//!
//! ## Deterministic signing
//!
//! [`SecretKey::sign`] is deterministic: `ρ' = PRF(K, 0^32, μ̂)` with the
//! 32-byte secret PRF key `K`. Repeated signing of the same `(ctx, μ)` gives
//! the same signature, and signing needs no RNG. [`SecretKey::sign_hedged`]
//! mixes 32 RNG bytes into `ρ'` (hedged signing). Both verify identically.
//! Deterministic nonces are safe here because a Fiat–Shamir-with-aborts
//! signature reveals nothing about `S` from the *accepted* `(c̃, z)`; the
//! danger of nonce reuse in Schnorr-style schemes (two different challenges
//! for one `y`) cannot occur, because `y` is a function of `μ̂`, and `c̃` a
//! function of `(μ̂, y)`.
//!
//! **This does not carry over to LWE-MS2** (§16.5): its round-1 randomness
//! must never be derived deterministically from the message, see the
//! signer safety rules of §16.5.
//!
//! ## Side channels
//!
//! Verification handles public data and is not constant-time. Signing is
//! **not constant-time** either:
//!
//! * the number of attempts (≈2.4 for the provisional set) is visible in the
//!   timing. This is inherent to rejection sampling and leaks nothing about
//!   the key by itself, since rejected attempts are independent of the output;
//! * the rejection checks scan all coefficients without early exit, but
//!   `Decompose` branches on its (secret-dependent) input, and `S·c` and
//!   `E·c` access the columns of `S` and `E` selected by the challenge of
//!   each attempt. For a *rejected* attempt this challenge and `w` are never
//!   published, and leaking them (e.g. through cache or branch timing)
//!   together with the fact of rejection gives information about `S` and
//!   `E`. Validators sign on dedicated machines; do not co-locate untrusted
//!   code with a signer.
//! * secret buffers (`S`, `E`, `K`, `y`, `S·c`, `ρ'`) are zeroized on drop.
//!
//! ## Sizes (provisional set)
//!
//! | object      | bytes   |
//! |-------------|---------|
//! | public key  | 901 124 |
//! | secret key  | 163 876 (or the 32-byte seed) |
//! | signature   | 3 072   |
//!
//! `address(pk) = keccak256(encoded pk)` (Ethereum Keccak-256) is the
//! validator key hash of the FIP.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod error;
mod hash;
mod keys;
mod matrix;
mod packing;
pub mod params;
mod rounding;
mod sampling;
mod sign;

pub use error::Error;
pub use hash::{keccak256, DS_EXPAND_A};
pub use keys::{Keypair, PublicKey, SecretKey};
pub use matrix::{expand_a, expand_a_uncached, MatrixA};
pub use params::{ParamSet, ParamStatus, GOLDILOCKS_P};
pub use sampling::Challenge;
pub use sign::{
    prove_possession, verify_possession, Signature, MAX_CONTEXT_LEN, MAX_SIGN_ATTEMPTS, POP_CONTEXT,
};

/// `address(pk) = keccak256(encoded pk)`.
pub fn address(pk: &PublicKey) -> [u8; 32] {
    pk.address()
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
