//! Cryptographic primitives for hypersnap.
//!
//! - [`dkls_threshold`] / [`dkls_ceremony`] / [`dkls_sign`] —
//!   DKLS23 threshold ECDSA over secp256k1: the validator-set
//!   signing stack and DKG. The bridge contract verifies these
//!   signatures via `ECDSA.recover` against the per-epoch group
//!   address.
//! - [`ecdsa`] — `EcdsaSignature` wrapper around
//!   `alloy_primitives::PrimitiveSignature` with recovery and
//!   address-equality checks.
//! - [`bls`] — minimal BLS12-381 surface retained for the snapchain
//!   consensus layer's own validator-set parsing (independent of
//!   the hypersnap signing stack, which is DKLS23).
//! - [`bridge_payload`] / [`bridge_state`] — bridge owner key +
//!   typed-data signing helpers.
//! - [`kzg`] / [`kzg_lagrange`] / [`kzg_loader`] / [`verkle`] —
//!   verkle tree primitives for the hyper state root.
//! - [`merkle`] — merkle tree primitives.
//! - [`tokens`] — Decaf448 stealth-address token layer (token
//!   transfers + nullifiers, separate from the signing stack).

pub mod bls;
pub mod bridge_payload;
pub mod bridge_state;
pub mod dkls_ceremony;
pub mod dkls_sign;
pub mod dkls_threshold;
pub mod ecdsa;
pub mod kzg;
pub mod kzg_lagrange;
pub mod kzg_loader;
pub mod merkle;
pub mod tokens;
pub mod transport_encrypt;
pub mod verkle;

// Re-export the underlying curve crates so downstream callers don't
// need to depend on them directly.
pub use bls12_381;
pub use bulletproofs;
pub use dkls23;
pub use k256;
