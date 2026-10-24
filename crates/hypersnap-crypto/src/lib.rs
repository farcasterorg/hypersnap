//! Cryptographic primitives for hypersnap.
//!
//! - [`bridge_payload`]: the bridge lock leaves and the typed-data digests
//!   of the bridge contract.
//! - [`merkle`]: the sorted-pair Keccak tree of the bridge lock set
//!   (OpenZeppelin `MerkleProof`).

pub mod bridge_payload;
pub mod merkle;
