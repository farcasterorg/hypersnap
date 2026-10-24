//! Hypersnap message encodings, shared by the node and wallets
//! (FIP-proof-of-work-tokenization §14.1, §16.7, §16.8).
//!
//! The node verifies messages with these functions and a wallet signs with
//! them, so both sides use the same bytes:
//!
//! - [`envelope`]: the message hash, the Falcon-512 signer ID, and the signed
//!   forms of a `Message` (§16.8).
//! - [`second`]: the payload of a second signature in a body (§14.1), and,
//!   for each body with second-signature fields, the function that empties
//!   them.
//! - [`eip712`]: the EIP-712 form of a second signature (§16.7).

pub mod eip712;
pub mod envelope;
pub mod second;

pub use eip712::{
    eip712_hash, eip712_sign, eip712_sign_hash, recover_eip712, Eip712Error,
    EIP712_CUSTODY_MIGRATION, EIP712_DOMAIN_NAME, EIP712_DOMAIN_VERSION,
    EIP712_TOKEN_ESCROW_BRIDGE, EIP712_TOKEN_ESCROW_CLAIM,
};
pub use envelope::{
    blake3_20, dual_message, ed25519_message, falcon_key_hash, falcon_message, falcon_public,
    falcon_sign, unsigned_message, EXTENSION_VERSION,
};
pub use second::{
    clear_custody_migration, clear_custody_rotation, clear_escrow_bridge, clear_escrow_claim,
    clear_key_add_falcon, clear_node_attestation, clear_spend_key_add,
    clear_validator_registration, pair_key_add_custody_parts, second_signature_payload,
};
