//! Hypersnap wallet SDK (FIP-proof-of-work-tokenization §13, §14, §16.7-§16.11).
//!
//! - [`keys`]: Falcon-512 keys (account, recovery, spend, signer and node
//!   keys), Ed25519 app keys, and the Ethereum key of a classical custody
//!   address.
//! - [`tx`]: builders that return a signed `Message` in the form that the
//!   node's shard-0 verifiers accept. The envelope, the second-signature
//!   payloads and the EIP-712 forms come from `hypersnap_messages`, the
//!   encoders that the node verifies with.
//! - [`client`]: `POST /v1/submitMessage` to a node.
//!
//! A hardware wallet signs the EIP-712 hash of [`tx::eip712_digest`] (or of a
//! `*_digest` builder) as a prehash; the builder then takes the signature
//! ([`tx::Eip712Auth::Signature`]).
//!
//! The genesis entry of a bootstrap validator (FIP §17.3) is made by
//! `hypersnap_pivot entry` in the node crate.

pub mod client;
pub mod error;
pub mod keys;
pub mod tx;

pub use client::HypersnapClient;
pub use error::WalletError;
pub use keys::{
    generate_ed25519, generate_falcon_seed, load_ed25519_key, load_eth_key, load_falcon_key,
    load_falcon_public, write_secret,
};
