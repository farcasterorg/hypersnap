//! Hypersnap <-> snapchain relay worker (FIP-proof-of-work-tokenization,
//! Appendix A).
//!
//! After the epoch-1 pivot, snapchain and Hypersnap are separate networks.
//! This process copies user messages between them:
//!
//! - **Inbound** (snapchain -> Hypersnap): finalized snapchain chunks
//!   (`GetShardChunks`, shards 1 and 2) and blocks (`GetBlocks`, shard 0),
//!   without system messages, to Hypersnap with `SubmitBulkMessages`.
//! - **Outbound** (Hypersnap -> snapchain): certified Hypersnap blocks through
//!   [`source::hypersnap::HypersnapBlockSource`], filtered by the snapchain
//!   `MessageType` allowlist and rewritten to their Ed25519 form, to snapchain.
//!
//! The relay holds no keys. It persists one cursor per (network, shard) and
//! two bounded seen sets whose membership is the origin tag of a message, so
//! a message is never sent back to the network it came from.

pub mod classify;
pub mod config;
pub mod endpoints;
pub mod filter;
pub mod metrics;
pub mod relay;
pub mod retry;
pub mod source;
pub mod store;
pub mod submit;
pub mod types;
pub mod worker;

pub use config::RelayConfig;
pub use relay::{RelayBuilder, RelayError};
pub use retry::{Shutdown, ShutdownTrigger};
pub use source::hypersnap::{HypersnapBlockSource, MemoryHypersnapSource};

pub use hypersnap_proto;

#[cfg(test)]
#[path = "../tests/common/messages.rs"]
pub(crate) mod testutil;
