//! Hypersnap: the Farcaster data network of snapchain, then its own chain
//! from the epoch-1 pivot (FIP-proof-of-work-tokenization).
//!
//! ## Module map
//!
//! - [`chain`]: the chain after the pivot. Shard 0 (FID registry, signers,
//!   token ledger, validators, work markets) in [`chain::shard0`], the
//!   blocks of shards 1 and 2, the replica, checkpoints, the pivot and the
//!   genesis.
//! - [`node`]: the snapchain node before the pivot, the pivot boot, and the
//!   Hypersnap node after it ([`node::hypersnap_main`]).
//! - [`storage`]: the snapchain stores and the Keccak state trie.
//! - [`network`], [`consensus`], [`mempool`]: gossip, Malachite consensus and
//!   the mempool, for both chains.
//! - [`api`], [`connectors`], [`utils`]: supporting subsystems.
//!
//! The scoring (FIP §6-§8) is the `proof-of-quality` crate.

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

#[cfg(not(target_env = "msvc"))]
#[allow(non_upper_case_globals)]
#[export_name = "malloc_conf"]
pub static malloc_conf: &[u8] =
    b"background_thread:true,dirty_decay_ms:5000,muzzy_decay_ms:10000,narenas:16\0";

pub mod api;
pub mod bootstrap;
pub mod cfg;
pub mod chain;
pub mod connectors;
pub mod consensus;
pub mod core;
pub mod jobs;
pub mod mempool;
pub mod network;
pub mod node;
pub mod perf;
pub mod storage;
pub mod utils;
pub mod version;

mod tests;

pub use hypersnap_proto::proto;
