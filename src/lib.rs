//! Hypersnap — proof-of-quality + threshold-signed hyperblocks +
//! validator selection on top of the snapchain data network.
//!
//! ## Module map
//!
//! - [`hyper`] — the hyper-layer protocol surface: validator
//!   registration ([`hyper::validator_registry`]), in-protocol scoring
//!   driver ([`hyper::scoring_driver`]), threshold-signed hyperblocks
//!   ([`hyper::builder`], [`hyper::importer`]), trust snapshot store
//!   ([`hyper::trust_store`]), epoch resolver ([`hyper::epoch_resolver`]),
//!   DKLS23 DKG ceremony ([`hyper::dkls_supervisor`], [`hyper::dkls_driver`]),
//!   actor wrapper ([`hyper::actor`]), and the production reader
//!   ([`hyper::poq_reader`]).
//! - [`storage`] — the snapchain-compatible storage layer (cast/like/
//!   follow/reaction stores + the hyper trie).
//! - [`network`] — libp2p gossip, snapchain-compatible topics + the
//!   hyper-layer topics.
//! - [`node`] — the validator binary's main loop.
//! - [`api`], [`connectors`], [`emission`], [`mempool`], [`consensus`],
//!   [`utils`] — supporting subsystems.
//!
//! ## FIPs implemented
//!
//! - **FIP-hyper-validator-selection** — validator registration with
//!   FID binding + cross-sign, max 3 per FID, trust gating, DKG
//!   ceremonies at epoch boundaries, missed-proposal scoring.
//!   Surfaces: [`hyper::validator_registry`], [`hyper::dkls_supervisor`],
//!   [`hyper::epoch`].
//! - **FIP-proof-of-work-tokenization** — three work markets (Data
//!   Availability, Growth, App Usage) with per-epoch budget caps,
//!   per-FID per-market replay protection, in-protocol scoring +
//!   threshold-signed reward issuance + trust snapshot rotation.
//!   Surfaces: [`hyper::rewards`], [`hyper::trust_store`],
//!   [`hyper::scoring_driver`], `proof_of_quality` crate.
//! - **§4.3 cutover** — block-pinned deterministic transition from
//!   static-PoA snapchain validator set to the epoch-based hyper
//!   validator set. Surface: [`hyper::runtime::HyperRuntime::apply_cutover`].
//! - **§5.2 slashing** — observational evidence detection +
//!   threshold-signed conflict eviction at the next epoch boundary.
//!   Surfaces: [`hyper::slashing`], [`hyper::slashing_store`].
//!
//! ## Determinism
//!
//! Every input that affects a threshold-signed payload is byte-
//! deterministic across validators:
//!
//! - FID universe — derived from the snapchain `OnchainEventStore`.
//! - Seeds — `fid ≤ runtime.seed_max_fid` (protocol constant).
//! - Scoring params — `runtime.scoring_params` (protocol constant).
//! - `now_unix` — committed in the imported hyperblock's
//!   [`hyper::HyperBlockMetadata::snapchain_anchor_timestamp`] and
//!   signed by the active set.
//! - Map iteration — `BTreeMap` everywhere in the scoring pipeline.
//!
//! See `crates/proof-of-quality/` for the canonical scoring math and
//! `src/hyper/determinism_test.rs` for the property tests that lock
//! the determinism contract.

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
pub mod connectors;
pub mod consensus;
pub mod core;
pub mod emission;
pub mod hyper;
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
