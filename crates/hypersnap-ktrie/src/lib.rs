//! # hypersnap-ktrie
//!
//! The Keccak-256 sparse binary Merkle trie that is the per-shard state
//! commitment of a Hypersnap node (FIP-proof-of-work-tokenization §16.13).
//!
//! # Hashing rules (normative)
//!
//! ```text
//! path(key)    = keccak256(key)
//! leaf(key, v) = keccak256(0x00 || keccak256(key) || keccak256(v))
//! inner(l, r)  = keccak256(0x01 || l || r)
//! empty        = 32 zero bytes
//! ```
//!
//! *Keccak-256* is Ethereum Keccak (original `0x01` padding), not FIPS-202
//! SHA3-256: `keccak256("") = c5d24601…5d85a470`. All concatenations are raw
//! bytes: a leaf preimage is 65 bytes, an inner preimage is 65 bytes.
//!
//! **Paths.** A key's path is the 256 bits of `keccak256(key)`, most
//! significant bit first: bit 0 is the top bit of byte 0, bit 255 the low bit
//! of byte 31. At depth `d` (the root is depth 0) bit `d` selects the left
//! (`0`) or right (`1`) child. The *subtree at depth `d` with prefix `P`*
//! (`|P| = d` bits) holds exactly the keys whose path starts with `P`.
//!
//! **Subtree hash.** For a set `S` of `(key, value)` pairs in the subtree at
//! depth `d`:
//!
//! ```text
//! H(S, d) = 0                               if |S| = 0   (empty subtree)
//!         = leaf(k, v)                      if S = {(k, v)}, at ANY depth
//!         = inner(H(S0, d+1), H(S1, d+1))   if |S| >= 2
//!   where Sb = { x in S : bit d of path(x) = b }
//!
//! state root = H(all pairs, 0)
//! ```
//!
//! "A subtree with one leaf is stored as that leaf" (path compression): a
//! single leaf's hash does not depend on its depth, and there are no hashes
//! for the empty levels between it and its parent. A subtree with two or more
//! leaves is always `inner(left, right)` at every level, and either side may be
//! `0`: if all its leaves share bit `d`, then `H = inner(H', 0)` (bit 0) or
//! `inner(0, H')` (bit 1). The recursion ends because distinct paths differ in
//! some bit below 256.
//!
//! **Edge cases.**
//!
//! * Empty trie: root = 32 zero bytes.
//! * One key `k`: root = `leaf(k, v)`. No inner node is hashed.
//! * Two keys whose paths share exactly `n` leading bits: the root is `n`
//!   nested one-sided inner nodes over `inner(leaf_a, leaf_b)`, where `leaf_a`
//!   is the one with bit `n = 0`. For example, with `n = 1` and shared bit
//!   `1`: `root = inner(0, inner(leaf_a, leaf_b))`.
//! * Values: the trie commits to `keccak256(v)`; the empty value is a valid
//!   value distinct from "absent". Deleting a key removes its leaf.
//! * Two keys with the same path (a Keccak collision) are treated as one key.
//!
//! The root depends only on the set of `(key, value)` pairs: never on
//! insertion order, batch boundaries, or deletions that happened before.
//! [`reference`] is a line-by-line transcription of the rules above, used to
//! test the stored implementation.
//!
//! # Storage layout
//!
//! Records live in a [`NodeStore`] under a [`NodeKey`]. The key of every
//! record is a function of the key set alone:
//!
//! | record | key bytes | value |
//! |---|---|---|
//! | root | `0x00` | `0x02 0x00` (empty) or `0x02 0x01 slot` |
//! | branch at bit `d` under prefix `P` | `0x01 d P[0..ceil(d/8)]` | `0x01 slot(left) slot(right)` |
//! | leaf of path `p` | `0x02 p` | `0x00 value_hash key` |
//!
//! ```text
//! slot = 0x00 path(32) hash(32)                                  child is one leaf
//!      | 0x01 d' P'[0..ceil(d'/8)] hash(32) count(u64 BE)        child is a branch
//! ```
//!
//! A slot's `hash` is the child subtree's hash at the parent's child depth
//! (`d + 1`), so an update or a proof reads exactly one record per stored
//! branch. Only *branching* levels are stored: a branch at `(d, P)` exists iff
//! the key set has keys under `P` on both sides of bit `d`. One-sided levels
//! above a branch are not stored; their hashes are recomputed on update.
//!
//! Why structural keys, rather than the two usual alternatives:
//!
//! * **Not hash-addressed** (Ethereum MPT style). Hash keys keep stale
//!   versions forever unless garbage collection or reference counting removes
//!   them. Here an update rewrites records in place and a delete removes them.
//! * **Not keyed by attachment position** (snapchain's trie keys a node by the
//!   path to it). With path compression, a node's position moves when a
//!   sibling is inserted above it or deleted. Here a leaf is keyed by its own
//!   path and a branch by its own `(depth, prefix)`, so neither ever moves.
//!   A put creates at most one leaf and one branch; a delete removes at most
//!   one leaf and one branch; everything else is an in-place rewrite of the
//!   branches on the path.
//!
//! As a result, the store contents are a canonical function of the state:
//! two nodes with the same key/value set have byte-identical trie records,
//! whatever their history. Branch keys are short (5 bytes at depth ~24, which
//! covers ~10M keys) and encode in path order within each depth. A RocksDB
//! adapter maps a key to `[RootPrefix byte] || NodeKey::encode()`, and maps
//! `get`/`put`/`delete` to the RocksDB calls.
//!
//! **Leaves store the original key.** [`KTrie::first_at_or_after`] returns
//! keys, not only paths. The data-availability protocol asks "the first key
//! at or after a path prefix", and the caller needs the key to load the value
//! from the state store. This costs `len(key)` bytes per leaf. The key is not
//! part of any hash: `leaf()` commits to `keccak256(key)` only.
//!
//! # Commit and rollback
//!
//! This follows the node's existing trie contract
//! (`src/storage/trie/merkle_trie.rs`: writes go into a batch that the caller
//! commits with the block; `reload()` discards in-memory state).
//!
//! * Updates ([`KTrie::apply`], [`KTrie::apply_ops`], [`KTrie::insert`],
//!   [`KTrie::delete`]) go into a *pending* overlay. [`KTrie::root`] includes
//!   them. Nothing is written to the store.
//! * [`KTrie::rollback`] discards the pending overlay, and the root returns
//!   to [`KTrie::committed_root`].
//! * [`KTrie::commit`] returns a [`CommitBatch`]: the new root, the key count,
//!   and the sorted, deduplicated puts and deletes. The pending overlay becomes
//!   the *staged* layer. The trie serves reads from the staged layer, so the
//!   caller can merge the batch into the block's atomic write and persist it
//!   later, provided that this happens **before the next `commit`**. At the
//!   next `commit`, the trie moves the staged layer into the node cache.
//!   [`KTrie::commit_to_store`] commits and applies the batch to the owned
//!   store in one step.
//! * [`KTrie::reload`] drops the pending, staged and cache layers and re-reads
//!   the root record. Use it after a restart (the result is the same root as
//!   before the restart), or to abandon a batch that was never persisted.
//!
//! The node cache holds only decoded records that are confirmed in the store.
//! It is a bounded two-generation LRU approximation
//! ([`KTrie::open_with_cache`]).
//!
//! # Proofs
//!
//! See [`proof`] for the format. [`verify_proof`] is pure: it needs only the
//! root, the key, the claimed value (or `None` for absence) and the proof.
//!
//! # Example
//!
//! ```
//! use hypersnap_ktrie::{verify_proof, KTrie, MemStore, NodeStore, ZERO};
//!
//! let mut trie = KTrie::open(MemStore::new()).unwrap();
//! assert_eq!(trie.root(), ZERO);
//! trie.apply([(b"alice".as_slice(), Some(b"1".as_slice())), (b"bob", Some(b"2"))]).unwrap();
//! let batch = trie.commit();
//! trie.store_mut().apply(&batch).unwrap();
//!
//! let proof = trie.prove(b"alice").unwrap();
//! assert!(verify_proof(&batch.root, b"alice", Some(b"1"), &proof));
//! let absent = trie.prove(b"carol").unwrap();
//! assert!(verify_proof(&batch.root, b"carol", None, &absent));
//!
//! // Restart: the same root comes back from the store.
//! let trie = KTrie::open(trie.into_store()).unwrap();
//! assert_eq!(trie.root(), batch.root);
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod cache;
pub mod hash;
mod node;
pub mod proof;
pub mod reference;
mod store;
mod trie;

pub use hash::{
    inner_hash, keccak256, leaf_hash, leaf_hash_kv, path_of, value_hash, Hash, Path, ZERO,
};
pub use node::NodeKey;
pub use proof::{
    verify_proof, verify_proof_bytes, verify_proof_hashed, Proof, ProofError, Terminal,
};
pub use store::{CommitBatch, MemStore, NodeStore, StoreError};
pub use trie::{KTrie, LeafEntry, Op, TrieError, DEFAULT_CACHE_NODES};
