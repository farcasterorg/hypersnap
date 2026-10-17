//! Storage abstraction: the trie reads serialized records through
//! [`NodeStore`] and hands every write back to the caller as a
//! [`CommitBatch`].

use crate::hash::Hash;
use crate::node::NodeKey;
use foldhash::HashMap;
use std::fmt;

/// An error raised by a [`NodeStore`] backend.
#[derive(Debug)]
pub struct StoreError(pub Box<dyn std::error::Error + Send + Sync>);

impl StoreError {
    /// Wrap any backend error.
    pub fn new(e: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> Self {
        StoreError(e.into())
    }
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "node store: {}", self.0)
    }
}

impl std::error::Error for StoreError {}

/// A key-value store of serialized trie records.
///
/// The trie only calls [`NodeStore::get`]. Writes reach the store when the
/// caller applies a [`CommitBatch`] (directly with [`NodeStore::apply`], or by
/// merging [`CommitBatch::writes`] into a larger atomic write batch). A RocksDB
/// adapter maps `key` to `[root prefix byte] || key.encode()` and `get` /
/// `put` / `delete` to the matching RocksDB calls.
pub trait NodeStore {
    /// The record stored under `key`, if any.
    fn get(&self, key: &NodeKey) -> Result<Option<Vec<u8>>, StoreError>;
    /// Store `value` under `key`, replacing any previous record.
    fn put(&mut self, key: &NodeKey, value: &[u8]) -> Result<(), StoreError>;
    /// Remove the record under `key` (no-op if absent).
    fn delete(&mut self, key: &NodeKey) -> Result<(), StoreError>;

    /// Apply every write of `batch`, in order. Override to make it atomic.
    fn apply(&mut self, batch: &CommitBatch) -> Result<(), StoreError> {
        for (key, value) in &batch.writes {
            match value {
                Some(v) => self.put(key, v)?,
                None => self.delete(key)?,
            }
        }
        Ok(())
    }
}

/// The output of [`crate::KTrie::commit`]: the new root and the store writes
/// that produce it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CommitBatch {
    /// State root after the batch.
    pub root: Hash,
    /// Number of keys in the trie after the batch.
    pub len: u64,
    /// `(key, Some(record))` = put, `(key, None)` = delete. Sorted by key and
    /// free of duplicates, so the batch is deterministic for a given sequence
    /// of operations.
    pub writes: Vec<(NodeKey, Option<Vec<u8>>)>,
}

impl CommitBatch {
    /// `true` if the batch has no writes.
    pub fn is_empty(&self) -> bool {
        self.writes.is_empty()
    }

    /// Number of puts and deletes.
    pub fn counts(&self) -> (usize, usize) {
        let puts = self.writes.iter().filter(|(_, v)| v.is_some()).count();
        (puts, self.writes.len() - puts)
    }
}

/// An in-memory [`NodeStore`].
#[derive(Clone, Debug, Default)]
pub struct MemStore {
    map: HashMap<NodeKey, Box<[u8]>>,
}

impl MemStore {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of records.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// `true` if the store has no records.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Total bytes of encoded keys plus values.
    pub fn byte_size(&self) -> usize {
        self.map
            .iter()
            .map(|(k, v)| k.encode().len() + v.len())
            .sum()
    }

    /// All records, sorted by key.
    pub fn records(&self) -> Vec<(NodeKey, Vec<u8>)> {
        let mut out: Vec<_> = self.map.iter().map(|(k, v)| (*k, v.to_vec())).collect();
        out.sort_unstable_by_key(|r| r.0);
        out
    }
}

impl NodeStore for MemStore {
    fn get(&self, key: &NodeKey) -> Result<Option<Vec<u8>>, StoreError> {
        Ok(self.map.get(key).map(|v| v.to_vec()))
    }

    fn put(&mut self, key: &NodeKey, value: &[u8]) -> Result<(), StoreError> {
        self.map.insert(*key, value.into());
        Ok(())
    }

    fn delete(&mut self, key: &NodeKey) -> Result<(), StoreError> {
        self.map.remove(key);
        Ok(())
    }
}
