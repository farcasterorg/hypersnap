//! Persisted deferred queue of one shard worker.
//!
//! A message goes here when the target rejects it for state that the target
//! can still get (see `classify::ErrorClass::StateDependent`). The worker
//! advances its cursor anyway, because the queue entry is a durable outcome,
//! and submits the message again when the entry is due. After
//! `max_attempts` submissions the message is a rule rejection.
//!
//! The file is small (bounded by `capacity`) and the worker rewrites it
//! atomically after each change.

use super::fsutil::atomic_write;
use crate::types::MessageHash;
use hypersnap_proto::Message;
use prost::Message as _;
use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};

const FILE_VERSION: u32 = 1;

#[derive(Clone, PartialEq, prost::Message)]
pub struct DeferredEntry {
    #[prost(bytes = "vec", tag = "1")]
    pub hash: Vec<u8>,
    /// The message in its target form (after the Ed25519-form rewrite).
    #[prost(message, optional, tag = "2")]
    pub message: Option<Message>,
    /// Submissions so far, the first one included.
    #[prost(uint32, tag = "3")]
    pub attempts: u32,
    #[prost(uint64, tag = "4")]
    pub next_attempt_unix_ms: u64,
    #[prost(string, tag = "5")]
    pub last_error: String,
    /// Source block height, for logs.
    #[prost(uint64, tag = "6")]
    pub source_height: u64,
}

#[derive(Clone, PartialEq, prost::Message)]
struct DeferredFile {
    #[prost(uint32, tag = "1")]
    version: u32,
    #[prost(message, repeated, tag = "2")]
    entries: Vec<DeferredEntry>,
}

pub struct DeferredQueue {
    path: PathBuf,
    capacity: usize,
    entries: BTreeMap<MessageHash, DeferredEntry>,
}

impl DeferredQueue {
    pub fn open(path: &Path, capacity: usize) -> io::Result<Self> {
        let mut entries = BTreeMap::new();
        match std::fs::read(path) {
            Ok(bytes) => {
                let file = DeferredFile::decode(bytes.as_slice()).map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("deferred queue {}: {e}", path.display()),
                    )
                })?;
                if file.version != FILE_VERSION {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "deferred queue {}: version {}",
                            path.display(),
                            file.version
                        ),
                    ));
                }
                for entry in file.entries {
                    if let Some(hash) = MessageHash::from_slice(&entry.hash) {
                        if entry.message.is_some() {
                            entries.insert(hash, entry);
                        }
                    }
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        Ok(Self {
            path: path.to_path_buf(),
            capacity,
            entries,
        })
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn contains(&self, hash: &MessageHash) -> bool {
        self.entries.contains_key(hash)
    }

    pub fn get(&self, hash: &MessageHash) -> Option<&DeferredEntry> {
        self.entries.get(hash)
    }

    /// Adds or replaces an entry. Returns false (and changes nothing) when the
    /// queue is full and `hash` is new.
    pub fn upsert(&mut self, hash: MessageHash, entry: DeferredEntry) -> bool {
        if !self.entries.contains_key(&hash) && self.entries.len() >= self.capacity {
            return false;
        }
        self.entries.insert(hash, entry);
        true
    }

    pub fn remove(&mut self, hash: &MessageHash) -> Option<DeferredEntry> {
        self.entries.remove(hash)
    }

    /// Entries due at `now_ms`, earliest first, at most `max`.
    pub fn due(&self, now_ms: u64, max: usize) -> Vec<(MessageHash, DeferredEntry)> {
        let mut due: Vec<_> = self
            .entries
            .iter()
            .filter(|(_, e)| e.next_attempt_unix_ms <= now_ms)
            .map(|(h, e)| (*h, e.clone()))
            .collect();
        due.sort_by_key(|(_, e)| e.next_attempt_unix_ms);
        due.truncate(max);
        due
    }

    pub fn persist(&self) -> io::Result<()> {
        let file = DeferredFile {
            version: FILE_VERSION,
            entries: self.entries.values().cloned().collect(),
        };
        atomic_write(&self.path, &file.encode_to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(n: u8, next: u64) -> (MessageHash, DeferredEntry) {
        let hash = MessageHash([n; 20]);
        let message = Message {
            hash: hash.0.to_vec(),
            ..Default::default()
        };
        (
            hash,
            DeferredEntry {
                hash: hash.0.to_vec(),
                message: Some(message),
                attempts: 1,
                next_attempt_unix_ms: next,
                last_error: "bad_request.validation_failure/invalid signer".into(),
                source_height: 10,
            },
        )
    }

    #[test]
    fn persists_and_bounds() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("deferred-inbound-1.pb");
        let mut q = DeferredQueue::open(&path, 2).unwrap();
        let (h1, e1) = entry(1, 500);
        let (h2, e2) = entry(2, 100);
        let (h3, e3) = entry(3, 50);
        assert!(q.upsert(h1, e1.clone()));
        assert!(q.upsert(h2, e2.clone()));
        assert!(!q.upsert(h3, e3), "full");
        let mut e1b = e1.clone();
        e1b.attempts = 2;
        assert!(q.upsert(h1, e1b.clone()), "replace is allowed when full");
        q.persist().unwrap();
        drop(q);

        let q = DeferredQueue::open(&path, 2).unwrap();
        assert_eq!(q.len(), 2);
        assert_eq!(q.get(&h1), Some(&e1b));
        assert_eq!(q.due(99, 10).len(), 0);
        let due = q.due(1000, 10);
        assert_eq!(
            due.iter().map(|(h, _)| *h).collect::<Vec<_>>(),
            vec![h2, h1]
        );
        assert_eq!(q.due(1000, 1).len(), 1);
    }
}
