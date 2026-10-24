//! One persisted cursor per (source network, shard) (FIP A.5).
//!
//! A cursor is the next source height to read. The worker stores it only
//! after every message of the block below it has a durable outcome (seen set
//! or deferred queue), so a restart re-reads at most one block.

use super::fsutil::{atomic_write, ensure_dir};
use crate::types::Network;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct CursorFile {
    network: String,
    shard: u32,
    next_height: u64,
}

#[derive(Debug, Clone)]
pub struct CursorStore {
    dir: PathBuf,
    /// The state-dir lock. Each worker holds the cursor store, so the lock
    /// lasts as long as any worker can still write.
    _lock: Option<Arc<File>>,
}

impl CursorStore {
    pub fn open(dir: &Path) -> io::Result<Self> {
        ensure_dir(dir)?;
        Ok(Self {
            dir: dir.to_path_buf(),
            _lock: None,
        })
    }

    pub(crate) fn open_locked(dir: &Path, lock: Arc<File>) -> io::Result<Self> {
        let mut store = Self::open(dir)?;
        store._lock = Some(lock);
        Ok(store)
    }

    fn path(&self, network: Network, shard: u32) -> PathBuf {
        self.dir
            .join(format!("{}-shard-{}.json", network.as_str(), shard))
    }

    pub fn load(&self, network: Network, shard: u32) -> io::Result<Option<u64>> {
        let path = self.path(network, shard);
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        let file: CursorFile = serde_json::from_slice(&bytes).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("cursor file {}: {e}", path.display()),
            )
        })?;
        if file.network != network.as_str() || file.shard != shard {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "cursor file {} is for {} shard {}",
                    path.display(),
                    file.network,
                    file.shard
                ),
            ));
        }
        Ok(Some(file.next_height))
    }

    pub fn store(&self, network: Network, shard: u32, next_height: u64) -> io::Result<()> {
        let file = CursorFile {
            network: network.as_str().to_string(),
            shard,
            next_height,
        };
        let bytes = serde_json::to_vec_pretty(&file).map_err(io::Error::other)?;
        atomic_write(&self.path(network, shard), &bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursors_survive_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let store = CursorStore::open(dir.path()).unwrap();
        assert_eq!(store.load(Network::Snapchain, 1).unwrap(), None);
        store.store(Network::Snapchain, 1, 101).unwrap();
        store.store(Network::Snapchain, 1, 102).unwrap();
        store.store(Network::Hypersnap, 1, 7).unwrap();
        drop(store);
        let store = CursorStore::open(dir.path()).unwrap();
        assert_eq!(store.load(Network::Snapchain, 1).unwrap(), Some(102));
        assert_eq!(store.load(Network::Hypersnap, 1).unwrap(), Some(7));
        assert_eq!(store.load(Network::Hypersnap, 0).unwrap(), None);
    }

    #[test]
    fn corrupt_cursor_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let store = CursorStore::open(dir.path()).unwrap();
        std::fs::write(dir.path().join("snapchain-shard-2.json"), b"{not json").unwrap();
        assert!(store.load(Network::Snapchain, 2).is_err());
    }
}
