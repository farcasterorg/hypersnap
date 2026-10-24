//! Relay state on disk.
//!
//! ```text
//! <state_dir>/
//!   LOCK                         exclusive lock: one relay process per state dir
//!   meta.json                    {"version":1,"network":"mainnet"}
//!   cursors/<network>-shard-<s>.json
//!   seen/inbound/<id>.seg        origin snapchain
//!   seen/outbound/<id>.seg       origin Hypersnap
//!   deferred/<direction>-shard-<s>.pb
//! ```
//!
//! Order of writes for one source block: seen-set records (fsync) and deferred
//! entries (atomic rewrite) for each batch, then the cursor (atomic rewrite).
//! A crash anywhere re-reads at most the last block; its already-recorded
//! messages are skipped, and an in-flight batch is submitted again, which the
//! target answers with duplicates. Delivery is at least once (FIP A.5).

pub mod cursor;
pub mod deferred;
pub mod fsutil;
pub mod seen;

pub use cursor::CursorStore;
pub use deferred::{DeferredEntry, DeferredQueue};
pub use seen::{Claim, SeenLog, SeenStatus, SeenStore};

use crate::config::NetworkName;
use crate::types::Direction;
use fsutil::{atomic_write, ensure_dir};
use serde::{Deserialize, Serialize};
use std::fs::{OpenOptions, TryLockError};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

const META_VERSION: u32 = 1;

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct Meta {
    version: u32,
    network: String,
}

/// The opened state directory. It holds an exclusive lock until it is dropped.
pub struct StateDir {
    root: PathBuf,
    pub cursors: Arc<CursorStore>,
    pub seen: Arc<SeenStore>,
}

/// How long `open` waits for another instance to release the lock.
const LOCK_WAIT: Duration = Duration::from_secs(5);

impl StateDir {
    pub fn open(root: &Path, network: NetworkName, seen_capacity: usize) -> io::Result<Self> {
        Self::open_with_lock_wait(root, network, seen_capacity, LOCK_WAIT)
    }

    pub fn open_with_lock_wait(
        root: &Path,
        network: NetworkName,
        seen_capacity: usize,
        lock_wait: Duration,
    ) -> io::Result<Self> {
        ensure_dir(root)?;
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(root.join("LOCK"))?;
        let deadline = Instant::now() + lock_wait;
        loop {
            match lock.try_lock() {
                Ok(()) => break,
                Err(TryLockError::WouldBlock) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(50));
                }
                Err(e) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WouldBlock,
                        format!(
                            "state dir {} is in use by another relay process ({e}); each relay needs its own state_dir",
                            root.display()
                        ),
                    ))
                }
            }
        }
        let lock = Arc::new(lock);

        let meta_path = root.join("meta.json");
        match std::fs::read(&meta_path) {
            Ok(bytes) => {
                let meta: Meta = serde_json::from_slice(&bytes).map_err(|e| {
                    io::Error::new(io::ErrorKind::InvalidData, format!("meta.json: {e}"))
                })?;
                if meta.version != META_VERSION || meta.network != network.as_str() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "state dir {} is for network {} (version {}), config is {}",
                            root.display(),
                            meta.network,
                            meta.version,
                            network.as_str()
                        ),
                    ));
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                let meta = Meta {
                    version: META_VERSION,
                    network: network.as_str().to_string(),
                };
                atomic_write(
                    &meta_path,
                    &serde_json::to_vec_pretty(&meta).map_err(io::Error::other)?,
                )?;
            }
            Err(e) => return Err(e),
        }

        ensure_dir(&root.join("deferred"))?;
        Ok(Self {
            root: root.to_path_buf(),
            cursors: Arc::new(CursorStore::open_locked(&root.join("cursors"), lock)?),
            seen: Arc::new(SeenStore::open(&root.join("seen"), seen_capacity)?),
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn deferred_path(&self, direction: Direction, shard: u32) -> PathBuf {
        self.root
            .join("deferred")
            .join(format!("{}-shard-{}.pb", direction.as_str(), shard))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lock_and_network_check() {
        let dir = tempfile::tempdir().unwrap();
        let wait = Duration::from_millis(100);
        let a = StateDir::open(dir.path(), NetworkName::Mainnet, 100).unwrap();
        assert!(
            StateDir::open_with_lock_wait(dir.path(), NetworkName::Mainnet, 100, wait).is_err(),
            "locked"
        );
        // The lock lasts while a worker still holds the cursor store.
        let cursors = a.cursors.clone();
        drop(a);
        assert!(
            StateDir::open_with_lock_wait(dir.path(), NetworkName::Mainnet, 100, wait).is_err()
        );
        drop(cursors);
        let b = StateDir::open(dir.path(), NetworkName::Mainnet, 100).unwrap();
        drop(b);
        assert!(
            StateDir::open(dir.path(), NetworkName::Testnet, 100).is_err(),
            "network mismatch"
        );
    }
}
