//! Production `DaTrieLookup` implementation backed by the
//! `BlockEngine`'s hyper merkle trie.
//!
//! The hyper merkle trie is owned by a `BlockEngine` that lives
//! behind a `tokio::sync::Mutex` in the SnapchainNode. Phase 5c
//! defined `DaTrieLookup::contains_key` as a synchronous predicate;
//! we reconcile the two by using `tokio::task::block_in_place` +
//! `tokio::runtime::Handle::current().block_on` to acquire the
//! async lock from a sync context. This is safe inside the
//! multi-thread tokio runtime the `HyperActor` runs in. The
//! sync-only test path uses `TrustingDaTrieLookup` and never hits
//! this code.
//!
//! Operators that want to extend the lookup to per-shard tries can
//! compose multiple `DaTrieLookup` impls — `contains_key` returning
//! true if ANY underlying lookup reports the key present.

use crate::hyper::da_pow::DaTrieLookup;
use crate::storage::store::block_engine::BlockEngine;
use crate::storage::trie::merkle_trie;
use std::sync::Arc;
use tokio::sync::Mutex;

pub struct BlockEngineDaTrieLookup {
    engine: Arc<Mutex<BlockEngine>>,
}

impl BlockEngineDaTrieLookup {
    pub fn new(engine: Arc<Mutex<BlockEngine>>) -> Self {
        Self { engine }
    }
}

impl DaTrieLookup for BlockEngineDaTrieLookup {
    fn contains_key(&self, key: &[u8]) -> bool {
        let key_vec = key.to_vec();
        // Acquire the async mutex from sync code. `block_in_place`
        // tells tokio it's safe to park this worker thread while
        // we synchronously block — only valid inside a multi-thread
        // runtime. The `HyperActor` is spawned in main.rs under
        // the default tokio runtime which is multi-thread, so this
        // contract holds for production callers.
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async move {
                let mut engine = self.engine.lock().await;
                engine.trie_key_exists(&merkle_trie::Context::new(), &key_vec)
            })
        })
    }
}
