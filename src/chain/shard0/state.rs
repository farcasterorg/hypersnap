//! Block state of shard 0: one write batch for each block over the shard-0
//! RocksDB, a write set for each message on top of it, and the Keccak state
//! trie update at the end of the block (FIP §16.13).
//!
//! A message runs against a [`MsgTxn`]. If the message is not valid, its
//! writes are dropped, so a block's state is the result of its valid messages
//! only. The snapchain stores that shard 0 reuses (on-chain events, KEY_ADD,
//! storage lends) write to the block batch directly; they read through it with
//! `get_from_db_or_txn`.

use super::keys::{self, is_shard0_consensus_prefix};
use super::Shard0Error;
use crate::storage::db::{PageOptions, RocksDB, RocksDbTransactionBatch};
use crate::storage::trie::shadow_trie::{stage_into, RocksNodeStore};
use hypersnap_ktrie::KTrie;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

fn db_err(e: impl std::fmt::Display) -> Shard0Error {
    Shard0Error::Internal(e.to_string())
}

/// The writes of one block that are not committed yet.
pub struct BlockState {
    db: Arc<RocksDB>,
    batch: RocksDbTransactionBatch,
    /// Ordered index of the keys that `apply` wrote, for prefix scans. The
    /// snapchain stores write the batch directly; their prefixes are not
    /// scanned here.
    keys: BTreeSet<Vec<u8>>,
}

impl BlockState {
    pub fn new(db: Arc<RocksDB>) -> Self {
        BlockState {
            db,
            batch: RocksDbTransactionBatch::new(),
            keys: BTreeSet::new(),
        }
    }

    pub fn db(&self) -> &Arc<RocksDB> {
        &self.db
    }

    pub fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Shard0Error> {
        if let Some(v) = self.batch.batch.get(key) {
            return Ok(v.clone());
        }
        self.db.get(key).map_err(db_err)
    }

    /// All live entries whose key starts with `prefix`, in key order.
    pub fn scan(&self, prefix: &[u8]) -> Result<BTreeMap<Vec<u8>, Vec<u8>>, Shard0Error> {
        let mut out = BTreeMap::new();
        let stop = crate::storage::util::increment_vec_u8(&prefix.to_vec());
        self.db
            .for_each_iterator_by_prefix(
                Some(prefix.to_vec()),
                Some(stop),
                &PageOptions::default(),
                |k, v| {
                    out.insert(k.to_vec(), v.to_vec());
                    Ok(false)
                },
            )
            .map_err(db_err)?;
        for k in self
            .keys
            .range(prefix.to_vec()..)
            .take_while(|k| k.starts_with(prefix))
        {
            match self.batch.batch.get(k) {
                Some(Some(v)) => {
                    out.insert(k.clone(), v.clone());
                }
                Some(None) => {
                    out.remove(k);
                }
                None => {}
            }
        }
        Ok(out)
    }

    pub fn txn(&self) -> MsgTxn<'_> {
        MsgTxn {
            base: self,
            writes: BTreeMap::new(),
        }
    }

    pub fn apply(&mut self, writes: Writes) {
        for (k, v) in writes.0 {
            self.keys.insert(k.clone());
            self.batch.batch.insert(k, v);
        }
    }

    /// The batch, for the snapchain stores.
    pub fn batch_mut(&mut self) -> &mut RocksDbTransactionBatch {
        &mut self.batch
    }

    pub fn batch(&self) -> &RocksDbTransactionBatch {
        &self.batch
    }

    /// The consensus writes of the block, in key order: the trie operations.
    pub fn trie_ops(&self) -> Vec<(Vec<u8>, Option<Vec<u8>>)> {
        let mut ops: Vec<(Vec<u8>, Option<Vec<u8>>)> = self
            .batch
            .batch
            .iter()
            .filter(|(k, _)| k.first().is_some_and(|p| is_shard0_consensus_prefix(*p)))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        ops.sort_by(|a, b| a.0.cmp(&b.0));
        ops
    }

    pub fn into_batch(self) -> RocksDbTransactionBatch {
        self.batch
    }
}

/// The writes of one message.
#[derive(Default)]
pub struct Writes(BTreeMap<Vec<u8>, Option<Vec<u8>>>);

impl Writes {
    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&Vec<u8>, &Option<Vec<u8>>)> {
        self.0.iter()
    }
}

/// A write set on top of a [`BlockState`].
pub struct MsgTxn<'a> {
    base: &'a BlockState,
    writes: BTreeMap<Vec<u8>, Option<Vec<u8>>>,
}

impl<'a> MsgTxn<'a> {
    pub fn base(&self) -> &'a BlockState {
        self.base
    }

    pub fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Shard0Error> {
        if let Some(v) = self.writes.get(key) {
            return Ok(v.clone());
        }
        self.base.get(key)
    }

    pub fn exists(&self, key: &[u8]) -> Result<bool, Shard0Error> {
        Ok(self.get(key)?.is_some())
    }

    pub fn put(&mut self, key: Vec<u8>, value: Vec<u8>) {
        self.writes.insert(key, Some(value));
    }

    pub fn delete(&mut self, key: Vec<u8>) {
        self.writes.insert(key, None);
    }

    pub fn scan(&self, prefix: &[u8]) -> Result<BTreeMap<Vec<u8>, Vec<u8>>, Shard0Error> {
        let mut out = self.base.scan(prefix)?;
        for (k, v) in self
            .writes
            .range(prefix.to_vec()..)
            .take_while(|(k, _)| k.starts_with(prefix))
        {
            match v {
                Some(v) => {
                    out.insert(k.clone(), v.clone());
                }
                None => {
                    out.remove(k);
                }
            }
        }
        Ok(out)
    }

    pub fn get_u64(&self, key: &[u8]) -> Result<u64, Shard0Error> {
        Ok(self.get(key)?.map(|v| keys::decode_u64(&v)).unwrap_or(0))
    }

    /// Store `v`, or delete the key if `v` is 0 (absent reads as 0).
    pub fn put_u64(&mut self, key: Vec<u8>, v: u64) {
        if v == 0 {
            self.delete(key);
        } else {
            self.put(key, keys::u64_value(v));
        }
    }

    pub fn add_u64(&mut self, key: Vec<u8>, amount: u64) -> Result<u64, Shard0Error> {
        let v = self
            .get_u64(&key)?
            .checked_add(amount)
            .ok_or_else(|| Shard0Error::invalid("amount overflow"))?;
        self.put_u64(key, v);
        Ok(v)
    }

    pub fn sub_u64(&mut self, key: Vec<u8>, amount: u64) -> Result<u64, Shard0Error> {
        let v = self
            .get_u64(&key)?
            .checked_sub(amount)
            .ok_or_else(|| Shard0Error::invalid("insufficient balance"))?;
        self.put_u64(key, v);
        Ok(v)
    }

    pub fn get_proto<T: prost::Message + Default>(
        &self,
        key: &[u8],
    ) -> Result<Option<T>, Shard0Error> {
        match self.get(key)? {
            Some(bytes) => T::decode(bytes.as_slice())
                .map(Some)
                .map_err(|e| Shard0Error::Internal(format!("corrupt record: {}", e))),
            None => Ok(None),
        }
    }

    pub fn put_proto<T: prost::Message>(&mut self, key: Vec<u8>, value: &T) {
        self.put(key, value.encode_to_vec());
    }

    pub fn into_writes(self) -> Writes {
        Writes(self.writes)
    }
}

/// The Keccak state trie of shard 0.
pub struct Shard0Trie {
    trie: KTrie<RocksNodeStore>,
}

impl Shard0Trie {
    pub fn open(db: Arc<RocksDB>) -> Result<Self, Shard0Error> {
        let trie = KTrie::open_with_cache(RocksNodeStore::new(db), 1 << 16).map_err(db_err)?;
        Ok(Shard0Trie { trie })
    }

    pub fn root(&self) -> [u8; 32] {
        self.trie.committed_root()
    }

    pub fn len(&self) -> u64 {
        self.trie.len()
    }

    /// Root after the block's writes, without keeping them.
    pub fn root_with(&mut self, state: &BlockState) -> Result<[u8; 32], Shard0Error> {
        let result = self.trie.apply(state.trie_ops()).map(|_| self.trie.root());
        self.trie.rollback();
        result.map_err(db_err)
    }

    /// Apply the block's writes and stage the trie records into `txn`. The
    /// caller commits `txn` before the next call.
    pub fn stage(
        &mut self,
        state: &BlockState,
        txn: &mut RocksDbTransactionBatch,
    ) -> Result<[u8; 32], Shard0Error> {
        self.trie.apply(state.trie_ops()).map_err(db_err)?;
        let batch = self.trie.commit();
        stage_into(&batch, txn);
        Ok(batch.root)
    }

    /// Drop staged records that were not persisted (after a failed commit).
    pub fn reload(&mut self) -> Result<(), Shard0Error> {
        self.trie.reload().map_err(db_err)
    }

    pub fn prove(&self, key: &[u8]) -> Result<hypersnap_ktrie::Proof, Shard0Error> {
        self.trie.prove(key).map_err(db_err)
    }

    pub fn inner(&self) -> &KTrie<RocksNodeStore> {
        &self.trie
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn db() -> (Arc<RocksDB>, tempfile::TempDir) {
        let dir = tempfile::TempDir::new().unwrap();
        let db = Arc::new(RocksDB::new(dir.path().join("s0").to_str().unwrap()));
        db.open().unwrap();
        (db, dir)
    }

    #[test]
    fn overlays_read_through_and_scan_in_order() {
        let (db, _dir) = db();
        db.put(&keys::balance(1), &keys::u64_value(10)).unwrap();
        db.put(&keys::balance(3), &keys::u64_value(30)).unwrap();
        let mut state = BlockState::new(db.clone());

        let mut txn = state.txn();
        txn.add_u64(keys::balance(2), 20).unwrap();
        txn.sub_u64(keys::balance(3), 30).unwrap();
        assert!(txn.sub_u64(keys::balance(1), 11).is_err());
        let scanned: Vec<u64> = txn
            .scan(&[crate::storage::constants::RootPrefix::HyperRewardBalance as u8])
            .unwrap()
            .values()
            .map(|v| keys::decode_u64(v))
            .collect();
        assert_eq!(scanned, vec![10, 20]);
        let writes = txn.into_writes();
        state.apply(writes);

        // A dropped message leaves nothing.
        let mut dropped = state.txn();
        dropped.put_u64(keys::balance(9), 9);
        drop(dropped);
        assert!(state.get(&keys::balance(9)).unwrap().is_none());

        let scanned = state
            .scan(&[crate::storage::constants::RootPrefix::HyperRewardBalance as u8])
            .unwrap();
        assert_eq!(scanned.len(), 2);
        assert_eq!(state.trie_ops().len(), 2);
    }

    #[test]
    fn trie_root_follows_the_block_and_survives_reopen() {
        let (db, _dir) = db();
        let mut trie = Shard0Trie::open(db.clone()).unwrap();
        let mut state = BlockState::new(db.clone());
        let mut txn = state.txn();
        txn.put_u64(keys::balance(7), 70);
        // A node-local key is not in the trie.
        txn.put(
            vec![
                crate::storage::constants::RootPrefix::NodeLocalState as u8,
                1,
            ],
            vec![1],
        );
        let writes = txn.into_writes();
        state.apply(writes);

        let expected = hypersnap_ktrie::reference::root(&[(keys::balance(7), keys::u64_value(70))]);
        assert_eq!(trie.root_with(&state).unwrap(), expected);
        assert_eq!(trie.root(), [0u8; 32]);

        let mut txn = RocksDbTransactionBatch::new();
        let root = trie.stage(&state, &mut txn).unwrap();
        txn.merge(state.into_batch());
        db.commit(txn).unwrap();
        assert_eq!(root, expected);
        let reopened = Shard0Trie::open(db).unwrap();
        assert_eq!(reopened.root(), expected);
    }
}
