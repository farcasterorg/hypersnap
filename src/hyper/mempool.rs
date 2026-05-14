//! In-memory mempool of pending hyper messages.
//!
//! Messages live here from the time they're received via gossip until they're
//! included in a hyperblock. The mempool:
//!  - Validates structural correctness on insertion
//!  - Deduplicates by content key (lock_id for locks, nullifier set for transfers)
//!  - Surfaces a stable, deterministic ordering for block proposers
//!
//! This is the hyper-side counterpart to snapchain's transaction mempool. It
//! lives entirely in process memory; persistence is the responsibility of the
//! gossip + receive-handler layer (which can refeed messages on restart).

use crate::hyper::lock_event::{validate_lock_event, LockError};
use crate::hyper::transfer_codec::{tx_from_proto, TransferCodecError};
use crate::proto;
use std::collections::{BTreeMap, BTreeSet};

#[derive(thiserror::Error, Debug)]
pub enum MempoolError {
    #[error("invalid lock event: {0}")]
    Lock(#[from] LockError),
    #[error("invalid transfer: {0}")]
    TransferCodec(#[from] TransferCodecError),
    #[error("transfer validation failed: {0}")]
    TransferValidation(String),
    #[error("duplicate lock_id")]
    DuplicateLockId,
    #[error("duplicate transfer (nullifier already pending)")]
    DuplicateNullifier,
}

/// Sortable identifier so the mempool can deduplicate and order messages.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum MessageKey {
    Lock(Vec<u8>),     // lock_id (32B)
    Transfer(Vec<u8>), // first input's nullifier (32B) — unique per spend
}

/// Default mempool capacity. Reasonable for testnet operation; production
/// nodes may want larger if they're block proposers, smaller if relaying.
pub const DEFAULT_MEMPOOL_CAPACITY: usize = 10_000;

pub struct HyperMempool {
    /// Keyed by deterministic content identifier; iteration follows BTreeMap
    /// natural order (lock_ids and nullifiers compared lexicographically).
    locks: BTreeMap<Vec<u8>, proto::HyperLockEvent>,
    transfers: BTreeMap<Vec<u8>, proto::HyperTransferTx>,
    /// All nullifiers across pending transfers — used to reject overlapping
    /// double-spend attempts within a single mempool view.
    pending_nullifiers: BTreeSet<Vec<u8>>,
    /// Insertion order tracker for LRU eviction. Keys are tagged with their
    /// type discriminator so we can route eviction to the right map.
    insertion_order: std::collections::VecDeque<MempoolKey>,
    capacity: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum MempoolKey {
    Lock(Vec<u8>),
    Transfer(Vec<u8>),
}

impl Default for HyperMempool {
    fn default() -> Self {
        Self::with_capacity(DEFAULT_MEMPOOL_CAPACITY)
    }
}

impl HyperMempool {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            locks: BTreeMap::new(),
            transfers: BTreeMap::new(),
            pending_nullifiers: BTreeSet::new(),
            insertion_order: std::collections::VecDeque::new(),
            capacity,
        }
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    pub fn lock_count(&self) -> usize {
        self.locks.len()
    }

    pub fn transfer_count(&self) -> usize {
        self.transfers.len()
    }

    pub fn total_count(&self) -> usize {
        self.locks.len() + self.transfers.len()
    }

    /// Evict the oldest entry if at capacity. Called before each insertion.
    fn evict_if_full(&mut self) {
        while self.total_count() >= self.capacity {
            match self.insertion_order.pop_front() {
                Some(MempoolKey::Lock(id)) => {
                    self.locks.remove(&id);
                }
                Some(MempoolKey::Transfer(first_nullifier)) => {
                    if let Some(tx) = self.transfers.remove(&first_nullifier) {
                        for input in &tx.inputs {
                            self.pending_nullifiers.remove(&input.nullifier);
                        }
                    }
                }
                None => break,
            }
        }
    }

    pub fn submit_lock(&mut self, event: proto::HyperLockEvent) -> Result<(), MempoolError> {
        validate_lock_event(&event)?;
        if self.locks.contains_key(&event.lock_id) {
            return Err(MempoolError::DuplicateLockId);
        }
        self.evict_if_full();
        self.insertion_order
            .push_back(MempoolKey::Lock(event.lock_id.clone()));
        self.locks.insert(event.lock_id.clone(), event);
        Ok(())
    }

    pub fn submit_transfer(&mut self, tx: proto::HyperTransferTx) -> Result<(), MempoolError> {
        // Decode and validate structurally.
        let typed = tx_from_proto(&tx)?;
        typed
            .validate()
            .map_err(|e| MempoolError::TransferValidation(format!("{:?}", e)))?;

        if typed.inputs.is_empty() {
            return Err(MempoolError::TransferValidation(
                "transfer must have at least one input".into(),
            ));
        }

        // Reject if any nullifier overlaps with another pending transfer.
        for input in &typed.inputs {
            if self
                .pending_nullifiers
                .contains(&input.nullifier.0.to_vec())
            {
                return Err(MempoolError::DuplicateNullifier);
            }
        }

        // Index by first nullifier (deterministic per transfer).
        let key = typed.inputs[0].nullifier.0.to_vec();
        if self.transfers.contains_key(&key) {
            return Err(MempoolError::DuplicateNullifier);
        }

        self.evict_if_full();
        for input in &typed.inputs {
            self.pending_nullifiers.insert(input.nullifier.0.to_vec());
        }
        self.insertion_order
            .push_back(MempoolKey::Transfer(key.clone()));
        self.transfers.insert(key, tx);
        Ok(())
    }

    pub fn locks(&self) -> impl Iterator<Item = &proto::HyperLockEvent> {
        self.locks.values()
    }

    pub fn transfers(&self) -> impl Iterator<Item = &proto::HyperTransferTx> {
        self.transfers.values()
    }

    /// Remove and return all pending messages, leaving the mempool empty.
    /// The proposer calls this when assembling the next hyperblock.
    pub fn drain(&mut self) -> (Vec<proto::HyperLockEvent>, Vec<proto::HyperTransferTx>) {
        let locks: Vec<_> = std::mem::take(&mut self.locks).into_values().collect();
        let transfers: Vec<_> = std::mem::take(&mut self.transfers).into_values().collect();
        self.pending_nullifiers.clear();
        self.insertion_order.clear();
        (locks, transfers)
    }

    /// Drop a specific lock if it's no longer needed (e.g. it was included
    /// in a peer's block we've now imported).
    pub fn forget_lock(&mut self, lock_id: &[u8]) -> bool {
        if self.locks.remove(lock_id).is_some() {
            self.insertion_order
                .retain(|k| !matches!(k, MempoolKey::Lock(id) if id.as_slice() == lock_id));
            true
        } else {
            false
        }
    }

    /// Drop a specific transfer by its first-nullifier key. Removes all of
    /// its nullifiers from the pending set.
    pub fn forget_transfer(&mut self, first_nullifier: &[u8]) -> bool {
        if let Some(tx) = self.transfers.remove(first_nullifier) {
            for input in &tx.inputs {
                self.pending_nullifiers.remove(&input.nullifier);
            }
            self.insertion_order.retain(
                |k| !matches!(k, MempoolKey::Transfer(id) if id.as_slice() == first_nullifier),
            );
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hyper::transfer_codec::tx_to_proto;
    use hypersnap_crypto::bulletproofs::curve_adapter::Scalar;
    use hypersnap_crypto::tokens::{
        prove_value_range, schnorr_sign, Nullifier as Nf, PedersenCommitment as PC,
        SchnorrSignature, TransferInput, TransferOutput, TransferTx, DEFAULT_RANGE_BITS,
    };
    use rand::rngs::OsRng;

    fn sample_lock(lock_id_byte: u8) -> proto::HyperLockEvent {
        proto::HyperLockEvent {
            amount: 1_000_000,
            dest_chain_id: 1,
            dest_address: vec![0xab; 20],
            spend_pubkey: vec![0x02; 33],
            lock_id: vec![lock_id_byte; 32],
            lock_height: 100,
            lock_timestamp: 1_700_000_000,
            lock_signature: vec![0u8; 64],
        }
    }

    fn sample_transfer(seed: u8) -> proto::HyperTransferTx {
        let mut rng = OsRng;
        let r_in = Scalar::random(&mut rng);
        let r_out = Scalar::random(&mut rng);
        // Mix seed into the spend secret so distinct transfers produce distinct nullifiers.
        let mut x_bytes = [0u8; 56];
        x_bytes[0] = seed;
        let x = Scalar::from_bytes_mod_order(x_bytes);

        let in_commitment = PC::commit(100, &r_in);
        let nullifier = Nf::derive(&x, &in_commitment);
        let spend_signature: SchnorrSignature = schnorr_sign(&x, &[0u8; 32], &mut rng);

        let out_commitment = PC::commit(100, &r_out);
        let (range_proof, _) =
            prove_value_range(100, &r_out, DEFAULT_RANGE_BITS, &mut rng).unwrap();

        let typed = TransferTx {
            inputs: vec![TransferInput {
                commitment: in_commitment,
                nullifier,
                spend_signature,
            }],
            outputs: vec![TransferOutput {
                commitment: out_commitment,
                range_proof,
            }],
            fee_atoms: 0,
        };
        tx_to_proto(&typed)
    }

    #[test]
    fn submit_and_count_locks() {
        let mut mp = HyperMempool::new();
        assert_eq!(mp.lock_count(), 0);
        mp.submit_lock(sample_lock(1)).unwrap();
        mp.submit_lock(sample_lock(2)).unwrap();
        assert_eq!(mp.lock_count(), 2);
    }

    #[test]
    fn submit_rejects_duplicate_lock_id() {
        let mut mp = HyperMempool::new();
        mp.submit_lock(sample_lock(1)).unwrap();
        assert!(matches!(
            mp.submit_lock(sample_lock(1)),
            Err(MempoolError::DuplicateLockId)
        ));
    }

    #[test]
    fn submit_rejects_invalid_lock() {
        let mut mp = HyperMempool::new();
        let mut bad = sample_lock(1);
        bad.amount = 0;
        assert!(matches!(
            mp.submit_lock(bad),
            Err(MempoolError::Lock(LockError::ZeroAmount))
        ));
    }

    #[test]
    fn submit_and_count_transfers() {
        let mut mp = HyperMempool::new();
        mp.submit_transfer(sample_transfer(1)).unwrap();
        mp.submit_transfer(sample_transfer(2)).unwrap();
        assert_eq!(mp.transfer_count(), 2);
    }

    #[test]
    fn submit_rejects_duplicate_nullifier_transfer() {
        let mut mp = HyperMempool::new();
        let tx = sample_transfer(7);
        mp.submit_transfer(tx.clone()).unwrap();
        // Same transfer shouldn't be re-acceptable.
        assert!(matches!(
            mp.submit_transfer(tx),
            Err(MempoolError::DuplicateNullifier)
        ));
    }

    #[test]
    fn drain_empties_mempool() {
        let mut mp = HyperMempool::new();
        mp.submit_lock(sample_lock(1)).unwrap();
        mp.submit_lock(sample_lock(2)).unwrap();
        mp.submit_transfer(sample_transfer(3)).unwrap();

        let (locks, transfers) = mp.drain();
        assert_eq!(locks.len(), 2);
        assert_eq!(transfers.len(), 1);
        assert_eq!(mp.total_count(), 0);
    }

    #[test]
    fn forget_lock_removes_entry() {
        let mut mp = HyperMempool::new();
        let l = sample_lock(1);
        mp.submit_lock(l.clone()).unwrap();
        assert!(mp.forget_lock(&l.lock_id));
        assert_eq!(mp.lock_count(), 0);
        assert!(!mp.forget_lock(&l.lock_id));
    }

    #[test]
    fn forget_transfer_clears_nullifiers() {
        let mut mp = HyperMempool::new();
        let tx = sample_transfer(5);
        let first_nullifier = tx.inputs[0].nullifier.clone();
        mp.submit_transfer(tx.clone()).unwrap();

        // Re-submit the *exact same* tx (same nullifiers) → must fail.
        assert!(matches!(
            mp.submit_transfer(tx.clone()),
            Err(MempoolError::DuplicateNullifier)
        ));

        // After forgetting, the nullifiers are free again — re-submission of
        // the exact same tx now succeeds.
        assert!(mp.forget_transfer(&first_nullifier));
        assert_eq!(mp.transfer_count(), 0);
        assert!(mp.submit_transfer(tx).is_ok());
    }

    #[test]
    fn capacity_bound_evicts_oldest() {
        let mut mp = HyperMempool::with_capacity(3);
        mp.submit_lock(sample_lock(1)).unwrap();
        mp.submit_lock(sample_lock(2)).unwrap();
        mp.submit_lock(sample_lock(3)).unwrap();
        assert_eq!(mp.lock_count(), 3);

        // Submitting a 4th evicts the oldest (lock 1).
        mp.submit_lock(sample_lock(4)).unwrap();
        assert_eq!(mp.lock_count(), 3);
        let ids: Vec<_> = mp.locks().map(|l| l.lock_id[0]).collect();
        // BTreeMap iteration is sorted, so the surviving locks are sorted by lock_id.
        assert_eq!(ids, vec![2, 3, 4]);
    }

    #[test]
    fn capacity_bound_works_across_message_types() {
        let mut mp = HyperMempool::with_capacity(2);
        mp.submit_lock(sample_lock(1)).unwrap();
        mp.submit_transfer(sample_transfer(7)).unwrap();
        assert_eq!(mp.total_count(), 2);

        // Adding another lock evicts the oldest message regardless of type.
        mp.submit_lock(sample_lock(2)).unwrap();
        assert_eq!(mp.total_count(), 2);
        // Lock 1 evicted, transfer + lock 2 remain.
        assert_eq!(mp.lock_count(), 1);
        assert_eq!(mp.transfer_count(), 1);
    }

    #[test]
    fn forget_removes_from_insertion_order() {
        let mut mp = HyperMempool::with_capacity(2);
        let lock1 = sample_lock(1);
        mp.submit_lock(lock1.clone()).unwrap();
        mp.submit_lock(sample_lock(2)).unwrap();
        // Forget lock 1 explicitly (e.g. block imported it).
        assert!(mp.forget_lock(&lock1.lock_id));

        // Now we have capacity for one more without eviction.
        mp.submit_lock(sample_lock(3)).unwrap();
        assert_eq!(mp.lock_count(), 2);
        let ids: Vec<_> = mp.locks().map(|l| l.lock_id[0]).collect();
        assert_eq!(ids, vec![2, 3]);
    }

    #[test]
    fn deterministic_iteration_order() {
        // Locks are stored in a BTreeMap keyed by lock_id, so iteration order
        // is independent of insertion order.
        let mut mp1 = HyperMempool::new();
        mp1.submit_lock(sample_lock(1)).unwrap();
        mp1.submit_lock(sample_lock(2)).unwrap();
        mp1.submit_lock(sample_lock(3)).unwrap();

        let mut mp2 = HyperMempool::new();
        mp2.submit_lock(sample_lock(3)).unwrap();
        mp2.submit_lock(sample_lock(1)).unwrap();
        mp2.submit_lock(sample_lock(2)).unwrap();

        let order1: Vec<_> = mp1.locks().map(|l| l.lock_id.clone()).collect();
        let order2: Vec<_> = mp2.locks().map(|l| l.lock_id.clone()).collect();
        assert_eq!(order1, order2);
    }
}
