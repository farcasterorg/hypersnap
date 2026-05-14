//! RocksDB-backed implementation of `hypersnap_crypto::tokens::NoteStore`.
//!
//! Two key spaces:
//!  - `[RootPrefix::HyperNoteCommitment][commitment 56B] → one_time_pubkey 56B`
//!  - `[RootPrefix::HyperNullifier][nullifier 32B] → empty`
//!
//! The note-commitment index lives separately from the verkle tree so that
//! validation lookups don't need a verkle proof — that's the validator's
//! local view. The verkle tree itself contains the canonical note set as
//! authenticated state for bridge-side proofs and full-state replication;
//! this store is a derived index.

use crate::core::error::HubError;
use crate::storage::constants::RootPrefix;
use crate::storage::db::{RocksDB, RocksdbError};
use hypersnap_crypto::bulletproofs::curve_adapter::Point;
use hypersnap_crypto::tokens::{
    point_from_compressed_bytes, point_to_compressed_bytes, NoteStore, NoteStoreMut, Nullifier,
    PedersenCommitment,
};
use std::sync::Arc;

#[derive(Clone)]
pub struct RocksDbNoteStore {
    db: Arc<RocksDB>,
}

impl RocksDbNoteStore {
    pub fn new(db: Arc<RocksDB>) -> Self {
        Self { db }
    }

    fn note_key(commitment: &PedersenCommitment) -> Vec<u8> {
        let mut k = Vec::with_capacity(1 + 56);
        k.push(RootPrefix::HyperNoteCommitment as u8);
        k.extend_from_slice(&commitment.to_bytes());
        k
    }

    fn nullifier_key(nullifier: &Nullifier) -> Vec<u8> {
        let mut k = Vec::with_capacity(1 + 32);
        k.push(RootPrefix::HyperNullifier as u8);
        k.extend_from_slice(&nullifier.0);
        k
    }

    /// Convenience: total notes recorded. O(prefix scan).
    pub fn note_count(&self) -> Result<usize, HubError> {
        use crate::storage::db::PageOptions;
        let prefix = vec![RootPrefix::HyperNoteCommitment as u8];
        let mut count = 0usize;
        self.db.for_each_iterator_by_prefix(
            Some(prefix),
            None,
            &PageOptions::default(),
            |_k, _v| {
                count += 1;
                Ok(false)
            },
        )?;
        Ok(count)
    }
}

impl NoteStore for RocksDbNoteStore {
    fn lookup_owner(&self, commitment: &PedersenCommitment) -> Option<Point> {
        let key = Self::note_key(commitment);
        let bytes = match self.db.get(&key) {
            Ok(Some(b)) => b,
            _ => return None,
        };
        if bytes.len() != 56 {
            return None;
        }
        let mut decaf_bytes = [0u8; 56];
        decaf_bytes.copy_from_slice(&bytes);
        point_from_compressed_bytes(&decaf_bytes)
    }

    fn is_spent(&self, nullifier: &Nullifier) -> bool {
        let key = Self::nullifier_key(nullifier);
        matches!(self.db.get(&key), Ok(Some(_)))
    }
}

impl NoteStoreMut for RocksDbNoteStore {
    fn record_note(&mut self, commitment: PedersenCommitment, one_time_pubkey: Point) {
        let key = Self::note_key(&commitment);
        let value = point_to_compressed_bytes(&one_time_pubkey);
        let _: Result<(), RocksdbError> = self.db.put(&key, &value);
    }

    fn mark_spent(&mut self, nullifier: Nullifier) {
        let key = Self::nullifier_key(&nullifier);
        let _: Result<(), RocksdbError> = self.db.put(&key, &[]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hypersnap_crypto::bulletproofs::curve_adapter::Scalar;
    use hypersnap_crypto::bulletproofs::PedersenGens;
    use rand::rngs::OsRng;
    use tempfile::TempDir;

    fn make_store() -> (RocksDbNoteStore, TempDir) {
        let dir = TempDir::new().unwrap();
        let db = RocksDB::new(dir.path().to_str().unwrap());
        db.open().unwrap();
        (RocksDbNoteStore::new(Arc::new(db)), dir)
    }

    fn random_commitment_and_pubkey() -> (PedersenCommitment, Point) {
        let mut rng = OsRng;
        let blinding = Scalar::random(&mut rng);
        let commitment = PedersenCommitment::commit(42, &blinding);
        let pc = PedersenGens::default();
        let secret = Scalar::random(&mut rng);
        let pubkey = Point::multiscalar_mul(&[secret], &[pc.B]);
        (commitment, pubkey)
    }

    #[test]
    fn record_and_lookup_round_trip() {
        let (mut store, _dir) = make_store();
        let (commitment, pubkey) = random_commitment_and_pubkey();
        store.record_note(commitment, pubkey);

        let found = store.lookup_owner(&commitment).expect("must exist");
        assert_eq!(found, pubkey);
    }

    #[test]
    fn unknown_commitment_returns_none() {
        let (store, _dir) = make_store();
        let (commitment, _) = random_commitment_and_pubkey();
        assert!(store.lookup_owner(&commitment).is_none());
    }

    #[test]
    fn mark_spent_then_is_spent_returns_true() {
        let (mut store, _dir) = make_store();
        let nf = Nullifier([0xab; 32]);
        assert!(!store.is_spent(&nf));
        store.mark_spent(nf);
        assert!(store.is_spent(&nf));
    }

    #[test]
    fn distinct_nullifiers_independent() {
        let (mut store, _dir) = make_store();
        let nf1 = Nullifier([0x01; 32]);
        let nf2 = Nullifier([0x02; 32]);
        store.mark_spent(nf1);
        assert!(store.is_spent(&nf1));
        assert!(!store.is_spent(&nf2));
    }

    #[test]
    fn distinct_commitments_independent() {
        let (mut store, _dir) = make_store();
        let (c1, pk1) = random_commitment_and_pubkey();
        let (c2, pk2) = random_commitment_and_pubkey();
        store.record_note(c1, pk1);
        store.record_note(c2, pk2);

        assert_eq!(store.lookup_owner(&c1).unwrap(), pk1);
        assert_eq!(store.lookup_owner(&c2).unwrap(), pk2);
    }

    #[test]
    fn note_count_tracks_records() {
        let (mut store, _dir) = make_store();
        assert_eq!(store.note_count().unwrap(), 0);

        for _ in 0..5 {
            let (c, pk) = random_commitment_and_pubkey();
            store.record_note(c, pk);
        }
        assert_eq!(store.note_count().unwrap(), 5);
    }

    #[test]
    fn end_to_end_transfer_validates_against_rocksdb_store() {
        // The full privacy-preserving flow with a real RocksDB-backed store.
        use hypersnap_crypto::tokens::{
            create_stealth_output, prove_value_range, scan_stealth_note, schnorr_sign,
            Nullifier as Nf, PedersenCommitment as PC, StealthKeypair, TransferInput,
            TransferOutput, TransferTx, DEFAULT_RANGE_BITS,
        };

        let mut rng = OsRng;
        let recipient = StealthKeypair::generate(&mut rng);
        let address = recipient.public_address();

        let value = 100u64;
        let blinding = Scalar::random(&mut rng);
        let stealth = create_stealth_output(&address, &mut rng);
        let commitment = PC::commit(value, &blinding);

        let (mut store, _dir) = make_store();
        store.record_note(commitment, stealth.one_time_pubkey);

        let spend_secret =
            scan_stealth_note(&recipient, &stealth.tx_pubkey, &stealth.one_time_pubkey)
                .expect("must scan");
        let nullifier = Nf::derive(&spend_secret, &commitment);

        let r_out = Scalar::random(&mut rng);
        let (out_proof, _) =
            prove_value_range(value, &r_out, DEFAULT_RANGE_BITS, &mut rng).unwrap();
        let mut tx = TransferTx {
            inputs: vec![TransferInput {
                commitment,
                nullifier,
                spend_signature: schnorr_sign(&spend_secret, &[0u8; 32], &mut rng),
            }],
            outputs: vec![TransferOutput {
                commitment: PC::commit(value, &r_out),
                range_proof: out_proof,
            }],
            fee_atoms: 0,
        };

        // Sign properly under the spend secret over the canonical payload.
        let payload = tx.signing_payload();
        tx.inputs[0].spend_signature = schnorr_sign(&spend_secret, &payload, &mut rng);

        assert!(tx.validate_against_store(&store).is_ok());

        store.mark_spent(tx.inputs[0].nullifier);
        let result = tx.validate_against_store(&store);
        assert!(result.is_err(), "second spend must fail");
    }
}
