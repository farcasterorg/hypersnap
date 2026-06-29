//! Per-FID trust score store.
//!
//! Backs the validator-registration trust gate (FIP-hyper-validator-selection
//! §2.2): only FIDs with trust ≥ `min_validator_trust_score` may register a
//! validator. The score is also surfaced to other hyper-layer logic (e.g.
//! the proof-of-quality reward calculation) as the canonical "is this FID
//! organically credible" signal.
//!
//! At cutover, the operator-supplied snapshot from the retro evaluation is
//! installed via `set_many`. After cutover, every successful in-protocol
//! reward issuance refreshes the snapshot from the threshold-signed scoring
//! output (Phase D).

use crate::core::error::HubError;
use crate::storage::constants::RootPrefix;
use crate::storage::db::RocksDB;
use std::sync::Arc;

/// Key layout: `[HyperTrustScore][fid BE u64]` — 9 bytes.
/// Value: 8-byte big-endian f64 (IEEE-754).
fn make_key(fid: u64) -> [u8; 9] {
    let mut k = [0u8; 9];
    k[0] = RootPrefix::HyperTrustScore as u8;
    k[1..].copy_from_slice(&fid.to_be_bytes());
    k
}

#[derive(Clone)]
pub struct TrustScoreStore {
    db: Arc<RocksDB>,
}

impl TrustScoreStore {
    pub fn new(db: Arc<RocksDB>) -> Self {
        Self { db }
    }

    pub fn set(&self, fid: u64, score: f64) -> Result<(), HubError> {
        let key = make_key(fid);
        let value = score.to_be_bytes();
        self.db.put(&key, &value).map_err(HubError::from)
    }

    pub fn get(&self, fid: u64) -> Result<Option<f64>, HubError> {
        let key = make_key(fid);
        match self.db.get(&key).map_err(HubError::from)? {
            Some(bytes) if bytes.len() == 8 => {
                let mut be = [0u8; 8];
                be.copy_from_slice(&bytes);
                Ok(Some(f64::from_be_bytes(be)))
            }
            _ => Ok(None),
        }
    }

    /// Bulk set used at cutover to install the bootstrap trust snapshot
    /// and at epoch boundaries to rotate from a freshly-signed scoring
    /// output.
    pub fn set_many(&self, entries: &[(u64, f64)]) -> Result<(), HubError> {
        for &(fid, score) in entries {
            self.set(fid, score)?;
        }
        Ok(())
    }

    /// Delete the trust score record for a single FID. F014 fix.
    pub fn delete(&self, fid: u64) -> Result<(), HubError> {
        let key = make_key(fid);
        self.db.del(&key).map_err(HubError::from)
    }

    /// Bulk-replace: install every FID listed in `entries` and
    /// delete every FID currently in the store that is not in
    /// `entries`. This is the snapshot-apply semantic the audit
    /// finding F014 calls for — `set_many` alone is PUT-only and
    /// leaves stale FIDs in the store indefinitely, feeding the
    /// validator-trust gate, soft-evict filter, and the fee
    /// discount path with arbitrarily stale data.
    pub fn replace_with(&self, entries: &[(u64, f64)]) -> Result<(), HubError> {
        use crate::storage::db::PageOptions;
        use std::collections::BTreeSet;
        let new_fids: BTreeSet<u64> = entries.iter().map(|(f, _)| *f).collect();

        // Walk the existing store and collect FIDs that aren't in
        // the new set.
        let prefix = vec![RootPrefix::HyperTrustScore as u8];
        let mut to_delete: Vec<u64> = Vec::new();
        self.db.for_each_iterator_by_prefix(
            Some(prefix.clone()),
            None,
            &PageOptions::default(),
            |key, _value| {
                if key.len() == 9 {
                    let mut fid_bytes = [0u8; 8];
                    fid_bytes.copy_from_slice(&key[1..9]);
                    let fid = u64::from_be_bytes(fid_bytes);
                    if !new_fids.contains(&fid) {
                        to_delete.push(fid);
                    }
                }
                Ok(false)
            },
        )?;

        // Apply: deletes + sets in a single batch.
        let mut batch = self.db.txn();
        for fid in to_delete {
            batch.delete(make_key(fid).to_vec());
        }
        for &(fid, score) in entries {
            batch.put(make_key(fid).to_vec(), score.to_be_bytes().to_vec());
        }
        self.db.commit(batch).map_err(HubError::from)?;
        Ok(())
    }
}

/// `TrustScoreResolver` adapter for the validator registry. Reads the
/// score from disk on demand. Callers that want to avoid the per-call
/// disk hit can plug in their own in-memory resolver implementing the
/// same trait.
impl crate::hyper::validator_registry::TrustScoreResolver for TrustScoreStore {
    fn trust_score_for_fid(&self, fid: u64) -> Result<Option<f64>, HubError> {
        self.get(fid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn store() -> (TrustScoreStore, TempDir) {
        let dir = TempDir::new().unwrap();
        let db = RocksDB::new(dir.path().to_str().unwrap());
        db.open().unwrap();
        (TrustScoreStore::new(Arc::new(db)), dir)
    }

    #[test]
    fn round_trip_score() {
        let (s, _d) = store();
        s.set(42, 0.6789).unwrap();
        let got = s.get(42).unwrap().unwrap();
        assert!((got - 0.6789).abs() < 1e-12);
    }

    #[test]
    fn missing_fid_returns_none() {
        let (s, _d) = store();
        assert!(s.get(99).unwrap().is_none());
    }

    #[test]
    fn set_many_overwrites_existing() {
        let (s, _d) = store();
        s.set(10, 0.1).unwrap();
        s.set_many(&[(10, 0.5), (11, 0.7)]).unwrap();
        assert_eq!(s.get(10).unwrap().unwrap(), 0.5);
        assert_eq!(s.get(11).unwrap().unwrap(), 0.7);
    }
}
