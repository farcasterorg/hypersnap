//! FIP-proof-of-quality §3 rolling content-fingerprint store.
//!
//! Backs the live `uniqueness_score` used by the trust×uniqueness fee
//! discount. Inserts the SimHash of every CastAdd that passes the merge
//! pipeline; serves prefix-scan + hamming-distance lookups against the
//! last 30 days of fingerprints.
//!
//! Key layout (under `RootPrefix::HyperContentFingerprint`):
//!   `[87][simhash_high u64 BE][ts u64 BE][fid u64 BE]`
//! Value:
//!   16-byte little-endian full SimHash `u128`.
//!
//! Bucketing on the top 64 bits of the SimHash gives O(1) lookup for the
//! exact-content-repost case (which is what most spammers do). For each
//! candidate at lookup time we prefix-scan the bucket and run a Hamming
//! check on the full 128-bit hash, so near-dups whose top half happens to
//! collide are also caught.
//!
//! Rolling-window eviction: lookups simultaneously delete entries whose
//! `ts` is older than 30 days. This amortizes maintenance across the
//! read path so no background scrubber is needed.

use std::sync::Arc;

use proof_of_quality::uniqueness::{
    fingerprint, hamming_distance_128, uniqueness_score_from_neighbor_count,
    NEAR_DUP_HAMMING_THRESHOLD,
};

use crate::core::error::HubError;
use crate::storage::constants::RootPrefix;
use crate::storage::db::{PageOptions, RocksDB};

#[derive(thiserror::Error, Debug)]
pub enum FingerprintError {
    #[error(transparent)]
    Hub(#[from] HubError),
    #[error("malformed fingerprint key (len {0})")]
    MalformedKey(usize),
    #[error("malformed fingerprint value (len {0})")]
    MalformedValue(usize),
}

/// 30-day rolling window in seconds.
pub const FINGERPRINT_WINDOW_SECS: u64 = 30 * 24 * 60 * 60;

/// Key prefix size: `[prefix u8][bucket u64 BE]`.
const BUCKET_PREFIX_LEN: usize = 1 + 8;
/// Full key size: bucket prefix + `[ts u64 BE][fid u64 BE]`.
const FULL_KEY_LEN: usize = BUCKET_PREFIX_LEN + 8 + 8;

#[derive(Clone)]
pub struct FingerprintStore {
    db: Arc<RocksDB>,
}

impl FingerprintStore {
    pub fn new(db: Arc<RocksDB>) -> Self {
        Self { db }
    }

    fn bucket_prefix(simhash_high: u64) -> [u8; BUCKET_PREFIX_LEN] {
        let mut k = [0u8; BUCKET_PREFIX_LEN];
        k[0] = RootPrefix::HyperContentFingerprint as u8;
        k[1..9].copy_from_slice(&simhash_high.to_be_bytes());
        k
    }

    fn full_key(simhash_high: u64, ts: u64, fid: u64) -> [u8; FULL_KEY_LEN] {
        let mut k = [0u8; FULL_KEY_LEN];
        k[0] = RootPrefix::HyperContentFingerprint as u8;
        k[1..9].copy_from_slice(&simhash_high.to_be_bytes());
        k[9..17].copy_from_slice(&ts.to_be_bytes());
        k[17..25].copy_from_slice(&fid.to_be_bytes());
        k
    }

    /// Persist a fingerprint for `(fid, text)` at timestamp `ts_secs`.
    /// Direct disk write — only safe outside a `merge_message` flow
    /// (e.g. test fixtures). Production code must use `stage_insert`
    /// so the write composes with the engine's `RocksDbTransactionBatch`
    /// (F133).
    #[cfg(test)]
    pub fn insert(&self, fid: u64, text: &str, ts_secs: u64) -> Result<u128, FingerprintError> {
        let fp = fingerprint(text);
        let high = (fp >> 64) as u64;
        let key = Self::full_key(high, ts_secs, fid);
        let val = fp.to_le_bytes();
        self.db.put(&key, &val).map_err(HubError::from)?;
        Ok(fp)
    }

    /// Batch-aware insert. Stages the fingerprint write on `batch`
    /// so it commits atomically with the surrounding merge — critical
    /// for deterministic state replay, because a direct `db.put`
    /// would let the proposer's fingerprint become visible to
    /// validators replaying the same proposal, perturbing their
    /// `uniqueness_score` and producing a different effective fee +
    /// state root (state-validation `HashMismatch`).
    pub fn stage_insert(
        &self,
        fid: u64,
        text: &str,
        ts_secs: u64,
        batch: &mut crate::storage::db::RocksDbTransactionBatch,
    ) -> u128 {
        let fp = fingerprint(text);
        let high = (fp >> 64) as u64;
        let key = Self::full_key(high, ts_secs, fid);
        let val = fp.to_le_bytes();
        batch.put(key.to_vec(), val.to_vec());
        fp
    }

    /// Score the candidate text against the rolling window. Stale
    /// fingerprints (`ts < now_secs - FINGERPRINT_WINDOW_SECS`) in
    /// the inspected bucket are staged for eviction on the caller's
    /// `batch` — see F133. This is critical for deterministic state
    /// replay: a direct `self.db.commit` here would leak eviction
    /// side-effects out of the engine's `RocksDbTransactionBatch`
    /// (the simulate path discards the batch but live disk would
    /// retain the deletes, perturbing peer validators' fingerprint
    /// state and the `uniqueness_score` they compute against the
    /// next CastAdd → fee divergence → state-root fork).
    pub fn uniqueness_score(
        &self,
        text: &str,
        now_secs: u64,
        batch: &mut crate::storage::db::RocksDbTransactionBatch,
    ) -> Result<f64, FingerprintError> {
        let candidate = fingerprint(text);
        let high = (candidate >> 64) as u64;
        let prefix = Self::bucket_prefix(high);
        let mut stop = prefix.to_vec();
        // Stop key = prefix + 0xFF * 16 so the scan covers the full bucket.
        stop.extend_from_slice(&[0xFFu8; 16]);

        let cutoff = now_secs.saturating_sub(FINGERPRINT_WINDOW_SECS);
        let mut near_dup_count: u32 = 0;
        let mut to_evict: Vec<Vec<u8>> = Vec::new();

        self.db
            .for_each_iterator_by_prefix(
                Some(prefix.to_vec()),
                Some(stop),
                &PageOptions::default(),
                |key, value| {
                    if key.len() != FULL_KEY_LEN {
                        return Ok(false);
                    }
                    if value.len() != 16 {
                        return Ok(false);
                    }
                    let mut ts_bytes = [0u8; 8];
                    ts_bytes.copy_from_slice(&key[9..17]);
                    let ts = u64::from_be_bytes(ts_bytes);
                    if ts < cutoff {
                        to_evict.push(key.to_vec());
                        return Ok(false);
                    }
                    let mut val_bytes = [0u8; 16];
                    val_bytes.copy_from_slice(&value);
                    let stored = u128::from_le_bytes(val_bytes);
                    if hamming_distance_128(candidate, stored) <= NEAR_DUP_HAMMING_THRESHOLD {
                        near_dup_count = near_dup_count.saturating_add(1);
                    }
                    Ok(false)
                },
            )
            .map_err(HubError::from)?;

        for k in to_evict {
            batch.delete(k);
        }

        Ok(uniqueness_score_from_neighbor_count(near_dup_count))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::db::RocksDB;
    use std::sync::Arc;
    use tempfile::TempDir;

    fn make_store() -> (FingerprintStore, TempDir) {
        let dir = TempDir::new().unwrap();
        let mut db = RocksDB::new(dir.path().to_str().unwrap());
        db.open().unwrap();
        (FingerprintStore::new(Arc::new(db)), dir)
    }

    #[test]
    fn novel_text_scores_one() {
        let (store, _d) = make_store();
        let mut batch = crate::storage::db::RocksDbTransactionBatch::new();
        let score = store
            .uniqueness_score("first cast ever", 1_000, &mut batch)
            .unwrap();
        assert_eq!(score, 1.0);
    }

    #[test]
    fn duplicate_text_drops_score() {
        let (store, _d) = make_store();
        let text = "exact same memetic cast that just keeps coming";
        for fid in 1..=8u64 {
            store.insert(fid, text, 1_000).unwrap();
        }
        let mut batch = crate::storage::db::RocksDbTransactionBatch::new();
        let score = store.uniqueness_score(text, 1_000, &mut batch).unwrap();
        assert!(
            score < 1.0,
            "duplicate should drive score below 1.0, got {score}"
        );
    }

    #[test]
    fn old_fingerprints_evicted_on_read() {
        let (store, _d) = make_store();
        let text = "ancient repost from long ago";
        store.insert(1, text, 1_000).unwrap();
        // Far past the 30-day window
        let now = 1_000 + FINGERPRINT_WINDOW_SECS + 1;
        let mut batch = crate::storage::db::RocksDbTransactionBatch::new();
        let score = store.uniqueness_score(text, now, &mut batch).unwrap();
        assert_eq!(score, 1.0, "ancient entries must not count");
        // Eviction was staged on `batch` (F133 fix), so committing
        // here mirrors what the engine's outer commit would do.
        store.db.commit(batch).unwrap();
        let mut batch2 = crate::storage::db::RocksDbTransactionBatch::new();
        let score = store.uniqueness_score(text, now, &mut batch2).unwrap();
        assert_eq!(score, 1.0);
    }
}
