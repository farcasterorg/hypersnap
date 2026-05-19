//! FIP-proof-of-work-tokenization §10.5 retroactive-distribution store.
//!
//! Persists per-FID `HyperRetroactiveRecord` entries under
//! `RootPrefix::HyperRetroactiveScore`. The record carries the FID's
//! remaining undisbursed retroactive allocation in atoms — the
//! per-epoch vesting tranche pass walks this store, credits a tranche
//! to the FID's reward balance, and decrements `remaining_atoms`.
//!
//! Bootstrap: at cutover, the operator-supplied retro CSV is loaded
//! into this store via `seed_records`. Each row carries the FID's
//! non-disbursed atoms — the first 7 of the §10.5 36-tranche schedule
//! have already paid out off-protocol, so on-protocol vesting runs for
//! the remaining 29 epochs.
//!
//! Idempotency: the per-tranche credit is keyed in `RewardStore` by
//! `(epoch, fid, WorkMarket::Retroactive)`. Re-importing a historical
//! block cannot double-pay because `credit_if_unissued` no-ops on the
//! second call. The store side is also idempotent — re-seeding a row
//! overwrites with the same value if the input CSV is unchanged.

use crate::core::error::HubError;
use crate::proto;
use crate::storage::constants::RootPrefix;
use crate::storage::db::{PageOptions, RocksDB};
use prost::Message;
use std::path::Path;
use std::sync::Arc;

#[derive(thiserror::Error, Debug)]
pub enum RetroStoreError {
    #[error(transparent)]
    Hub(#[from] HubError),
    #[error("encode: {0}")]
    Encode(prost::EncodeError),
    #[error("decode: {0}")]
    Decode(#[from] prost::DecodeError),
}

#[derive(thiserror::Error, Debug)]
pub enum RetroCsvError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("line {line}: {msg}")]
    Parse { line: usize, msg: String },
    #[error("duplicate fid {fid} on line {line}")]
    DuplicateFid { fid: u64, line: usize },
}

/// Parse a retroactive-distribution CSV into the proto records that
/// `RetroStore::seed_records` / `HyperRuntime::apply_cutover` expect.
///
/// Format: one entry per line, two comma-separated columns —
///
///   fid,remaining_atoms
///
/// `fid` is decimal; `remaining_atoms` is decimal in atoms (1 HYPER =
/// 1,000,000 atoms). An optional header line `fid,remaining_atoms`
/// (or any non-numeric first cell) is auto-detected and skipped.
/// Whitespace around values is tolerated; blank lines are skipped.
/// Duplicate FIDs raise an error so seeding is unambiguous.
///
/// `remaining_atoms` is the *non-disbursed* portion that must vest
/// on protocol — the FIP §10.5 schedule has 7 of 36 tranches paid
/// off-protocol before cutover, so callers should write each row's
/// remaining as the post-off-protocol balance owed.
pub fn load_retro_csv(
    path: impl AsRef<Path>,
) -> Result<Vec<proto::HyperRetroactiveRecord>, RetroCsvError> {
    use std::collections::BTreeSet;
    use std::fs::File;
    use std::io::{BufRead, BufReader};
    let f = File::open(path)?;
    let reader = BufReader::new(f);
    let mut out = Vec::new();
    let mut seen: BTreeSet<u64> = BTreeSet::new();
    let mut header_skipped = false;
    for (idx, line) in reader.lines().enumerate() {
        let line = line?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        // Auto-skip a header on the first non-blank line if the
        // first column doesn't parse as a u64.
        if !header_skipped {
            header_skipped = true;
            let first = trimmed.split(',').next().unwrap_or("").trim();
            if first.parse::<u64>().is_err() {
                continue;
            }
        }
        let mut parts = trimmed.splitn(2, ',');
        let fid_s = parts.next().ok_or(RetroCsvError::Parse {
            line: idx + 1,
            msg: "missing fid column".into(),
        })?;
        let amt_s = parts.next().ok_or(RetroCsvError::Parse {
            line: idx + 1,
            msg: "missing remaining_atoms column".into(),
        })?;
        let fid: u64 = fid_s.trim().parse().map_err(|_| RetroCsvError::Parse {
            line: idx + 1,
            msg: format!("fid not a u64: {fid_s:?}"),
        })?;
        let remaining: u64 = amt_s.trim().parse().map_err(|_| RetroCsvError::Parse {
            line: idx + 1,
            msg: format!("remaining_atoms not a u64: {amt_s:?}"),
        })?;
        if !seen.insert(fid) {
            return Err(RetroCsvError::DuplicateFid { fid, line: idx + 1 });
        }
        out.push(proto::HyperRetroactiveRecord {
            fid,
            remaining_atoms: remaining,
        });
    }
    Ok(out)
}

/// Persistent store for the retroactive-vesting per-FID state.
#[derive(Clone)]
pub struct RetroStore {
    db: Arc<RocksDB>,
}

impl RetroStore {
    pub fn new(db: Arc<RocksDB>) -> Self {
        Self { db }
    }

    fn key_for(fid: u64) -> Vec<u8> {
        let mut k = Vec::with_capacity(9);
        k.push(RootPrefix::HyperRetroactiveScore as u8);
        k.extend_from_slice(&fid.to_be_bytes());
        k
    }

    /// Insert or overwrite a record. Used by the cutover-time CSV
    /// bootstrap. Re-seeding the same `(fid, remaining_atoms)` pair
    /// is a no-op write.
    pub fn put(&self, record: &proto::HyperRetroactiveRecord) -> Result<(), RetroStoreError> {
        let mut buf = Vec::with_capacity(record.encoded_len());
        record.encode(&mut buf).map_err(RetroStoreError::Encode)?;
        self.db
            .put(&Self::key_for(record.fid), &buf)
            .map_err(HubError::from)?;
        Ok(())
    }

    /// Bulk-seed the store from an iterator of records. Convenient
    /// for the operator CSV path. Each row writes via `put` —
    /// duplicates within the input overwrite, so the last entry for a
    /// given FID wins.
    pub fn seed_records<'a, I>(&self, records: I) -> Result<usize, RetroStoreError>
    where
        I: IntoIterator<Item = &'a proto::HyperRetroactiveRecord>,
    {
        let mut count = 0usize;
        for r in records {
            self.put(r)?;
            count += 1;
        }
        Ok(count)
    }

    pub fn get(&self, fid: u64) -> Result<Option<proto::HyperRetroactiveRecord>, RetroStoreError> {
        match self.db.get(&Self::key_for(fid)).map_err(HubError::from)? {
            Some(bytes) => Ok(Some(proto::HyperRetroactiveRecord::decode(bytes.as_ref())?)),
            None => Ok(None),
        }
    }

    /// Iterate every record in ascending-fid order. Used by the
    /// per-epoch tranche pass.
    pub fn iter_all(&self) -> Result<Vec<proto::HyperRetroactiveRecord>, RetroStoreError> {
        let start = vec![RootPrefix::HyperRetroactiveScore as u8];
        let stop = vec![RootPrefix::HyperRetroactiveScore as u8 + 1];
        let mut out = Vec::new();
        self.db
            .for_each_iterator_by_prefix(
                Some(start),
                Some(stop),
                &PageOptions::default(),
                |_key, value| {
                    let rec = proto::HyperRetroactiveRecord::decode(value)?;
                    out.push(rec);
                    Ok(false)
                },
            )
            .map_err(HubError::from)?;
        Ok(out)
    }

    /// Remove a record. Optional convenience — emptied records can
    /// also stay in the store with `remaining_atoms == 0`; the
    /// per-epoch pass treats them as no-ops either way.
    pub fn remove(&self, fid: u64) -> Result<(), RetroStoreError> {
        self.db.del(&Self::key_for(fid)).map_err(HubError::from)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn make_store() -> (RetroStore, TempDir) {
        let dir = TempDir::new().unwrap();
        let db = RocksDB::new(dir.path().to_str().unwrap());
        db.open().unwrap();
        (RetroStore::new(Arc::new(db)), dir)
    }

    fn rec(fid: u64, remaining: u64) -> proto::HyperRetroactiveRecord {
        proto::HyperRetroactiveRecord {
            fid,
            remaining_atoms: remaining,
        }
    }

    #[test]
    fn put_then_get_round_trips() {
        let (store, _dir) = make_store();
        store.put(&rec(7, 1_000_000)).unwrap();
        let got = store.get(7).unwrap().unwrap();
        assert_eq!(got.fid, 7);
        assert_eq!(got.remaining_atoms, 1_000_000);
    }

    #[test]
    fn get_missing_returns_none() {
        let (store, _dir) = make_store();
        assert!(store.get(42).unwrap().is_none());
    }

    #[test]
    fn put_overwrites_prior_value() {
        let (store, _dir) = make_store();
        store.put(&rec(7, 100)).unwrap();
        store.put(&rec(7, 200)).unwrap();
        assert_eq!(store.get(7).unwrap().unwrap().remaining_atoms, 200);
    }

    #[test]
    fn iter_all_returns_records_sorted_by_fid() {
        let (store, _dir) = make_store();
        // Seed out of order to confirm the iterator reorders.
        store.put(&rec(7, 700)).unwrap();
        store.put(&rec(1, 100)).unwrap();
        store.put(&rec(42, 4200)).unwrap();
        let all = store.iter_all().unwrap();
        let fids: Vec<u64> = all.iter().map(|r| r.fid).collect();
        assert_eq!(fids, vec![1, 7, 42]);
    }

    #[test]
    fn seed_records_bulk_inserts() {
        let (store, _dir) = make_store();
        let rows = vec![rec(1, 10), rec(2, 20), rec(3, 30)];
        let n = store.seed_records(rows.iter()).unwrap();
        assert_eq!(n, 3);
        assert_eq!(store.iter_all().unwrap().len(), 3);
    }

    #[test]
    fn remove_deletes_record() {
        let (store, _dir) = make_store();
        store.put(&rec(7, 100)).unwrap();
        store.remove(7).unwrap();
        assert!(store.get(7).unwrap().is_none());
    }

    #[test]
    fn iter_all_empty_returns_empty() {
        let (store, _dir) = make_store();
        assert!(store.iter_all().unwrap().is_empty());
    }

    #[test]
    fn load_retro_csv_parses_minimal() {
        use std::io::Write;
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("retro.csv");
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(f, "1,1000000").unwrap();
        writeln!(f, "2,2000000").unwrap();
        writeln!(f, "3,3000000").unwrap();
        let recs = load_retro_csv(&path).unwrap();
        assert_eq!(recs.len(), 3);
        assert_eq!((recs[0].fid, recs[0].remaining_atoms), (1, 1_000_000));
        assert_eq!((recs[2].fid, recs[2].remaining_atoms), (3, 3_000_000));
    }

    #[test]
    fn load_retro_csv_skips_header_and_blanks() {
        use std::io::Write;
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("retro.csv");
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(f, "fid,remaining_atoms").unwrap();
        writeln!(f).unwrap(); // blank
        writeln!(f, "  42, 12345  ").unwrap(); // whitespace tolerated
        let recs = load_retro_csv(&path).unwrap();
        assert_eq!(recs.len(), 1);
        assert_eq!((recs[0].fid, recs[0].remaining_atoms), (42, 12_345));
    }

    #[test]
    fn load_retro_csv_rejects_duplicate_fid() {
        use std::io::Write;
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("retro.csv");
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(f, "1,100").unwrap();
        writeln!(f, "1,200").unwrap();
        let r = load_retro_csv(&path);
        assert!(matches!(r, Err(RetroCsvError::DuplicateFid { fid: 1, .. })));
    }

    #[test]
    fn load_retro_csv_rejects_malformed() {
        use std::io::Write;
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("retro.csv");
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(f, "1,not_a_number").unwrap();
        let r = load_retro_csv(&path);
        assert!(matches!(r, Err(RetroCsvError::Parse { .. })));
    }
}
