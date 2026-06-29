//! FIP-proof-of-work-tokenization §8.3 F0 reverse index.
//!
//! Maintains a ref-counted per-(requester_fid, user_fid) marker so
//! the production `PoqReader::signer_authorizations(fid)` can
//! prefix-scan `HyperSignerAuthByRequester[fid][*]` to count the
//! distinct users that have at least one active signer attributable
//! to `fid`'s app-fid via SignedKeyRequestMetadata.
//!
//! Wired into the gasless KEY_ADD / KEY_REMOVE merge flow:
//!
//! - `inc(request_fid, user_fid)` is called on the FIRST-time-add
//!   branch (a real new signer record); same-FID upserts are no-ops
//!   per the existing per-FID-count semantics.
//! - `dec(request_fid, user_fid)` is called on every KEY_REMOVE
//!   that succeeds; when the count would drop to zero the entry is
//!   deleted so the prefix scan only ever sees pairs with at least
//!   one active signer.
//!
//! The legacy on-chain `SignerEvent` path is NOT yet wired —
//! request_fid extraction from the embedded SignedKeyRequestMetadata
//! would need to happen at on-chain merge time. Documented as a
//! follow-up; the gasless path is the modern majority.

use super::get_from_db_or_txn;
use crate::core::error::HubError;
use crate::storage::constants::RootPrefix;
use crate::storage::db::{RocksDB, RocksDbTransactionBatch};

const COUNT_BYTES: usize = 4;

fn make_key(request_fid: u64, user_fid: u64) -> Vec<u8> {
    let mut k = Vec::with_capacity(1 + 8 + 8);
    k.push(RootPrefix::HyperSignerAuthByRequester as u8);
    k.extend_from_slice(&request_fid.to_be_bytes());
    k.extend_from_slice(&user_fid.to_be_bytes());
    k
}

fn read(
    db: &RocksDB,
    txn: &RocksDbTransactionBatch,
    request_fid: u64,
    user_fid: u64,
) -> Result<u32, HubError> {
    let k = make_key(request_fid, user_fid);
    match get_from_db_or_txn(db, txn, &k)? {
        None => Ok(0),
        Some(bytes) => {
            if bytes.len() != COUNT_BYTES {
                return Err(HubError {
                    code: "internal_error".to_string(),
                    message: format!(
                        "corrupt signer-auth-index value: expected {} bytes, got {}",
                        COUNT_BYTES,
                        bytes.len()
                    ),
                });
            }
            let mut be = [0u8; 4];
            be.copy_from_slice(&bytes);
            Ok(u32::from_be_bytes(be))
        }
    }
}

/// Increment the per-(requester, user) signer count. Saturates at
/// `u32::MAX` (≈ 4B signers from one app for one user is well
/// beyond any realistic operation).
pub fn inc(
    db: &RocksDB,
    txn: &mut RocksDbTransactionBatch,
    request_fid: u64,
    user_fid: u64,
) -> Result<(), HubError> {
    if request_fid == 0 || user_fid == 0 {
        return Ok(());
    }
    let current = read(db, txn, request_fid, user_fid)?;
    let next = current.saturating_add(1);
    txn.put(make_key(request_fid, user_fid), next.to_be_bytes().to_vec());
    Ok(())
}

/// Decrement the per-(requester, user) signer count. When the
/// count would drop to zero the entry is deleted so the prefix
/// scan only sees pairs with at least one active signer.
/// Underflows are clamped to zero (and then deleted).
pub fn dec(
    db: &RocksDB,
    txn: &mut RocksDbTransactionBatch,
    request_fid: u64,
    user_fid: u64,
) -> Result<(), HubError> {
    if request_fid == 0 || user_fid == 0 {
        return Ok(());
    }
    let current = read(db, txn, request_fid, user_fid)?;
    if current <= 1 {
        txn.delete(make_key(request_fid, user_fid));
    } else {
        let next = current - 1;
        txn.put(make_key(request_fid, user_fid), next.to_be_bytes().to_vec());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::db::RocksDB;
    use std::sync::Arc;
    use tempfile::TempDir;

    fn fresh_db() -> (Arc<RocksDB>, TempDir) {
        let dir = TempDir::new().unwrap();
        let db = RocksDB::new(dir.path().to_str().unwrap());
        db.open().unwrap();
        (Arc::new(db), dir)
    }

    #[test]
    fn inc_then_dec_zeroes_and_deletes() {
        let (db, _dir) = fresh_db();
        let mut txn = RocksDbTransactionBatch::new();
        inc(&db, &mut txn, 42, 7).unwrap();
        assert_eq!(read(&db, &txn, 42, 7).unwrap(), 1);
        dec(&db, &mut txn, 42, 7).unwrap();
        assert_eq!(read(&db, &txn, 42, 7).unwrap(), 0);
        // After zeroing, the key is deleted (no record).
        let k = make_key(42, 7);
        assert!(get_from_db_or_txn(&db, &txn, &k).unwrap().is_none());
    }

    #[test]
    fn multiple_inc_then_single_dec_keeps_entry() {
        let (db, _dir) = fresh_db();
        let mut txn = RocksDbTransactionBatch::new();
        inc(&db, &mut txn, 42, 7).unwrap();
        inc(&db, &mut txn, 42, 7).unwrap();
        inc(&db, &mut txn, 42, 7).unwrap();
        assert_eq!(read(&db, &txn, 42, 7).unwrap(), 3);
        dec(&db, &mut txn, 42, 7).unwrap();
        assert_eq!(read(&db, &txn, 42, 7).unwrap(), 2);
        // Entry still present.
        let k = make_key(42, 7);
        assert!(get_from_db_or_txn(&db, &txn, &k).unwrap().is_some());
    }

    #[test]
    fn zero_request_fid_is_noop() {
        let (db, _dir) = fresh_db();
        let mut txn = RocksDbTransactionBatch::new();
        inc(&db, &mut txn, 0, 7).unwrap();
        dec(&db, &mut txn, 0, 7).unwrap();
        // No keys written.
        let k = make_key(0, 7);
        assert!(get_from_db_or_txn(&db, &txn, &k).unwrap().is_none());
    }
}
