//! FIP-proof-of-work-tokenization §13.9 FID custody escrow.
//!
//! When an `ID_REGISTER_EVENT_TYPE_TRANSFER` event is observed on
//! Optimism for FID X, X's available token balance moves to an
//! escrow keyed by the **previous** custody address. The
//! previous custodian retains full ownership and can later claim
//! to a different FID (via `TokenEscrowClaim`) or bridge out
//! (via `TokenEscrowBridge`). These are signed by the old
//! custody address using EIP-712.
//!
//! ## Why escrow rather than transfer-with-FID
//!
//! The FIP rationale (§13.9): tokens are earned by the operator
//! behind the FID, not by the FID itself. Buying an FID with a
//! token balance attached would let bad actors monetize behavior
//! they didn't earn. Escrow keeps economic value with the original
//! operator while custody transfers the identity-control role.
//!
//! ## Storage shape
//!
//! ```text
//! [RootPrefix::HyperTokenEscrow] ++ [custody_address 20B]
//!     -> u64 BE atoms (escrowed balance)
//! ```
//!
//! ## What Phase 4a covers
//!
//! - The store + accessors.
//! - `move_balance_to_escrow(fid, old_custody_address)` — the
//!   atomic mechanic the watcher / event-observer calls when
//!   it sees a transfer.
//!
//! ## What Phase 4b will add
//!
//! - `TokenEscrowClaim` proto + apply path (EIP-712 signed by
//!   the old custody address, specifies a destination FID).
//! - Watcher hook that triggers `move_balance_to_escrow` when
//!   `ID_REGISTER_EVENT_TYPE_TRANSFER` is observed.
//! - `TokenEscrowBridge` for bridge-out from escrow.

use crate::core::error::HubError;
use crate::storage::constants::RootPrefix;
use crate::storage::db::RocksDB;
use std::sync::Arc;

#[derive(thiserror::Error, Debug)]
pub enum CustodyEscrowError {
    #[error(transparent)]
    Hub(#[from] HubError),
    #[error("custody_address must be exactly 20 bytes (got {0})")]
    BadAddressLen(usize),
    #[error("escrow balance overflow on address {address_hex:?}")]
    BalanceOverflow { address_hex: String },
}

/// Persistent escrow ledger keyed by 20-byte EVM custody address.
#[derive(Clone)]
pub struct CustodyEscrowStore {
    db: Arc<RocksDB>,
}

impl CustodyEscrowStore {
    pub fn new(db: Arc<RocksDB>) -> Self {
        Self { db }
    }

    fn key(custody_address: &[u8]) -> Vec<u8> {
        let mut k = Vec::with_capacity(1 + 20);
        k.push(RootPrefix::HyperTokenEscrow as u8);
        k.extend_from_slice(custody_address);
        k
    }

    /// Read the escrow balance for `custody_address`. Returns 0
    /// for addresses with no recorded escrow.
    pub fn balance_of(&self, custody_address: &[u8]) -> Result<u64, CustodyEscrowError> {
        if custody_address.len() != 20 {
            return Err(CustodyEscrowError::BadAddressLen(custody_address.len()));
        }
        match self
            .db
            .get(&Self::key(custody_address))
            .map_err(HubError::from)?
        {
            Some(bytes) if bytes.len() == 8 => {
                let mut be = [0u8; 8];
                be.copy_from_slice(&bytes);
                Ok(u64::from_be_bytes(be))
            }
            _ => Ok(0),
        }
    }

    /// Set the escrow balance for `custody_address`. Used by the
    /// `move_balance_to_escrow` flow and by `TokenEscrowClaim` /
    /// `TokenEscrowBridge` apply paths to debit escrow.
    pub fn set_balance(
        &self,
        custody_address: &[u8],
        amount: u64,
    ) -> Result<(), CustodyEscrowError> {
        if custody_address.len() != 20 {
            return Err(CustodyEscrowError::BadAddressLen(custody_address.len()));
        }
        self.db
            .put(&Self::key(custody_address), &amount.to_be_bytes())
            .map_err(HubError::from)?;
        Ok(())
    }

    /// Add to the existing escrow balance. Returns the new total.
    /// Saturates against u64 overflow with `BalanceOverflow`.
    pub fn credit(&self, custody_address: &[u8], amount: u64) -> Result<u64, CustodyEscrowError> {
        if custody_address.len() != 20 {
            return Err(CustodyEscrowError::BadAddressLen(custody_address.len()));
        }
        let current = self.balance_of(custody_address)?;
        let new =
            current
                .checked_add(amount)
                .ok_or_else(|| CustodyEscrowError::BalanceOverflow {
                    address_hex: hex::encode(custody_address),
                })?;
        self.set_balance(custody_address, new)?;
        Ok(new)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn make_store() -> (CustodyEscrowStore, TempDir) {
        let dir = TempDir::new().unwrap();
        let db = RocksDB::new(dir.path().to_str().unwrap());
        db.open().unwrap();
        (CustodyEscrowStore::new(Arc::new(db)), dir)
    }

    #[test]
    fn unknown_address_balance_is_zero() {
        let (store, _dir) = make_store();
        assert_eq!(store.balance_of(&[0xab; 20]).unwrap(), 0);
    }

    #[test]
    fn set_then_get_round_trips() {
        let (store, _dir) = make_store();
        store.set_balance(&[0xab; 20], 1_000_000).unwrap();
        assert_eq!(store.balance_of(&[0xab; 20]).unwrap(), 1_000_000);
    }

    #[test]
    fn credit_accumulates() {
        let (store, _dir) = make_store();
        store.credit(&[0xab; 20], 100).unwrap();
        store.credit(&[0xab; 20], 200).unwrap();
        assert_eq!(store.balance_of(&[0xab; 20]).unwrap(), 300);
    }

    #[test]
    fn credit_overflow_errors() {
        let (store, _dir) = make_store();
        store.set_balance(&[0xab; 20], u64::MAX).unwrap();
        let r = store.credit(&[0xab; 20], 1);
        assert!(matches!(r, Err(CustodyEscrowError::BalanceOverflow { .. })));
    }

    #[test]
    fn rejects_bad_address_length() {
        let (store, _dir) = make_store();
        assert!(matches!(
            store.balance_of(&[0xab; 19]),
            Err(CustodyEscrowError::BadAddressLen(19))
        ));
        assert!(matches!(
            store.set_balance(&[0xab; 21], 100),
            Err(CustodyEscrowError::BadAddressLen(21))
        ));
        assert!(matches!(
            store.credit(&[0xab; 16], 100),
            Err(CustodyEscrowError::BadAddressLen(16))
        ));
    }

    #[test]
    fn distinct_addresses_independent() {
        let (store, _dir) = make_store();
        store.credit(&[0xaa; 20], 100).unwrap();
        store.credit(&[0xbb; 20], 200).unwrap();
        assert_eq!(store.balance_of(&[0xaa; 20]).unwrap(), 100);
        assert_eq!(store.balance_of(&[0xbb; 20]).unwrap(), 200);
    }
}
