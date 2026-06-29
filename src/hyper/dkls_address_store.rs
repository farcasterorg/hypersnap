//! Per-epoch DKLS23 group address store.
//!
//! Persists the 20-byte secp256k1 address derived from each epoch's
//! DKG group public key, so historical DKLS-signed blocks remain
//! verifiable across node restarts. Without this, the in-memory
//! `HyperRuntime::dkls_group_addresses` map empties on restart and
//! `sig_verify::dispatch` falls back to the BLS path (or fails
//! closed for ECDSA-only blocks), breaking historical verification.
//!
//! Key layout: `[HyperDklsGroupAddress][epoch BE u64]` — 9 bytes.
//! Value: 20-byte address.

use crate::core::error::HubError;
use crate::storage::constants::RootPrefix;
use crate::storage::db::RocksDB;
use alloy_primitives::Address;
use std::sync::Arc;

fn make_key(epoch: u64) -> [u8; 9] {
    let mut k = [0u8; 9];
    k[0] = RootPrefix::HyperDklsGroupAddress as u8;
    k[1..].copy_from_slice(&epoch.to_be_bytes());
    k
}

#[derive(Clone)]
pub struct DklsAddressStore {
    db: Arc<RocksDB>,
}

impl DklsAddressStore {
    pub fn new(db: Arc<RocksDB>) -> Self {
        Self { db }
    }

    pub fn set(&self, epoch: u64, addr: Address) -> Result<(), HubError> {
        let key = make_key(epoch);
        let value = addr.as_slice();
        self.db.put(&key, value).map_err(HubError::from)
    }

    pub fn get(&self, epoch: u64) -> Result<Option<Address>, HubError> {
        let key = make_key(epoch);
        match self.db.get(&key).map_err(HubError::from)? {
            Some(bytes) if bytes.len() == 20 => Ok(Some(Address::from_slice(&bytes))),
            _ => Ok(None),
        }
    }

    /// Hydrate a `BTreeMap<u64, Address>` from disk. Used on
    /// runtime construction so all known epoch addresses are
    /// available in memory immediately.
    pub fn load_all(&self) -> Result<std::collections::BTreeMap<u64, Address>, HubError> {
        use crate::storage::db::PageOptions;
        let prefix = [RootPrefix::HyperDklsGroupAddress as u8];
        let mut out = std::collections::BTreeMap::new();
        self.db
            .for_each_iterator_by_prefix(
                Some(prefix.to_vec()),
                Some(vec![RootPrefix::HyperDklsGroupAddress as u8 + 1]),
                &PageOptions::default(),
                |key, value| {
                    if key.len() != 9 || value.len() != 20 {
                        return Ok(false);
                    }
                    let mut be = [0u8; 8];
                    be.copy_from_slice(&key[1..9]);
                    let epoch = u64::from_be_bytes(be);
                    out.insert(epoch, Address::from_slice(value));
                    Ok(false)
                },
            )
            .map_err(HubError::from)?;
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn store() -> (DklsAddressStore, TempDir) {
        let dir = TempDir::new().unwrap();
        let db = RocksDB::new(dir.path().to_str().unwrap());
        db.open().unwrap();
        (DklsAddressStore::new(Arc::new(db)), dir)
    }

    #[test]
    fn round_trip_address() {
        let (s, _d) = store();
        let addr = Address::repeat_byte(0xab);
        s.set(7, addr).unwrap();
        let got = s.get(7).unwrap().unwrap();
        assert_eq!(got, addr);
    }

    #[test]
    fn missing_epoch_returns_none() {
        let (s, _d) = store();
        assert!(s.get(99).unwrap().is_none());
    }

    #[test]
    fn load_all_reconstructs_map() {
        let (s, _d) = store();
        let a = Address::repeat_byte(0x11);
        let b = Address::repeat_byte(0x22);
        let c = Address::repeat_byte(0x33);
        s.set(0, a).unwrap();
        s.set(5, b).unwrap();
        s.set(99, c).unwrap();
        let map = s.load_all().unwrap();
        assert_eq!(map.len(), 3);
        assert_eq!(map[&0], a);
        assert_eq!(map[&5], b);
        assert_eq!(map[&99], c);
    }

    #[test]
    fn load_all_empty_returns_empty_map() {
        let (s, _d) = store();
        let map = s.load_all().unwrap();
        assert!(map.is_empty());
    }

    #[test]
    fn set_overwrites_existing() {
        let (s, _d) = store();
        let a = Address::repeat_byte(0xaa);
        let b = Address::repeat_byte(0xbb);
        s.set(3, a).unwrap();
        s.set(3, b).unwrap();
        assert_eq!(s.get(3).unwrap().unwrap(), b);
    }
}
