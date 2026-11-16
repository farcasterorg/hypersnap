use super::{config::Side, Error};
use crate::storage::db::RocksDB;
use serde::{Deserialize, Serialize};
use std::{path::Path, sync::Arc};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Cursor {
    pub next: u64,
    pub hash: Vec<u8>,
}
pub struct State {
    db: Arc<RocksDB>,
}
impl State {
    pub fn open(path: &Path, network: i32) -> Result<Self, Error> {
        std::fs::create_dir_all(path)?;
        let db = Arc::new(RocksDB::new(path.to_str().ok_or("non-UTF8 state path")?));
        db.open()?;
        match db.get(&[4])? {
            Some(bytes) if bytes != network.to_be_bytes() => {
                return Err("state directory belongs to a different Farcaster network".into())
            }
            Some(_) => {}
            None => db.put(&[4], &network.to_be_bytes())?,
        }
        Ok(Self { db })
    }
    fn cursor_key(side: Side, shard: u32) -> Vec<u8> {
        [vec![1, side as u8], shard.to_be_bytes().to_vec()].concat()
    }
    pub fn cursor(&self, side: Side, shard: u32) -> Result<Option<Cursor>, Error> {
        self.db
            .get(&Self::cursor_key(side, shard))?
            .map(|v| serde_json::from_slice(&v).map_err(Into::into))
            .transpose()
    }
    pub fn save(&self, side: Side, shard: u32, cursor: &Cursor) -> Result<(), Error> {
        self.db
            .put(&Self::cursor_key(side, shard), &serde_json::to_vec(cursor)?)?;
        Ok(())
    }
    fn seen_key(side: Side, hash: &[u8]) -> Vec<u8> {
        [vec![2, side as u8], hash.to_vec()].concat()
    }
    pub fn seen(&self, side: Side, hash: &[u8]) -> Result<bool, Error> {
        Ok(self.db.get(&Self::seen_key(side, hash))?.is_some())
    }
    pub fn mark(&self, side: Side, hash: &[u8]) -> Result<(), Error> {
        self.db.put(&Self::seen_key(side, hash), &[1])?;
        Ok(())
    }
    pub fn identity(&self, side: Side) -> Result<libp2p::identity::Keypair, Error> {
        let key = [3, side as u8];
        let secret = match self.db.get(&key)? {
            Some(bytes) => bytes,
            None => {
                let secret = libp2p::identity::ed25519::SecretKey::generate();
                let bytes = secret.as_ref().to_vec();
                self.db.put(&key, &bytes)?;
                bytes
            }
        };
        Ok(libp2p::identity::Keypair::ed25519_from_bytes(secret)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn restart_preserves_cursor_identity_and_receipts_and_checks_network() {
        let dir = tempfile::tempdir().unwrap();
        let identity;
        {
            let state = State::open(dir.path(), 1).unwrap();
            identity = state.identity(Side::Hypersnap).unwrap().public();
            assert_ne!(identity, state.identity(Side::Snapchain).unwrap().public());
            state
                .save(
                    Side::Hypersnap,
                    2,
                    &Cursor {
                        next: 1234,
                        hash: vec![42],
                    },
                )
                .unwrap();
            state.mark(Side::Snapchain, &[10; 20]).unwrap();
        }
        {
            let state = State::open(dir.path(), 1).unwrap();
            assert_eq!(state.identity(Side::Hypersnap).unwrap().public(), identity);
            let cursor = state.cursor(Side::Hypersnap, 2).unwrap().unwrap();
            assert_eq!(cursor.next, 1234);
            assert_eq!(cursor.hash, vec![42]);
            assert!(state.cursor(Side::Snapchain, 2).unwrap().is_none());
            assert!(state.seen(Side::Snapchain, &[10; 20]).unwrap());
            assert!(!state.seen(Side::Hypersnap, &[10; 20]).unwrap());
        }
        assert!(State::open(dir.path(), 2).is_err());
    }
}
