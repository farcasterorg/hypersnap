//! The store walk of a genesis state snapshot (FIP §17.5).
//!
//! The Keccak root of a snapshot proves the objects that its sync trie
//! names. A forged snapshot can keep that root and add records that no trie
//! key names: an object only in a store, or an index entry. The store walk
//! closes this gap. It needs the Keccak trie built from the snapshot (with
//! the certified root) in the same DB:
//!
//! 1. Each object in the stores (a message, a link compact state, a gasless
//!    key record, a `KEY_REMOVE`, an on-chain event, an fname proof) must be a leaf of the
//!    Keccak trie under its trie key, with the same value. The nonces and
//!    the last-use times of the gasless keys are leaves under their storage
//!    keys (`shadow_entries::GASLESS_STATE`).
//! 2. For each object, the walk writes the records that the stores keep for
//!    it (the record, the add and remove sets, the indexes and the counters)
//!    into an empty DB. The store records of the snapshot must be identical
//!    to these records.
//! 3. The snapshot must have no records under other prefixes, except the
//!    history (chunks, hub events, block events), the tries, and local data.

use super::merkle_trie::TrieKey;
use super::shadow_entries::GASLESS_STATE;
use super::shadow_trie::RocksNodeStore;
use crate::core::validations::key::{verify_signed_key_request_metadata, ETH_MAINNET_CHAIN_ID};
use crate::proto::{self, message_data::Body, MessageType, OnChainEvent};
use crate::storage::constants::{OnChainEventPostfix, RootPrefix, UserPostfix};
use crate::storage::db::{PageOptions, RocksDB, RocksDbTransactionBatch};
use crate::storage::store::account::{
    increment_gasless_key_count, make_fname_username_proof_key, make_gasless_key_by_fid_key,
    make_key_remove_message_key, make_onchain_event_primary_key, merge_onchain_event,
    put_gasless_key_owner, put_gasless_key_record, put_username_proof_transaction,
    signer_auth_index, GaslessKeyRecord, StoreOptions, FID_BYTES,
};
use crate::storage::store::stores::Stores;
use hypersnap_ktrie::KTrie;
use prost::Message as _;
use std::collections::VecDeque;
use std::sync::Arc;
use tracing::info;

/// Records read from a DB at a time.
const PAGE: usize = 10_000;
/// Objects between two commits of the derived DB.
const COMMIT_EVERY: u64 = 50_000;

/// The prefixes whose records the walk derives and compares.
const DERIVED: &[u8] = &[
    RootPrefix::User as u8,
    RootPrefix::CastsByParent as u8,
    RootPrefix::CastsByMention as u8,
    RootPrefix::LinksByTarget as u8,
    RootPrefix::ReactionsByTarget as u8,
    RootPrefix::FNameUserNameProof as u8,
    RootPrefix::OnChainEvent as u8,
    RootPrefix::VerificationByAddress as u8,
    RootPrefix::FNameUserNameProofByFid as u8,
    RootPrefix::UserNameProofByName as u8,
    RootPrefix::LendStorageByRecipient as u8,
    RootPrefix::GaslessKey as u8,
    RootPrefix::HyperSignerAuthByRequester as u8,
    RootPrefix::HyperCustodyToFid as u8,
    RootPrefix::HyperKeyRemoveMessage as u8,
];

/// The prefixes that the walk does not compare: the history, the tries and
/// local data.
const NOT_DERIVED: &[u8] = &[
    RootPrefix::Shard as u8,
    RootPrefix::MerkleTrieNode as u8,
    RootPrefix::HubEvents as u8,
    RootPrefix::DBSchemaVersion as u8,
    RootPrefix::NodeLocalState as u8,
    RootPrefix::BlockIndex as u8,
    RootPrefix::BlockEvent as u8,
    RootPrefix::MerkleTrieMetadata as u8,
    RootPrefix::ReplicationBootstrapStatus as u8,
    RootPrefix::KeccakTrieNode as u8,
    RootPrefix::KeccakTrieMeta as u8,
];

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WalkReport {
    /// Objects found in the stores and in the Keccak trie.
    pub objects: u64,
    /// Store records compared.
    pub records: u64,
}

/// Walk the stores of `db` (FIP §17.5). `derived` is an empty shard DB of
/// the same shard; the walk writes the derived records into it.
pub fn check(db: &Arc<RocksDB>, derived: &Stores) -> Result<WalkReport, String> {
    check_prefixes(db)?;
    let trie = KTrie::open(RocksNodeStore::new(db.clone())).map_err(|e| e.to_string())?;
    let mut walk = Walk {
        trie,
        derived,
        txn: RocksDbTransactionBatch::new(),
        objects: 0,
    };
    walk.messages(db)?;
    walk.gasless_keys(db)?;
    walk.gasless_state(db)?;
    walk.key_removes(db)?;
    walk.onchain_events(db)?;
    walk.fnames(db)?;
    walk.commit()?;
    info!(
        shard = derived.shard_id,
        objects = walk.objects,
        "Store walk: each object is in the Keccak trie"
    );
    let mut records = 0;
    for prefix in DERIVED {
        records += compare(db, &derived.db, *prefix)?;
    }
    info!(
        shard = derived.shard_id,
        records, "Store walk: the store records are the derived records"
    );
    Ok(WalkReport {
        objects: walk.objects,
        records,
    })
}

fn check_prefixes(db: &RocksDB) -> Result<(), String> {
    for p in 0..=u8::MAX {
        if DERIVED.contains(&p) || NOT_DERIVED.contains(&p) {
            continue;
        }
        let stop = p.checked_add(1).map(|q| vec![q]);
        if !read_page(db, &[p], stop.as_deref(), 1)?.is_empty() {
            return Err(format!("the snapshot has records under prefix {}", p));
        }
    }
    Ok(())
}

struct Walk<'a> {
    trie: KTrie<RocksNodeStore>,
    derived: &'a Stores,
    txn: RocksDbTransactionBatch,
    objects: u64,
}

impl Walk<'_> {
    /// `value` must be the leaf of `key` in the Keccak trie.
    fn in_trie(&self, key: &[u8], value: &[u8], what: &str) -> Result<(), String> {
        match self.trie.get(key).map_err(|e| e.to_string())? {
            Some(hash) if hash == hypersnap_ktrie::value_hash(value) => Ok(()),
            Some(_) => Err(format!(
                "the {} at trie key {} is not the one in the Keccak trie",
                what,
                hex::encode(key)
            )),
            None => Err(format!(
                "the {} at trie key {} is not in the Keccak trie",
                what,
                hex::encode(key)
            )),
        }
    }

    fn done_one(&mut self) -> Result<(), String> {
        self.objects += 1;
        if self.objects % COMMIT_EVERY == 0 {
            self.commit()?;
        }
        Ok(())
    }

    fn commit(&mut self) -> Result<(), String> {
        let txn = std::mem::replace(&mut self.txn, RocksDbTransactionBatch::new());
        self.derived.db.commit(txn).map_err(|e| e.to_string())
    }

    fn message_in_trie(&self, message: &proto::Message) -> Result<(), String> {
        if message.data.is_none() {
            return Err(format!(
                "message {} has no data",
                hex::encode(&message.hash)
            ));
        }
        let value = message.encode_to_vec();
        for key in TrieKey::for_message(message) {
            self.in_trie(&key, &value, "message")?;
        }
        Ok(())
    }

    /// The messages and link compact states (`RootPrefix::User`).
    fn messages(&mut self, db: &RocksDB) -> Result<(), String> {
        let user = RootPrefix::User as u8;
        for_each(db, &[user], &[user + 1], |key, value| {
            let postfix = *key
                .get(1 + FID_BYTES)
                .ok_or_else(|| format!("short user record {}", hex::encode(key)))?;
            let is_message = (UserPostfix::CastMessage as u8
                ..=UserPostfix::LendStorageMessage as u8)
                .contains(&postfix)
                || postfix == UserPostfix::LinkCompactStateMessage as u8;
            if !is_message {
                // An index; the comparison checks it.
                return Ok(());
            }
            let message = proto::Message::decode(value)
                .map_err(|_| format!("user record {} does not decode", hex::encode(key)))?;
            self.message_in_trie(&message)?;
            let stores = self.derived;
            let put: &dyn Put = match message.msg_type() {
                MessageType::CastAdd | MessageType::CastRemove => &stores.cast_store,
                MessageType::LinkAdd | MessageType::LinkRemove | MessageType::LinkCompactState => {
                    &stores.link_store
                }
                MessageType::ReactionAdd | MessageType::ReactionRemove => &stores.reaction_store,
                MessageType::VerificationAddEthAddress | MessageType::VerificationRemove => {
                    &stores.verification_store
                }
                MessageType::UserDataAdd => &stores.user_data_store,
                MessageType::UsernameProof => &stores.username_proof_store,
                MessageType::LendStorage => &stores.storage_lend_store,
                t => return Err(format!("a {:?} message in a message store", t)),
            };
            put.put(&mut self.txn, &message)
                .map_err(|e| e.to_string())?;
            self.done_one()
        })
    }

    /// The gasless key records (the `KEY_ADD` messages).
    fn gasless_keys(&mut self, db: &RocksDB) -> Result<(), String> {
        let start = [
            RootPrefix::GaslessKey as u8,
            UserPostfix::GaslessKeyByFid as u8,
        ];
        let stop = [start[0], start[1] + 1];
        let derived = self.derived.db.clone();
        for_each(db, &start, &stop, |key, value| {
            let record = GaslessKeyRecord::decode(value)
                .map_err(|_| format!("gasless key record {} does not decode", hex::encode(key)))?;
            let message = record
                .message
                .ok_or_else(|| format!("gasless key record {} has no message", hex::encode(key)))?;
            self.message_in_trie(&message)?;
            let data = message.data.as_ref().unwrap();
            let Some(Body::KeyAddBody(body)) = &data.body else {
                return Err(format!(
                    "gasless key record {} has no KEY_ADD",
                    hex::encode(key)
                ));
            };
            if make_gasless_key_by_fid_key(data.fid, &body.key).map_err(|e| e.to_string())? != key {
                return Err(format!(
                    "gasless key record {} is not under its key",
                    hex::encode(key)
                ));
            }
            let request_fid = verify_signed_key_request_metadata(
                body.metadata_type,
                &body.metadata,
                &body.key,
                data.timestamp as u64,
                ETH_MAINNET_CHAIN_ID,
            )
            .map_err(|e| format!("gasless key record {}: {}", hex::encode(key), e))?
            .request_fid;
            let fid = data.fid;
            let pk = body.key.clone();
            let derived_record = GaslessKeyRecord {
                message: Some(message),
                request_fid,
            };
            (|| {
                put_gasless_key_record(&derived, &mut self.txn, fid, &pk, &derived_record)?;
                put_gasless_key_owner(&derived, &mut self.txn, &pk, fid)?;
                increment_gasless_key_count(&derived, &mut self.txn, fid)?;
                signer_auth_index::inc(&derived, &mut self.txn, request_fid, fid)
            })()
            .map_err(|e| e.to_string())?;
            self.done_one()
        })
    }

    /// The nonces and the last-use times of the gasless keys: leaves of the
    /// trie as they are stored.
    fn gasless_state(&mut self, db: &RocksDB) -> Result<(), String> {
        let prefix = RootPrefix::GaslessKey as u8;
        for postfix in GASLESS_STATE {
            for_each(
                db,
                &[prefix, postfix],
                &[prefix, postfix + 1],
                |key, value| {
                    self.in_trie(key, value, "gasless key state")?;
                    self.txn.put(key.to_vec(), value.to_vec());
                    self.done_one()
                },
            )?;
        }
        Ok(())
    }

    /// The `KEY_REMOVE` messages (`key_remove_store`).
    fn key_removes(&mut self, db: &RocksDB) -> Result<(), String> {
        let p = RootPrefix::HyperKeyRemoveMessage as u8;
        for_each(db, &[p], &[p + 1], |key, value| {
            let message = proto::Message::decode(value)
                .map_err(|_| format!("KEY_REMOVE record {} does not decode", hex::encode(key)))?;
            if message.msg_type() != MessageType::KeyRemove
                || make_key_remove_message_key(message.fid(), &message.hash) != key
            {
                return Err(format!(
                    "KEY_REMOVE record {} is not under its key",
                    hex::encode(key)
                ));
            }
            self.message_in_trie(&message)?;
            self.txn.put(key.to_vec(), value.to_vec());
            self.done_one()
        })
    }

    /// The on-chain events, in the order of their keys: for each type and
    /// FID, in chain order, as the indexes need.
    fn onchain_events(&mut self, db: &RocksDB) -> Result<(), String> {
        let start = [
            RootPrefix::OnChainEvent as u8,
            OnChainEventPostfix::OnChainEvents as u8,
        ];
        let stop = [start[0], start[1] + 1];
        let derived = self.derived.db.clone();
        for_each(db, &start, &stop, |key, value| {
            let event = OnChainEvent::decode(value)
                .map_err(|_| format!("on-chain event {} does not decode", hex::encode(key)))?;
            if make_onchain_event_primary_key(&event) != key {
                return Err(format!(
                    "on-chain event {} is not under its key",
                    hex::encode(key)
                ));
            }
            self.in_trie(
                &TrieKey::for_onchain_event(&event),
                &event.encode_to_vec(),
                "on-chain event",
            )?;
            merge_onchain_event(&derived, &mut self.txn, event, &StoreOptions::default())
                .map_err(|e| e.to_string())?;
            self.done_one()
        })
    }

    /// The fname proofs.
    fn fnames(&mut self, db: &RocksDB) -> Result<(), String> {
        let p = RootPrefix::FNameUserNameProof as u8;
        for_each(db, &[p], &[p + 1], |key, value| {
            let proof = proto::UserNameProof::decode(value)
                .map_err(|_| format!("fname proof {} does not decode", hex::encode(key)))?;
            if make_fname_username_proof_key(&proof.name) != key {
                return Err(format!(
                    "fname proof {} is not under its key",
                    hex::encode(key)
                ));
            }
            let name = String::from_utf8(proof.name.clone())
                .map_err(|_| format!("fname proof {} is not UTF-8", hex::encode(key)))?;
            self.in_trie(
                &TrieKey::for_fname(proof.fid, &name),
                &proof.encode_to_vec(),
                "fname proof",
            )?;
            put_username_proof_transaction(&mut self.txn, &proof, None);
            self.done_one()
        })
    }
}

/// A message store, for `Walk::messages`.
trait Put {
    fn put(
        &self,
        txn: &mut RocksDbTransactionBatch,
        message: &proto::Message,
    ) -> Result<(), crate::core::error::HubError>;
}

impl<T: crate::storage::store::account::StoreDef + Clone> Put
    for crate::storage::store::account::Store<T>
{
    fn put(
        &self,
        txn: &mut RocksDbTransactionBatch,
        message: &proto::Message,
    ) -> Result<(), crate::core::error::HubError> {
        self.put_message_records(txn, message)
    }
}

/// Up to `limit` records of `db` in `[start, stop)`.
fn read_page(
    db: &RocksDB,
    start: &[u8],
    stop: Option<&[u8]>,
    limit: usize,
) -> Result<Vec<(Vec<u8>, Vec<u8>)>, String> {
    let mut page = Vec::with_capacity(limit.min(PAGE));
    db.for_each_iterator_by_prefix_paged(
        Some(start.to_vec()),
        stop.map(|s| s.to_vec()),
        &PageOptions::default(),
        |k, v| {
            page.push((k.to_vec(), v.to_vec()));
            Ok(page.len() >= limit)
        },
    )
    .map_err(|e| e.to_string())?;
    Ok(page)
}

/// The key after `key` in key order.
fn after(key: &[u8]) -> Vec<u8> {
    let mut next = key.to_vec();
    next.push(0);
    next
}

fn for_each(
    db: &RocksDB,
    start: &[u8],
    stop: &[u8],
    mut f: impl FnMut(&[u8], &[u8]) -> Result<(), String>,
) -> Result<(), String> {
    let mut from = start.to_vec();
    loop {
        let page = read_page(db, &from, Some(stop), PAGE)?;
        for (k, v) in &page {
            f(k, v)?;
        }
        match page.last() {
            Some((k, _)) if page.len() == PAGE => from = after(k),
            _ => return Ok(()),
        }
    }
}

/// The records of one DB in a range, in key order.
struct Cursor<'a> {
    db: &'a RocksDB,
    from: Vec<u8>,
    stop: Vec<u8>,
    buf: VecDeque<(Vec<u8>, Vec<u8>)>,
    done: bool,
}

impl<'a> Cursor<'a> {
    fn new(db: &'a RocksDB, prefix: u8) -> Self {
        Cursor {
            db,
            from: vec![prefix],
            stop: vec![prefix + 1],
            buf: VecDeque::new(),
            done: false,
        }
    }

    fn next(&mut self) -> Result<Option<(Vec<u8>, Vec<u8>)>, String> {
        loop {
            if let Some(entry) = self.buf.pop_front() {
                return Ok(Some(entry));
            }
            if self.done {
                return Ok(None);
            }
            let page = read_page(self.db, &self.from, Some(&self.stop), PAGE)?;
            self.done = page.len() < PAGE;
            if let Some((k, _)) = page.last() {
                self.from = after(k);
            }
            self.buf.extend(page);
        }
    }
}

/// The records of `snapshot` under `prefix` must be the records of
/// `derived`. Returns the number of records.
fn compare(snapshot: &RocksDB, derived: &RocksDB, prefix: u8) -> Result<u64, String> {
    let mut a = Cursor::new(snapshot, prefix);
    let mut b = Cursor::new(derived, prefix);
    let mut n = 0;
    loop {
        match (a.next()?, b.next()?) {
            (None, None) => return Ok(n),
            (Some(x), Some(y)) if x == y => n += 1,
            (x, y) => return Err(difference(x.map(|x| x.0), y.map(|y| y.0))),
        }
    }
}

/// The first difference of a snapshot record `x` and a derived record `y`.
fn difference(x: Option<Vec<u8>>, y: Option<Vec<u8>>) -> String {
    match (x, y) {
        (Some(x), Some(y)) if x == y => format!(
            "the snapshot record {} is not the derived record",
            hex::encode(x)
        ),
        (Some(x), y) if y.as_ref().map_or(true, |y| x < *y) => format!(
            "the snapshot has the record {}, which no object derives",
            hex::encode(x)
        ),
        (_, Some(y)) => format!(
            "the snapshot does not have the derived record {}",
            hex::encode(y)
        ),
        (_, None) => "the records differ".to_string(),
    }
}

/// Delete the records of `db` in `[start, stop)`. Returns their number.
pub fn delete_range(db: &RocksDB, start: &[u8], stop: &[u8]) -> Result<u64, String> {
    let mut n = 0;
    loop {
        let page = read_page(db, start, Some(stop), PAGE)?;
        if page.is_empty() {
            return Ok(n);
        }
        let mut txn = RocksDbTransactionBatch::new();
        for (k, _) in page {
            txn.delete(k);
            n += 1;
        }
        db.commit(txn).map_err(|e| e.to_string())?;
    }
}
