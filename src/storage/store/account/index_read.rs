//! Secondary-index reads that span a hyper store's index roots.
//!
//! A hyper store indexes its messages under its own `Hyper*` roots. A message
//! it shares with the legacy store can still be indexed only under the legacy
//! root (for example, one that reached legacy without a hyper merge), and a
//! message pruned from legacy is indexed only under the hyper root. Hyper reads
//! walk both roots and merge the entries by key suffix, so they see the union.
//! Legacy reads use a single root and keep their original code paths.

use super::{
    get_from_db_or_txn, make_message_primary_key_with_prefix, message_decode, read_fid_key,
    read_ts_hash, MessagesPage, TS_HASH_LENGTH,
};
use crate::core::error::HubError;
use crate::storage::db::{PageOptions, RocksDB, RocksDbTransactionBatch};
use crate::storage::util::increment_vec_u8;

/// Root bytes to read for an index: the reading store's own root, then the
/// legacy root when it differs.
pub fn index_roots(own: u8, legacy: u8) -> Vec<u8> {
    if own == legacy {
        vec![own]
    } else {
        vec![own, legacy]
    }
}

/// Up to `limit` key suffixes (the key after its root byte) under
/// `[root][tail]` for each root, whose values pass `keep`, merged in page
/// order with duplicates collapsed. Also returns whether more entries remain.
/// A page token is a full key under any of the roots; its suffix is the
/// resume point for every root.
fn union_suffixes<F: Fn(&[u8]) -> bool>(
    db: &RocksDB,
    roots: &[u8],
    tail: &[u8],
    page_options: &PageOptions,
    limit: usize,
    keep: F,
) -> Result<(Vec<Vec<u8>>, bool), HubError> {
    let resume = page_options
        .page_token
        .as_ref()
        .filter(|token| !token.is_empty())
        .map(|token| token[1..].to_vec());

    let mut merged: Vec<Vec<u8>> = Vec::new();
    for &root in roots {
        let mut start = Vec::with_capacity(1 + tail.len());
        start.push(root);
        start.extend_from_slice(tail);
        let stop = increment_vec_u8(&start);
        let root_options = PageOptions {
            page_size: None,
            page_token: resume.as_ref().map(|suffix| [&[root][..], suffix].concat()),
            reverse: page_options.reverse,
        };
        let mut taken = 0usize;
        db.for_each_iterator_by_prefix(Some(start), Some(stop), &root_options, |key, value| {
            if keep(value) {
                merged.push(key[1..].to_vec());
                taken += 1;
            }
            // Each root contributes at most `limit + 1` entries, which is
            // enough to fill the merged page and tell whether more remain.
            Ok(taken > limit)
        })?;
    }

    merged.sort();
    merged.dedup();
    if page_options.reverse {
        merged.reverse();
    }
    let more = merged.len() > limit;
    merged.truncate(limit);
    Ok((merged, more))
}

/// One page of messages for the index entries `[root][tail][ts_hash][fid]`
/// across `roots`, loaded from the `postfix` primary key under the first of
/// `user_roots` that holds the message. Entries whose message is gone from
/// every user root are skipped.
pub fn get_union_index_page<F: Fn(&[u8]) -> bool>(
    db: &RocksDB,
    roots: &[u8],
    user_roots: &[u8],
    tail: &[u8],
    postfix: u8,
    page_options: &PageOptions,
    limit: usize,
    keep: F,
) -> Result<MessagesPage, HubError> {
    let (suffixes, more) = union_suffixes(db, roots, tail, page_options, limit, keep)?;

    let mut messages = Vec::with_capacity(suffixes.len());
    for suffix in &suffixes {
        let ts_hash = read_ts_hash(suffix, tail.len());
        let fid = read_fid_key(suffix, tail.len() + TS_HASH_LENGTH);
        for &user_root in user_roots {
            let key = make_message_primary_key_with_prefix(user_root, fid, postfix, Some(&ts_hash));
            if let Some(bytes) = db.get(&key)? {
                messages.push(message_decode(&bytes)?);
                break;
            }
        }
    }

    let next_page_token = match (more, suffixes.last()) {
        (true, Some(last)) => Some([&roots[..1], last.as_slice()].concat()),
        _ => None,
    };
    Ok(MessagesPage {
        messages,
        next_page_token,
    })
}

/// Number of distinct index entries under `[root][tail]` across `roots`.
pub fn count_union_index_entries(db: &RocksDB, roots: &[u8], tail: &[u8]) -> Result<u64, HubError> {
    let (suffixes, _) = union_suffixes(
        db,
        roots,
        tail,
        &PageOptions::default(),
        usize::MAX - 1,
        |_| true,
    )?;
    Ok(suffixes.len() as u64)
}

/// The value at `[root][tail]` under the first of `roots` that has one,
/// checking `txn` before the database.
pub fn get_union_index_value(
    db: &RocksDB,
    txn: Option<&RocksDbTransactionBatch>,
    roots: &[u8],
    tail: &[u8],
) -> Result<Option<Vec<u8>>, HubError> {
    for &root in roots {
        let key = [&[root][..], tail].concat();
        let value = match txn {
            Some(txn) => get_from_db_or_txn(db, txn, &key)?,
            None => db.get(&key)?,
        };
        if value.is_some() {
            return Ok(value);
        }
    }
    Ok(None)
}
