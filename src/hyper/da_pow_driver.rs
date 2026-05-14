//! DA-PoW challenge response batch producer driven by the actor at
//! each epoch boundary.

use crate::hyper::da_pow::{
    da_response_signing_payload, derive_challenge_prefix, CHALLENGES_PER_EPOCH,
    CHALLENGE_PREFIX_BYTES,
};
use crate::proto;
use crate::storage::db::RocksDB;
use crate::storage::trie::merkle_trie::{Context, MerkleTrie};
use ed25519_dalek::{Signer, SigningKey};

pub trait DaResponseProducer: Send + Sync {
    fn produce_for_epoch(
        &self,
        epoch: u64,
        epoch_boundary_seed: &[u8],
    ) -> Vec<proto::DaChallengeResponseBody>;
}

/// Build one signed response for `challenge_index`. `None` when
/// the trie has no key beginning with the derived prefix.
pub fn produce_da_response_for_index(
    epoch: u64,
    epoch_boundary_hash: &[u8],
    validator_pubkey: &[u8],
    fid: u64,
    challenge_index: u32,
    chain_id: u64,
    signer_sk: &SigningKey,
    trie: &mut MerkleTrie,
    db: &RocksDB,
) -> Option<proto::DaChallengeResponseBody> {
    produce_da_response_for_index_via(
        epoch,
        epoch_boundary_hash,
        validator_pubkey,
        fid,
        challenge_index,
        chain_id,
        signer_sk,
        |prefix| {
            trie.get_all_values(&Context::new(), db, prefix)
                .ok()
                .and_then(|v| v.into_iter().next())
        },
    )
}

/// Closure-based variant — caller supplies prefix lookup. Lets a
/// caller hold its trie's lock once across the full batch.
pub fn produce_da_response_for_index_via<F>(
    epoch: u64,
    epoch_boundary_hash: &[u8],
    validator_pubkey: &[u8],
    fid: u64,
    challenge_index: u32,
    chain_id: u64,
    signer_sk: &SigningKey,
    mut lookup: F,
) -> Option<proto::DaChallengeResponseBody>
where
    F: FnMut(&[u8]) -> Option<Vec<u8>>,
{
    if validator_pubkey.len() != 32 {
        return None;
    }
    let prefix = derive_challenge_prefix(
        epoch_boundary_hash,
        validator_pubkey,
        epoch,
        challenge_index,
        chain_id,
    );
    let served = lookup(&prefix)?;
    // Pad short keys to the on-wire 32-byte width.
    let mut served_key = [0u8; 32];
    let copy_len = served.len().min(32);
    served_key[..copy_len].copy_from_slice(&served[..copy_len]);
    if served_key[..CHALLENGE_PREFIX_BYTES] != prefix[..] {
        return None;
    }

    let pk = signer_sk.verifying_key();
    let mut body = proto::DaChallengeResponseBody {
        fid,
        validator_pubkey: validator_pubkey.to_vec(),
        epoch,
        challenge_index,
        served_key: served_key.to_vec(),
        signer_pubkey: pk.to_bytes().to_vec(),
        signature: Vec::new(),
    };
    body.signature = signer_sk
        .sign(&da_response_signing_payload(&body, chain_id))
        .to_bytes()
        .to_vec();
    Some(body)
}

/// Up to `CHALLENGES_PER_EPOCH` signed responses, ascending by
/// `challenge_index`, skipping indices with no matching trie key.
pub fn produce_da_responses(
    epoch: u64,
    epoch_boundary_hash: &[u8],
    validator_pubkey: &[u8],
    fid: u64,
    chain_id: u64,
    signer_sk: &SigningKey,
    trie: &mut MerkleTrie,
    db: &RocksDB,
) -> Vec<proto::DaChallengeResponseBody> {
    produce_da_responses_via(
        epoch,
        epoch_boundary_hash,
        validator_pubkey,
        fid,
        chain_id,
        signer_sk,
        |prefix| {
            trie.get_all_values(&Context::new(), db, prefix)
                .ok()
                .and_then(|v| v.into_iter().next())
        },
    )
}

/// Closure-based batch producer.
pub fn produce_da_responses_via<F>(
    epoch: u64,
    epoch_boundary_hash: &[u8],
    validator_pubkey: &[u8],
    fid: u64,
    chain_id: u64,
    signer_sk: &SigningKey,
    mut lookup: F,
) -> Vec<proto::DaChallengeResponseBody>
where
    F: FnMut(&[u8]) -> Option<Vec<u8>>,
{
    let mut out = Vec::with_capacity(CHALLENGES_PER_EPOCH as usize);
    for i in 0..CHALLENGES_PER_EPOCH {
        if let Some(resp) = produce_da_response_for_index_via(
            epoch,
            epoch_boundary_hash,
            validator_pubkey,
            fid,
            i,
            chain_id,
            signer_sk,
            &mut lookup,
        ) {
            out.push(resp);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::db::RocksDbTransactionBatch;
    use ed25519_dalek::SigningKey;
    use tempfile::TempDir;

    fn fresh_db_and_trie() -> (std::sync::Arc<RocksDB>, MerkleTrie, TempDir) {
        let dir = TempDir::new().unwrap();
        let db = RocksDB::new(dir.path().to_str().unwrap());
        db.open().unwrap();
        let db = std::sync::Arc::new(db);
        let mut trie = MerkleTrie::new().unwrap();
        trie.initialize(&db).unwrap();
        (db, trie, dir)
    }

    #[test]
    fn empty_trie_yields_no_responses() {
        let (db, mut trie, _dir) = fresh_db_and_trie();
        let sk = SigningKey::from_bytes(&[3u8; 32]);
        let validator_pk = SigningKey::from_bytes(&[11u8; 32])
            .verifying_key()
            .to_bytes();
        let out = produce_da_responses(
            5,
            &[0xabu8; 32],
            &validator_pk,
            42,
            crate::hyper::DEFAULT_PROTOCOL_CHAIN_ID,
            &sk,
            &mut trie,
            &db,
        );
        assert_eq!(out.len(), 0);
    }

    /// Two keys sharing the prefix and diverging past byte 16 give
    /// the trie a non-leaf node `get_all_values` can walk into.
    #[test]
    fn matching_trie_key_produces_signed_response() {
        let (db, mut trie, _dir) = fresh_db_and_trie();
        let sk = SigningKey::from_bytes(&[3u8; 32]);
        let validator_pk = SigningKey::from_bytes(&[11u8; 32])
            .verifying_key()
            .to_bytes();
        let boundary_hash = [0xabu8; 32];
        let prefix = derive_challenge_prefix(
            &boundary_hash,
            &validator_pk,
            5,
            0,
            crate::hyper::DEFAULT_PROTOCOL_CHAIN_ID,
        );
        let mut key_a = [0u8; 32];
        let mut key_b = [0u8; 32];
        key_a[..CHALLENGE_PREFIX_BYTES].copy_from_slice(&prefix);
        key_b[..CHALLENGE_PREFIX_BYTES].copy_from_slice(&prefix);
        key_b[CHALLENGE_PREFIX_BYTES] = 0x80;
        let mut txn = RocksDbTransactionBatch::new();
        trie.insert(&Context::new(), &db, &mut txn, vec![&key_a[..], &key_b[..]])
            .unwrap();
        let resp = produce_da_response_for_index(
            5,
            &boundary_hash,
            &validator_pk,
            42,
            0,
            crate::hyper::DEFAULT_PROTOCOL_CHAIN_ID,
            &sk,
            &mut trie,
            &db,
        )
        .expect("matching key → Some(response)");
        assert_eq!(resp.fid, 42);
        assert_eq!(resp.epoch, 5);
        assert_eq!(resp.challenge_index, 0);
        assert_eq!(&resp.served_key[..CHALLENGE_PREFIX_BYTES], &prefix[..]);
        crate::hyper::da_pow::validate_da_response(&resp, crate::hyper::DEFAULT_PROTOCOL_CHAIN_ID)
            .unwrap();
    }
}
