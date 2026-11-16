//! Unified active-key lookup across on-chain signer events and the gasless-key store.
//!
//! NEYN-10575 introduces scope enforcement for off-chain (gasless) keys: a KEY_ADD declares a
//! list of allowed `MessageType` values ("scopes"), and every user message signed by that key
//! must fall within that list. This module centralizes the lookup that answers
//!
//! > Is `signer` an active key for `fid`, and if so, what (if any) constraints apply?
//!
//! so validation sites in both `ShardEngine` and `BlockEngine` can call one function and
//! pattern-match on the result.
//!
//! ## Lookup order: on-chain first, gasless on miss
//!
//! On-chain signers are grandfathered (no scope check) and are the hot path today. Keeping them
//! first means the common case stays at one RocksDB read. A miss on on-chain falls through to
//! the gasless-key store — a second read, but only for off-chain traffic.
//!
//! The order also avoids a correctness surprise: if the same Ed25519 key somehow appeared in
//! both stores (it shouldn't by construction — on-chain keys are minted via the L2 KeyRegistry
//! and off-chain keys via custody-signed KEY_ADD), preferring on-chain yields the more lenient
//! (scope-free) interpretation. That matches the grandfathering intent.
//!
//! ## Scopes as a bitmask
//!
//! Scopes are stored as a `repeated int32` list in `KeyAddBody`, but evaluated as a `u64`
//! bitmask: bit N is set iff `MessageType` value N is allowed. Admission check is one `AND`.
//! `MessageType` enum values currently top out at 21 (`MESSAGE_TYPE_CHANNEL_MODERATE`), so a `u64`
//! comfortably fits the full table with headroom. Only a subset is ever an admissible scope —
//! `validate_key_add_scopes` denies the custody-level and not-yet-mergeable types — so bits for
//! those values are never set on a persisted record.
//!
//! Mask construction is O(scopes.len()) and runs once per read; the per-message check itself
//! is O(1). The record is not mutated to cache the mask — `GaslessKeyRecord` intentionally
//! stores only the originating message plus the expensive-to-recompute `request_fid` (see the
//! doc header on `GaslessKeyRecord`), and a bitwise shift-OR over ≤15 ints is cheap enough to
//! keep on the read path.

use std::sync::Arc;

use super::{get_gasless_key_record, OnchainEventStore};
use crate::core::util::FarcasterTime;
use crate::core::validations::key::KeyAddAuthorizationType;
use crate::proto::{self, message_data::Body, MessageType};
use crate::storage::db::{RocksDB, RocksDbTransactionBatch};
use crate::storage::store::account::onchain_event_store::OnchainEventStorageError;
use crate::version::version::{EngineVersion, ProtocolFeature};

/// Result of resolving `(fid, signer)` against the active-key indexes.
///
/// `OnChain` carries no data because on-chain signers bypass scope enforcement entirely — they
/// predate the scope model and are grandfathered. `Gasless` carries the bitmask plus the `ttl`
/// value from the originating KEY_ADD so downstream validation (scope check now, sliding
/// expiry in NEYN-10576) can operate without a second lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActiveKey {
    OnChain,
    Gasless {
        scopes_mask: u64,
        ttl_seconds: u32,
        /// `Some(timestamp of the KEY_ADD)` when the stored KEY_ADD carries
        /// `authorization_type = 200`. This is the raw field, not a verdict: whether the key was
        /// really authorized by sign-in depends on `ProtocolFeature::SignInKeyAuthorization`
        /// having been active at that timestamp, which only the engine (it knows the network)
        /// can decide. See `is_fixed_expiry_sign_in_key`.
        sign_in_added_at: Option<u32>,
    },
}

impl ActiveKey {
    /// Returns true iff `msg_type` is admitted by this key's scope. On-chain keys admit
    /// everything; gasless keys admit only the types whose bit is set in `scopes_mask`.
    pub fn admits(&self, msg_type: MessageType) -> bool {
        match self {
            ActiveKey::OnChain => true,
            ActiveKey::Gasless { scopes_mask, .. } => {
                let bit = message_type_bit(msg_type);
                (scopes_mask & bit) != 0
            }
        }
    }
}

/// Compute the `u64` scope bitmask from the `KeyAddBody.scopes` list.
///
/// Unknown/out-of-range scope values are dropped rather than erroring — `validate_key_add_body`
/// already rejects any KEY_ADD whose scopes list contains an invalid `MessageType` (see
/// `core::validations::key::validate_key_add_scopes`), so by the time a `GaslessKeyRecord` is
/// persisted the list is already clean. Silent drop here is defense in depth against a future
/// MessageType variant being added without a corresponding store-layer update.
pub fn compute_scopes_mask(scopes: &[i32]) -> u64 {
    let mut mask: u64 = 0;
    for &scope in scopes {
        // MessageType enum values are small non-negative integers; anything else is invalid.
        if let Ok(bit_pos) = u32::try_from(scope) {
            if bit_pos < 64 {
                mask |= 1u64 << bit_pos;
            }
        }
    }
    mask
}

/// Bit position for a `MessageType` in the scope bitmask.
#[inline]
fn message_type_bit(msg_type: MessageType) -> u64 {
    let v = msg_type as i32;
    // `MessageType::None` (0) should never be admitted by any scope — but encoding it as bit 0
    // is harmless: `validate_key_add_scopes` rejects `MessageType::None` in the scopes list, so
    // no `GaslessKeyRecord` can have bit 0 set.
    if let Ok(bit_pos) = u32::try_from(v) {
        if bit_pos < 64 {
            return 1u64 << bit_pos;
        }
    }
    0
}

/// Resolve `(fid, signer)` against both signer indexes. Returns `None` if the key is not active
/// in either.
///
/// The on-chain store is checked first so the hot path remains a single RocksDB read for
/// messages signed by on-chain keys. A gasless-only signer incurs one additional read.
pub fn get_active_key(
    onchain_event_store: &OnchainEventStore,
    db: &Arc<RocksDB>,
    txn_batch: &RocksDbTransactionBatch,
    fid: u64,
    signer: &[u8],
) -> Result<Option<ActiveKey>, OnchainEventStorageError> {
    if onchain_event_store
        .get_active_signer(fid, signer.to_vec(), Some(txn_batch))?
        .is_some()
    {
        return Ok(Some(ActiveKey::OnChain));
    }

    // Gasless store miss/corrupt-record errors are surfaced as on-chain-store errors so the
    // caller can treat them uniformly. The DB is the same RocksDB instance; any error here is
    // a storage failure, not a validation failure.
    let record = get_gasless_key_record(db, txn_batch, fid, signer)
        .map_err(OnchainEventStorageError::HubError)?;
    let Some(record) = record else {
        return Ok(None);
    };

    // A corrupt record whose embedded message lacks `data.body.key_add_body` would have failed
    // to merge in the first place (see `merge_key_add`). Treat it as a miss defensively rather
    // than panicking on a malformed row.
    let (scopes_mask, ttl_seconds, sign_in_added_at) =
        extract_scope_and_ttl(&record.message).unwrap_or((0, 0, None));
    Ok(Some(ActiveKey::Gasless {
        scopes_mask,
        ttl_seconds,
        sign_in_added_at,
    }))
}

/// Whether a gasless key's expiry window is fixed at its KEY_ADD rather than sliding with use.
///
/// True only for keys authorized by a sign-in message: the stored KEY_ADD says
/// `authorization_type = 200` *and* the feature was active at that KEY_ADD's timestamp, which is
/// the same test `merge_key_add_with_options` applied when it chose the authorization path. A
/// custody-authorized KEY_ADD from before activation that happens to carry a 2 in the then-unread
/// field keeps its sliding window, as it has on every binary so far.
pub fn is_fixed_expiry_sign_in_key(
    sign_in_added_at: Option<u32>,
    network: proto::FarcasterNetwork,
) -> bool {
    sign_in_added_at.is_some_and(|added_at| {
        EngineVersion::version_for(&FarcasterTime::new(added_at as u64), network)
            .is_enabled(ProtocolFeature::SignInKeyAuthorization)
    })
}

fn extract_scope_and_ttl(message: &Option<proto::Message>) -> Option<(u64, u32, Option<u32>)> {
    let data = message.as_ref()?.data.as_ref()?;
    let key_add = match data.body.as_ref()? {
        Body::KeyAddBody(body) => body,
        _ => return None,
    };
    let sign_in_added_at = (key_add.authorization_type == KeyAddAuthorizationType::SignIn as u32)
        .then_some(data.timestamp);
    Some((
        compute_scopes_mask(&key_add.scopes),
        key_add.ttl,
        sign_in_added_at,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{
        self, message_data::Body, KeyAddBody, MessageData, MessageType, SignerEventType,
    };
    use crate::storage::db::{self, RocksDbTransactionBatch};
    use crate::storage::store::account::{
        put_gasless_key_record, GaslessKeyRecord, StoreEventHandler,
    };
    use crate::utils::factory::{events_factory, signers};
    use std::sync::Arc;
    use tempfile::TempDir;

    fn fresh_store() -> (OnchainEventStore, Arc<db::RocksDB>, TempDir) {
        let dir = tempfile::TempDir::new().unwrap();
        let db_path = dir.path().join("active_key.db");
        let rocks = db::RocksDB::new(db_path.to_str().unwrap());
        rocks.open().unwrap();
        let rocks = Arc::new(rocks);
        let store = OnchainEventStore::new(rocks.clone(), StoreEventHandler::new());
        (store, rocks, dir)
    }

    fn sample_gasless_record(signer_pubkey: &[u8], scopes: Vec<i32>, ttl: u32) -> GaslessKeyRecord {
        GaslessKeyRecord {
            message: Some(proto::Message {
                data: Some(MessageData {
                    native_onboard_body: None,
                    r#type: MessageType::KeyAdd as i32,
                    fid: 0,
                    timestamp: 0,
                    network: 0,
                    body: Some(Body::KeyAddBody(KeyAddBody {
                        key: signer_pubkey.to_vec(),
                        key_type: 1,
                        custody_signature: vec![],
                        deadline: 0,
                        nonce: 0,
                        metadata: vec![],
                        metadata_type: 1,
                        registration_tx_hash: vec![],
                        scopes,
                        ttl,
                        authorization_type: 0,
                        authorization_message: vec![],
                    })),
                }),
                hash: vec![],
                hash_scheme: 0,
                signature: vec![],
                signature_scheme: 0,
                signer: vec![],
                data_bytes: None,
            }),
            request_fid: 0,
        }
    }

    #[test]
    fn mask_is_empty_for_empty_scopes() {
        assert_eq!(compute_scopes_mask(&[]), 0);
    }

    #[test]
    fn mask_sets_expected_bits() {
        // CAST_ADD = 1, REACTION_ADD = 3, LINK_ADD = 5
        let mask = compute_scopes_mask(&[1, 3, 5]);
        assert_eq!(mask, (1u64 << 1) | (1u64 << 3) | (1u64 << 5));
    }

    #[test]
    fn mask_silently_drops_out_of_range_values() {
        // Negative values and values >= 64 are dropped (validation elsewhere prevents these
        // from reaching the store, but the mask path is defensive).
        let mask = compute_scopes_mask(&[-1, 1, 64, 100]);
        assert_eq!(mask, 1u64 << 1);
    }

    #[test]
    fn onchain_variant_admits_any_message_type() {
        let k = ActiveKey::OnChain;
        assert!(k.admits(MessageType::CastAdd));
        assert!(k.admits(MessageType::LinkRemove));
        assert!(k.admits(MessageType::UserDataAdd));
    }

    #[test]
    fn gasless_variant_admits_only_scoped_types() {
        let k = ActiveKey::Gasless {
            scopes_mask: compute_scopes_mask(&[MessageType::CastAdd as i32]),
            ttl_seconds: 3600,
            sign_in_added_at: None,
        };
        assert!(k.admits(MessageType::CastAdd));
        assert!(!k.admits(MessageType::ReactionAdd));
        assert!(!k.admits(MessageType::LinkAdd));
    }

    #[test]
    fn gasless_variant_with_empty_mask_admits_nothing() {
        let k = ActiveKey::Gasless {
            scopes_mask: 0,
            ttl_seconds: 3600,
            sign_in_added_at: None,
        };
        assert!(!k.admits(MessageType::CastAdd));
        assert!(!k.admits(MessageType::None));
    }

    #[test]
    fn get_active_key_returns_none_when_no_record_in_either_store() {
        let (store, rocks, _dir) = fresh_store();
        let txn = RocksDbTransactionBatch::new();
        let result = get_active_key(&store, &rocks, &txn, 42, &[0xAA; 32]).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn get_active_key_returns_onchain_for_an_onchain_signer() {
        let (store, rocks, _dir) = fresh_store();
        let signing_key = signers::generate_signer();
        let pubkey = signing_key.verifying_key().as_bytes().to_vec();
        let event =
            events_factory::create_signer_event(7, signing_key, SignerEventType::Add, None, None);

        let mut merge_txn = RocksDbTransactionBatch::new();
        store.merge_onchain_event(event, &mut merge_txn).unwrap();
        rocks.commit(merge_txn).unwrap();

        let txn = RocksDbTransactionBatch::new();
        let result = get_active_key(&store, &rocks, &txn, 7, &pubkey).unwrap();
        assert_eq!(result, Some(ActiveKey::OnChain));
    }

    #[test]
    fn get_active_key_returns_gasless_variant_with_mask_and_ttl() {
        let (store, rocks, _dir) = fresh_store();
        let signer_pubkey = [0xCC; 32];
        let scopes = vec![MessageType::CastAdd as i32, MessageType::LinkAdd as i32];
        let record = sample_gasless_record(&signer_pubkey, scopes.clone(), 7200);

        let mut merge_txn = RocksDbTransactionBatch::new();
        put_gasless_key_record(&rocks, &mut merge_txn, 9, &signer_pubkey, &record).unwrap();
        rocks.commit(merge_txn).unwrap();

        let txn = RocksDbTransactionBatch::new();
        let result = get_active_key(&store, &rocks, &txn, 9, &signer_pubkey).unwrap();
        match result {
            Some(ActiveKey::Gasless {
                scopes_mask,
                ttl_seconds,
                sign_in_added_at,
            }) => {
                assert_eq!(sign_in_added_at, None);
                assert_eq!(scopes_mask, compute_scopes_mask(&scopes));
                assert_eq!(ttl_seconds, 7200);
                // Positive and negative admission inside the scope bitmask.
                let k = ActiveKey::Gasless {
                    scopes_mask,
                    ttl_seconds,
                    sign_in_added_at,
                };
                assert!(k.admits(MessageType::CastAdd));
                assert!(k.admits(MessageType::LinkAdd));
                assert!(!k.admits(MessageType::ReactionAdd));
            }
            other => panic!("expected Gasless, got {other:?}"),
        }
    }

    #[test]
    fn onchain_takes_priority_when_key_is_in_both_stores() {
        // Belt-and-suspenders: construction shouldn't let the same key appear in both stores, but
        // if it ever did, Fork C (on-chain first) should yield the more lenient OnChain variant.
        let (store, rocks, _dir) = fresh_store();
        let signing_key = signers::generate_signer();
        let pubkey = signing_key.verifying_key().as_bytes().to_vec();
        let event =
            events_factory::create_signer_event(3, signing_key, SignerEventType::Add, None, None);

        let mut merge_txn = RocksDbTransactionBatch::new();
        store.merge_onchain_event(event, &mut merge_txn).unwrap();
        let record = sample_gasless_record(&pubkey, vec![MessageType::CastAdd as i32], 3600);
        put_gasless_key_record(&rocks, &mut merge_txn, 3, &pubkey, &record).unwrap();
        rocks.commit(merge_txn).unwrap();

        let txn = RocksDbTransactionBatch::new();
        let result = get_active_key(&store, &rocks, &txn, 3, &pubkey).unwrap();
        assert_eq!(result, Some(ActiveKey::OnChain));
    }

    // -- Sign-in keys: fixed expiry ---------------------------------------------------------------

    fn sign_in_record(signer_pubkey: &[u8], ttl: u32, added_at: u32) -> GaslessKeyRecord {
        let mut record =
            sample_gasless_record(signer_pubkey, vec![MessageType::CastAdd as i32], ttl);
        let data = record.message.as_mut().unwrap().data.as_mut().unwrap();
        data.timestamp = added_at;
        match data.body.as_mut().unwrap() {
            Body::KeyAddBody(body) => body.authorization_type = 200,
            _ => unreachable!(),
        }
        record
    }

    #[test]
    fn get_active_key_reports_when_a_sign_in_key_was_added() {
        let (store, rocks, _dir) = fresh_store();
        let signer_pubkey = [0xDD; 32];
        let mut txn = RocksDbTransactionBatch::new();
        put_gasless_key_record(
            &rocks,
            &mut txn,
            9,
            &signer_pubkey,
            &sign_in_record(&signer_pubkey, 3600, 123_456),
        )
        .unwrap();
        rocks.commit(txn).unwrap();

        let txn = RocksDbTransactionBatch::new();
        match get_active_key(&store, &rocks, &txn, 9, &signer_pubkey).unwrap() {
            Some(ActiveKey::Gasless {
                sign_in_added_at, ..
            }) => assert_eq!(sign_in_added_at, Some(123_456)),
            other => panic!("expected a gasless key, got {other:?}"),
        }
    }

    #[test]
    fn fixed_expiry_applies_only_where_the_feature_was_active_at_key_add() {
        let added_at = 200_000_000;
        // Custody-authorized keys always slide.
        assert!(!is_fixed_expiry_sign_in_key(
            None,
            proto::FarcasterNetwork::Devnet
        ));
        // Devnet runs the latest engine version, where the feature is on.
        assert!(is_fixed_expiry_sign_in_key(
            Some(added_at),
            proto::FarcasterNetwork::Devnet
        ));
        // Mainnet has not scheduled it: a KEY_ADD carrying a 2 in the unread field was
        // custody-authorized there and keeps its sliding window.
        assert!(!is_fixed_expiry_sign_in_key(
            Some(added_at),
            proto::FarcasterNetwork::Mainnet
        ));
    }

    /// With `slide = false` a key lives exactly `ttl` from when it was added, however much it
    /// is used; with `slide = true` (every other gasless key) use keeps extending it.
    #[test]
    fn a_fixed_window_is_not_extended_by_use() {
        use crate::storage::store::account::{
            check_last_used_at, get_last_used_at, init_last_used_at,
        };

        let ttl = 1_000u32;
        let added_at = 10_000u32;
        for slide in [false, true] {
            let (_store, rocks, _dir) = fresh_store();
            let key = [0xEE; 32];
            let mut txn = RocksDbTransactionBatch::new();
            init_last_used_at(&rocks, &mut txn, 9, &key, added_at).unwrap();
            rocks.commit(txn).unwrap();

            // Used 900 seconds in: accepted either way.
            let mut txn = RocksDbTransactionBatch::new();
            check_last_used_at(
                &rocks,
                &mut txn,
                9,
                &key,
                ttl,
                added_at + 900,
                10_900,
                slide,
            )
            .unwrap();
            rocks.commit(txn).unwrap();
            let read = RocksDbTransactionBatch::new();
            let stored = get_last_used_at(&rocks, &read, 9, &key).unwrap().unwrap();
            assert_eq!(stored, if slide { added_at + 900 } else { added_at });

            // Used again 1,500 seconds after it was added: past the fixed window, inside the
            // slid one.
            let mut txn = RocksDbTransactionBatch::new();
            let later = check_last_used_at(
                &rocks,
                &mut txn,
                9,
                &key,
                ttl,
                added_at + 1_500,
                11_500,
                slide,
            );
            assert_eq!(later.is_ok(), slide, "slide={slide}: {later:?}");
        }
    }
}
