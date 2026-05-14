//! FIP §C-2 (proof-of-work-tokenization) reward issuance + balance store.
//!
//! `compute_emissions` produces a per-FID reward total each epoch. The
//! output is wrapped in `proto::HyperRewardIssuance`, threshold-signed
//! by the epoch's group key, and gossiped as a HyperMessage. On import:
//!  1. Verify the threshold signature over the canonical payload.
//!  2. For each `(fid, amount)` entry that hasn't been issued yet for
//!     this epoch, increment the FID's balance.
//!
//! The (epoch, fid) replay-prevention key means re-importing the same
//! issuance is a no-op.

use crate::core::error::HubError;
use crate::proto;
use crate::storage::constants::RootPrefix;
use crate::storage::db::RocksDB;
use std::sync::Arc;

#[derive(thiserror::Error, Debug)]
pub enum RewardError {
    #[error(transparent)]
    Hub(#[from] HubError),
    #[error("issuance signature does not verify under the epoch's group key")]
    InvalidSignature,
    #[error("epoch group pubkey not installed for epoch {0}")]
    UnknownEpoch(u64),
    #[error("balance overflow on fid {fid}")]
    BalanceOverflow { fid: u64 },
    #[error("insufficient balance: fid {fid} has {available}, transfer requires {needed}")]
    InsufficientBalance {
        fid: u64,
        available: u64,
        needed: u64,
    },
    #[error("transfer nonce mismatch on fid {fid}: expected {expected}, got {got}")]
    NonceMismatch { fid: u64, expected: u64, got: u64 },
    #[error("signer key is not active for fid {fid}")]
    SignerNotAuthorized { fid: u64 },
    #[error("lock_id collision on fid {fid}: {lock_id_hex}")]
    LockIdCollision { fid: u64, lock_id_hex: String },
    #[error("lock_id must be exactly 32 bytes (got {got})")]
    BadLockIdLen { got: usize },
    #[error(
        "issuance for epoch {epoch} would exceed budget (would_total={would_total}, cap={cap})"
    )]
    BudgetExceeded {
        epoch: u64,
        would_total: u128,
        cap: u128,
    },
    /// General-purpose error wrapper for RewardError-returning paths
    /// that carry messages from other subsystems (e.g. signature
    /// verification failures on a `HyperTrustSnapshotUpdate`).
    #[error("{0}")]
    Custom(String),
}

/// Persistent per-FID reward balance store with replay prevention.
#[derive(Clone)]
pub struct RewardStore {
    db: Arc<RocksDB>,
}

impl RewardStore {
    pub fn new(db: Arc<RocksDB>) -> Self {
        Self { db }
    }

    fn balance_key(fid: u64) -> Vec<u8> {
        let mut k = Vec::with_capacity(9);
        k.push(RootPrefix::HyperRewardBalance as u8);
        k.extend_from_slice(&fid.to_be_bytes());
        k
    }

    fn issued_key(epoch: u64, fid: u64, market: i32) -> Vec<u8> {
        let mut k = Vec::with_capacity(21);
        k.push(RootPrefix::HyperRewardIssued as u8);
        k.extend_from_slice(&epoch.to_be_bytes());
        k.extend_from_slice(&fid.to_be_bytes());
        k.extend_from_slice(&(market as u32).to_be_bytes());
        k
    }

    /// Read the balance for a single FID. Returns 0 for FIDs with no
    /// recorded credits.
    pub fn balance_of(&self, fid: u64) -> Result<u64, RewardError> {
        match self
            .db
            .get(&Self::balance_key(fid))
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

    /// Whether this (epoch, fid, market) triple has already been
    /// credited. Used for replay prevention; same FID can be paid from
    /// distinct markets in the same epoch without collision.
    pub fn was_issued(&self, epoch: u64, fid: u64, market: i32) -> Result<bool, RewardError> {
        Ok(self
            .db
            .get(&Self::issued_key(epoch, fid, market))
            .map_err(HubError::from)?
            .is_some())
    }

    /// Read the cumulative amount already issued at this epoch within a
    /// single market. Used for per-market budget enforcement.
    pub fn issued_total_for_epoch_market(
        &self,
        epoch: u64,
        market: i32,
    ) -> Result<u128, RewardError> {
        // Walk the issued-key prefix for this epoch, filtering by the
        // 4-byte market suffix in the key.
        use crate::storage::db::PageOptions;
        let mut start = vec![RootPrefix::HyperRewardIssued as u8];
        start.extend_from_slice(&epoch.to_be_bytes());
        let mut stop = vec![RootPrefix::HyperRewardIssued as u8];
        stop.extend_from_slice(&epoch.saturating_add(1).to_be_bytes());
        let market_bytes = (market as u32).to_be_bytes();
        let mut total: u128 = 0;
        self.db
            .for_each_iterator_by_prefix(
                Some(start),
                Some(stop),
                &PageOptions::default(),
                |key, value| {
                    // Key layout: [prefix][epoch BE][fid BE][market BE u32]
                    // Total len: 1 + 8 + 8 + 4 = 21
                    if key.len() == 21 && value.len() == 8 && key[17..21] == market_bytes {
                        let mut be = [0u8; 8];
                        be.copy_from_slice(&value);
                        total = total.saturating_add(u64::from_be_bytes(be) as u128);
                    }
                    Ok(false)
                },
            )
            .map_err(HubError::from)?;
        Ok(total)
    }

    /// Total issued for an epoch across all markets. Useful for
    /// auditing the global ceiling regardless of per-market split.
    pub fn issued_total_for_epoch(&self, epoch: u64) -> Result<u128, RewardError> {
        use crate::storage::db::PageOptions;
        let mut start = vec![RootPrefix::HyperRewardIssued as u8];
        start.extend_from_slice(&epoch.to_be_bytes());
        let mut stop = vec![RootPrefix::HyperRewardIssued as u8];
        stop.extend_from_slice(&epoch.saturating_add(1).to_be_bytes());
        let mut total: u128 = 0;
        self.db
            .for_each_iterator_by_prefix(
                Some(start),
                Some(stop),
                &PageOptions::default(),
                |_key, value| {
                    if value.len() == 8 {
                        let mut be = [0u8; 8];
                        be.copy_from_slice(&value);
                        total = total.saturating_add(u64::from_be_bytes(be) as u128);
                    }
                    Ok(false)
                },
            )
            .map_err(HubError::from)?;
        Ok(total)
    }

    /// Apply a single (epoch, fid, market, amount) credit if not
    /// already issued for that triple. Returns true if applied; false
    /// if it was a no-op (already issued).
    pub fn credit_if_unissued(
        &self,
        epoch: u64,
        fid: u64,
        market: i32,
        amount: u64,
    ) -> Result<bool, RewardError> {
        if self.was_issued(epoch, fid, market)? {
            return Ok(false);
        }
        let new_balance = self
            .balance_of(fid)?
            .checked_add(amount)
            .ok_or(RewardError::BalanceOverflow { fid })?;
        self.db
            .put(&Self::balance_key(fid), &new_balance.to_be_bytes())
            .map_err(HubError::from)?;
        self.db
            .put(&Self::issued_key(epoch, fid, market), &amount.to_be_bytes())
            .map_err(HubError::from)?;
        Ok(true)
    }

    fn lock_key(fid: u64, lock_id: &[u8]) -> Vec<u8> {
        let mut k = Vec::with_capacity(1 + 8 + lock_id.len());
        k.push(RootPrefix::HyperTokenLocked as u8);
        k.extend_from_slice(&fid.to_be_bytes());
        k.extend_from_slice(lock_id);
        k
    }

    /// Iterate every persisted `TokenLockState` across all FIDs in
    /// ascending key order (`fid BE || lock_id`). Used by the
    /// protocol-side merkle tree builder to assemble the
    /// unclaimed-lock set whose root the validator set signs
    /// before posting to the EVM bridge.
    pub fn iter_all_locks(&self) -> Result<Vec<proto::TokenLockState>, RewardError> {
        use crate::storage::db::PageOptions;
        use prost::Message;
        let start = vec![RootPrefix::HyperTokenLocked as u8];
        let stop = vec![RootPrefix::HyperTokenLocked as u8 + 1];
        let mut out = Vec::new();
        self.db
            .for_each_iterator_by_prefix(
                Some(start),
                Some(stop),
                &PageOptions::default(),
                |_key, value| {
                    let state = proto::TokenLockState::decode(value)
                        .map_err(crate::core::error::HubError::from)?;
                    out.push(state);
                    Ok(false)
                },
            )
            .map_err(HubError::from)?;
        Ok(out)
    }

    /// Read the persisted `TokenLockState` for a `(fid, lock_id)`
    /// lock. Returns `None` if no such lock exists. The leaf hash
    /// the bridge contract verifies is recomputed deterministically
    /// from the state via
    /// [`crate::hyper::token_lock::encode_token_lock_leaf`].
    pub fn lock_state(
        &self,
        fid: u64,
        lock_id: &[u8],
    ) -> Result<Option<proto::TokenLockState>, RewardError> {
        use prost::Message;
        match self
            .db
            .get(&Self::lock_key(fid, lock_id))
            .map_err(HubError::from)?
        {
            None => Ok(None),
            Some(bytes) => {
                let state = proto::TokenLockState::decode(bytes.as_ref())
                    .map_err(|e| RewardError::Custom(format!("decode lock state: {e}")))?;
                Ok(Some(state))
            }
        }
    }

    /// FIP §13.5 transparent token lock. Validates `nonce`,
    /// available balance, and `lock_id` uniqueness, then atomically
    /// (single RocksDB write batch) decrements sender, bumps nonce,
    /// and persists the canonical `TokenLockState` at
    /// `RootPrefix::HyperTokenLocked || fid || lock_id`.
    ///
    /// Replay protection: per-FID monotonic nonce. `lock_id`
    /// collision is also explicitly rejected — the bridge contract
    /// uses `lock_id` as its replay nullifier, so any duplicate is
    /// a bug or replay attempt regardless of nonce state.
    ///
    /// The on-chain merkle leaf is recomputed deterministically
    /// from the stored `TokenLockState` via the canonical
    /// `bridge_payload::lock_leaf_evm` encoder shared with the
    /// contract — there's no need to persist the leaf hash here.
    pub fn apply_lock(
        &self,
        sender_fid: u64,
        amount: u64,
        nonce: u64,
        state: &proto::TokenLockState,
    ) -> Result<(), RewardError> {
        use prost::Message;
        if state.lock_id.len() != 32 {
            return Err(RewardError::BadLockIdLen {
                got: state.lock_id.len(),
            });
        }
        let current_nonce = self.nonce_of(sender_fid)?;
        let expected = current_nonce.saturating_add(1);
        if nonce != expected {
            return Err(RewardError::NonceMismatch {
                fid: sender_fid,
                expected,
                got: nonce,
            });
        }
        if self.lock_state(sender_fid, &state.lock_id)?.is_some() {
            return Err(RewardError::LockIdCollision {
                fid: sender_fid,
                lock_id_hex: hex::encode(&state.lock_id),
            });
        }
        let sender_bal = self.balance_of(sender_fid)?;
        if sender_bal < amount {
            return Err(RewardError::InsufficientBalance {
                fid: sender_fid,
                available: sender_bal,
                needed: amount,
            });
        }
        let new_sender = sender_bal - amount;
        let mut state_bytes = Vec::with_capacity(state.encoded_len());
        state
            .encode(&mut state_bytes)
            .map_err(|e| RewardError::Custom(format!("encode lock state: {e}")))?;

        let mut batch = self.db.txn();
        batch.put(
            Self::balance_key(sender_fid),
            new_sender.to_be_bytes().to_vec(),
        );
        batch.put(Self::nonce_key(sender_fid), nonce.to_be_bytes().to_vec());
        batch.put(Self::lock_key(sender_fid, &state.lock_id), state_bytes);
        self.db.commit(batch).map_err(HubError::from)?;
        Ok(())
    }

    fn nonce_key(fid: u64) -> Vec<u8> {
        let mut k = Vec::with_capacity(9);
        k.push(RootPrefix::HyperTokenNonce as u8);
        k.extend_from_slice(&fid.to_be_bytes());
        k
    }

    /// Read the per-FID transfer nonce. FIDs that have never
    /// transacted return 0. The next valid `TokenTransferBody` for
    /// `fid` must carry `nonce == nonce_of(fid) + 1`.
    pub fn nonce_of(&self, fid: u64) -> Result<u64, RewardError> {
        match self.db.get(&Self::nonce_key(fid)).map_err(HubError::from)? {
            Some(bytes) if bytes.len() == 8 => {
                let mut be = [0u8; 8];
                be.copy_from_slice(&bytes);
                Ok(u64::from_be_bytes(be))
            }
            _ => Ok(0),
        }
    }

    /// FIP §13.1 transparent transfer. Validates `nonce` and
    /// available balance, then atomically (single RocksDB write
    /// batch) decrements sender, increments recipient, and bumps
    /// sender's nonce.
    ///
    /// Replay protection: per-FID monotonic nonce. Re-applying the
    /// same `(sender, nonce)` pair fails with `NonceMismatch` — the
    /// nonce has already advanced past it. This makes block
    /// re-import safe.
    ///
    /// Self-transfers are allowed (recipient == sender) — useful
    /// for advancing nonce without moving balance. The balance
    /// pre-check still runs so wallet UX stays predictable
    /// regardless of self vs. cross transfer.
    pub fn apply_transfer(
        &self,
        sender_fid: u64,
        recipient_fid: u64,
        amount: u64,
        nonce: u64,
    ) -> Result<(), RewardError> {
        let current_nonce = self.nonce_of(sender_fid)?;
        let expected = current_nonce.saturating_add(1);
        if nonce != expected {
            return Err(RewardError::NonceMismatch {
                fid: sender_fid,
                expected,
                got: nonce,
            });
        }

        let sender_bal = self.balance_of(sender_fid)?;
        if sender_bal < amount {
            return Err(RewardError::InsufficientBalance {
                fid: sender_fid,
                available: sender_bal,
                needed: amount,
            });
        }

        let mut batch = self.db.txn();
        if sender_fid == recipient_fid {
            // Net-zero balance change. Only the nonce advances.
            batch.put(Self::nonce_key(sender_fid), nonce.to_be_bytes().to_vec());
        } else {
            let new_sender = sender_bal - amount;
            let recipient_bal = self.balance_of(recipient_fid)?;
            let new_recipient = recipient_bal
                .checked_add(amount)
                .ok_or(RewardError::BalanceOverflow { fid: recipient_fid })?;
            batch.put(
                Self::balance_key(sender_fid),
                new_sender.to_be_bytes().to_vec(),
            );
            batch.put(
                Self::balance_key(recipient_fid),
                new_recipient.to_be_bytes().to_vec(),
            );
            batch.put(Self::nonce_key(sender_fid), nonce.to_be_bytes().to_vec());
        }
        self.db.commit(batch).map_err(HubError::from)?;
        Ok(())
    }
}

/// Canonical signing payload for a reward issuance. Domain-separated so
/// the threshold signature can't collide with anything else signed by
/// the epoch's group key. Commits to: epoch, work market, sorted entries.
pub fn issuance_signing_payload(issuance: &proto::HyperRewardIssuance) -> Vec<u8> {
    const DST: &[u8] = b"hypersnap-reward-issuance-v2:";
    let mut buf = Vec::new();
    buf.extend_from_slice(DST);
    buf.extend_from_slice(&issuance.epoch.to_be_bytes());
    // Market binds the signature to a specific reward stream — without
    // this, an attacker could replay a sig from one market into
    // another.
    buf.extend_from_slice(&(issuance.market as u32).to_be_bytes());
    buf.extend_from_slice(&(issuance.recipients.len() as u32).to_be_bytes());
    // Sort by fid for deterministic payload (the wire entries can be in
    // any order; we hash a canonical ordering).
    let mut sorted = issuance.recipients.clone();
    sorted.sort_by_key(|r| r.fid);
    for entry in &sorted {
        buf.extend_from_slice(&entry.fid.to_be_bytes());
        buf.extend_from_slice(&entry.amount.to_be_bytes());
    }
    buf
}

/// Signing payload the epoch-`N-1` committee threshold-signs to
/// seed DA challenges for epoch `N`.
pub fn da_epoch_seed_signing_payload(target_epoch: u64, chain_id: u64) -> Vec<u8> {
    const DST: &[u8] = b"hypersnap-da-epoch-seed-v1:";
    let mut buf = Vec::with_capacity(DST.len() + 16);
    buf.extend_from_slice(DST);
    buf.extend_from_slice(&chain_id.to_be_bytes());
    buf.extend_from_slice(&target_epoch.to_be_bytes());
    buf
}

/// Canonical signing payload for a `HyperTrustSnapshotUpdate`.
/// Domain-separated, length-prefixed, sorted by fid for determinism.
pub fn trust_snapshot_signing_payload(update: &proto::HyperTrustSnapshotUpdate) -> Vec<u8> {
    const DST: &[u8] = b"hypersnap-trust-snapshot-v1:";
    let mut buf = Vec::new();
    buf.extend_from_slice(DST);
    buf.extend_from_slice(&update.epoch.to_be_bytes());
    buf.extend_from_slice(&(update.entries.len() as u32).to_be_bytes());
    let mut sorted = update.entries.clone();
    sorted.sort_by_key(|e| e.fid);
    for e in &sorted {
        buf.extend_from_slice(&e.fid.to_be_bytes());
        buf.extend_from_slice(&e.score_bits.to_be_bytes());
    }
    buf
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn make_store() -> (RewardStore, TempDir) {
        let dir = TempDir::new().unwrap();
        let db = RocksDB::new(dir.path().to_str().unwrap());
        db.open().unwrap();
        (RewardStore::new(Arc::new(db)), dir)
    }

    #[test]
    fn unknown_fid_balance_is_zero() {
        let (store, _dir) = make_store();
        assert_eq!(store.balance_of(42).unwrap(), 0);
    }

    #[test]
    fn credit_increments_balance() {
        let (store, _dir) = make_store();
        assert!(store
            .credit_if_unissued(1, 7, proto::WorkMarket::Growth as i32, 100)
            .unwrap());
        assert_eq!(store.balance_of(7).unwrap(), 100);
    }

    #[test]
    fn credit_is_idempotent_per_epoch_fid() {
        let (store, _dir) = make_store();
        assert!(store
            .credit_if_unissued(1, 7, proto::WorkMarket::Growth as i32, 100)
            .unwrap());
        // Second credit at same (epoch, fid) is a no-op.
        assert!(!store
            .credit_if_unissued(1, 7, proto::WorkMarket::Growth as i32, 999)
            .unwrap());
        assert_eq!(store.balance_of(7).unwrap(), 100);
    }

    #[test]
    fn distinct_epochs_credit_independently() {
        let (store, _dir) = make_store();
        store
            .credit_if_unissued(1, 7, proto::WorkMarket::Growth as i32, 100)
            .unwrap();
        store
            .credit_if_unissued(2, 7, proto::WorkMarket::Growth as i32, 50)
            .unwrap();
        assert_eq!(store.balance_of(7).unwrap(), 150);
    }

    #[test]
    fn distinct_fids_credit_independently() {
        let (store, _dir) = make_store();
        store
            .credit_if_unissued(1, 7, proto::WorkMarket::Growth as i32, 100)
            .unwrap();
        store
            .credit_if_unissued(1, 8, proto::WorkMarket::Growth as i32, 200)
            .unwrap();
        assert_eq!(store.balance_of(7).unwrap(), 100);
        assert_eq!(store.balance_of(8).unwrap(), 200);
    }

    #[test]
    fn balance_overflow_errors() {
        let (store, _dir) = make_store();
        store
            .credit_if_unissued(1, 7, proto::WorkMarket::Growth as i32, u64::MAX)
            .unwrap();
        let r = store.credit_if_unissued(2, 7, proto::WorkMarket::Growth as i32, 1);
        assert!(matches!(r, Err(RewardError::BalanceOverflow { fid: 7 })));
    }

    #[test]
    fn signing_payload_is_order_independent() {
        let p1 = issuance_signing_payload(&proto::HyperRewardIssuance {
            epoch: 5,
            recipients: vec![
                proto::RewardEntry {
                    fid: 1,
                    amount: 100,
                },
                proto::RewardEntry {
                    fid: 2,
                    amount: 200,
                },
            ],
            market: proto::WorkMarket::Growth as i32,
            ..Default::default()
        });
        let p2 = issuance_signing_payload(&proto::HyperRewardIssuance {
            epoch: 5,
            recipients: vec![
                proto::RewardEntry {
                    fid: 2,
                    amount: 200,
                },
                proto::RewardEntry {
                    fid: 1,
                    amount: 100,
                },
            ],
            market: proto::WorkMarket::Growth as i32,
            ..Default::default()
        });
        assert_eq!(p1, p2);
    }

    #[test]
    fn unknown_fid_nonce_is_zero() {
        let (store, _dir) = make_store();
        assert_eq!(store.nonce_of(99).unwrap(), 0);
    }

    /// Happy path: sender at nonce 0 + balance 1000 transfers 100 to
    /// a fresh recipient. Sender balance = 900, recipient = 100,
    /// sender nonce = 1.
    #[test]
    fn transfer_moves_balance_and_advances_nonce() {
        let (store, _dir) = make_store();
        store
            .credit_if_unissued(0, 1, proto::WorkMarket::Growth as i32, 1_000)
            .unwrap();
        store.apply_transfer(1, 2, 100, 1).unwrap();
        assert_eq!(store.balance_of(1).unwrap(), 900);
        assert_eq!(store.balance_of(2).unwrap(), 100);
        assert_eq!(store.nonce_of(1).unwrap(), 1);
        // Recipient's nonce is untouched — only sender's advances.
        assert_eq!(store.nonce_of(2).unwrap(), 0);
    }

    #[test]
    fn transfer_rejects_wrong_nonce() {
        let (store, _dir) = make_store();
        store
            .credit_if_unissued(0, 1, proto::WorkMarket::Growth as i32, 1_000)
            .unwrap();
        let r = store.apply_transfer(1, 2, 100, 2); // expected 1
        assert!(matches!(
            r,
            Err(RewardError::NonceMismatch {
                fid: 1,
                expected: 1,
                got: 2
            })
        ));
        // No state mutation on validation failure.
        assert_eq!(store.balance_of(1).unwrap(), 1_000);
        assert_eq!(store.balance_of(2).unwrap(), 0);
        assert_eq!(store.nonce_of(1).unwrap(), 0);
    }

    #[test]
    fn transfer_replay_fails_after_nonce_advances() {
        let (store, _dir) = make_store();
        store
            .credit_if_unissued(0, 1, proto::WorkMarket::Growth as i32, 1_000)
            .unwrap();
        store.apply_transfer(1, 2, 100, 1).unwrap();
        // Replay of nonce=1 must fail (nonce has advanced to 1, expects 2).
        let r = store.apply_transfer(1, 2, 100, 1);
        assert!(matches!(r, Err(RewardError::NonceMismatch { .. })));
    }

    #[test]
    fn transfer_rejects_insufficient_balance() {
        let (store, _dir) = make_store();
        store
            .credit_if_unissued(0, 1, proto::WorkMarket::Growth as i32, 50)
            .unwrap();
        let r = store.apply_transfer(1, 2, 100, 1);
        assert!(matches!(
            r,
            Err(RewardError::InsufficientBalance {
                fid: 1,
                available: 50,
                needed: 100
            })
        ));
        // Pre-check failure: nonce stays at 0.
        assert_eq!(store.nonce_of(1).unwrap(), 0);
    }

    /// Self-transfer: net balance change is zero, but nonce
    /// advances. Useful for nonce-only advancement (e.g., wallet
    /// recovering from a stuck nonce).
    #[test]
    fn self_transfer_only_advances_nonce() {
        let (store, _dir) = make_store();
        store
            .credit_if_unissued(0, 1, proto::WorkMarket::Growth as i32, 1_000)
            .unwrap();
        store.apply_transfer(1, 1, 100, 1).unwrap();
        assert_eq!(store.balance_of(1).unwrap(), 1_000);
        assert_eq!(store.nonce_of(1).unwrap(), 1);
    }

    #[test]
    fn self_transfer_still_requires_sufficient_balance() {
        let (store, _dir) = make_store();
        store
            .credit_if_unissued(0, 1, proto::WorkMarket::Growth as i32, 50)
            .unwrap();
        let r = store.apply_transfer(1, 1, 100, 1);
        assert!(matches!(r, Err(RewardError::InsufficientBalance { .. })));
    }

    #[test]
    fn sequential_transfers_advance_nonce_each_time() {
        let (store, _dir) = make_store();
        store
            .credit_if_unissued(0, 1, proto::WorkMarket::Growth as i32, 1_000)
            .unwrap();
        store.apply_transfer(1, 2, 100, 1).unwrap();
        store.apply_transfer(1, 2, 200, 2).unwrap();
        store.apply_transfer(1, 3, 50, 3).unwrap();
        assert_eq!(store.balance_of(1).unwrap(), 650);
        assert_eq!(store.balance_of(2).unwrap(), 300);
        assert_eq!(store.balance_of(3).unwrap(), 50);
        assert_eq!(store.nonce_of(1).unwrap(), 3);
    }

    fn lock_state(fid: u64, amount: u64, lock_id: [u8; 32]) -> proto::TokenLockState {
        proto::TokenLockState {
            sender_fid: fid,
            amount,
            destination_chain_id: 10,
            destination_address: vec![0xab; 20],
            lock_id: lock_id.to_vec(),
        }
    }

    #[test]
    fn apply_lock_decrements_balance_and_persists_state() {
        let (store, _dir) = make_store();
        store
            .credit_if_unissued(0, 1, proto::WorkMarket::Growth as i32, 1_000)
            .unwrap();
        let lock_id = [0xaau8; 32];
        let state = lock_state(1, 250, lock_id);
        store.apply_lock(1, 250, 1, &state).unwrap();
        assert_eq!(store.balance_of(1).unwrap(), 750);
        assert_eq!(store.nonce_of(1).unwrap(), 1);
        let stored = store.lock_state(1, &lock_id).unwrap().unwrap();
        assert_eq!(stored.amount, 250);
        assert_eq!(stored.destination_chain_id, 10);
        assert_eq!(stored.destination_address, vec![0xab; 20]);
        assert_eq!(stored.lock_id, lock_id.to_vec());
    }

    #[test]
    fn apply_lock_rejects_collision_on_lock_id() {
        let (store, _dir) = make_store();
        store
            .credit_if_unissued(0, 1, proto::WorkMarket::Growth as i32, 1_000)
            .unwrap();
        let lock_id = [0xaau8; 32];
        store
            .apply_lock(1, 100, 1, &lock_state(1, 100, lock_id))
            .unwrap();
        // Second lock with the same lock_id: rejected even with a
        // valid next nonce.
        let r = store.apply_lock(1, 100, 2, &lock_state(1, 100, lock_id));
        assert!(matches!(
            r,
            Err(RewardError::LockIdCollision { fid: 1, .. })
        ));
        // First lock untouched.
        assert!(store.lock_state(1, &lock_id).unwrap().is_some());
        // Nonce did not advance on collision.
        assert_eq!(store.nonce_of(1).unwrap(), 1);
    }

    #[test]
    fn apply_lock_rejects_bad_nonce() {
        let (store, _dir) = make_store();
        store
            .credit_if_unissued(0, 1, proto::WorkMarket::Growth as i32, 1_000)
            .unwrap();
        let lock_id = [0xaau8; 32];
        let r = store.apply_lock(1, 100, 5, &lock_state(1, 100, lock_id)); // expected 1
        assert!(matches!(r, Err(RewardError::NonceMismatch { .. })));
    }

    #[test]
    fn apply_lock_rejects_insufficient_balance() {
        let (store, _dir) = make_store();
        store
            .credit_if_unissued(0, 1, proto::WorkMarket::Growth as i32, 50)
            .unwrap();
        let lock_id = [0xaau8; 32];
        let r = store.apply_lock(1, 100, 1, &lock_state(1, 100, lock_id));
        assert!(matches!(
            r,
            Err(RewardError::InsufficientBalance {
                fid: 1,
                available: 50,
                needed: 100
            })
        ));
    }

    #[test]
    fn apply_lock_rejects_bad_lock_id_length() {
        let (store, _dir) = make_store();
        store
            .credit_if_unissued(0, 1, proto::WorkMarket::Growth as i32, 1_000)
            .unwrap();
        let mut bad = lock_state(1, 100, [0u8; 32]);
        bad.lock_id = vec![0xaa; 16]; // wrong length
        let r = store.apply_lock(1, 100, 1, &bad);
        assert!(matches!(r, Err(RewardError::BadLockIdLen { got: 16 })));
    }

    /// Distinct lock_ids on the same FID coexist; balance and
    /// nonce advance with each lock.
    #[test]
    fn distinct_lock_ids_coexist_on_same_fid() {
        let (store, _dir) = make_store();
        store
            .credit_if_unissued(0, 1, proto::WorkMarket::Growth as i32, 1_000)
            .unwrap();
        let lid_a = [0xaau8; 32];
        let lid_b = [0xbbu8; 32];
        store
            .apply_lock(1, 100, 1, &lock_state(1, 100, lid_a))
            .unwrap();
        store
            .apply_lock(1, 200, 2, &lock_state(1, 200, lid_b))
            .unwrap();
        assert_eq!(store.balance_of(1).unwrap(), 700);
        assert_eq!(store.nonce_of(1).unwrap(), 2);
        assert!(store.lock_state(1, &lid_a).unwrap().is_some());
        assert!(store.lock_state(1, &lid_b).unwrap().is_some());
    }

    /// Same lock_id on distinct FIDs is allowed — the storage key
    /// includes both. The bridge contract treats lock_id as
    /// globally unique, but enforcement of that is up to the user
    /// generating the IDs.
    #[test]
    fn same_lock_id_on_distinct_fids_is_allowed() {
        let (store, _dir) = make_store();
        store
            .credit_if_unissued(0, 1, proto::WorkMarket::Growth as i32, 1_000)
            .unwrap();
        store
            .credit_if_unissued(0, 2, proto::WorkMarket::Growth as i32, 1_000)
            .unwrap();
        let lock_id = [0xaau8; 32];
        store
            .apply_lock(1, 100, 1, &lock_state(1, 100, lock_id))
            .unwrap();
        store
            .apply_lock(2, 200, 1, &lock_state(2, 200, lock_id))
            .unwrap();
        assert!(store.lock_state(1, &lock_id).unwrap().is_some());
        assert!(store.lock_state(2, &lock_id).unwrap().is_some());
    }
}
