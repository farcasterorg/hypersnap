//! Validator registration registry per FIP-hyper-validator-selection §2.
//!
//! Each `HyperValidatorEventBody` is recorded into the hyper trie keyed by
//! `[RootPrefix::HyperValidatorEvent][validator_key][epoch BE]`. At each
//! epoch transition, an active validator set is computed by walking events
//! from `epoch − EPOCH_BUFFER − 1` and earlier. The buffer ensures
//! registrations from epoch N-1 take effect at epoch N+1, giving validators
//! one full epoch to prepare (DKG ceremony participation, key rotation).

use crate::core::error::HubError;
use crate::hyper::epoch::EPOCH_BUFFER;
use crate::proto;
use crate::storage::constants::RootPrefix;
use crate::storage::db::{PageOptions, RocksDB};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use prost::Message;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::sync::Arc;

/// FIP-hyper-validator-selection §2.1: a single FID may not run more than
/// `MAX_VALIDATORS_PER_FID` validator slots simultaneously. Counted at
/// registration time over the per-FID active index.
pub const MAX_VALIDATORS_PER_FID: u32 = 3;

#[derive(thiserror::Error, Debug)]
pub enum RegistryError {
    #[error("validator_key must be exactly 32 bytes")]
    BadValidatorKey,
    #[error("validator_address must be exactly 20 bytes for register events")]
    BadValidatorAddress,
    #[error("transport_pubkey must be exactly 32 bytes for register events")]
    BadTransportPubkey,
    #[error("event signature missing")]
    MissingSignature,
    #[error("event signature must be exactly 64 bytes")]
    BadSignatureLength,
    #[error("event signature does not verify under validator_key")]
    InvalidSignature,
    #[error("custody_signature must be exactly 65 bytes (r||s||v)")]
    BadCustodySignatureLength,
    #[error("custody_signature missing for register event")]
    MissingCustodySignature,
    #[error("custody_signature does not recover to the FID's custody address")]
    InvalidCustodySignature,
    #[error("EIP-712 typed-data construction failed: {0}")]
    TypedDataConstruction(String),
    #[error("EIP-712 prehash computation failed: {0}")]
    TypedDataPrehash(String),
    #[error("registration_epoch ({event}) does not match current epoch ({current})")]
    EpochMismatch { event: u64, current: u64 },
    #[error("event_type NONE is not a valid registration event")]
    NoneEventType,
    #[error("event must specify a non-zero fid")]
    MissingFid,
    #[error(
        "fid {fid} already has {count} active validators (max {max}); cannot register another"
    )]
    PerFidQuotaExceeded { fid: u64, count: u32, max: u32 },
    #[error("fid {fid} trust score {score} is below the validator floor {min}; cannot register")]
    TrustBelowFloor { fid: u64, score: f64, min: f64 },
    #[error("custody address must be exactly 20 bytes (Ethereum address)")]
    BadCustodyAddress,
    #[error("custody address resolution failed for fid {fid}")]
    CustodyAddressUnknown { fid: u64 },
    #[error(transparent)]
    Hub(#[from] HubError),
    #[error(transparent)]
    Decode(#[from] prost::DecodeError),
}

/// Resolves an FID to its current custody address (Ethereum-controlled).
/// Implementations are typically backed by snapchain's `OnchainEventStore`
/// (which tracks `IdRegistry.Register/Transfer/Recover` events). The
/// registry takes a `&dyn CustodyResolver` so it can validate cross-signed
/// validator events without a hard dependency on the snapchain store
/// types.
pub trait CustodyResolver: Send + Sync {
    /// Returns the 20-byte Ethereum custody address for `fid`, or
    /// `None` if the FID is not registered.
    fn custody_address_for_fid(&self, fid: u64) -> Result<Option<[u8; 20]>, HubError>;
}

/// Production `CustodyResolver` backed by snapchain's
/// `OnchainEventStore`. Reads the latest `IdRegister` event for
/// `fid` and returns its `to` field (the current custody address).
pub struct StoreBackedCustodyResolver {
    pub store: crate::storage::store::account::OnchainEventStore,
}

impl StoreBackedCustodyResolver {
    pub fn new(store: crate::storage::store::account::OnchainEventStore) -> Self {
        Self { store }
    }
}

impl CustodyResolver for StoreBackedCustodyResolver {
    fn custody_address_for_fid(&self, fid: u64) -> Result<Option<[u8; 20]>, HubError> {
        let evt = self
            .store
            .get_id_register_event_by_fid(fid, None)
            .map_err(|e| HubError::invalid_internal_state(&e.to_string()))?;
        let Some(evt) = evt else {
            return Ok(None);
        };
        let body = match evt.body {
            Some(proto::on_chain_event::Body::IdRegisterEventBody(b)) => b,
            _ => return Ok(None),
        };
        if body.to.len() != 20 {
            return Ok(None);
        }
        let mut out = [0u8; 20];
        out.copy_from_slice(&body.to);
        Ok(Some(out))
    }
}

/// Resolves an FID to its current trust score. Backed by `TrustScoreStore`
/// in production (refreshed each epoch by the in-protocol scoring output)
/// and by an in-memory map in tests.
pub trait TrustScoreResolver: Send + Sync {
    /// Returns the FID's current trust score in `[0.0, 1.0]`, or `None`
    /// if the FID has no recorded score (treated as zero by the gate).
    fn trust_score_for_fid(&self, fid: u64) -> Result<Option<f64>, HubError>;
}

/// Domain-separated canonical signing payload for `HyperValidatorEventBody`.
/// The validator signs these bytes with their Ed25519 identity key. `fid`
/// is included so a single Ed25519 key signature cannot be replayed for a
/// different FID — every signature commits to exactly one (validator_key,
/// fid) pair.
pub fn validator_event_signing_payload(event: &proto::HyperValidatorEventBody) -> Vec<u8> {
    // DST bumped from v3 → v4 in Phase 6.2c when the legacy BLS
    // `bls_public_key` field was removed entirely from the proto.
    const DST: &[u8] = b"hypersnap-validator-event-v4";
    let mut buf = Vec::with_capacity(
        DST.len()
            + 4
            + event.validator_key.len()
            + 2
            + event.transport_pubkey.len()
            + 8
            + 2
            + event.operator_address.len()
            + 8
            + 2
            + event.validator_address.len(),
    );
    buf.extend_from_slice(DST);
    buf.extend_from_slice(&event.event_type.to_be_bytes());
    buf.extend_from_slice(&event.validator_key);
    buf.extend_from_slice(&(event.transport_pubkey.len() as u16).to_be_bytes());
    buf.extend_from_slice(&event.transport_pubkey);
    buf.extend_from_slice(&event.registration_epoch.to_be_bytes());
    buf.extend_from_slice(&(event.operator_address.len() as u16).to_be_bytes());
    buf.extend_from_slice(&event.operator_address);
    buf.extend_from_slice(&event.fid.to_be_bytes());
    buf.extend_from_slice(&(event.validator_address.len() as u16).to_be_bytes());
    buf.extend_from_slice(&event.validator_address);
    buf
}

fn verify_event_signature(event: &proto::HyperValidatorEventBody) -> Result<(), RegistryError> {
    if event.signature.len() != 64 {
        return Err(RegistryError::BadSignatureLength);
    }
    let mut sig_bytes = [0u8; 64];
    sig_bytes.copy_from_slice(&event.signature);
    let sig = Signature::from_bytes(&sig_bytes);

    let mut pk_bytes = [0u8; 32];
    pk_bytes.copy_from_slice(&event.validator_key);
    let vk = VerifyingKey::from_bytes(&pk_bytes).map_err(|_| RegistryError::BadValidatorKey)?;

    let message = validator_event_signing_payload(event);
    vk.verify(&message, &sig)
        .map_err(|_| RegistryError::InvalidSignature)
}

// ---------------------------------------------------------------------------
// EIP-712 cross-signature: the FID's custody address must authorize each
// validator slot. The hash domain is fixed below; clients build the same
// typed-data and sign with the custody key (e.g. via Wagmi/Viem on the web).
// ---------------------------------------------------------------------------

const VALIDATOR_AUTH_EIP712_DOMAIN_NAME: &str = "Hypersnap";
const VALIDATOR_AUTH_EIP712_DOMAIN_VERSION: &str = "1";
/// OP Mainnet chain id. The EIP-712 domain references it as a separator;
/// no on-chain contract is involved.
const VALIDATOR_AUTH_EIP712_CHAIN_ID: u64 = 10;

fn validator_authorization_eip712_types() -> Value {
    // Phase 5b: schema bound to a `validator_address` field so the
    // FID owner's custody EIP-712 signature commits to the
    // post-migration secp256k1 identity. Pre-migration events emit
    // an empty bytes value here; the field's presence in the
    // schema (= type-hash input) means an old v1 signature won't
    // verify against the v2 schema. Coordinated cutover.
    json!({
        "EIP712Domain": [
            {"name": "name", "type": "string"},
            {"name": "version", "type": "string"},
            {"name": "chainId", "type": "uint256"},
        ],
        "ValidatorAuthorization": [
            {"name": "fid", "type": "uint256"},
            {"name": "validator_key", "type": "bytes32"},
            {"name": "transport_pubkey", "type": "bytes32"},
            {"name": "event_type", "type": "uint8"},
            {"name": "registration_epoch", "type": "uint256"},
            {"name": "validator_address", "type": "bytes"},
        ],
    })
}

fn validator_authorization_eip712_domain() -> Value {
    json!({
        "name": VALIDATOR_AUTH_EIP712_DOMAIN_NAME,
        "version": VALIDATOR_AUTH_EIP712_DOMAIN_VERSION,
        "chainId": VALIDATOR_AUTH_EIP712_CHAIN_ID,
    })
}

/// Build the EIP-712 typed data for `event`. Returned as a serde_json
/// `Value` ready to be parsed into `alloy_dyn_abi::TypedData`.
pub fn validator_authorization_typed_data(event: &proto::HyperValidatorEventBody) -> Value {
    let mut validator_key_hex = String::with_capacity(2 + 64);
    validator_key_hex.push_str("0x");
    validator_key_hex.push_str(&hex::encode(&event.validator_key));

    let mut transport_hex = String::with_capacity(2 + 64);
    transport_hex.push_str("0x");
    transport_hex.push_str(&hex::encode(&event.transport_pubkey));

    let mut validator_address_hex = String::with_capacity(2 + event.validator_address.len() * 2);
    validator_address_hex.push_str("0x");
    validator_address_hex.push_str(&hex::encode(&event.validator_address));

    json!({
        "types": validator_authorization_eip712_types(),
        "primaryType": "ValidatorAuthorization",
        "domain": validator_authorization_eip712_domain(),
        "message": {
            "fid": event.fid.to_string(),
            "validator_key": validator_key_hex,
            "transport_pubkey": transport_hex,
            "event_type": event.event_type as u32,
            "registration_epoch": event.registration_epoch.to_string(),
            "validator_address": validator_address_hex,
        },
    })
}

/// Verify the FID custody-key EIP-712 signature.
///
/// Recovers the signer address from `event.custody_signature` over the
/// EIP-712 prehash of `validator_authorization_typed_data(event)` and
/// compares to `custody_address`.
fn verify_custody_signature(
    event: &proto::HyperValidatorEventBody,
    custody_address: &[u8; 20],
) -> Result<(), RegistryError> {
    use alloy_dyn_abi::TypedData;

    if event.custody_signature.len() != 65 {
        return Err(RegistryError::BadCustodySignatureLength);
    }

    let json = validator_authorization_typed_data(event);
    let typed: TypedData = serde_json::from_value(json)
        .map_err(|e| RegistryError::TypedDataConstruction(e.to_string()))?;
    let prehash = typed
        .eip712_signing_hash()
        .map_err(|e| RegistryError::TypedDataPrehash(e.to_string()))?;

    let v_byte = event.custody_signature[64];
    let parity = v_byte != 0x1b && v_byte != 0x00;
    let sig = alloy_primitives::PrimitiveSignature::from_bytes_and_parity(
        &event.custody_signature[0..64],
        parity,
    );

    let recovered = sig
        .recover_address_from_prehash(&prehash)
        .map_err(|_| RegistryError::InvalidCustodySignature)?;

    let expected = alloy_primitives::Address::from(*custody_address);
    if recovered != expected {
        return Err(RegistryError::InvalidCustodySignature);
    }
    Ok(())
}

#[derive(Clone)]
pub struct ValidatorRegistry {
    db: Arc<RocksDB>,
}

impl ValidatorRegistry {
    pub fn new(db: Arc<RocksDB>) -> Self {
        Self { db }
    }

    fn make_event_key(validator_key: &[u8], epoch: u64) -> Vec<u8> {
        let mut k = Vec::with_capacity(1 + validator_key.len() + 8);
        k.push(RootPrefix::HyperValidatorEvent as u8);
        k.extend_from_slice(validator_key);
        k.extend_from_slice(&epoch.to_be_bytes());
        k
    }

    fn make_validator_by_fid_key(fid: u64, validator_key: &[u8]) -> Vec<u8> {
        let mut k = Vec::with_capacity(1 + 8 + validator_key.len());
        k.push(RootPrefix::HyperValidatorByFid as u8);
        k.extend_from_slice(&fid.to_be_bytes());
        k.extend_from_slice(validator_key);
        k
    }

    fn make_validator_fid_lookup_key(validator_key: &[u8]) -> Vec<u8> {
        let mut k = Vec::with_capacity(1 + validator_key.len());
        k.push(RootPrefix::HyperValidatorFidLookup as u8);
        k.extend_from_slice(validator_key);
        k
    }

    /// Return the FID currently bound to `validator_key`, or
    /// `None` if the validator is not registered (or has been
    /// deregistered). Reads the by-key fid index maintained by
    /// `record_event` on Register/Deregister.
    pub fn fid_for_validator_key(
        &self,
        validator_key: &[u8],
    ) -> Result<Option<u64>, RegistryError> {
        let lookup = Self::make_validator_fid_lookup_key(validator_key);
        match self.db.get(&lookup).map_err(HubError::from)? {
            Some(bytes) if bytes.len() == 8 => {
                let mut be = [0u8; 8];
                be.copy_from_slice(&bytes);
                Ok(Some(u64::from_be_bytes(be)))
            }
            _ => Ok(None),
        }
    }

    /// Lenient validation: checks structural properties and verifies any
    /// signatures that *are* present, but does not require both sigs or a
    /// non-zero FID. Intended for tests, migration paths, and contexts
    /// where the strict cross-sign requirement can't be enforced.
    ///
    /// `custody_address` is optional. When `None`, the EIP-712 custody
    /// sig is not checked. When `Some(addr)`, any non-empty
    /// `custody_signature` MUST verify against that address.
    ///
    /// Production paths use `validate_and_check_quota` instead, which
    /// requires a `CustodyResolver` and enforces the cross-sign + 3-cap
    /// rules.
    pub fn validate_event(
        event: &proto::HyperValidatorEventBody,
        current_epoch: u64,
        custody_address: Option<&[u8; 20]>,
    ) -> Result<(), RegistryError> {
        if event.event_type == proto::HyperValidatorEventType::None as i32 {
            return Err(RegistryError::NoneEventType);
        }
        if event.validator_key.len() != 32 {
            return Err(RegistryError::BadValidatorKey);
        }
        if event.registration_epoch != current_epoch {
            return Err(RegistryError::EpochMismatch {
                event: event.registration_epoch,
                current: current_epoch,
            });
        }

        let is_register = event.event_type == proto::HyperValidatorEventType::Register as i32;
        if is_register {
            if event.validator_address.len() != 20 {
                return Err(RegistryError::BadValidatorAddress);
            }
            if event.transport_pubkey.len() != 32 {
                return Err(RegistryError::BadTransportPubkey);
            }
        }

        // At least one signature must be present — empty events are
        // never accepted regardless of mode.
        let has_ed25519 = !event.signature.is_empty();
        let has_custody = !event.custody_signature.is_empty();
        if !has_ed25519 && !has_custody {
            return Err(RegistryError::MissingSignature);
        }

        if has_ed25519 {
            verify_event_signature(event)?;
        }
        if has_custody {
            let addr =
                custody_address.ok_or(RegistryError::CustodyAddressUnknown { fid: event.fid })?;
            verify_custody_signature(event, addr)?;
        }
        Ok(())
    }

    /// Strict validation: the protocol path used at the gossip-message
    /// boundary (router and importer). Enforces:
    /// - non-zero `fid`
    /// - custody address resolvable from `custody_resolver`
    /// - Ed25519 signature verifies for both Register and Deregister
    /// - EIP-712 custody signature verifies, REQUIRED for Register
    /// - per-FID validator quota (max `MAX_VALIDATORS_PER_FID`) on Register
    pub fn validate_and_check_quota(
        &self,
        event: &proto::HyperValidatorEventBody,
        current_epoch: u64,
        custody_resolver: &dyn CustodyResolver,
    ) -> Result<(), RegistryError> {
        if event.fid == 0 {
            return Err(RegistryError::MissingFid);
        }
        let custody = custody_resolver
            .custody_address_for_fid(event.fid)
            .map_err(RegistryError::Hub)?
            .ok_or(RegistryError::CustodyAddressUnknown { fid: event.fid })?;

        let is_register = event.event_type == proto::HyperValidatorEventType::Register as i32;
        if is_register && event.custody_signature.is_empty() {
            return Err(RegistryError::MissingCustodySignature);
        }
        if event.signature.is_empty() {
            return Err(RegistryError::MissingSignature);
        }

        // Lenient call validates whatever sigs are present; we've
        // already enforced the strict subset above.
        Self::validate_event(event, current_epoch, Some(&custody))?;

        if is_register {
            let count = self.count_active_validators_for_fid(event.fid)?;
            if count >= MAX_VALIDATORS_PER_FID {
                return Err(RegistryError::PerFidQuotaExceeded {
                    fid: event.fid,
                    count,
                    max: MAX_VALIDATORS_PER_FID,
                });
            }
        }
        Ok(())
    }

    /// Strict validation including the trust gate. Required for production
    /// register paths. Wraps `validate_and_check_quota` and additionally
    /// rejects Register events whose FID's trust score is below
    /// `min_trust_score`. Deregister events bypass the trust gate (a
    /// previously-trusted validator must always be able to leave the set
    /// even if their trust later collapses).
    pub fn validate_register_with_trust(
        &self,
        event: &proto::HyperValidatorEventBody,
        current_epoch: u64,
        custody_resolver: &dyn CustodyResolver,
        trust_resolver: &dyn TrustScoreResolver,
        min_trust_score: f64,
    ) -> Result<(), RegistryError> {
        self.validate_and_check_quota(event, current_epoch, custody_resolver)?;
        if event.event_type == proto::HyperValidatorEventType::Register as i32 {
            let score = trust_resolver
                .trust_score_for_fid(event.fid)
                .map_err(RegistryError::Hub)?
                .unwrap_or(0.0);
            if score < min_trust_score {
                return Err(RegistryError::TrustBelowFloor {
                    fid: event.fid,
                    score,
                    min: min_trust_score,
                });
            }
        }
        Ok(())
    }

    /// Count currently-active validators for `fid` by scanning the
    /// per-FID secondary index. The index is maintained by `record_event`:
    /// Register inserts a marker, Deregister removes it.
    pub fn count_active_validators_for_fid(&self, fid: u64) -> Result<u32, RegistryError> {
        let mut start = Vec::with_capacity(1 + 8);
        start.push(RootPrefix::HyperValidatorByFid as u8);
        start.extend_from_slice(&fid.to_be_bytes());

        // Stop at the next FID's prefix so we don't bleed into other FIDs
        // (or other root prefixes after the FID space ends). For fid =
        // u64::MAX the bound becomes the next root prefix; in practice
        // FIDs are tiny u32-range numbers, so saturating semantics are
        // safe.
        let mut stop = Vec::with_capacity(1 + 8);
        stop.push(RootPrefix::HyperValidatorByFid as u8);
        match fid.checked_add(1) {
            Some(next) => stop.extend_from_slice(&next.to_be_bytes()),
            None => {
                // fid == u64::MAX: stop at the next root prefix.
                stop.clear();
                stop.push((RootPrefix::HyperValidatorByFid as u8).saturating_add(1));
            }
        }

        let mut count: u32 = 0;
        self.db
            .for_each_iterator_by_prefix(
                Some(start),
                Some(stop),
                &PageOptions::default(),
                |_, _| {
                    count = count.saturating_add(1);
                    Ok(false)
                },
            )
            .map_err(HubError::from)?;
        Ok(count)
    }

    /// Persist an event and maintain the per-FID active index.
    ///
    /// On Register: writes the event at `[HyperValidatorEvent][vk][epoch]`,
    /// inserts a presence marker at `[HyperValidatorByFid][fid][vk]`, and
    /// records `[HyperValidatorFidLookup][vk] → fid` so a later Deregister
    /// (which carries the FID itself, but as a sanity-check lookup) can
    /// remove the right marker.
    ///
    /// On Deregister: writes the event, removes the per-FID marker, and
    /// clears the FID lookup. No-op if the marker was never set
    /// (idempotent).
    pub fn record_event(
        &self,
        event: &proto::HyperValidatorEventBody,
    ) -> Result<(), RegistryError> {
        let key = Self::make_event_key(&event.validator_key, event.registration_epoch);
        let value = event.encode_to_vec();
        self.db.put(&key, &value).map_err(HubError::from)?;

        if event.event_type == proto::HyperValidatorEventType::Register as i32 {
            let by_fid = Self::make_validator_by_fid_key(event.fid, &event.validator_key);
            self.db.put(&by_fid, &[]).map_err(HubError::from)?;
            let lookup = Self::make_validator_fid_lookup_key(&event.validator_key);
            self.db
                .put(&lookup, &event.fid.to_be_bytes())
                .map_err(HubError::from)?;
        } else if event.event_type == proto::HyperValidatorEventType::Deregister as i32 {
            // Deregister carries the FID itself (validate_event enforces
            // it). Use it directly to remove the marker; fall back to the
            // lookup index only if needed.
            let fid = if event.fid != 0 {
                event.fid
            } else {
                let lookup = Self::make_validator_fid_lookup_key(&event.validator_key);
                match self.db.get(&lookup).map_err(HubError::from)? {
                    Some(bytes) if bytes.len() == 8 => {
                        let mut be = [0u8; 8];
                        be.copy_from_slice(&bytes);
                        u64::from_be_bytes(be)
                    }
                    _ => 0,
                }
            };
            if fid != 0 {
                let by_fid = Self::make_validator_by_fid_key(fid, &event.validator_key);
                self.db.del(&by_fid).map_err(HubError::from)?;
                let lookup = Self::make_validator_fid_lookup_key(&event.validator_key);
                self.db.del(&lookup).map_err(HubError::from)?;
            }
        }
        Ok(())
    }

    /// Fetch all events from epochs `[0, max_epoch]` for a single validator.
    /// Useful for resolving the latest state of a single validator.
    pub fn events_for_validator(
        &self,
        validator_key: &[u8],
        max_epoch: u64,
    ) -> Result<Vec<proto::HyperValidatorEventBody>, RegistryError> {
        let start = {
            let mut k = Vec::with_capacity(1 + validator_key.len() + 8);
            k.push(RootPrefix::HyperValidatorEvent as u8);
            k.extend_from_slice(validator_key);
            k.extend_from_slice(&0u64.to_be_bytes());
            k
        };
        let stop = {
            let mut k = Vec::with_capacity(1 + validator_key.len() + 8);
            k.push(RootPrefix::HyperValidatorEvent as u8);
            k.extend_from_slice(validator_key);
            // saturating_add handles `max_epoch == u64::MAX`. The
            // overflowed +1 would have been "all events for this
            // validator key" which is the same intent.
            k.extend_from_slice(&max_epoch.saturating_add(1).to_be_bytes());
            // If saturated, push one more byte so the stop key exceeds
            // any possible 8-byte epoch suffix and we cover everything.
            if max_epoch == u64::MAX {
                k.push(0u8);
            }
            k
        };
        let mut out: Vec<proto::HyperValidatorEventBody> = Vec::new();
        let mut decode_err: Option<prost::DecodeError> = None;
        self.db
            .for_each_iterator_by_prefix(
                Some(start),
                Some(stop),
                &PageOptions::default(),
                |_, value| {
                    match proto::HyperValidatorEventBody::decode(value) {
                        Ok(e) => out.push(e),
                        Err(e) => {
                            decode_err = Some(e);
                            return Ok(true);
                        }
                    }
                    Ok(false)
                },
            )
            .map_err(HubError::from)?;
        if let Some(e) = decode_err {
            return Err(RegistryError::Decode(e));
        }
        Ok(out)
    }

    /// Latest `validator_address` registered for `validator_key` up
    /// to and including `max_epoch`, derived from the most recent
    /// register event. Returns `None` if the validator never
    /// registered (or registered with an empty `validator_address`,
    /// which is the pre-migration case).
    ///
    /// During the BLS → DKLS23 migration window this is `None` for
    /// validators registered before Phase 5b lands; once the
    /// validator re-registers post-migration their secp256k1 address
    /// is recorded and surfaceable here. Bridge contracts and
    /// committee-membership consumers go through this API.
    pub fn validator_address_for(
        &self,
        validator_key: &[u8],
        max_epoch: u64,
    ) -> Result<Option<[u8; 20]>, RegistryError> {
        let events = self.events_for_validator(validator_key, max_epoch)?;
        // Walk newest-first to find the most recent register event
        // with a non-empty validator_address.
        for event in events.iter().rev() {
            if event.event_type != proto::HyperValidatorEventType::Register as i32 {
                continue;
            }
            if event.validator_address.len() == 20 {
                let mut out = [0u8; 20];
                out.copy_from_slice(&event.validator_address);
                return Ok(Some(out));
            }
        }
        Ok(None)
    }

    /// Compute the active validator set at `epoch`, applying all events from
    /// epochs `[0, epoch − EPOCH_BUFFER − 1]` to the bootstrap set. Returns
    /// `validator_key → (validator_address, transport_pubkey)` for active
    /// members. The 20-byte secp256k1 `validator_address` replaces the
    /// pre-Phase-6 BLS pubkey in the second tuple slot.
    pub fn compute_active_set(
        &self,
        epoch: u64,
        bootstrap: &[(Vec<u8>, Vec<u8>, Vec<u8>)], // (validator_key, bls_pk, transport_pk)
    ) -> Result<BTreeMap<Vec<u8>, (Vec<u8>, Vec<u8>)>, RegistryError> {
        let mut active: BTreeMap<Vec<u8>, (Vec<u8>, Vec<u8>)> = bootstrap
            .iter()
            .map(|(vk, blspk, tpk)| (vk.clone(), (blspk.clone(), tpk.clone())))
            .collect();

        // Active set at epoch N reflects events from epochs ≤ (N − EPOCH_BUFFER − 1).
        // For EPOCH_BUFFER = 1 this means events from epochs 0..=(N − 2).
        let cutoff = match epoch.checked_sub(EPOCH_BUFFER + 1) {
            Some(c) => c,
            None => return Ok(active),
        };

        // Iterate over all event entries with epoch ≤ cutoff. Walk the prefix
        // [HyperValidatorEvent][...] and parse keys to extract per-event epoch.
        let prefix = vec![RootPrefix::HyperValidatorEvent as u8];

        let mut events: Vec<(u64, proto::HyperValidatorEventBody)> = Vec::new();
        let mut decode_err: Option<prost::DecodeError> = None;
        self.db
            .for_each_iterator_by_prefix(
                Some(prefix),
                None,
                &PageOptions::default(),
                |key, value| {
                    // Key layout: [1B prefix][32B validator_key][8B epoch BE]
                    if key.len() < 1 + 32 + 8 {
                        return Ok(false);
                    }
                    let mut be = [0u8; 8];
                    be.copy_from_slice(&key[1 + 32..1 + 32 + 8]);
                    let event_epoch = u64::from_be_bytes(be);
                    if event_epoch > cutoff {
                        return Ok(false);
                    }
                    match proto::HyperValidatorEventBody::decode(value) {
                        Ok(e) => events.push((event_epoch, e)),
                        Err(e) => {
                            decode_err = Some(e);
                            return Ok(true);
                        }
                    }
                    Ok(false)
                },
            )
            .map_err(HubError::from)?;
        if let Some(e) = decode_err {
            return Err(RegistryError::Decode(e));
        }

        // Apply chronologically.
        events.sort_by_key(|(ep, e)| (*ep, e.validator_key.clone()));

        for (_ep, e) in events {
            if e.event_type == proto::HyperValidatorEventType::Register as i32 {
                active.insert(
                    e.validator_key.clone(),
                    (e.validator_address.clone(), e.transport_pubkey.clone()),
                );
            } else if e.event_type == proto::HyperValidatorEventType::Deregister as i32 {
                active.remove(&e.validator_key);
            }
        }

        Ok(active)
    }

    /// Like `compute_active_set`, but additionally excludes validators
    /// flagged by `is_auto_deregistered` (per FIP §5.3, after
    /// `AUTO_DEREGISTER_CONSECUTIVE_MISSES` consecutive missed
    /// proposals). Bootstrap validators are subject to the same filter —
    /// they're not protected from inactivity-based eviction.
    ///
    /// The predicate is called once per candidate active validator key.
    /// Callers typically pass `|vk| score_tracker.should_auto_deregister(epoch - 1, vk).unwrap_or(false)`.
    pub fn compute_active_set_with_filter<F>(
        &self,
        epoch: u64,
        bootstrap: &[(Vec<u8>, Vec<u8>, Vec<u8>)],
        is_auto_deregistered: F,
    ) -> Result<BTreeMap<Vec<u8>, (Vec<u8>, Vec<u8>)>, RegistryError>
    where
        F: Fn(&[u8]) -> bool,
    {
        let mut active = self.compute_active_set(epoch, bootstrap)?;
        active.retain(|vk, _| !is_auto_deregistered(vk));
        Ok(active)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;
    use rand::RngCore;
    use tempfile::TempDir;

    fn make_registry() -> (ValidatorRegistry, TempDir) {
        let dir = TempDir::new().unwrap();
        let db = RocksDB::new(dir.path().to_str().unwrap());
        db.open().unwrap();
        (ValidatorRegistry::new(Arc::new(db)), dir)
    }

    fn deterministic_signing_key(seed: u8) -> SigningKey {
        let mut bytes = [0u8; 32];
        bytes[0] = seed;
        SigningKey::from_bytes(&bytes)
    }

    fn random_signing_key() -> SigningKey {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        SigningKey::from_bytes(&bytes)
    }

    /// Build a properly Ed25519-signed register event for `validator_idx`.
    /// `fid` defaults to 0 for the legacy lenient-validation tests; tests
    /// of the strict path build their own events with non-zero fid + a
    /// real custody signature.
    fn make_register_event(validator_idx: u8, epoch: u64) -> proto::HyperValidatorEventBody {
        make_register_event_for_fid(validator_idx, epoch, 0)
    }

    fn make_register_event_for_fid(
        validator_idx: u8,
        epoch: u64,
        fid: u64,
    ) -> proto::HyperValidatorEventBody {
        let sk = deterministic_signing_key(validator_idx);
        let pk = sk.verifying_key().to_bytes();
        let mut event = proto::HyperValidatorEventBody {
            event_type: proto::HyperValidatorEventType::Register as i32,
            validator_key: pk.to_vec(),
            transport_pubkey: vec![validator_idx; 32],
            validator_address: vec![validator_idx; 20],
            registration_epoch: epoch,
            operator_address: Vec::new(),
            fid,
            custody_signature: Vec::new(),
            ..Default::default()
        };
        let payload = validator_event_signing_payload(&event);
        let sig = sk.sign(&payload);
        event.signature = sig.to_bytes().to_vec();
        event
    }

    fn make_deregister_event(validator_idx: u8, epoch: u64) -> proto::HyperValidatorEventBody {
        let sk = deterministic_signing_key(validator_idx);
        let pk = sk.verifying_key().to_bytes();
        let mut event = proto::HyperValidatorEventBody {
            event_type: proto::HyperValidatorEventType::Deregister as i32,
            validator_key: pk.to_vec(),
            transport_pubkey: Vec::new(),
            registration_epoch: epoch,
            operator_address: Vec::new(),
            fid: 0,
            custody_signature: Vec::new(),
            ..Default::default()
        };
        let payload = validator_event_signing_payload(&event);
        let sig = sk.sign(&payload);
        event.signature = sig.to_bytes().to_vec();
        event
    }

    fn validator_pk_for(idx: u8) -> Vec<u8> {
        deterministic_signing_key(idx)
            .verifying_key()
            .to_bytes()
            .to_vec()
    }

    #[test]
    fn validate_accepts_register_event() {
        let e = make_register_event(1, 5);
        assert!(ValidatorRegistry::validate_event(&e, 5, None).is_ok());
    }

    #[test]
    fn validate_rejects_none_event_type() {
        let mut e = make_register_event(1, 5);
        e.event_type = proto::HyperValidatorEventType::None as i32;
        assert!(matches!(
            ValidatorRegistry::validate_event(&e, 5, None),
            Err(RegistryError::NoneEventType)
        ));
    }

    #[test]
    fn validate_rejects_wrong_epoch() {
        let e = make_register_event(1, 4);
        assert!(matches!(
            ValidatorRegistry::validate_event(&e, 5, None),
            Err(RegistryError::EpochMismatch {
                event: 4,
                current: 5
            })
        ));
    }

    #[test]
    fn validate_rejects_short_validator_key() {
        let mut e = make_register_event(1, 5);
        e.validator_key = vec![0u8; 16];
        assert!(matches!(
            ValidatorRegistry::validate_event(&e, 5, None),
            Err(RegistryError::BadValidatorKey)
        ));
    }

    #[test]
    fn validate_rejects_register_without_validator_address() {
        let mut e = make_register_event(1, 5);
        e.validator_address = Vec::new();
        // Re-sign so the Ed25519 sig matches the (address-empty) payload;
        // otherwise we'd hit InvalidSignature first.
        let sk = deterministic_signing_key(1);
        let payload = validator_event_signing_payload(&e);
        e.signature = sk.sign(&payload).to_bytes().to_vec();
        assert!(matches!(
            ValidatorRegistry::validate_event(&e, 5, None),
            Err(RegistryError::BadValidatorAddress)
        ));
    }

    #[test]
    fn record_then_lookup_for_validator() {
        let (reg, _dir) = make_registry();
        let e = make_register_event(7, 3);
        reg.record_event(&e).unwrap();
        let events = reg.events_for_validator(&e.validator_key, 10).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].validator_key, e.validator_key);
    }

    #[test]
    fn validator_address_lookup_returns_latest_register_value() {
        // A register event with validator_address populated lands
        // in the lookup; the most recent register event with a
        // 20-byte validator_address wins.
        let (reg, _dir) = make_registry();
        let sk = deterministic_signing_key(11);
        let pk = sk.verifying_key().to_bytes();
        let addr_a = [0xaau8; 20];
        let addr_b = [0xbbu8; 20];

        let mut event_a = proto::HyperValidatorEventBody {
            event_type: proto::HyperValidatorEventType::Register as i32,
            validator_key: pk.to_vec(),
            transport_pubkey: vec![11u8; 32],
            registration_epoch: 1,
            operator_address: Vec::new(),
            fid: 0,
            custody_signature: Vec::new(),
            validator_address: addr_a.to_vec(),
            ..Default::default()
        };
        let payload_a = validator_event_signing_payload(&event_a);
        event_a.signature = sk.sign(&payload_a).to_bytes().to_vec();
        reg.record_event(&event_a).unwrap();
        // Lookup at epoch 1 returns addr_a.
        assert_eq!(reg.validator_address_for(&pk, 10).unwrap(), Some(addr_a));

        // A re-registration at a later epoch with a different
        // validator_address replaces the lookup result.
        let mut event_b = proto::HyperValidatorEventBody {
            event_type: proto::HyperValidatorEventType::Register as i32,
            validator_key: pk.to_vec(),
            transport_pubkey: vec![11u8; 32],
            registration_epoch: 5,
            operator_address: Vec::new(),
            fid: 0,
            custody_signature: Vec::new(),
            validator_address: addr_b.to_vec(),
            ..Default::default()
        };
        let payload_b = validator_event_signing_payload(&event_b);
        event_b.signature = sk.sign(&payload_b).to_bytes().to_vec();
        reg.record_event(&event_b).unwrap();
        assert_eq!(reg.validator_address_for(&pk, 10).unwrap(), Some(addr_b));
        // Bounded lookup at max_epoch=4 sees only addr_a.
        assert_eq!(reg.validator_address_for(&pk, 4).unwrap(), Some(addr_a));
    }

    #[test]
    fn validator_address_lookup_returns_none_for_unknown_validator() {
        let (reg, _dir) = make_registry();
        assert_eq!(reg.validator_address_for(&[0u8; 32], 10).unwrap(), None);
    }

    #[test]
    fn signing_payload_changes_when_validator_address_set() {
        // Pin the v3 DST + validator_address binding: two events
        // differing only in validator_address produce distinct
        // signing payloads (and therefore distinct Ed25519 sigs).
        let mut a = make_register_event(17, 0);
        let mut b = a.clone();
        a.validator_address = vec![0u8; 20];
        b.validator_address = vec![0xff; 20];
        let payload_a = validator_event_signing_payload(&a);
        let payload_b = validator_event_signing_payload(&b);
        assert_ne!(payload_a, payload_b);
    }

    #[test]
    fn active_set_is_bootstrap_before_buffer() {
        let (reg, _dir) = make_registry();
        let bootstrap = vec![(vec![1u8; 32], vec![1u8; 48], vec![1u8; 32])];

        // Register validator 2 at epoch 0. With EPOCH_BUFFER = 1, this becomes
        // active at epoch 2. At epoch 0 and 1 the active set is just bootstrap.
        let e = make_register_event(2, 0);
        reg.record_event(&e).unwrap();

        let active_at_0 = reg.compute_active_set(0, &bootstrap).unwrap();
        assert_eq!(active_at_0.len(), 1);
        assert!(active_at_0.contains_key(&vec![1u8; 32]));

        let active_at_1 = reg.compute_active_set(1, &bootstrap).unwrap();
        assert_eq!(active_at_1.len(), 1);
    }

    #[test]
    fn active_set_includes_registration_after_buffer() {
        let (reg, _dir) = make_registry();
        let bootstrap = vec![(vec![1u8; 32], vec![1u8; 48], vec![1u8; 32])];

        reg.record_event(&make_register_event(2, 0)).unwrap();
        // At epoch 2, events from epoch ≤ 0 take effect.
        let active = reg.compute_active_set(2, &bootstrap).unwrap();
        assert_eq!(active.len(), 2);
        assert!(active.contains_key(&validator_pk_for(2)));
    }

    #[test]
    fn deregister_removes_validator() {
        let (reg, _dir) = make_registry();
        let bootstrap = vec![(vec![1u8; 32], vec![1u8; 48], vec![1u8; 32])];

        reg.record_event(&make_register_event(2, 0)).unwrap();
        reg.record_event(&make_deregister_event(2, 1)).unwrap();
        // At epoch 2: events from epoch ≤ 0 are effective → registered at epoch 0.
        let active_at_2 = reg.compute_active_set(2, &bootstrap).unwrap();
        assert!(active_at_2.contains_key(&validator_pk_for(2)));

        // At epoch 3: events from epoch ≤ 1 are effective → registered at 0, deregistered at 1.
        let active_at_3 = reg.compute_active_set(3, &bootstrap).unwrap();
        assert!(!active_at_3.contains_key(&validator_pk_for(2)));
    }

    #[test]
    fn validate_rejects_invalid_signature() {
        let mut e = make_register_event(1, 5);
        // Flip one byte of the signature.
        e.signature[0] ^= 0xff;
        assert!(matches!(
            ValidatorRegistry::validate_event(&e, 5, None),
            Err(RegistryError::InvalidSignature)
        ));
    }

    #[test]
    fn validate_rejects_signature_under_wrong_key() {
        // Sign with key A but claim ownership of key B.
        let mut e = make_register_event(1, 5);
        let other_pk = random_signing_key().verifying_key().to_bytes().to_vec();
        e.validator_key = other_pk;
        // The signature was over the previous payload (with the original key);
        // changing validator_key changes the payload AND the verification key,
        // so verification should fail.
        assert!(matches!(
            ValidatorRegistry::validate_event(&e, 5, None),
            Err(RegistryError::InvalidSignature)
        ));
    }

    #[test]
    fn validate_rejects_tampered_validator_address() {
        // Tamper with the validator_address after signing — payload
        // changes, sig fails.
        let mut e = make_register_event(1, 5);
        if e.validator_address.is_empty() {
            e.validator_address = vec![0u8; 20];
        }
        e.validator_address[0] ^= 0xff;
        assert!(matches!(
            ValidatorRegistry::validate_event(&e, 5, None),
            Err(RegistryError::InvalidSignature)
        ));
    }

    #[test]
    fn validate_rejects_short_signature() {
        let mut e = make_register_event(1, 5);
        e.signature.truncate(32);
        assert!(matches!(
            ValidatorRegistry::validate_event(&e, 5, None),
            Err(RegistryError::BadSignatureLength)
        ));
    }

    #[test]
    fn signing_payload_changes_with_any_field() {
        let e1 = make_register_event(1, 5);
        let mut e2 = e1.clone();
        e2.transport_pubkey[0] ^= 0x01;
        assert_ne!(
            validator_event_signing_payload(&e1),
            validator_event_signing_payload(&e2)
        );

        let mut e3 = e1.clone();
        e3.registration_epoch = 6;
        assert_ne!(
            validator_event_signing_payload(&e1),
            validator_event_signing_payload(&e3)
        );
    }

    #[test]
    fn filtered_active_set_evicts_auto_deregistered_validators() {
        let (reg, _dir) = make_registry();
        let bootstrap = vec![
            (vec![1u8; 32], vec![1u8; 48], vec![1u8; 32]),
            (vec![2u8; 32], vec![2u8; 48], vec![2u8; 32]),
            (vec![3u8; 32], vec![3u8; 48], vec![3u8; 32]),
        ];

        // Predicate marks validator 2 as auto-deregistered.
        let active = reg
            .compute_active_set_with_filter(0, &bootstrap, |vk| vk == &[2u8; 32])
            .unwrap();
        assert_eq!(active.len(), 2);
        assert!(active.contains_key(&vec![1u8; 32]));
        assert!(active.contains_key(&vec![3u8; 32]));
        assert!(!active.contains_key(&vec![2u8; 32]));
    }

    #[test]
    fn filtered_active_set_with_no_evictions_matches_unfiltered() {
        let (reg, _dir) = make_registry();
        let bootstrap = vec![
            (vec![1u8; 32], vec![1u8; 48], vec![1u8; 32]),
            (vec![2u8; 32], vec![2u8; 48], vec![2u8; 32]),
        ];
        let unfiltered = reg.compute_active_set(0, &bootstrap).unwrap();
        let filtered = reg
            .compute_active_set_with_filter(0, &bootstrap, |_| false)
            .unwrap();
        assert_eq!(unfiltered, filtered);
    }

    #[test]
    fn registrations_apply_in_chronological_order() {
        let (reg, _dir) = make_registry();
        let bootstrap: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> = Vec::new();

        // Register/deregister/re-register pattern across epochs.
        reg.record_event(&make_register_event(2, 0)).unwrap();
        reg.record_event(&make_deregister_event(2, 1)).unwrap();
        reg.record_event(&make_register_event(2, 2)).unwrap();

        // At epoch 4: events from ≤ 2 effective → register, deregister, register
        // → final state: registered with the most recent BLS key.
        let active = reg.compute_active_set(4, &bootstrap).unwrap();
        assert!(active.contains_key(&validator_pk_for(2)));
    }

    // ----- Cross-sign + per-FID quota (Phase A) ----------------------------

    use alloy_signer::SignerSync;
    use alloy_signer_local::PrivateKeySigner;

    /// Build a fully cross-signed register event: Ed25519 sig from the
    /// validator's identity key + EIP-712 sig from the FID's custody key.
    fn make_cross_signed_register(
        validator_idx: u8,
        epoch: u64,
        fid: u64,
        custody_signer: &PrivateKeySigner,
    ) -> proto::HyperValidatorEventBody {
        use alloy_dyn_abi::TypedData;

        let sk = deterministic_signing_key(validator_idx);
        let pk = sk.verifying_key().to_bytes();
        let mut event = proto::HyperValidatorEventBody {
            event_type: proto::HyperValidatorEventType::Register as i32,
            validator_key: pk.to_vec(),
            transport_pubkey: vec![validator_idx; 32],
            validator_address: vec![validator_idx; 20],
            registration_epoch: epoch,
            operator_address: Vec::new(),
            fid,
            custody_signature: Vec::new(),
            ..Default::default()
        };

        let payload = validator_event_signing_payload(&event);
        event.signature = sk.sign(&payload).to_bytes().to_vec();

        let json = validator_authorization_typed_data(&event);
        let typed: TypedData = serde_json::from_value(json).unwrap();
        let prehash = typed.eip712_signing_hash().unwrap();
        let sig = custody_signer.sign_hash_sync(&prehash).unwrap();
        event.custody_signature = sig.as_bytes().to_vec();
        event
    }

    /// In-memory `CustodyResolver` for tests.
    struct StaticCustodyResolver(BTreeMap<u64, [u8; 20]>);
    impl CustodyResolver for StaticCustodyResolver {
        fn custody_address_for_fid(&self, fid: u64) -> Result<Option<[u8; 20]>, HubError> {
            Ok(self.0.get(&fid).copied())
        }
    }

    #[test]
    fn cross_signed_register_passes_strict_validation() {
        let (reg, _dir) = make_registry();
        let custody = PrivateKeySigner::random();
        let custody_addr: [u8; 20] = custody.address().into();
        let mut resolver_map = BTreeMap::new();
        resolver_map.insert(42u64, custody_addr);
        let resolver = StaticCustodyResolver(resolver_map);

        let event = make_cross_signed_register(1, 5, 42, &custody);

        // Strict path: passes.
        reg.validate_and_check_quota(&event, 5, &resolver).unwrap();

        // Lenient path also passes when the custody address is supplied.
        ValidatorRegistry::validate_event(&event, 5, Some(&custody_addr)).unwrap();
    }

    #[test]
    fn register_with_wrong_custody_address_rejected() {
        let custody = PrivateKeySigner::random();
        let wrong: [u8; 20] = PrivateKeySigner::random().address().into();
        let event = make_cross_signed_register(1, 5, 42, &custody);
        let result = ValidatorRegistry::validate_event(&event, 5, Some(&wrong));
        assert!(matches!(
            result,
            Err(RegistryError::InvalidCustodySignature)
        ));
    }

    #[test]
    fn register_without_custody_signature_strict_rejected() {
        let (reg, _dir) = make_registry();
        let custody = PrivateKeySigner::random();
        let custody_addr: [u8; 20] = custody.address().into();
        let mut resolver_map = BTreeMap::new();
        resolver_map.insert(42u64, custody_addr);
        let resolver = StaticCustodyResolver(resolver_map);

        // Build a register event with valid Ed25519 sig but EMPTY custody sig.
        let mut event = make_register_event_for_fid(1, 5, 42);
        event.custody_signature = Vec::new();

        let result = reg.validate_and_check_quota(&event, 5, &resolver);
        assert!(matches!(
            result,
            Err(RegistryError::MissingCustodySignature)
        ));
    }

    #[test]
    fn register_with_unknown_fid_strict_rejected() {
        let (reg, _dir) = make_registry();
        let custody = PrivateKeySigner::random();
        let resolver = StaticCustodyResolver(BTreeMap::new()); // empty: no FID known

        let event = make_cross_signed_register(1, 5, 42, &custody);
        let result = reg.validate_and_check_quota(&event, 5, &resolver);
        assert!(matches!(
            result,
            Err(RegistryError::CustodyAddressUnknown { fid: 42 })
        ));
    }

    #[test]
    fn register_with_zero_fid_strict_rejected() {
        let (reg, _dir) = make_registry();
        let resolver = StaticCustodyResolver(BTreeMap::new());
        let custody = PrivateKeySigner::random();
        let event = make_cross_signed_register(1, 5, 0, &custody);
        let result = reg.validate_and_check_quota(&event, 5, &resolver);
        assert!(matches!(result, Err(RegistryError::MissingFid)));
    }

    #[test]
    fn per_fid_quota_blocks_fourth_register() {
        let (reg, _dir) = make_registry();
        let custody = PrivateKeySigner::random();
        let custody_addr: [u8; 20] = custody.address().into();
        let mut map = BTreeMap::new();
        map.insert(99u64, custody_addr);
        let resolver = StaticCustodyResolver(map);

        // Three successful registrations under fid=99.
        for idx in 1u8..=3 {
            let e = make_cross_signed_register(idx, 5, 99, &custody);
            reg.validate_and_check_quota(&e, 5, &resolver).unwrap();
            reg.record_event(&e).unwrap();
        }
        assert_eq!(reg.count_active_validators_for_fid(99).unwrap(), 3);

        // Fourth must fail.
        let e4 = make_cross_signed_register(4, 5, 99, &custody);
        let r = reg.validate_and_check_quota(&e4, 5, &resolver);
        assert!(matches!(
            r,
            Err(RegistryError::PerFidQuotaExceeded {
                fid: 99,
                count: 3,
                max: MAX_VALIDATORS_PER_FID
            })
        ));
    }

    #[test]
    fn deregister_releases_quota_slot() {
        let (reg, _dir) = make_registry();
        let custody = PrivateKeySigner::random();
        let custody_addr: [u8; 20] = custody.address().into();
        let mut map = BTreeMap::new();
        map.insert(99u64, custody_addr);
        let resolver = StaticCustodyResolver(map);

        // Register 3, deregister 1.
        for idx in 1u8..=3 {
            let e = make_cross_signed_register(idx, 5, 99, &custody);
            reg.record_event(&e).unwrap();
        }
        let mut dereg = make_deregister_event(2, 6);
        dereg.fid = 99;
        // Re-sign with the new fid (signing payload includes fid).
        let sk = deterministic_signing_key(2);
        let payload = validator_event_signing_payload(&dereg);
        dereg.signature = sk.sign(&payload).to_bytes().to_vec();
        reg.record_event(&dereg).unwrap();

        assert_eq!(reg.count_active_validators_for_fid(99).unwrap(), 2);

        // A 3rd active slot can register again.
        let e_new = make_cross_signed_register(4, 7, 99, &custody);
        let resolver_e7 = StaticCustodyResolver({
            let mut m = BTreeMap::new();
            m.insert(99u64, custody_addr);
            m
        });
        reg.validate_and_check_quota(&e_new, 7, &resolver_e7)
            .unwrap();
    }

    /// In-memory `TrustScoreResolver` for tests.
    struct StaticTrustResolver(BTreeMap<u64, f64>);
    impl TrustScoreResolver for StaticTrustResolver {
        fn trust_score_for_fid(&self, fid: u64) -> Result<Option<f64>, HubError> {
            Ok(self.0.get(&fid).copied())
        }
    }

    #[test]
    fn trust_gate_blocks_register_below_floor() {
        let (reg, _dir) = make_registry();
        let custody = PrivateKeySigner::random();
        let custody_addr: [u8; 20] = custody.address().into();
        let mut cmap = BTreeMap::new();
        cmap.insert(99u64, custody_addr);
        let custody_resolver = StaticCustodyResolver(cmap);

        let mut tmap = BTreeMap::new();
        tmap.insert(99u64, 0.02); // below 0.05 floor
        let trust_resolver = StaticTrustResolver(tmap);

        let event = make_cross_signed_register(1, 5, 99, &custody);
        let r =
            reg.validate_register_with_trust(&event, 5, &custody_resolver, &trust_resolver, 0.05);
        assert!(matches!(
            r,
            Err(RegistryError::TrustBelowFloor { fid: 99, .. })
        ));
    }

    #[test]
    fn trust_gate_admits_register_above_floor() {
        let (reg, _dir) = make_registry();
        let custody = PrivateKeySigner::random();
        let custody_addr: [u8; 20] = custody.address().into();
        let mut cmap = BTreeMap::new();
        cmap.insert(99u64, custody_addr);
        let custody_resolver = StaticCustodyResolver(cmap);

        let mut tmap = BTreeMap::new();
        tmap.insert(99u64, 0.5); // well above 0.05 floor
        let trust_resolver = StaticTrustResolver(tmap);

        let event = make_cross_signed_register(1, 5, 99, &custody);
        reg.validate_register_with_trust(&event, 5, &custody_resolver, &trust_resolver, 0.05)
            .unwrap();
    }

    #[test]
    fn trust_gate_treats_missing_score_as_zero() {
        let (reg, _dir) = make_registry();
        let custody = PrivateKeySigner::random();
        let custody_addr: [u8; 20] = custody.address().into();
        let mut cmap = BTreeMap::new();
        cmap.insert(99u64, custody_addr);
        let custody_resolver = StaticCustodyResolver(cmap);

        // Empty trust resolver — FID has no recorded score.
        let trust_resolver = StaticTrustResolver(BTreeMap::new());

        let event = make_cross_signed_register(1, 5, 99, &custody);
        let r =
            reg.validate_register_with_trust(&event, 5, &custody_resolver, &trust_resolver, 0.05);
        assert!(matches!(
            r,
            Err(RegistryError::TrustBelowFloor { fid: 99, score, .. }) if score == 0.0
        ));
    }

    #[test]
    fn signing_payload_binds_fid_to_signature() {
        // Same validator + epoch but different fid → different signing
        // payload → original sig won't verify if you swap the fid.
        let custody = PrivateKeySigner::random();
        let mut e = make_cross_signed_register(1, 5, 100, &custody);
        // Tamper: swap fid without re-signing.
        e.fid = 200;
        let r = ValidatorRegistry::validate_event(&e, 5, None);
        assert!(matches!(r, Err(RegistryError::InvalidSignature)));
    }
}
