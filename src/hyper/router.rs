//! Message routing between the hyper gossip topic and protocol handlers.
//!
//! This module is transport-agnostic: it consumes already-deserialized
//! `proto::HyperMessage` values and dispatches them to the right handler
//! (mempool, validator registry, etc.). The gossip transport that calls in
//! is responsible for the wire-level deserialization and authenticity.
//!
//! Two responsibilities:
//!  1. **Inbound dispatch**: `route_inbound(&mut self, msg)` decodes the
//!     `oneof body`, runs validation, and inserts into the appropriate
//!     pending-state structure (mempool for tokens, validator registry for
//!     identity events).
//!  2. **Outbound assembly**: `outbound_lock(event)` / `outbound_transfer(tx)` /
//!     `outbound_register(event)` wrap a typed message into the canonical
//!     `proto::HyperMessage` envelope ready for serialization.

use crate::hyper::mempool::{HyperMempool, MempoolError};
use crate::hyper::validator_registry::{RegistryError, ValidatorRegistry};
use crate::proto;

#[derive(thiserror::Error, Debug)]
pub enum RoutingError {
    #[error("missing message body")]
    MissingBody,
    #[error("mempool rejected message: {0}")]
    Mempool(#[from] MempoolError),
    #[error("validator registry rejected message: {0}")]
    Registry(#[from] RegistryError),
    #[error("validator event for unsupported type: {0}")]
    UnsupportedValidatorEventType(i32),
    #[error("unsupported message type: {0}")]
    UnsupportedMessageType(i32),
    #[error("reward issuance rejected: {0}")]
    RewardIssuance(String),
    #[error("trust snapshot update rejected: {0}")]
    TrustSnapshotUpdate(String),
    #[error("token transfer rejected: {0}")]
    TokenTransfer(String),
    #[error("fee deposit rejected: {0}")]
    FeeDeposit(String),
    #[error("confidential transfer rejected: {0}")]
    Transfer(String),
    #[error("token lock rejected: {0}")]
    TokenLock(String),
    #[error("lock merkle root update rejected: {0}")]
    LockMerkleRootUpdate(String),
    #[error("owner rotation rejected: {0}")]
    OwnerRotation(String),
    #[error("inbound burn rejected: {0}")]
    InboundBurn(String),
    #[error("token escrow claim rejected: {0}")]
    TokenEscrowClaim(String),
    #[error("token escrow bridge rejected: {0}")]
    TokenEscrowBridge(String),
    #[error("token stake rejected: {0}")]
    TokenStake(String),
    #[error("token unstake rejected: {0}")]
    TokenUnstake(String),
    #[error("node attestation rejected: {0}")]
    NodeAttestation(String),
    #[error("node attestation revoke rejected: {0}")]
    NodeAttestationRevoke(String),
    #[error("app usage receipt rejected: {0}")]
    AppUsageReceipt(String),
    #[error("miniapp register rejected: {0}")]
    MiniappRegister(String),
    #[error("miniapp unregister rejected: {0}")]
    MiniappUnregister(String),
    #[error("miniapp update rejected: {0}")]
    MiniappUpdate(String),
    #[error("miniapp add rejected: {0}")]
    MiniappAdd(String),
    #[error("miniapp remove rejected: {0}")]
    MiniappRemove(String),
    #[error("DA challenge response rejected: {0}")]
    DaChallengeResponse(String),
    #[error("DA epoch seed rejected: {0}")]
    DaEpochSeed(String),
    #[error(
        "validator-trust below floor for fid {fid}: have {available:.4}, need {needed:.4} ({reason})"
    )]
    ValidatorTrustBelowFloor {
        fid: u64,
        available: f64,
        needed: f64,
        reason: String,
    },
}

pub struct HyperRouter {
    pub mempool: HyperMempool,
    pub registry: Option<ValidatorRegistry>,
    pub current_epoch: u64,
    /// Optional custody resolver — when present, the router runs strict
    /// cross-sign + per-FID-quota validation on inbound validator events.
    /// Production runtimes attach this via `with_custody_resolver`.
    pub custody_resolver:
        Option<std::sync::Arc<dyn crate::hyper::validator_registry::CustodyResolver>>,
}

impl HyperRouter {
    pub fn new(mempool: HyperMempool, registry: Option<ValidatorRegistry>, epoch: u64) -> Self {
        Self {
            mempool,
            registry,
            current_epoch: epoch,
            custody_resolver: None,
        }
    }

    pub fn with_custody_resolver(
        mut self,
        resolver: std::sync::Arc<dyn crate::hyper::validator_registry::CustodyResolver>,
    ) -> Self {
        self.custody_resolver = Some(resolver);
        self
    }

    pub fn set_epoch(&mut self, epoch: u64) {
        self.current_epoch = epoch;
    }

    /// Dispatch a deserialized hyper message to its handler. Returns Ok if the
    /// message was accepted into pending state, or an error describing why
    /// it was rejected. Validation errors do not propagate as transport errors —
    /// the caller may log and continue.
    pub fn route_inbound(&mut self, msg: proto::HyperMessage) -> Result<(), RoutingError> {
        match msg.body.ok_or(RoutingError::MissingBody)? {
            proto::hyper_message::Body::Lock(event) => {
                self.mempool.submit_lock(event)?;
                Ok(())
            }
            proto::hyper_message::Body::Transfer(_) => {
                // Confidential transfers must be admitted through
                // `HyperRuntime::submit_message` so the strong
                // validators (`validate_against_store` +
                // `verify_balance_with_blinding_diff`) can run
                // against the runtime's note store and the
                // wire-supplied blinding-difference scalar. The
                // router alone can only run the structural stub —
                // refuse here so a misuse can't bypass the gate.
                Err(RoutingError::Transfer(
                    "must route through HyperRuntime::submit_message for strong validation"
                        .to_string(),
                ))
            }
            proto::hyper_message::Body::ValidatorEvent(event) => {
                let registry = self
                    .registry
                    .as_ref()
                    .ok_or_else(|| RoutingError::UnsupportedValidatorEventType(event.event_type))?;
                // Strict path when a custody resolver is wired; lenient
                // otherwise (tests + migration). Production runtimes
                // attach a resolver via `with_custody_resolver`.
                match self.custody_resolver.as_deref() {
                    Some(r) => registry.validate_and_check_quota(&event, self.current_epoch, r)?,
                    None => ValidatorRegistry::validate_event(&event, self.current_epoch, None)?,
                }
                registry.record_event(&event)?;
                Ok(())
            }
            proto::hyper_message::Body::RewardIssuance(_) => {
                // RewardIssuance must be handled by the runtime (it
                // needs access to epoch_resolver + reward_store). The
                // router signals "wrong place" so the caller knows to
                // dispatch it elsewhere; in practice
                // HyperRuntime::submit_message intercepts this body
                // before delegating to the router, so this branch is
                // only ever taken if a caller bypasses the runtime.
                Err(RoutingError::UnsupportedMessageType(
                    proto::HyperMessageType::RewardIssuance as i32,
                ))
            }
            proto::hyper_message::Body::TrustSnapshotUpdate(_) => {
                // Trust snapshot updates need the runtime's epoch_resolver
                // and trust_store. Same dispatch pattern as RewardIssuance:
                // HyperRuntime::submit_message intercepts before delegating
                // to the router.
                Err(RoutingError::UnsupportedMessageType(
                    proto::HyperMessageType::TrustSnapshotUpdate as i32,
                ))
            }
            proto::hyper_message::Body::TokenTransfer(_) => {
                // Transparent FID-keyed token transfers need
                // `HyperRuntime::balance_store` + `nonce_store` to
                // validate and apply. `HyperRuntime::submit_message`
                // intercepts this body before delegating to the router,
                // mirroring the RewardIssuance / TrustSnapshotUpdate
                // dispatch pattern.
                Err(RoutingError::UnsupportedMessageType(
                    proto::HyperMessageType::TokenTransfer as i32,
                ))
            }
            proto::hyper_message::Body::TokenLock(_) => {
                // Transparent FID-keyed token locks (FIP §13.5) need
                // the runtime's balance + lock stores. Same intercept
                // pattern as TokenTransfer.
                Err(RoutingError::UnsupportedMessageType(
                    proto::HyperMessageType::TokenLock as i32,
                ))
            }
            proto::hyper_message::Body::LockMerkleRootUpdate(_) => {
                // FIP §13.5/§13.4 signed merkle-root update —
                // verifies + persists in the runtime, not the
                // router. Same intercept pattern as RewardIssuance.
                Err(RoutingError::UnsupportedMessageType(
                    proto::HyperMessageType::LockMerkleRootUpdate as i32,
                ))
            }
            proto::hyper_message::Body::OwnerRotation(_) => {
                // FIP §13.5 bridge owner-rotation — verifies + persists
                // in the runtime. Same intercept pattern.
                Err(RoutingError::UnsupportedMessageType(
                    proto::HyperMessageType::OwnerRotation as i32,
                ))
            }
            proto::hyper_message::Body::InboundBurn(_) => {
                // FIP §13.6 inbound burn — verifies + credits in the
                // runtime. Same intercept pattern.
                Err(RoutingError::UnsupportedMessageType(
                    proto::HyperMessageType::InboundBurn as i32,
                ))
            }
            proto::hyper_message::Body::TokenEscrowClaim(_) => {
                // FIP §13.9 escrow claim — verifies EIP-712 + debits
                // escrow + credits destination FID. Runtime intercepts.
                Err(RoutingError::UnsupportedMessageType(
                    proto::HyperMessageType::TokenEscrowClaim as i32,
                ))
            }
            proto::hyper_message::Body::TokenEscrowBridge(_) => {
                // FIP §13.9 escrow bridge — verifies EIP-712, debits
                // escrow, creates outbound bridge lock state.
                // Runtime intercepts.
                Err(RoutingError::UnsupportedMessageType(
                    proto::HyperMessageType::TokenEscrowBridge as i32,
                ))
            }
            proto::hyper_message::Body::TokenStake(_) => {
                // FIP §12 stake — runtime intercepts.
                Err(RoutingError::UnsupportedMessageType(
                    proto::HyperMessageType::TokenStake as i32,
                ))
            }
            proto::hyper_message::Body::TokenUnstake(_) => {
                // FIP §12 unstake — runtime intercepts.
                Err(RoutingError::UnsupportedMessageType(
                    proto::HyperMessageType::TokenUnstake as i32,
                ))
            }
            proto::hyper_message::Body::NodeAttestation(_) => {
                // FIP §3 node-FID attestation (both attest and
                // revoke share this body). Runtime intercepts —
                // needs DB access for cap + uniqueness checks.
                Err(RoutingError::UnsupportedMessageType(
                    proto::HyperMessageType::NodeAttestation as i32,
                ))
            }
            proto::hyper_message::Body::AppUsageReceipt(_) => {
                // FIP §7 App-PoW signed receipt. Runtime intercepts
                // — needs DB access for rate-limit count + epoch
                // resolution.
                Err(RoutingError::UnsupportedMessageType(
                    proto::HyperMessageType::AppUsageReceipt as i32,
                ))
            }
            proto::hyper_message::Body::MiniappRegister(_) => {
                // FIP-native-miniapp-index: runtime intercepts to
                // verify account-association proof and write
                // miniapp state.
                Err(RoutingError::UnsupportedMessageType(
                    proto::HyperMessageType::MiniappRegister as i32,
                ))
            }
            proto::hyper_message::Body::MiniappUnregister(_) => {
                Err(RoutingError::UnsupportedMessageType(
                    proto::HyperMessageType::MiniappUnregister as i32,
                ))
            }
            proto::hyper_message::Body::MiniappUpdate(_) => Err(
                RoutingError::UnsupportedMessageType(proto::HyperMessageType::MiniappUpdate as i32),
            ),
            proto::hyper_message::Body::MiniappAdd(_) => Err(RoutingError::UnsupportedMessageType(
                proto::HyperMessageType::MiniappAdd as i32,
            )),
            proto::hyper_message::Body::MiniappRemove(_) => Err(
                RoutingError::UnsupportedMessageType(proto::HyperMessageType::MiniappRemove as i32),
            ),
            proto::hyper_message::Body::DaChallengeResponse(_) => {
                Err(RoutingError::UnsupportedMessageType(
                    proto::HyperMessageType::DaChallengeResponse as i32,
                ))
            }
            proto::hyper_message::Body::DaEpochSeed(_) => Err(
                RoutingError::UnsupportedMessageType(proto::HyperMessageType::DaEpochSeed as i32),
            ),
            proto::hyper_message::Body::FeeDeposit(_) => Err(
                // FIP-proof-of-quality §5 fee deposit — runtime intercepts
                // (needs RewardStore + signer-set check).
                RoutingError::UnsupportedMessageType(proto::HyperMessageType::FeeDeposit as i32),
            ),
        }
    }

    pub fn outbound_lock(event: proto::HyperLockEvent) -> proto::HyperMessage {
        proto::HyperMessage {
            message_type: proto::HyperMessageType::Lock as i32,
            body: Some(proto::hyper_message::Body::Lock(event)),
        }
    }

    pub fn outbound_transfer(tx: proto::HyperTransferTx) -> proto::HyperMessage {
        proto::HyperMessage {
            message_type: proto::HyperMessageType::Transfer as i32,
            body: Some(proto::hyper_message::Body::Transfer(tx)),
        }
    }

    pub fn outbound_validator_register(
        event: proto::HyperValidatorEventBody,
    ) -> proto::HyperMessage {
        let mt = match event.event_type {
            x if x == proto::HyperValidatorEventType::Register as i32 => {
                proto::HyperMessageType::ValidatorRegister
            }
            x if x == proto::HyperValidatorEventType::Deregister as i32 => {
                proto::HyperMessageType::ValidatorDeregister
            }
            _ => proto::HyperMessageType::None,
        };
        proto::HyperMessage {
            message_type: mt as i32,
            body: Some(proto::hyper_message::Body::ValidatorEvent(event)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hyper::transfer_codec::tx_to_proto;
    use hypersnap_crypto::bulletproofs::curve_adapter::Scalar;
    use hypersnap_crypto::tokens::{
        prove_value_range, schnorr_sign, Nullifier as Nf, PedersenCommitment as PC,
        SchnorrSignature, TransferInput, TransferOutput, TransferTx, DEFAULT_RANGE_BITS,
    };
    use prost::Message;
    use rand::rngs::OsRng;

    fn sample_lock(byte: u8) -> proto::HyperLockEvent {
        proto::HyperLockEvent {
            amount: 1_000_000,
            dest_chain_id: 1,
            dest_address: vec![0xab; 20],
            spend_pubkey: vec![0x02; 33],
            lock_id: vec![byte; 32],
            lock_height: 100,
            lock_timestamp: 1_700_000_000,
            lock_signature: vec![0u8; 64],
        }
    }

    fn sample_transfer(seed: u8) -> proto::HyperTransferTx {
        let mut rng = OsRng;
        let r_in = Scalar::random(&mut rng);
        let r_out = Scalar::random(&mut rng);
        let mut x_bytes = [0u8; 56];
        x_bytes[0] = seed;
        let x = Scalar::from_bytes_mod_order(x_bytes);

        let in_commitment = PC::commit(100, &r_in);
        let nullifier = Nf::derive(&x, &in_commitment);
        let spend_signature: SchnorrSignature = schnorr_sign(&x, &[0u8; 32], &mut rng);
        let out_commitment = PC::commit(100, &r_out);
        let (range_proof, _) =
            prove_value_range(100, &r_out, DEFAULT_RANGE_BITS, &mut rng).unwrap();

        let typed = TransferTx {
            inputs: vec![TransferInput {
                commitment: in_commitment,
                nullifier,
                spend_signature,
            }],
            outputs: vec![TransferOutput {
                commitment: out_commitment,
                range_proof,
            }],
            fee_atoms: 0,
        };
        tx_to_proto(&typed)
    }

    #[test]
    fn outbound_lock_wraps_correctly() {
        let event = sample_lock(1);
        let env = HyperRouter::outbound_lock(event.clone());
        assert_eq!(env.message_type, proto::HyperMessageType::Lock as i32);
        match env.body {
            Some(proto::hyper_message::Body::Lock(decoded)) => {
                assert_eq!(decoded.lock_id, event.lock_id);
            }
            _ => panic!("expected Lock body"),
        }
    }

    #[test]
    fn outbound_transfer_wraps_correctly() {
        let tx = sample_transfer(7);
        let env = HyperRouter::outbound_transfer(tx.clone());
        assert_eq!(env.message_type, proto::HyperMessageType::Transfer as i32);
        match env.body {
            Some(proto::hyper_message::Body::Transfer(decoded)) => {
                assert_eq!(decoded.fee_atoms, tx.fee_atoms);
            }
            _ => panic!("expected Transfer body"),
        }
    }

    #[test]
    fn inbound_lock_routes_to_mempool() {
        let mempool = HyperMempool::new();
        let mut router = HyperRouter::new(mempool, None, 0);
        let env = HyperRouter::outbound_lock(sample_lock(1));
        router.route_inbound(env).unwrap();
        assert_eq!(router.mempool.lock_count(), 1);
    }

    #[test]
    fn inbound_transfer_at_router_layer_is_sealed() {
        // Confidential transfers must route through
        // `HyperRuntime::submit_message` so the strong validators
        // (`validate_against_store` + `verify_balance_with_blinding_diff`)
        // can run. The router-only path is sealed.
        let mempool = HyperMempool::new();
        let mut router = HyperRouter::new(mempool, None, 0);
        let env = HyperRouter::outbound_transfer(sample_transfer(2));
        let err = router
            .route_inbound(env)
            .expect_err("router path is sealed");
        assert!(matches!(err, RoutingError::Transfer(_)));
        assert_eq!(router.mempool.transfer_count(), 0);
    }

    #[test]
    fn missing_body_rejected() {
        let mempool = HyperMempool::new();
        let mut router = HyperRouter::new(mempool, None, 0);
        let env = proto::HyperMessage {
            message_type: proto::HyperMessageType::Lock as i32,
            body: None,
        };
        assert!(matches!(
            router.route_inbound(env),
            Err(RoutingError::MissingBody)
        ));
    }

    #[test]
    fn full_wire_round_trip_lock() {
        // Wire path: outbound → encode → decode → route → mempool.
        let event = sample_lock(42);
        let outbound = HyperRouter::outbound_lock(event.clone());
        let bytes = outbound.encode_to_vec();
        let inbound = proto::HyperMessage::decode(bytes.as_slice()).unwrap();

        let mempool = HyperMempool::new();
        let mut router = HyperRouter::new(mempool, None, 0);
        router.route_inbound(inbound).unwrap();
        assert_eq!(router.mempool.lock_count(), 1);
        let recovered = router.mempool.locks().next().unwrap();
        assert_eq!(recovered.lock_id, event.lock_id);
        assert_eq!(recovered.amount, event.amount);
    }

    #[test]
    fn full_wire_round_trip_transfer_sealed_at_router() {
        let tx = sample_transfer(11);
        let outbound = HyperRouter::outbound_transfer(tx.clone());
        let bytes = outbound.encode_to_vec();
        let inbound = proto::HyperMessage::decode(bytes.as_slice()).unwrap();

        let mempool = HyperMempool::new();
        let mut router = HyperRouter::new(mempool, None, 0);
        let err = router
            .route_inbound(inbound)
            .expect_err("router path is sealed");
        assert!(matches!(err, RoutingError::Transfer(_)));
        assert_eq!(router.mempool.transfer_count(), 0);
    }

    #[test]
    fn outbound_validator_register_wraps_correctly() {
        let event = proto::HyperValidatorEventBody {
            event_type: proto::HyperValidatorEventType::Register as i32,
            validator_key: vec![0u8; 32],
            transport_pubkey: vec![0u8; 32],
            registration_epoch: 1,
            operator_address: vec![],
            fid: 0,
            custody_signature: vec![],
            ..Default::default()
        };
        let env = HyperRouter::outbound_validator_register(event.clone());
        assert_eq!(
            env.message_type,
            proto::HyperMessageType::ValidatorRegister as i32
        );
        match env.body {
            Some(proto::hyper_message::Body::ValidatorEvent(decoded)) => {
                assert_eq!(decoded.validator_key, event.validator_key);
            }
            _ => panic!("expected ValidatorEvent body"),
        }
    }

    #[test]
    fn inbound_validator_event_without_registry_errors() {
        let event = proto::HyperValidatorEventBody {
            event_type: proto::HyperValidatorEventType::Register as i32,
            validator_key: vec![0u8; 32],
            transport_pubkey: vec![0u8; 32],
            registration_epoch: 1,
            operator_address: vec![],
            fid: 0,
            custody_signature: vec![],
            ..Default::default()
        };
        let env = HyperRouter::outbound_validator_register(event);

        // Router has no registry installed.
        let mut router = HyperRouter::new(HyperMempool::new(), None, 1);
        let result = router.route_inbound(env);
        assert!(matches!(
            result,
            Err(RoutingError::UnsupportedValidatorEventType(_))
        ));
    }

    #[test]
    fn duplicate_inbound_lock_returns_mempool_error() {
        let mempool = HyperMempool::new();
        let mut router = HyperRouter::new(mempool, None, 0);
        let env = HyperRouter::outbound_lock(sample_lock(1));
        router.route_inbound(env.clone()).unwrap();
        let result = router.route_inbound(env);
        assert!(matches!(result, Err(RoutingError::Mempool(_))));
    }
}
