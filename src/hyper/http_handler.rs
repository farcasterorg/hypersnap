//! HTTP handler exposing the actor's read API as JSON endpoints.
//!
//! Sits in front of `HyperActorClient` and translates HTTP requests
//! into client calls. Operator wires this into the existing snapchain
//! HTTP router via `can_handle` / `handle`.
//!
//! Routes (all GET):
//!  - `/hyper/v1/head`                              → last height + hash hex
//!  - `/hyper/v1/epoch`                              → current epoch
//!  - `/hyper/v1/mempool/pending`                    → pending count
//!  - `/hyper/v1/block/{height}`                    → stored block (proto JSON)
//!  - `/hyper/v1/block/by-hash/{hash_hex}`           → stored block
//!  - `/hyper/v1/validator/{key_hex}/score/{epoch}`  → score record
//!  - `/hyper/v1/epoch/{n}/active`                   → raw active set (vk hex → bls/transport hex)
//!  - `/hyper/v1/epoch/{n}/active-enforced`          → enforced active set
//!  - `/hyper/v1/epoch/{n}/evidence`                 → slashing evidence
//!  - `/hyper/v1/epoch/{n}/slashed`                  → slashed validator keys
//!  - `/hyper/v1/nullifier/{hex}`                    → spent / not spent
//!
//! Wire shape uses prost JSON for proto types and small ad-hoc structs
//! for the rest. Errors are JSON `{"error":"..."}` with appropriate
//! status codes.

use crate::hyper::actor::{HyperActorClient, HyperActorClientError, HyperActorEvent};
use crate::proto;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::{Method, Response, StatusCode};
use prost::Message;
use serde::{Deserialize, Serialize};
use std::convert::Infallible;
use tokio::sync::mpsc;

/// Wraps a `HyperActorClient` with HTTP routing. The cloned `inbound`
/// sender is used for write endpoints (e.g. POST /messages).
#[derive(Clone)]
pub struct HyperHttpHandler {
    client: HyperActorClient,
    inbound: mpsc::Sender<HyperActorEvent>,
}

impl HyperHttpHandler {
    pub fn new(client: HyperActorClient, inbound: mpsc::Sender<HyperActorEvent>) -> Self {
        Self { client, inbound }
    }

    /// Whether this handler claims responsibility for a request. Used
    /// by the parent router to route `/hyper/v1/*` here without a
    /// `Router::merge` dependency.
    pub fn can_handle(&self, method: &Method, path: &str) -> bool {
        path.starts_with("/hyper/v1/") && (method == Method::GET || method == Method::POST)
    }

    /// Dispatch a request to the matching handler. GET endpoints
    /// ignore `body`; POST endpoints use it. Returns appropriate
    /// status codes (404 / 400 / 500 / 202).
    pub async fn handle(
        &self,
        method: &Method,
        path: &str,
        body: Bytes,
    ) -> Response<BoxBody<Bytes, Infallible>> {
        match self.dispatch(method, path, body).await {
            Ok(resp) => resp,
            Err(HandlerError::NotFound) => json_response(
                StatusCode::NOT_FOUND,
                &ErrorBody {
                    error: "not found".into(),
                },
            ),
            Err(HandlerError::BadRequest(msg)) => {
                json_response(StatusCode::BAD_REQUEST, &ErrorBody { error: msg })
            }
            Err(HandlerError::Internal(msg)) => {
                json_response(StatusCode::INTERNAL_SERVER_ERROR, &ErrorBody { error: msg })
            }
            Err(HandlerError::MethodNotAllowed) => json_response(
                StatusCode::METHOD_NOT_ALLOWED,
                &ErrorBody {
                    error: "method not allowed".into(),
                },
            ),
        }
    }

    async fn dispatch(
        &self,
        method: &Method,
        path: &str,
        body: Bytes,
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, HandlerError> {
        let segments: Vec<&str> = path
            .strip_prefix("/hyper/v1/")
            .ok_or(HandlerError::NotFound)?
            .trim_end_matches('/')
            .split('/')
            .collect();

        match (method, segments.as_slice()) {
            (&Method::GET, ["head"]) => self.head().await,
            (&Method::GET, ["epoch"]) => self.current_epoch().await,
            (&Method::GET, ["status"]) => self.status().await,
            (&Method::GET, ["score-weights"]) => self.score_weights().await,
            (&Method::GET, ["mempool", "pending"]) => self.pending().await,
            (&Method::GET, ["block", height]) => self.block_by_height(height).await,
            (&Method::GET, ["block", "by-hash", hash]) => self.block_by_hash(hash).await,
            (&Method::GET, ["validator", vk, "score", epoch]) => self.score(vk, epoch).await,
            (&Method::GET, ["validator", vk, "events"]) => self.validator_events(vk).await,
            (&Method::GET, ["rewards", fid]) => self.reward_balance(fid).await,
            (&Method::GET, ["nonce", fid]) => self.token_nonce(fid).await,
            (&Method::GET, ["lock", fid, lock_id_hex]) => {
                self.token_lock_state(fid, lock_id_hex).await
            }
            (&Method::GET, ["lock-tree", "root"]) => self.lock_merkle_root().await,
            (&Method::GET, ["lock-tree", "signed-root"]) => self.lock_signed_root().await,
            (&Method::GET, ["lock-tree", "proof", lock_id_hex]) => {
                self.lock_merkle_proof(lock_id_hex).await
            }
            (&Method::GET, ["bridge", "signed-owner-rotation"]) => {
                self.bridge_signed_owner_rotation().await
            }
            (&Method::GET, ["bridge", "inbound-burn", chain_id, burn_id_hex]) => {
                self.bridge_inbound_burn(chain_id, burn_id_hex).await
            }
            (&Method::GET, ["bridge", "observed-burns"]) => self.bridge_observed_burns().await,
            (&Method::GET, ["staked", fid]) => self.staked_breakdown(fid).await,
            (&Method::GET, ["unstake-queue", fid]) => self.unstake_queue(fid).await,
            (&Method::GET, ["trust", fid]) => self.trust_score(fid).await,
            (&Method::GET, ["validators", fid]) => self.validator_count_for_fid(fid).await,
            (&Method::GET, ["scoring", "last-epoch"]) => self.last_scored_epoch().await,
            (&Method::GET, ["cutover"]) => self.cutover_status().await,
            (&Method::GET, ["epoch", n, "active"]) => self.active_set(n, false).await,
            (&Method::GET, ["epoch", n, "active-enforced"]) => self.active_set(n, true).await,
            (&Method::GET, ["epoch", n, "evidence"]) => self.evidence(n).await,
            (&Method::GET, ["epoch", n, "slashed"]) => self.slashed(n).await,
            (&Method::GET, ["nullifier", hex]) => self.nullifier_spent(hex).await,
            (&Method::POST, ["messages"]) => self.submit_message(body).await,
            (&Method::POST, ["validator", "register"]) => {
                self.submit_validator_event(body, proto::HyperValidatorEventType::Register)
                    .await
            }
            (&Method::POST, ["validator", "deregister"]) => {
                self.submit_validator_event(body, proto::HyperValidatorEventType::Deregister)
                    .await
            }
            (&Method::GET, _) => Err(HandlerError::NotFound),
            (&Method::POST, _) => Err(HandlerError::NotFound),
            _ => Err(HandlerError::MethodNotAllowed),
        }
    }

    async fn submit_message(
        &self,
        body: Bytes,
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, HandlerError> {
        let msg = proto::HyperMessage::decode(body.as_ref())
            .map_err(|e| HandlerError::BadRequest(format!("decode HyperMessage: {}", e)))?;
        self.inbound
            .send(HyperActorEvent::LocalSubmitMessage(msg))
            .await
            .map_err(|_| HandlerError::Internal("actor inbound closed".into()))?;
        Ok(json_response(
            StatusCode::ACCEPTED,
            &AcceptedResponse { accepted: true },
        ))
    }

    /// Wrap a JSON-encoded ValidatorEventInput into a HyperValidatorEventBody
    /// of the given type and submit it via the actor. Friendlier than
    /// asking clients to construct + prost-encode the proto themselves.
    ///
    /// Length sanity-checks happen here so the actor doesn't have to
    /// see structurally-broken events. The runtime still verifies the
    /// Ed25519 signature; this layer just rejects obviously-malformed
    /// inputs early.
    async fn submit_validator_event(
        &self,
        body: Bytes,
        event_type: proto::HyperValidatorEventType,
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, HandlerError> {
        let input: ValidatorEventInput = serde_json::from_slice(body.as_ref()).map_err(|e| {
            HandlerError::BadRequest(format!("decode ValidatorEventInput JSON: {}", e))
        })?;
        let validator_key = parse_hex(&input.validator_key)?;
        if validator_key.len() != 32 {
            return Err(HandlerError::BadRequest(format!(
                "validator_key must be 32 bytes, got {}",
                validator_key.len()
            )));
        }
        let signature_hex = parse_hex(&input.signature_hex)?;
        if signature_hex.len() != 64 {
            return Err(HandlerError::BadRequest(format!(
                "signature must be 64 bytes, got {}",
                signature_hex.len()
            )));
        }
        let validator_address = input
            .validator_address
            .as_deref()
            .map(parse_hex)
            .transpose()?
            .unwrap_or_default();
        if event_type == proto::HyperValidatorEventType::Register && validator_address.len() != 20 {
            return Err(HandlerError::BadRequest(format!(
                "validator_address must be 20 bytes for register events, got {}",
                validator_address.len()
            )));
        }
        let transport = input
            .transport_pubkey
            .as_deref()
            .map(parse_hex)
            .transpose()?
            .unwrap_or_default();
        if event_type == proto::HyperValidatorEventType::Register && transport.len() != 32 {
            return Err(HandlerError::BadRequest(format!(
                "transport_pubkey must be 32 bytes for register events, got {}",
                transport.len()
            )));
        }
        let fid = input.fid.unwrap_or(0);
        let custody_signature = input
            .custody_signature
            .as_deref()
            .map(parse_hex)
            .transpose()?
            .unwrap_or_default();
        let event = proto::HyperValidatorEventBody {
            event_type: event_type as i32,
            validator_key,
            transport_pubkey: transport,
            registration_epoch: input.registration_epoch,
            operator_address: input
                .operator_address
                .as_deref()
                .map(parse_hex)
                .transpose()?
                .unwrap_or_default(),
            signature: signature_hex,
            fid,
            custody_signature,
            validator_address,
        };
        let msg = crate::hyper::router::HyperRouter::outbound_validator_register(event);
        self.inbound
            .send(HyperActorEvent::LocalSubmitMessage(msg))
            .await
            .map_err(|_| HandlerError::Internal("actor inbound closed".into()))?;
        Ok(json_response(
            StatusCode::ACCEPTED,
            &AcceptedResponse { accepted: true },
        ))
    }

    async fn head(&self) -> Result<Response<BoxBody<Bytes, Infallible>>, HandlerError> {
        let height = self.client.last_block_height().await.map_err(client_err)?;
        let hash = self.client.last_block_hash().await.map_err(client_err)?;
        Ok(json_response(
            StatusCode::OK,
            &HeadResponse {
                height,
                hash: hash.map(|h| hex(&h)),
            },
        ))
    }

    async fn current_epoch(&self) -> Result<Response<BoxBody<Bytes, Infallible>>, HandlerError> {
        let epoch = self.client.current_epoch().await.map_err(client_err)?;
        Ok(json_response(StatusCode::OK, &EpochResponse { epoch }))
    }

    async fn score_weights(&self) -> Result<Response<BoxBody<Bytes, Infallible>>, HandlerError> {
        let w = self.client.score_weights().await.map_err(client_err)?;
        Ok(json_response(
            StatusCode::OK,
            &ScoreWeightsResponse {
                proposal: w.proposal,
                participation: w.participation,
                miss_penalty: w.miss_penalty,
                invalid_penalty: w.invalid_penalty,
                auto_deregister_consecutive_misses:
                    crate::hyper::validator_score::AUTO_DEREGISTER_CONSECUTIVE_MISSES,
            },
        ))
    }

    async fn status(&self) -> Result<Response<BoxBody<Bytes, Infallible>>, HandlerError> {
        // Issue queries concurrently — each is independent and the
        // actor serializes them, so the wall-clock cost is dominated
        // by the slowest single query plus actor scheduling.
        let (h1, h2, h3, h4, h5) = tokio::join!(
            self.client.last_block_height(),
            self.client.last_block_hash(),
            self.client.current_epoch(),
            self.client.pending_count(),
            self.client.last_imported_at_unix_ms(),
        );
        let height = h1.map_err(client_err)?;
        let hash = h2.map_err(client_err)?;
        let epoch = h3.map_err(client_err)?;
        let pending = h4.map_err(client_err)?;
        let last_imported_at_unix_ms = h5.map_err(client_err)?;
        // active-set query depends on `epoch`, so it can't run in the
        // join above without an extra round-trip.
        let active_size = self
            .client
            .active_validators(epoch, false)
            .await
            .map_err(client_err)?
            .map_err(HandlerError::Internal)?
            .len();
        Ok(json_response(
            StatusCode::OK,
            &StatusResponse {
                height,
                hash: hash.map(|h| hex(&h)),
                epoch,
                pending,
                active_validator_count: active_size,
                last_imported_at_unix_ms,
            },
        ))
    }

    async fn pending(&self) -> Result<Response<BoxBody<Bytes, Infallible>>, HandlerError> {
        let count = self.client.pending_count().await.map_err(client_err)?;
        Ok(json_response(
            StatusCode::OK,
            &PendingResponse { pending: count },
        ))
    }

    async fn block_by_height(
        &self,
        height: &str,
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, HandlerError> {
        let height: u64 = height
            .parse()
            .map_err(|_| HandlerError::BadRequest(format!("invalid height: {}", height)))?;
        let block = self
            .client
            .get_block_by_height(height)
            .await
            .map_err(client_err)?;
        match block {
            Some(b) => Ok(json_response(StatusCode::OK, &block_summary(&b))),
            None => Err(HandlerError::NotFound),
        }
    }

    async fn block_by_hash(
        &self,
        hash_hex: &str,
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, HandlerError> {
        let hash = parse_hash32(hash_hex)?;
        let block = self
            .client
            .get_block_by_hash(hash)
            .await
            .map_err(client_err)?;
        match block {
            Some(b) => Ok(json_response(StatusCode::OK, &block_summary(&b))),
            None => Err(HandlerError::NotFound),
        }
    }

    async fn score(
        &self,
        vk_hex: &str,
        epoch: &str,
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, HandlerError> {
        let vk = parse_hex(vk_hex)?;
        let epoch: u64 = epoch
            .parse()
            .map_err(|_| HandlerError::BadRequest(format!("invalid epoch: {}", epoch)))?;
        let score = self
            .client
            .validator_score(epoch, vk)
            .await
            .map_err(client_err)?
            .map_err(HandlerError::Internal)?;
        Ok(json_response(
            StatusCode::OK,
            &ScoreResponse {
                successful_proposals: score.successful_proposals,
                missed_proposals: score.missed_proposals,
                invalid_proposals: score.invalid_proposals,
                commit_signatures: score.commit_signatures,
                score: score.score,
                consecutive_misses: score.consecutive_misses,
            },
        ))
    }

    async fn reward_balance(
        &self,
        fid_str: &str,
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, HandlerError> {
        let fid: u64 = fid_str
            .parse()
            .map_err(|_| HandlerError::BadRequest(format!("invalid fid: {}", fid_str)))?;
        let balance = self
            .client
            .reward_balance(fid)
            .await
            .map_err(client_err)?
            .map_err(HandlerError::Internal)?;
        Ok(json_response(
            StatusCode::OK,
            &RewardBalanceResponse { fid, balance },
        ))
    }

    async fn token_nonce(
        &self,
        fid_str: &str,
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, HandlerError> {
        let fid: u64 = fid_str
            .parse()
            .map_err(|_| HandlerError::BadRequest(format!("invalid fid: {}", fid_str)))?;
        let nonce = self
            .client
            .token_nonce(fid)
            .await
            .map_err(client_err)?
            .map_err(HandlerError::Internal)?;
        Ok(json_response(
            StatusCode::OK,
            &TokenNonceResponse { fid, nonce },
        ))
    }

    async fn lock_merkle_root(&self) -> Result<Response<BoxBody<Bytes, Infallible>>, HandlerError> {
        let root = self
            .client
            .lock_merkle_root()
            .await
            .map_err(client_err)?
            .map_err(HandlerError::Internal)?;
        Ok(json_response(
            StatusCode::OK,
            &LockMerkleRootResponse {
                root_hex: format!("0x{}", hex::encode(root.as_slice())),
            },
        ))
    }

    async fn bridge_inbound_burn(
        &self,
        chain_str: &str,
        burn_id_hex: &str,
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, HandlerError> {
        let chain_id: u32 = chain_str
            .parse()
            .map_err(|_| HandlerError::BadRequest(format!("invalid chain_id: {}", chain_str)))?;
        let stripped = burn_id_hex.strip_prefix("0x").unwrap_or(burn_id_hex);
        let burn_id = hex::decode(stripped)
            .map_err(|e| HandlerError::BadRequest(format!("invalid burn_id hex: {}", e)))?;
        if burn_id.len() != 32 {
            return Err(HandlerError::BadRequest(format!(
                "burn_id must be 32 bytes (got {})",
                burn_id.len()
            )));
        }
        let record = self
            .client
            .inbound_burn_record(chain_id, burn_id.clone())
            .await
            .map_err(client_err)?
            .map_err(HandlerError::Internal)?;
        let response = match record {
            None => InboundBurnResponse {
                source_chain_id: chain_id,
                burn_id_hex: format!("0x{}", hex::encode(&burn_id)),
                processed: false,
                epoch: 0,
                recipient_fid: 0,
                amount: 0,
                source_block_number: 0,
                source_tx_hash_hex: String::new(),
                signature_hex: String::new(),
            },
            Some(b) => InboundBurnResponse {
                source_chain_id: chain_id,
                burn_id_hex: format!("0x{}", hex::encode(&burn_id)),
                processed: true,
                epoch: b.epoch,
                recipient_fid: b.recipient_fid,
                amount: b.amount,
                source_block_number: b.source_block_number,
                source_tx_hash_hex: format!("0x{}", hex::encode(&b.source_tx_hash)),
                signature_hex: format!("0x{}", hex::encode(&b.ecdsa_signature)),
            },
        };
        Ok(json_response(StatusCode::OK, &response))
    }

    async fn staked_breakdown(
        &self,
        fid_str: &str,
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, HandlerError> {
        let fid: u64 = fid_str
            .parse()
            .map_err(|_| HandlerError::BadRequest(format!("invalid fid: {}", fid_str)))?;
        let breakdown = self
            .client
            .staked_breakdown(fid)
            .await
            .map_err(client_err)?
            .map_err(HandlerError::Internal)?;
        Ok(json_response(
            StatusCode::OK,
            &StakedBreakdownResponse {
                fid: breakdown.fid,
                validator_atoms: breakdown.validator_atoms,
                vouch_outgoing_atoms: breakdown.vouch_outgoing_atoms,
                vouch_incoming_atoms: breakdown.vouch_incoming_atoms,
                credibility_atoms: breakdown.credibility_atoms,
                // Vouch incoming is OTHER FIDs' atoms, so it is not
                // summed into this FID's total locked stake.
                total_atoms: breakdown
                    .validator_atoms
                    .saturating_add(breakdown.vouch_outgoing_atoms)
                    .saturating_add(breakdown.credibility_atoms),
            },
        ))
    }

    async fn unstake_queue(
        &self,
        fid_str: &str,
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, HandlerError> {
        let fid: u64 = fid_str
            .parse()
            .map_err(|_| HandlerError::BadRequest(format!("invalid fid: {}", fid_str)))?;
        let entries = self
            .client
            .unstake_queue_for_fid(fid)
            .await
            .map_err(client_err)?
            .map_err(HandlerError::Internal)?;
        let response = UnstakeQueueResponse {
            fid,
            count: entries.len(),
            total_pending_atoms: entries.iter().map(|e| e.amount).sum::<u64>(),
            entries: entries
                .into_iter()
                .map(|e| UnstakeQueueEntryView {
                    maturation_epoch: e.maturation_epoch,
                    stake_type: stake_type_name(e.stake_type),
                    nonce: e.nonce,
                    amount: e.amount,
                })
                .collect(),
        };
        Ok(json_response(StatusCode::OK, &response))
    }

    async fn bridge_observed_burns(
        &self,
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, HandlerError> {
        let observed = self
            .client
            .observed_burns()
            .await
            .map_err(client_err)?
            .map_err(HandlerError::Internal)?;
        let response = ObservedBurnsResponse {
            count: observed.len(),
            burns: observed
                .into_iter()
                .map(|b| ObservedBurnView {
                    source_chain_id: b.source_chain_id,
                    burn_id_hex: format!("0x{}", hex::encode(&b.burn_id)),
                    recipient_fid: b.recipient_fid,
                    amount: b.amount,
                    source_block_number: b.source_block_number,
                    source_tx_hash_hex: format!("0x{}", hex::encode(&b.source_tx_hash)),
                    observed_at_unix: b.observed_at_unix,
                })
                .collect(),
        };
        Ok(json_response(StatusCode::OK, &response))
    }

    async fn bridge_signed_owner_rotation(
        &self,
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, HandlerError> {
        let rot = self
            .client
            .latest_owner_rotation()
            .await
            .map_err(client_err)?
            .map_err(HandlerError::Internal)?;
        let response = match rot {
            None => OwnerRotationResponse {
                available: false,
                outgoing_epoch: 0,
                incoming_epoch: 0,
                block_number: 0,
                new_owner_address_hex: String::new(),
                authorization_signature_hex: String::new(),
                acceptance_signature_hex: String::new(),
            },
            Some(r) => OwnerRotationResponse {
                available: true,
                outgoing_epoch: r.outgoing_epoch,
                incoming_epoch: r.incoming_epoch,
                block_number: r.block_number,
                new_owner_address_hex: format!("0x{}", hex::encode(&r.new_owner_address)),
                authorization_signature_hex: format!(
                    "0x{}",
                    hex::encode(&r.authorization_signature)
                ),
                acceptance_signature_hex: format!("0x{}", hex::encode(&r.acceptance_signature)),
            },
        };
        Ok(json_response(StatusCode::OK, &response))
    }

    async fn lock_signed_root(&self) -> Result<Response<BoxBody<Bytes, Infallible>>, HandlerError> {
        let signed = self
            .client
            .latest_signed_lock_merkle_root()
            .await
            .map_err(client_err)?
            .map_err(HandlerError::Internal)?;
        let response = match signed {
            None => LockSignedRootResponse {
                available: false,
                epoch: 0,
                block_number: 0,
                root_hex: String::new(),
                signature_hex: String::new(),
            },
            Some(u) => LockSignedRootResponse {
                available: true,
                epoch: u.epoch,
                block_number: u.block_number,
                root_hex: format!("0x{}", hex::encode(&u.root)),
                signature_hex: format!("0x{}", hex::encode(&u.ecdsa_signature)),
            },
        };
        Ok(json_response(StatusCode::OK, &response))
    }

    async fn lock_merkle_proof(
        &self,
        lock_id_hex: &str,
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, HandlerError> {
        let stripped = lock_id_hex.strip_prefix("0x").unwrap_or(lock_id_hex);
        let lock_id = hex::decode(stripped)
            .map_err(|e| HandlerError::BadRequest(format!("invalid lock_id hex: {}", e)))?;
        if lock_id.len() != 32 {
            return Err(HandlerError::BadRequest(format!(
                "lock_id must be 32 bytes (got {})",
                lock_id.len()
            )));
        }
        let proof = self
            .client
            .lock_merkle_proof(lock_id.clone())
            .await
            .map_err(client_err)?
            .map_err(HandlerError::Internal)?;
        let response = match proof {
            None => LockMerkleProofResponse {
                lock_id_hex: format!("0x{}", hex::encode(&lock_id)),
                leaf_hex: None,
                proof_hex: Vec::new(),
                included: false,
            },
            Some((leaf, siblings)) => LockMerkleProofResponse {
                lock_id_hex: format!("0x{}", hex::encode(&lock_id)),
                leaf_hex: Some(format!("0x{}", hex::encode(leaf.as_slice()))),
                proof_hex: siblings
                    .iter()
                    .map(|h| format!("0x{}", hex::encode(h.as_slice())))
                    .collect(),
                included: true,
            },
        };
        Ok(json_response(StatusCode::OK, &response))
    }

    async fn token_lock_state(
        &self,
        fid_str: &str,
        lock_id_hex: &str,
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, HandlerError> {
        let fid: u64 = fid_str
            .parse()
            .map_err(|_| HandlerError::BadRequest(format!("invalid fid: {}", fid_str)))?;
        let stripped = lock_id_hex.strip_prefix("0x").unwrap_or(lock_id_hex);
        let lock_id = hex::decode(stripped)
            .map_err(|e| HandlerError::BadRequest(format!("invalid lock_id hex: {}", e)))?;
        if lock_id.len() != 32 {
            return Err(HandlerError::BadRequest(format!(
                "lock_id must be 32 bytes (got {})",
                lock_id.len()
            )));
        }
        let state = self
            .client
            .token_lock_state(fid, lock_id.clone())
            .await
            .map_err(client_err)?
            .map_err(HandlerError::Internal)?;
        // Recompute the canonical bridge leaf hash from the state.
        // The merkle proof verifier uses this exact hash; surfacing
        // it lets a relayer build claim calldata without
        // re-implementing the encoder.
        let leaf_hex = state.as_ref().map(|s| {
            let leaf = crate::hyper::token_lock::encode_token_lock_leaf(s);
            format!("0x{}", hex::encode(leaf.as_slice()))
        });
        let response = TokenLockResponse {
            fid,
            lock_id_hex: format!("0x{}", hex::encode(&lock_id)),
            state: state.map(|s| TokenLockStateView {
                sender_fid: s.sender_fid,
                amount: s.amount,
                destination_chain_id: s.destination_chain_id,
                destination_address_hex: format!("0x{}", hex::encode(&s.destination_address)),
            }),
            leaf_hex,
        };
        Ok(json_response(StatusCode::OK, &response))
    }

    async fn trust_score(
        &self,
        fid_str: &str,
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, HandlerError> {
        let fid: u64 = fid_str
            .parse()
            .map_err(|_| HandlerError::BadRequest(format!("invalid fid: {}", fid_str)))?;
        let score = self
            .client
            .trust_score(fid)
            .await
            .map_err(client_err)?
            .map_err(HandlerError::Internal)?;
        Ok(json_response(
            StatusCode::OK,
            &TrustScoreResponse { fid, score },
        ))
    }

    async fn validator_count_for_fid(
        &self,
        fid_str: &str,
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, HandlerError> {
        let fid: u64 = fid_str
            .parse()
            .map_err(|_| HandlerError::BadRequest(format!("invalid fid: {}", fid_str)))?;
        let count = self
            .client
            .validator_count_for_fid(fid)
            .await
            .map_err(client_err)?
            .map_err(HandlerError::Internal)?;
        Ok(json_response(
            StatusCode::OK,
            &ValidatorCountResponse {
                fid,
                count,
                max: crate::hyper::validator_registry::MAX_VALIDATORS_PER_FID,
            },
        ))
    }

    async fn last_scored_epoch(
        &self,
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, HandlerError> {
        let last = self.client.last_scored_epoch().await.map_err(client_err)?;
        Ok(json_response(
            StatusCode::OK,
            &LastScoredEpochResponse {
                last_scored_epoch: last,
            },
        ))
    }

    async fn cutover_status(&self) -> Result<Response<BoxBody<Bytes, Infallible>>, HandlerError> {
        let s = self.client.cutover_status().await.map_err(client_err)?;
        Ok(json_response(
            StatusCode::OK,
            &CutoverStatusResponse {
                configured_block: s.configured_block,
                is_post_cutover: s.is_post_cutover,
                min_validator_trust_score: s.min_validator_trust_score,
                protocol_chain_id: crate::hyper::DEFAULT_PROTOCOL_CHAIN_ID,
                seed_max_fid: s.seed_max_fid,
            },
        ))
    }

    async fn validator_events(
        &self,
        vk_hex: &str,
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, HandlerError> {
        let vk = parse_hex(vk_hex)?;
        let events = self
            .client
            .validator_events(vk, u64::MAX)
            .await
            .map_err(client_err)?
            .map_err(HandlerError::Internal)?;
        let entries: Vec<ValidatorEventEntry> = events
            .into_iter()
            .map(|e| ValidatorEventEntry {
                event_type: e.event_type,
                registration_epoch: e.registration_epoch,
                transport_pubkey: hex(&e.transport_pubkey),
                operator_address: hex(&e.operator_address),
            })
            .collect();
        Ok(json_response(
            StatusCode::OK,
            &ValidatorEventsResponse { events: entries },
        ))
    }

    async fn active_set(
        &self,
        epoch: &str,
        enforced: bool,
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, HandlerError> {
        let epoch: u64 = epoch
            .parse()
            .map_err(|_| HandlerError::BadRequest(format!("invalid epoch: {}", epoch)))?;
        let set = self
            .client
            .active_validators(epoch, enforced)
            .await
            .map_err(client_err)?
            .map_err(HandlerError::Internal)?;
        let validators: Vec<ActiveValidatorEntry> = set
            .into_iter()
            .map(|(vk, (bls, transport))| ActiveValidatorEntry {
                validator_key: hex(&vk),
                transport_pubkey: hex(&transport),
            })
            .collect();
        Ok(json_response(
            StatusCode::OK,
            &ActiveSetResponse { validators },
        ))
    }

    async fn evidence(
        &self,
        epoch: &str,
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, HandlerError> {
        let epoch: u64 = epoch
            .parse()
            .map_err(|_| HandlerError::BadRequest(format!("invalid epoch: {}", epoch)))?;
        let ev = self
            .client
            .evidence_for_epoch(epoch)
            .await
            .map_err(client_err)?
            .map_err(HandlerError::Internal)?;
        let entries: Vec<EvidenceEntry> = ev
            .into_iter()
            .map(|e| EvidenceEntry {
                block_a: e.block_a.as_ref().map(block_summary_proto),
                block_b: e.block_b.as_ref().map(block_summary_proto),
            })
            .collect();
        Ok(json_response(StatusCode::OK, &EvidenceResponse { entries }))
    }

    async fn slashed(
        &self,
        epoch: &str,
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, HandlerError> {
        let epoch: u64 = epoch
            .parse()
            .map_err(|_| HandlerError::BadRequest(format!("invalid epoch: {}", epoch)))?;
        let set = self
            .client
            .slashed_validators(epoch)
            .await
            .map_err(client_err)?
            .map_err(HandlerError::Internal)?;
        let keys: Vec<String> = set.into_iter().map(|k| hex(&k)).collect();
        Ok(json_response(
            StatusCode::OK,
            &SlashedResponse { validators: keys },
        ))
    }

    async fn nullifier_spent(
        &self,
        hash_hex: &str,
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, HandlerError> {
        let nullifier = parse_hash32(hash_hex)?;
        let spent = self
            .client
            .is_nullifier_spent(nullifier)
            .await
            .map_err(client_err)?;
        Ok(json_response(StatusCode::OK, &NullifierResponse { spent }))
    }
}

#[derive(thiserror::Error, Debug)]
enum HandlerError {
    #[error("not found")]
    NotFound,
    #[error("bad request: {0}")]
    BadRequest(String),
    #[error("internal: {0}")]
    Internal(String),
    #[error("method not allowed")]
    MethodNotAllowed,
}

fn client_err(e: HyperActorClientError) -> HandlerError {
    HandlerError::Internal(e.to_string())
}

fn parse_hex(s: &str) -> Result<Vec<u8>, HandlerError> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    if bytes.len() % 2 != 0 {
        return Err(HandlerError::BadRequest("odd-length hex".into()));
    }
    for chunk in bytes.chunks(2) {
        let hi = hex_nibble(chunk[0])?;
        let lo = hex_nibble(chunk[1])?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn hex_nibble(c: u8) -> Result<u8, HandlerError> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(HandlerError::BadRequest("invalid hex".into())),
    }
}

fn parse_hash32(s: &str) -> Result<[u8; 32], HandlerError> {
    let v = parse_hex(s)?;
    if v.len() != 32 {
        return Err(HandlerError::BadRequest(format!(
            "expected 32-byte hex, got {} bytes",
            v.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    Ok(out)
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(s, "{:02x}", b);
    }
    s
}

fn json_response<T: Serialize>(
    status: StatusCode,
    body: &T,
) -> Response<BoxBody<Bytes, Infallible>> {
    let bytes = serde_json::to_vec(body).unwrap_or_else(|_| b"{}".to_vec());
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(bytes)).boxed())
        .unwrap()
}

// ---- Response shapes ----

#[derive(Serialize)]
struct ErrorBody {
    error: String,
}

#[derive(Serialize)]
struct HeadResponse {
    height: Option<u64>,
    hash: Option<String>,
}

#[derive(Serialize)]
struct EpochResponse {
    epoch: u64,
}

#[derive(Serialize)]
struct PendingResponse {
    pending: usize,
}

#[derive(Serialize)]
struct BlockSummary {
    canonical_block_id: u64,
    parent_hash: String,
    hyper_state_root: String,
    extra_rules_version: u32,
    retained_message_count: u64,
    epoch: u64,
    signer_indices: Vec<u64>,
}

#[derive(Serialize)]
struct ScoreResponse {
    successful_proposals: u64,
    missed_proposals: u64,
    invalid_proposals: u64,
    commit_signatures: u64,
    score: i64,
    consecutive_misses: u64,
}

#[derive(Serialize)]
struct ActiveValidatorEntry {
    validator_key: String,
    transport_pubkey: String,
}

#[derive(Serialize)]
struct ActiveSetResponse {
    validators: Vec<ActiveValidatorEntry>,
}

#[derive(Serialize)]
struct EvidenceEntry {
    block_a: Option<BlockSummary>,
    block_b: Option<BlockSummary>,
}

#[derive(Serialize)]
struct EvidenceResponse {
    entries: Vec<EvidenceEntry>,
}

#[derive(Serialize)]
struct SlashedResponse {
    validators: Vec<String>,
}

#[derive(Serialize)]
struct NullifierResponse {
    spent: bool,
}

#[derive(Serialize)]
struct AcceptedResponse {
    accepted: bool,
}

/// JSON shape for POST /hyper/v1/validator/{register,deregister}.
/// Hex-encoded byte fields. `validator_address` and `transport_pubkey`
/// are required for register, optional for deregister.
#[derive(Deserialize)]
struct ValidatorEventInput {
    validator_key: String,
    transport_pubkey: Option<String>,
    /// 20-byte secp256k1 address (hex). Required for register events.
    validator_address: Option<String>,
    registration_epoch: u64,
    operator_address: Option<String>,
    #[serde(rename = "signature")]
    signature_hex: String,
    /// FID this validator slot belongs to. Required for new events; left
    /// optional in the input shape so legacy clients receive a clearer
    /// downstream error rather than a JSON parse failure.
    fid: Option<u64>,
    /// EIP-712 hex-encoded signature (65 bytes: r||s||v) by the FID's
    /// custody address authorizing this validator slot. Required for
    /// register events.
    custody_signature: Option<String>,
}

#[derive(Serialize)]
struct ValidatorEventEntry {
    event_type: i32,
    registration_epoch: u64,
    transport_pubkey: String,
    operator_address: String,
}

#[derive(Serialize)]
struct ValidatorEventsResponse {
    events: Vec<ValidatorEventEntry>,
}

#[derive(Serialize)]
struct ScoreWeightsResponse {
    proposal: i64,
    participation: i64,
    miss_penalty: i64,
    invalid_penalty: i64,
    auto_deregister_consecutive_misses: u64,
}

#[derive(Serialize)]
struct RewardBalanceResponse {
    fid: u64,
    balance: u64,
}

#[derive(Serialize)]
struct TokenNonceResponse {
    fid: u64,
    nonce: u64,
}

#[derive(Serialize)]
struct TokenLockResponse {
    fid: u64,
    lock_id_hex: String,
    /// Structured lock state. `None` if no lock exists at `(fid, lock_id)`.
    state: Option<TokenLockStateView>,
    /// Canonical bridge leaf hash (32 bytes hex-encoded), recomputed
    /// from `state` via `bridge_payload::lock_leaf_evm`. This is the
    /// value the on-chain `MerkleProof.verifyCalldata` looks up.
    leaf_hex: Option<String>,
}

#[derive(Serialize)]
struct TokenLockStateView {
    sender_fid: u64,
    amount: u64,
    destination_chain_id: u32,
    destination_address_hex: String,
}

#[derive(Serialize)]
struct LockMerkleRootResponse {
    root_hex: String,
}

#[derive(Serialize)]
struct InboundBurnResponse {
    source_chain_id: u32,
    burn_id_hex: String,
    /// True iff the burn has been threshold-signed + credited on
    /// this node.
    processed: bool,
    epoch: u64,
    recipient_fid: u64,
    amount: u64,
    source_block_number: u64,
    source_tx_hash_hex: String,
    signature_hex: String,
}

#[derive(Serialize)]
struct ObservedBurnsResponse {
    count: usize,
    burns: Vec<ObservedBurnView>,
}

#[derive(Serialize)]
struct ObservedBurnView {
    source_chain_id: u32,
    burn_id_hex: String,
    recipient_fid: u64,
    amount: u64,
    source_block_number: u64,
    source_tx_hash_hex: String,
    observed_at_unix: u64,
}

#[derive(Serialize)]
struct StakedBreakdownResponse {
    fid: u64,
    validator_atoms: u64,
    vouch_outgoing_atoms: u64,
    vouch_incoming_atoms: u64,
    credibility_atoms: u64,
    total_atoms: u64,
}

#[derive(Serialize)]
struct UnstakeQueueResponse {
    fid: u64,
    count: usize,
    total_pending_atoms: u64,
    entries: Vec<UnstakeQueueEntryView>,
}

#[derive(Serialize)]
struct UnstakeQueueEntryView {
    maturation_epoch: u64,
    stake_type: &'static str,
    nonce: u64,
    amount: u64,
}

fn stake_type_name(stake_type: i32) -> &'static str {
    match stake_type {
        x if x == proto::StakeType::Validator as i32 => "validator",
        x if x == proto::StakeType::Vouch as i32 => "vouch",
        x if x == proto::StakeType::Credibility as i32 => "credibility",
        _ => "none",
    }
}

#[derive(Serialize)]
struct OwnerRotationResponse {
    /// True iff a rotation has been applied locally.
    available: bool,
    outgoing_epoch: u64,
    incoming_epoch: u64,
    block_number: u64,
    /// 20-byte EVM address — the new threshold-derived owner.
    new_owner_address_hex: String,
    /// 65-byte ECDSA sig from the OUTGOING owner (epoch
    /// `outgoing_epoch`'s threshold key) over the rotation
    /// authorization. Pass as `authorizationSig` to
    /// `HypersnapBridge.rotateOwner`.
    authorization_signature_hex: String,
    /// 65-byte ECDSA sig from the INCOMING owner (epoch
    /// `incoming_epoch`'s threshold key) proving key possession.
    /// Pass as `acceptanceSig`.
    acceptance_signature_hex: String,
}

#[derive(Serialize)]
struct LockSignedRootResponse {
    /// True iff a signed root has been applied locally. Otherwise
    /// the rest of the fields are zero/empty.
    available: bool,
    epoch: u64,
    /// Strictly-monotonic block number the contract uses for
    /// `latestBlock` replay protection. The contract rejects
    /// updates with `block_number <= latestBlock`.
    block_number: u64,
    /// 32-byte merkle root, 0x-prefixed hex.
    root_hex: String,
    /// 65-byte ECDSA `(r||s||v)`, 0x-prefixed hex. Pass directly
    /// as `ownerSig` to `HypersnapBridge.claim` (or
    /// `proposeUpgrade` etc. — same domain-tagged sig shape).
    signature_hex: String,
}

#[derive(Serialize)]
struct LockMerkleProofResponse {
    lock_id_hex: String,
    /// Canonical leaf hash for the lock at `lock_id_hex`. `None`
    /// if the lock isn't in the unclaimed set.
    leaf_hex: Option<String>,
    /// Sibling-only merkle proof, in claim order. Empty when the
    /// lock is the only leaf in the tree (single-leaf root).
    proof_hex: Vec<String>,
    included: bool,
}

#[derive(Serialize)]
struct TrustScoreResponse {
    fid: u64,
    score: Option<f64>,
}

#[derive(Serialize)]
struct ValidatorCountResponse {
    fid: u64,
    count: u32,
    max: u32,
}

#[derive(Serialize)]
struct LastScoredEpochResponse {
    last_scored_epoch: Option<u64>,
}

#[derive(Serialize)]
struct CutoverStatusResponse {
    configured_block: u64,
    is_post_cutover: bool,
    min_validator_trust_score: f64,
    protocol_chain_id: u64,
    seed_max_fid: u64,
}

#[derive(Serialize)]
struct StatusResponse {
    height: Option<u64>,
    hash: Option<String>,
    epoch: u64,
    pending: usize,
    active_validator_count: usize,
    last_imported_at_unix_ms: Option<u64>,
}

fn block_summary(b: &crate::proto::HyperBlock) -> BlockSummary {
    block_summary_proto(b)
}

fn block_summary_proto(b: &crate::proto::HyperBlock) -> BlockSummary {
    let env = b.envelope.clone().unwrap_or_default();
    let meta = env.metadata.unwrap_or_default();
    let sig = b.signature.clone().unwrap_or_default();
    BlockSummary {
        canonical_block_id: meta.canonical_block_id,
        parent_hash: hex(&meta.parent_hash),
        hyper_state_root: hex(&meta.hyper_state_root),
        extra_rules_version: meta.extra_rules_version,
        retained_message_count: meta.retained_message_count,
        epoch: sig.epoch,
        signer_indices: sig.signer_indices,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hyper::actor::{HyperActor, HyperActorEvent};
    use crate::hyper::runtime::{HyperRuntime, HyperRuntimeConfig};
    use crate::hyper::validator_score::ScoreWeights;
    use crate::storage::db::RocksDB;
    use hypersnap_crypto::kzg::KzgSrs;
    use hypersnap_crypto::kzg_lagrange::VERKLE_DOMAIN;
    use rand::rngs::OsRng;
    use std::sync::Arc;
    use tempfile::TempDir;

    fn make_runtime(bootstrap: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)>) -> (HyperRuntime, TempDir) {
        let dir = TempDir::new().unwrap();
        let db = RocksDB::new(dir.path().to_str().unwrap());
        db.open().unwrap();
        let mut rng = OsRng;
        let srs = Arc::new(KzgSrs::random_unsafe(&mut rng, VERKLE_DOMAIN));
        let config = HyperRuntimeConfig {
            db: Arc::new(db),
            srs,
            mempool_capacity: 100,
            score_weights: ScoreWeights::default(),
            starting_epoch: 0,
            bootstrap_validators: bootstrap,
            max_reward_per_epoch: None,
            max_reward_per_epoch_per_market: std::collections::HashMap::new(),
            cutover_snapchain_block: 0,
            min_validator_trust_score: 0.0,
            protocol_chain_id: crate::hyper::DEFAULT_PROTOCOL_CHAIN_ID,
            scoring_params: proof_of_quality::ScoringParams::default(),
            seed_max_fid: 50_000,
            retro_vesting_on_protocol_epochs:
                crate::hyper::runtime::RETRO_VESTING_ON_PROTOCOL_EPOCHS_DEFAULT,
            local_transport_secret_bytes: [0u8; 32],
        };
        (HyperRuntime::new(config), dir)
    }

    async fn read_body(
        resp: Response<BoxBody<Bytes, Infallible>>,
    ) -> (StatusCode, serde_json::Value) {
        let status = resp.status();
        let collected = resp.into_body().collect().await.unwrap().to_bytes();
        let v: serde_json::Value =
            serde_json::from_slice(&collected).unwrap_or(serde_json::Value::Null);
        (status, v)
    }

    fn handler_for(handles: &crate::hyper::actor::HyperActorHandles) -> HyperHttpHandler {
        HyperHttpHandler::new(
            HyperActorClient::new(handles.inbound.clone()),
            handles.inbound.clone(),
        )
    }

    #[tokio::test]
    async fn can_handle_filters_by_method_and_prefix() {
        let (runtime, _dir) = make_runtime(vec![]);
        let handles = HyperActor::spawn(runtime, 4);
        let h = handler_for(&handles);
        assert!(h.can_handle(&Method::GET, "/hyper/v1/head"));
        assert!(h.can_handle(&Method::POST, "/hyper/v1/messages"));
        assert!(!h.can_handle(&Method::DELETE, "/hyper/v1/head"));
        assert!(!h.can_handle(&Method::GET, "/other/path"));
        handles
            .inbound
            .send(HyperActorEvent::Shutdown)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn head_endpoint_returns_pre_genesis_state() {
        let (runtime, _dir) = make_runtime(vec![]);
        let handles = HyperActor::spawn(runtime, 4);
        let h = handler_for(&handles);

        let (status, body) =
            read_body(h.handle(&Method::GET, "/hyper/v1/head", Bytes::new()).await).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body["height"].is_null());
        assert!(body["hash"].is_null());

        handles
            .inbound
            .send(HyperActorEvent::Shutdown)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn epoch_endpoint_returns_current() {
        let (runtime, _dir) = make_runtime(vec![]);
        let handles = HyperActor::spawn(runtime, 4);
        let h = handler_for(&handles);
        let (status, body) = read_body(
            h.handle(&Method::GET, "/hyper/v1/epoch", Bytes::new())
                .await,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["epoch"], 0);
        handles
            .inbound
            .send(HyperActorEvent::Shutdown)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn unknown_path_returns_404() {
        let (runtime, _dir) = make_runtime(vec![]);
        let handles = HyperActor::spawn(runtime, 4);
        let h = handler_for(&handles);
        let (status, body) =
            read_body(h.handle(&Method::GET, "/hyper/v1/nope", Bytes::new()).await).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body["error"], "not found");
        handles
            .inbound
            .send(HyperActorEvent::Shutdown)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn block_by_height_404_for_missing() {
        let (runtime, _dir) = make_runtime(vec![]);
        let handles = HyperActor::spawn(runtime, 4);
        let h = handler_for(&handles);
        let (status, _) = read_body(
            h.handle(&Method::GET, "/hyper/v1/block/99", Bytes::new())
                .await,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        handles
            .inbound
            .send(HyperActorEvent::Shutdown)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn block_by_height_400_for_non_numeric() {
        let (runtime, _dir) = make_runtime(vec![]);
        let handles = HyperActor::spawn(runtime, 4);
        let h = handler_for(&handles);
        let (status, body) = read_body(
            h.handle(&Method::GET, "/hyper/v1/block/abc", Bytes::new())
                .await,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body["error"].as_str().unwrap().contains("invalid height"));
        handles
            .inbound
            .send(HyperActorEvent::Shutdown)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn active_set_endpoint_returns_bootstrap() {
        let bootstrap: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> = (1u8..=2)
            .map(|i| (vec![i; 32], vec![i; 48], vec![i; 32]))
            .collect();
        let (runtime, _dir) = make_runtime(bootstrap);
        let handles = HyperActor::spawn(runtime, 4);
        let h = handler_for(&handles);
        let (status, body) = read_body(
            h.handle(&Method::GET, "/hyper/v1/epoch/0/active", Bytes::new())
                .await,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let arr = body["validators"].as_array().unwrap();
        assert_eq!(arr.len(), 2);
        // hex of vec![1u8;32] is "01" * 32
        assert!(arr
            .iter()
            .any(|v| v["validator_key"].as_str().unwrap() == "01".repeat(32)));
        handles
            .inbound
            .send(HyperActorEvent::Shutdown)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn reward_balance_endpoint_returns_zero_for_unknown_fid() {
        let (runtime, _dir) = make_runtime(vec![]);
        let handles = HyperActor::spawn(runtime, 4);
        let h = handler_for(&handles);
        let resp = h
            .handle(&Method::GET, "/hyper/v1/rewards/123", Bytes::new())
            .await;
        let (status, body) = read_body(resp).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["fid"], 123);
        assert_eq!(body["balance"], 0);
        handles
            .inbound
            .send(HyperActorEvent::Shutdown)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn trust_score_endpoint_returns_null_for_unknown_fid() {
        let (runtime, _dir) = make_runtime(vec![]);
        let handles = HyperActor::spawn(runtime, 4);
        let h = handler_for(&handles);
        let (status, body) = read_body(
            h.handle(&Method::GET, "/hyper/v1/trust/777", Bytes::new())
                .await,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["fid"], 777);
        assert!(body["score"].is_null());
        handles
            .inbound
            .send(HyperActorEvent::Shutdown)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn validator_count_endpoint_zero_with_max_3() {
        let (runtime, _dir) = make_runtime(vec![]);
        let handles = HyperActor::spawn(runtime, 4);
        let h = handler_for(&handles);
        let (status, body) = read_body(
            h.handle(&Method::GET, "/hyper/v1/validators/777", Bytes::new())
                .await,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["fid"], 777);
        assert_eq!(body["count"], 0);
        assert_eq!(body["max"], 3);
        handles
            .inbound
            .send(HyperActorEvent::Shutdown)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn last_scored_epoch_endpoint_returns_null_initially() {
        let (runtime, _dir) = make_runtime(vec![]);
        let handles = HyperActor::spawn(runtime, 4);
        let h = handler_for(&handles);
        let (status, body) = read_body(
            h.handle(&Method::GET, "/hyper/v1/scoring/last-epoch", Bytes::new())
                .await,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(body["last_scored_epoch"].is_null());
        handles
            .inbound
            .send(HyperActorEvent::Shutdown)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn cutover_status_endpoint_reflects_runtime_config() {
        let (runtime, _dir) = make_runtime(vec![]);
        let handles = HyperActor::spawn(runtime, 4);
        let h = handler_for(&handles);
        let (status, body) = read_body(
            h.handle(&Method::GET, "/hyper/v1/cutover", Bytes::new())
                .await,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        // make_runtime uses cutover_snapchain_block: 0 + min_validator_trust_score: 0.0
        // + seed_max_fid: 50_000 (the default). is_post_cutover is false
        // since no chain head exists yet.
        assert_eq!(body["configured_block"], 0);
        assert_eq!(body["is_post_cutover"], false);
        assert_eq!(body["seed_max_fid"], 50_000);
        handles
            .inbound
            .send(HyperActorEvent::Shutdown)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn nullifier_endpoint_returns_false_for_unspent() {
        let (runtime, _dir) = make_runtime(vec![]);
        let handles = HyperActor::spawn(runtime, 4);
        let h = handler_for(&handles);
        let path = format!("/hyper/v1/nullifier/{}", "ab".repeat(32));
        let (status, body) = read_body(h.handle(&Method::GET, &path, Bytes::new()).await).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["spent"], false);
        handles
            .inbound
            .send(HyperActorEvent::Shutdown)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn post_messages_accepts_well_formed_lock() {
        use crate::hyper::router::HyperRouter;

        let (runtime, _dir) = make_runtime(vec![]);
        let handles = HyperActor::spawn(runtime, 4);
        let h = handler_for(&handles);

        let lock = proto::HyperLockEvent {
            amount: 1_000_000,
            dest_chain_id: 1,
            dest_address: vec![0xab; 20],
            spend_pubkey: vec![0x02; 33],
            lock_id: vec![0xee; 32],
            lock_height: 100,
            lock_timestamp: 1_700_000_000,
            lock_signature: vec![0u8; 64],
        };
        let msg = HyperRouter::outbound_lock(lock);
        let bytes = Bytes::from(msg.encode_to_vec());

        let resp = h.handle(&Method::POST, "/hyper/v1/messages", bytes).await;
        let (status, body) = read_body(resp).await;
        assert_eq!(status, StatusCode::ACCEPTED);
        assert_eq!(body["accepted"], true);

        // Confirm the actor admitted it: pending count should be 1.
        let (status, body) = read_body(
            h.handle(&Method::GET, "/hyper/v1/mempool/pending", Bytes::new())
                .await,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["pending"], 1);

        handles
            .inbound
            .send(HyperActorEvent::Shutdown)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn post_validator_register_with_valid_json_is_accepted_for_decode() {
        // The actor will reject the event for signature failure (zero
        // bytes don't verify), but the HTTP layer's job is to decode
        // and forward — that's what we're testing here.
        let (runtime, _dir) = make_runtime(vec![]);
        let handles = HyperActor::spawn(runtime, 4);
        let h = handler_for(&handles);

        let json = serde_json::json!({
            "validator_key": "01".repeat(32),
            "validator_address": "02".repeat(20),
            "transport_pubkey": "03".repeat(32),
            "registration_epoch": 0,
            "signature": "04".repeat(64),
        });
        let resp = h
            .handle(
                &Method::POST,
                "/hyper/v1/validator/register",
                Bytes::from(serde_json::to_vec(&json).unwrap()),
            )
            .await;
        let (status, body) = read_body(resp).await;
        assert_eq!(status, StatusCode::ACCEPTED);
        assert_eq!(body["accepted"], true);
        handles
            .inbound
            .send(HyperActorEvent::Shutdown)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn post_validator_deregister_with_minimal_body() {
        let (runtime, _dir) = make_runtime(vec![]);
        let handles = HyperActor::spawn(runtime, 4);
        let h = handler_for(&handles);

        // Deregister: no bls/transport keys needed.
        let json = serde_json::json!({
            "validator_key": "01".repeat(32),
            "registration_epoch": 0,
            "signature": "00".repeat(64),
        });
        let resp = h
            .handle(
                &Method::POST,
                "/hyper/v1/validator/deregister",
                Bytes::from(serde_json::to_vec(&json).unwrap()),
            )
            .await;
        let (status, _) = read_body(resp).await;
        assert_eq!(status, StatusCode::ACCEPTED);
        handles
            .inbound
            .send(HyperActorEvent::Shutdown)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn post_validator_register_400_for_short_validator_key() {
        let (runtime, _dir) = make_runtime(vec![]);
        let handles = HyperActor::spawn(runtime, 4);
        let h = handler_for(&handles);
        // 16-byte validator key — too short.
        let json = serde_json::json!({
            "validator_key": "01".repeat(16),
            "validator_address": "02".repeat(20),
            "transport_pubkey": "03".repeat(32),
            "registration_epoch": 0,
            "signature": "04".repeat(64),
        });
        let resp = h
            .handle(
                &Method::POST,
                "/hyper/v1/validator/register",
                Bytes::from(serde_json::to_vec(&json).unwrap()),
            )
            .await;
        let (status, body) = read_body(resp).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body["error"]
            .as_str()
            .unwrap()
            .contains("validator_key must be 32 bytes"));
        handles
            .inbound
            .send(HyperActorEvent::Shutdown)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn post_validator_register_400_for_bad_hex() {
        let (runtime, _dir) = make_runtime(vec![]);
        let handles = HyperActor::spawn(runtime, 4);
        let h = handler_for(&handles);

        let json = serde_json::json!({
            "validator_key": "zzznotvalidhex",
            "validator_address": "02".repeat(20),
            "transport_pubkey": "03".repeat(32),
            "registration_epoch": 0,
            "signature": "04".repeat(64),
        });
        let resp = h
            .handle(
                &Method::POST,
                "/hyper/v1/validator/register",
                Bytes::from(serde_json::to_vec(&json).unwrap()),
            )
            .await;
        let (status, _) = read_body(resp).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        handles
            .inbound
            .send(HyperActorEvent::Shutdown)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn post_messages_rejects_garbage_body() {
        let (runtime, _dir) = make_runtime(vec![]);
        let handles = HyperActor::spawn(runtime, 4);
        let h = handler_for(&handles);
        // Random non-proto bytes.
        let resp = h
            .handle(
                &Method::POST,
                "/hyper/v1/messages",
                Bytes::from(vec![0xff; 1024]),
            )
            .await;
        let (status, body) = read_body(resp).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body["error"]
            .as_str()
            .unwrap()
            .contains("decode HyperMessage"));
        handles
            .inbound
            .send(HyperActorEvent::Shutdown)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn post_to_unknown_path_returns_404() {
        let (runtime, _dir) = make_runtime(vec![]);
        let handles = HyperActor::spawn(runtime, 4);
        let h = handler_for(&handles);
        let resp = h
            .handle(&Method::POST, "/hyper/v1/nowhere", Bytes::new())
            .await;
        let (status, _) = read_body(resp).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        handles
            .inbound
            .send(HyperActorEvent::Shutdown)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn score_weights_endpoint_returns_defaults() {
        let (runtime, _dir) = make_runtime(vec![]);
        let handles = HyperActor::spawn(runtime, 4);
        let h = handler_for(&handles);
        let resp = h
            .handle(&Method::GET, "/hyper/v1/score-weights", Bytes::new())
            .await;
        let (status, body) = read_body(resp).await;
        assert_eq!(status, StatusCode::OK);
        // ScoreWeights::default() values.
        assert_eq!(body["proposal"], 100);
        assert_eq!(body["participation"], 1);
        assert_eq!(body["miss_penalty"], 50);
        assert_eq!(body["invalid_penalty"], 1000);
        assert_eq!(body["auto_deregister_consecutive_misses"], 100);
        handles
            .inbound
            .send(HyperActorEvent::Shutdown)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn validator_events_endpoint_returns_empty_list_for_unknown() {
        let (runtime, _dir) = make_runtime(vec![]);
        let handles = HyperActor::spawn(runtime, 4);
        let h = handler_for(&handles);
        let path = format!("/hyper/v1/validator/{}/events", "ab".repeat(32));
        let resp = h.handle(&Method::GET, &path, Bytes::new()).await;
        let (status, body) = read_body(resp).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body["events"].as_array().unwrap().is_empty());
        handles
            .inbound
            .send(HyperActorEvent::Shutdown)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn validator_events_endpoint_400_for_bad_hex() {
        let (runtime, _dir) = make_runtime(vec![]);
        let handles = HyperActor::spawn(runtime, 4);
        let h = handler_for(&handles);
        let resp = h
            .handle(&Method::GET, "/hyper/v1/validator/zzz/events", Bytes::new())
            .await;
        let (status, _) = read_body(resp).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        handles
            .inbound
            .send(HyperActorEvent::Shutdown)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn status_endpoint_returns_combined_view() {
        let bootstrap: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> = (1u8..=3)
            .map(|i| (vec![i; 32], vec![i; 48], vec![i; 32]))
            .collect();
        let (runtime, _dir) = make_runtime(bootstrap);
        let handles = HyperActor::spawn(runtime, 4);
        let h = handler_for(&handles);

        let resp = h
            .handle(&Method::GET, "/hyper/v1/status", Bytes::new())
            .await;
        let (status, body) = read_body(resp).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body["height"].is_null());
        assert!(body["hash"].is_null());
        assert_eq!(body["epoch"], 0);
        assert_eq!(body["pending"], 0);
        assert_eq!(body["active_validator_count"], 3);

        handles
            .inbound
            .send(HyperActorEvent::Shutdown)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn nullifier_endpoint_400_for_short_hex() {
        let (runtime, _dir) = make_runtime(vec![]);
        let handles = HyperActor::spawn(runtime, 4);
        let h = handler_for(&handles);
        let (status, _) = read_body(
            h.handle(&Method::GET, "/hyper/v1/nullifier/abcd", Bytes::new())
                .await,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        handles
            .inbound
            .send(HyperActorEvent::Shutdown)
            .await
            .unwrap();
    }
}
