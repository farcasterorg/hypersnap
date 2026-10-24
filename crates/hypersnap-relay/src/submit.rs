//! Submission with retries, backoff and endpoint failover.
//!
//! [`Submitter::submit`] returns only when every message has a terminal
//! outcome, or on shutdown:
//!
//! - An RPC-level failure (transport, timeout, per-IP limit) never charges a
//!   message: the relay fails over and backs off until an endpoint answers.
//!   Messages wait (FIP A.7).
//! - A per-message transient or rate-limit error charges the message one
//!   attempt. After `max_attempts` the outcome is `GaveUp`, so one poison
//!   message cannot stop a shard.
//!
//! `SubmitBulkMessages` answers in shard-group order, not request order
//! (`src/network/server.rs`), so results are matched by hash.

use crate::classify::{
    classify_bulk_rpc_failure, is_endpoint_failure, Classifier, ErrorClass, HubErrorInfo,
    RpcFailure,
};
use crate::endpoints::{EndpointPool, EndpointRef};
use crate::metrics::{Counter, RelayMetrics};
use crate::retry::{reserve, Backoff, RetryPolicy, Shutdown, Stopped, TokenBucket};
use crate::types::{Direction, MessageHash};
use hypersnap_proto::{bulk_message_response, Message, SubmitBulkMessagesRequest};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, warn};

/// The terminal outcome of one submission.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    Relayed,
    Duplicate,
    Rejected {
        error: String,
    },
    /// State-dependent rejection; the worker parks the message.
    Deferred {
        error: String,
    },
    GaveUp {
        error: String,
    },
}

#[derive(Clone, Copy, Debug)]
pub struct SubmitConfig {
    pub retry: RetryPolicy,
    pub max_attempts: u32,
}

pub struct Submitter {
    direction: Direction,
    pool: Arc<EndpointPool>,
    classifier: Arc<Classifier>,
    cfg: SubmitConfig,
    message_limiter: Option<TokenBucket>,
    metrics: Arc<dyn RelayMetrics>,
}

struct Pending {
    hash: MessageHash,
    message: Message,
    attempts: u32,
}

type MessageResult = Result<(), (ErrorClass, String)>;

struct Round {
    results: HashMap<MessageHash, MessageResult>,
    /// The endpoint failed before it answered for every message. The
    /// messages without a result were not attempted.
    endpoint_failed: Option<(RpcFailure, tonic::Status)>,
}

impl Submitter {
    pub fn new(
        direction: Direction,
        pool: Arc<EndpointPool>,
        classifier: Arc<Classifier>,
        cfg: SubmitConfig,
        messages_per_second: u32,
        metrics: Arc<dyn RelayMetrics>,
    ) -> Self {
        Self {
            direction,
            pool,
            classifier,
            cfg,
            message_limiter: TokenBucket::per_second(messages_per_second),
            metrics,
        }
    }

    pub fn direction(&self) -> Direction {
        self.direction
    }

    pub async fn submit(
        &self,
        shard: u32,
        items: Vec<(MessageHash, Message)>,
        shutdown: &mut Shutdown,
    ) -> Result<Vec<(MessageHash, Message, Outcome)>, Stopped> {
        let mut pending: Vec<Pending> = items
            .into_iter()
            .map(|(hash, message)| Pending {
                hash,
                message,
                attempts: 0,
            })
            .collect();
        let mut done = Vec::with_capacity(pending.len());
        let mut backoff = Backoff::new(self.cfg.retry);

        while !pending.is_empty() {
            let wait =
                reserve(&self.message_limiter, pending.len() as u32).max(self.pool.rpc_delay());
            shutdown.sleep(wait).await?;
            let ep = self.pool.current();
            let round = if self.pool.bulk_unsupported(ep.index) {
                self.submit_singles(&ep, &pending, shutdown).await?
            } else {
                match self.submit_bulk(&ep, &pending).await {
                    Ok(round) => round,
                    Err((RpcFailure::BulkUnsupported, _)) => {
                        self.pool.mark_bulk_unsupported(ep.index);
                        continue;
                    }
                    Err(failure) => Round {
                        results: HashMap::new(),
                        endpoint_failed: Some(failure),
                    },
                }
            };

            let mut next = Vec::new();
            let mut message_transient = false;
            for mut p in pending.drain(..) {
                let result = match round.results.get(&p.hash) {
                    Some(r) => r.clone(),
                    None if round.endpoint_failed.is_some() => {
                        next.push(p);
                        continue;
                    }
                    None => Err((
                        ErrorClass::Transient,
                        "no result for the message in the response".into(),
                    )),
                };
                match result {
                    Ok(()) => done.push((p.hash, p.message, Outcome::Relayed)),
                    Err((ErrorClass::Duplicate, _)) => {
                        done.push((p.hash, p.message, Outcome::Duplicate))
                    }
                    Err((ErrorClass::RuleRejection, error)) => {
                        done.push((p.hash, p.message, Outcome::Rejected { error }))
                    }
                    Err((ErrorClass::StateDependent, error)) => {
                        done.push((p.hash, p.message, Outcome::Deferred { error }))
                    }
                    Err((class @ (ErrorClass::RateLimited | ErrorClass::Transient), error)) => {
                        let counter = if class == ErrorClass::RateLimited {
                            Counter::RateLimited
                        } else {
                            message_transient = true;
                            Counter::Transient
                        };
                        self.metrics.count(self.direction, shard, counter, 1);
                        p.attempts += 1;
                        if p.attempts >= self.cfg.max_attempts {
                            warn!(
                                direction = %self.direction, shard, hash = %p.hash, attempts = p.attempts,
                                error = %error, "giving up on message"
                            );
                            done.push((p.hash, p.message, Outcome::GaveUp { error }));
                        } else {
                            debug!(direction = %self.direction, shard, hash = %p.hash, error = %error, "retrying message");
                            next.push(p);
                        }
                    }
                }
            }
            pending = next;

            match &round.endpoint_failed {
                Some((failure, status)) => {
                    let counter = if *failure == RpcFailure::RateLimited {
                        Counter::RateLimited
                    } else {
                        Counter::Transient
                    };
                    self.metrics.count(self.direction, shard, counter, 1);
                    warn!(
                        direction = %self.direction, shard, endpoint = %ep.url, code = ?status.code(),
                        message = %status.message(), pending = pending.len(), "submission RPC failed"
                    );
                    self.pool.failover(ep.index);
                }
                None if message_transient => {
                    self.pool.failover(ep.index);
                }
                None => {}
            }
            if pending.is_empty() {
                break;
            }
            shutdown.sleep(backoff.next_delay()).await?;
        }
        Ok(done)
    }

    async fn submit_bulk(
        &self,
        ep: &EndpointRef,
        pending: &[Pending],
    ) -> Result<Round, (RpcFailure, tonic::Status)> {
        let request = SubmitBulkMessagesRequest {
            messages: pending.iter().map(|p| p.message.clone()).collect(),
        };
        let mut client = ep.client.clone();
        let response = client
            .submit_bulk_messages(self.pool.request(request))
            .await
            .map_err(|status| (classify_bulk_rpc_failure(&status), status))?;
        let mut results = HashMap::new();
        for item in response.into_inner().messages {
            match item.response {
                Some(bulk_message_response::Response::Message(m)) => {
                    if let Some(hash) = MessageHash::from_slice(&m.hash) {
                        results.insert(hash, Ok(()));
                    }
                }
                Some(bulk_message_response::Response::MessageError(e)) => {
                    if let Some(hash) = MessageHash::from_slice(&e.hash) {
                        let class = self.classifier.classify_hub_error(&e.err_code, &e.message);
                        results.insert(hash, Err((class, format!("{}/{}", e.err_code, e.message))));
                    }
                }
                None => {}
            }
        }
        Ok(Round {
            results,
            endpoint_failed: None,
        })
    }

    async fn submit_singles(
        &self,
        ep: &EndpointRef,
        pending: &[Pending],
        shutdown: &mut Shutdown,
    ) -> Result<Round, Stopped> {
        let mut results = HashMap::new();
        let mut client = ep.client.clone();
        for (i, p) in pending.iter().enumerate() {
            if i > 0 {
                shutdown.sleep(self.pool.rpc_delay()).await?;
            }
            match client
                .submit_message(self.pool.request(p.message.clone()))
                .await
            {
                Ok(_) => {
                    results.insert(p.hash, Ok(()));
                }
                Err(status) if is_endpoint_failure(&status) => {
                    return Ok(Round {
                        results,
                        endpoint_failed: Some((RpcFailure::Transient, status)),
                    });
                }
                Err(status)
                    if status.code() == tonic::Code::ResourceExhausted
                        && HubErrorInfo::from_status(&status).is_none() =>
                {
                    // The per-IP limiter, not the message.
                    return Ok(Round {
                        results,
                        endpoint_failed: Some((RpcFailure::RateLimited, status)),
                    });
                }
                Err(status) => {
                    let class = self.classifier.classify_status(&status);
                    results.insert(p.hash, Err((class, status.message().to_string())));
                }
            }
        }
        Ok(Round {
            results,
            endpoint_failed: None,
        })
    }
}
