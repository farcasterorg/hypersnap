//! gRPC endpoint pools with failover (FIP A.7).
//!
//! A pool holds one lazily connected channel per endpoint and a "current"
//! index. Callers report a failed endpoint with [`EndpointPool::failover`],
//! which moves the pool to the next endpoint. The pool stays on an endpoint
//! until it fails, so it does not flap between endpoints.

use crate::metrics::RelayMetrics;
use crate::retry::TokenBucket;
use crate::types::Network;
use base64::Engine as _;
use hypersnap_proto::hub_service_client::HubServiceClient;
use hypersnap_proto::{GetInfoRequest, GetInfoResponse, GetPivotRecordRequest, PivotRecord};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tonic::metadata::{Ascii, MetadataValue};
use tonic::transport::{Channel, ClientTlsConfig, Endpoint};
use tracing::warn;

pub type HubClient = HubServiceClient<Channel>;

#[derive(Debug, thiserror::Error)]
pub enum EndpointError {
    #[error("{network}: no endpoints")]
    Empty { network: Network },
    #[error("{network} endpoint {url}: {reason}")]
    Invalid {
        network: Network,
        url: String,
        reason: String,
    },
}

pub struct EndpointOptions {
    pub connect_timeout: Duration,
    pub request_timeout: Duration,
    pub max_message_bytes: usize,
    /// `user:password` for HTTP basic auth (`authorization` metadata).
    pub auth: Option<String>,
    pub rpcs_per_minute: u32,
}

struct PoolEntry {
    url: String,
    client: HubClient,
    bulk_unsupported: AtomicBool,
}

/// The current endpoint of a pool.
#[derive(Clone)]
pub struct EndpointRef {
    pub index: usize,
    pub url: String,
    pub client: HubClient,
}

pub struct EndpointPool {
    network: Network,
    entries: Vec<PoolEntry>,
    current: AtomicUsize,
    auth: Option<MetadataValue<Ascii>>,
    request_timeout: Duration,
    rpc_limiter: Option<TokenBucket>,
    metrics: Arc<dyn RelayMetrics>,
}

impl EndpointPool {
    /// Must run inside a Tokio runtime (the channels spawn their workers).
    pub fn new(
        network: Network,
        urls: &[String],
        opts: EndpointOptions,
        metrics: Arc<dyn RelayMetrics>,
    ) -> Result<Self, EndpointError> {
        if urls.is_empty() {
            return Err(EndpointError::Empty { network });
        }
        let invalid = |url: &str, reason: String| EndpointError::Invalid {
            network,
            url: url.to_string(),
            reason,
        };
        let mut entries = Vec::with_capacity(urls.len());
        for url in urls {
            let mut endpoint = Endpoint::from_shared(url.clone())
                .map_err(|e| invalid(url, e.to_string()))?
                .connect_timeout(opts.connect_timeout)
                .timeout(opts.request_timeout)
                .tcp_keepalive(Some(Duration::from_secs(30)))
                .http2_keep_alive_interval(Duration::from_secs(30))
                .keep_alive_while_idle(true);
            if url.starts_with("https://") {
                endpoint = endpoint
                    .tls_config(ClientTlsConfig::new().with_native_roots())
                    .map_err(|e| invalid(url, e.to_string()))?;
            }
            let client = HubServiceClient::new(endpoint.connect_lazy())
                .max_decoding_message_size(opts.max_message_bytes)
                .max_encoding_message_size(opts.max_message_bytes);
            entries.push(PoolEntry {
                url: url.clone(),
                client,
                bulk_unsupported: AtomicBool::new(false),
            });
        }
        let auth = match &opts.auth {
            Some(userpass) => {
                let token = base64::engine::general_purpose::STANDARD.encode(userpass);
                Some(
                    MetadataValue::try_from(format!("Basic {token}"))
                        .map_err(|e| invalid("auth", e.to_string()))?,
                )
            }
            None => None,
        };
        Ok(Self {
            network,
            entries,
            current: AtomicUsize::new(0),
            auth,
            request_timeout: opts.request_timeout,
            rpc_limiter: TokenBucket::per_minute(opts.rpcs_per_minute),
            metrics,
        })
    }

    pub fn network(&self) -> Network {
        self.network
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn current(&self) -> EndpointRef {
        let index = self.current.load(Ordering::Acquire) % self.entries.len();
        let entry = &self.entries[index];
        EndpointRef {
            index,
            url: entry.url.clone(),
            client: entry.client.clone(),
        }
    }

    pub fn url(&self, index: usize) -> &str {
        &self.entries[index].url
    }

    /// Moves to the endpoint after `failed`, unless another caller already
    /// moved the pool. Returns the new current index.
    pub fn failover(&self, failed: usize) -> usize {
        let n = self.entries.len();
        if n == 1 {
            return 0;
        }
        let next = (failed + 1) % n;
        match self
            .current
            .compare_exchange(failed, next, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) => {
                warn!(
                    network = %self.network,
                    from = %self.entries[failed].url,
                    to = %self.entries[next].url,
                    "endpoint failover"
                );
                self.metrics.endpoint_failover(self.network);
                next
            }
            Err(current) => current,
        }
    }

    /// A request with the auth metadata and the timeout of the pool.
    pub fn request<T>(&self, message: T) -> tonic::Request<T> {
        let mut request = tonic::Request::new(message);
        request.set_timeout(self.request_timeout);
        if let Some(auth) = &self.auth {
            request.metadata_mut().insert("authorization", auth.clone());
        }
        request
    }

    /// A request with the auth metadata and no deadline, for a stream that
    /// stays open.
    pub fn stream_request<T>(&self, message: T) -> tonic::Request<T> {
        let mut request = tonic::Request::new(message);
        if let Some(auth) = &self.auth {
            request.metadata_mut().insert("authorization", auth.clone());
        }
        request
    }

    /// Delay before the next RPC under `rpcs_per_minute`.
    pub fn rpc_delay(&self) -> Duration {
        crate::retry::reserve(&self.rpc_limiter, 1)
    }

    pub fn bulk_unsupported(&self, index: usize) -> bool {
        self.entries[index].bulk_unsupported.load(Ordering::Relaxed)
    }

    pub fn mark_bulk_unsupported(&self, index: usize) {
        if !self.entries[index]
            .bulk_unsupported
            .swap(true, Ordering::Relaxed)
        {
            warn!(
                network = %self.network,
                url = %self.entries[index].url,
                "endpoint does not take SubmitBulkMessages; using SubmitMessage"
            );
        }
    }

    /// `GetInfo` on the current endpoint (no failover).
    pub async fn get_info(&self) -> Result<GetInfoResponse, tonic::Status> {
        tokio::time::sleep(self.rpc_delay()).await;
        let ep = self.current();
        let mut client = ep.client;
        client
            .get_info(self.request(GetInfoRequest {}))
            .await
            .map(|r| r.into_inner())
    }

    /// `GetPivotRecord` of a Hypersnap node, trying each endpoint once.
    pub async fn get_pivot_record(&self) -> Result<PivotRecord, tonic::Status> {
        let mut last = tonic::Status::unavailable("no endpoints");
        for _ in 0..self.len() {
            tokio::time::sleep(self.rpc_delay()).await;
            let ep = self.current();
            let mut client = ep.client;
            match client
                .get_pivot_record(self.request(GetPivotRecordRequest {}))
                .await
            {
                Ok(r) => return Ok(r.into_inner()),
                Err(status) => {
                    self.failover(ep.index);
                    last = status;
                }
            }
        }
        Err(last)
    }
}
