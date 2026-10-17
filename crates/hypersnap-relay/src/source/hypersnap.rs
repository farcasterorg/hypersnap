//! The outbound source: certified Hypersnap blocks (FIP A.4 step 3).
//!
//! [`HypersnapBlockSource`] is the interface that the outbound path needs from
//! a Hypersnap node. [`CertifiedSource`] adapts any implementation to the
//! relay's [`BlockSource`]. Two implementations are here:
//!
//! - [`MemoryHypersnapSource`]: in memory, for tests and tools.
//! - [`GrpcHypersnapBlockSource`]: the gRPC client of a Hypersnap node
//!   (`GetCertifiedBlocks`, and the certified tips in `GetInfo`).
//!
//! # What the node must expose
//!
//! ```protobuf
//! // rpc.proto, service HubService
//! rpc GetCertifiedBlocks(CertifiedBlocksRequest) returns (stream HypersnapBlock);
//!
//! message CertifiedBlocksRequest {
//!   uint32 shard_id = 1;
//!   uint64 start_height = 2;           // inclusive
//!   optional uint64 stop_height = 3;   // exclusive; absent = follow the tip
//! }
//! ```
//!
//! - Only certified blocks: `HypersnapBlock.certificate` set, with
//!   `certificate.{shard_id, height, block_hash}` equal to the block.
//! - Ascending heights without gaps from `start_height`. With no
//!   `stop_height`, the stream stays open and sends each newly certified block.
//! - `messages` are the user messages exactly as merged: `data_bytes`, `hash`,
//!   `signer`, `signature_scheme` and the full `signature` (Ed25519 ||
//!   `HyperSignatureExtension` for dual-signed messages). The relay does the
//!   Ed25519-form rewrite itself.
//! - The certified tip of each shard, for example as
//!   `GetInfoResponse.shard_infos[s].max_height` (certified, not proposed).
//! - A height below the node's retained history fails with `OutOfRange`, so
//!   the relay can fail over to a node that has it.
//! - The relay must be exempt from the per-IP RPC limit (`src/main.rs`), or
//!   operators must set `rate_limits.hypersnap_rpcs_per_minute`.

use super::{BlockSource, BlockStream, RelayBlock, SourceError};
use crate::endpoints::EndpointPool;
use crate::types::Network;
use futures::stream::BoxStream;
use futures::StreamExt;
use hypersnap_proto::{
    CommitCertificate, HypersnapBlock, HypersnapBlockHeader, Message, Transaction,
};
use prost::Message as _;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub type HypersnapBlockStream = BoxStream<'static, Result<HypersnapBlock, SourceError>>;

/// A stream of certified Hypersnap blocks, per shard, from a cursor.
#[async_trait::async_trait]
pub trait HypersnapBlockSource: Send + Sync + 'static {
    /// The certified blocks of `shard_id` from `from_height` (inclusive), in
    /// height order without gaps. At the tip the stream waits for the next
    /// certified block. An `Err` item ends the subscription; the relay opens a
    /// new one from its cursor after a backoff.
    fn certified_blocks(&self, shard_id: u32, from_height: u64) -> HypersnapBlockStream;

    /// Highest certified height of `shard_id`.
    async fn certified_tip(&self, shard_id: u32) -> Result<Option<u64>, SourceError>;
}

/// Checks a certified block against the request and reduces it.
///
/// The relay does not verify the Falcon-512 commit signatures: it trusts its
/// configured Hypersnap nodes for liveness only, and snapchain verifies the
/// user signature of every relayed message. A bad node can only withhold or
/// replay signed messages.
pub fn certified_to_relay_block(
    shard_id: u32,
    block: HypersnapBlock,
) -> Result<RelayBlock, SourceError> {
    let header = block
        .header
        .as_ref()
        .ok_or_else(|| SourceError::Invalid("Hypersnap block without header".into()))?;
    if header.shard_id != shard_id {
        return Err(SourceError::Invalid(format!(
            "asked for shard {shard_id}, got a block of shard {}",
            header.shard_id
        )));
    }
    let cert = block.certificate.as_ref().ok_or_else(|| {
        SourceError::Invalid(format!(
            "block {} of shard {shard_id} is not certified",
            header.height
        ))
    })?;
    if cert.shard_id != shard_id || cert.height != header.height || cert.block_hash != block.hash {
        return Err(SourceError::Invalid(format!(
            "certificate of block {} of shard {shard_id} does not match the block",
            header.height
        )));
    }
    let height = header.height;
    // Shard 0 lists user messages in `messages`. Shards 1 and 2 group them into
    // one `Transaction` per FID (and leave `messages` empty). Execution order
    // either way; system messages of both forms are skipped.
    let system_messages = block.system_messages.len()
        + block
            .transactions
            .iter()
            .map(|t| t.system_messages.len())
            .sum::<usize>();
    let mut messages = block.messages;
    messages.extend(block.transactions.into_iter().flat_map(|t| t.user_messages));
    Ok(RelayBlock {
        shard_id,
        height,
        system_messages,
        hash: block.hash,
        messages,
    })
}

/// Adapts a [`HypersnapBlockSource`] to the relay's [`BlockSource`].
pub struct CertifiedSource<S: HypersnapBlockSource> {
    inner: Arc<S>,
}

impl<S: HypersnapBlockSource> CertifiedSource<S> {
    pub fn new(inner: S) -> Self {
        Self {
            inner: Arc::new(inner),
        }
    }

    pub fn from_arc(inner: Arc<S>) -> Self {
        Self { inner }
    }

    pub fn inner(&self) -> &Arc<S> {
        &self.inner
    }
}

#[async_trait::async_trait]
impl<S: HypersnapBlockSource> BlockSource for CertifiedSource<S> {
    fn network(&self) -> Network {
        Network::Hypersnap
    }

    fn open(&self, shard_id: u32, from_height: u64) -> BlockStream {
        self.inner
            .certified_blocks(shard_id, from_height)
            .map(move |item| item.and_then(|b| certified_to_relay_block(shard_id, b)))
            .boxed()
    }

    async fn tip(&self, shard_id: u32) -> Result<Option<u64>, SourceError> {
        self.inner.certified_tip(shard_id).await
    }
}

/// gRPC client of the certified-block stream.
pub struct GrpcHypersnapBlockSource {
    pool: Arc<EndpointPool>,
}

impl GrpcHypersnapBlockSource {
    pub fn new(pool: Arc<EndpointPool>) -> Self {
        Self { pool }
    }
}

#[async_trait::async_trait]
impl HypersnapBlockSource for GrpcHypersnapBlockSource {
    fn certified_blocks(&self, shard_id: u32, from_height: u64) -> HypersnapBlockStream {
        let pool = self.pool.clone();
        futures::stream::once(async move {
            tokio::time::sleep(pool.rpc_delay()).await;
            let ep = pool.current();
            let mut client = ep.client.clone();
            // No deadline: the stream stays open at the tip.
            let request = pool.stream_request(hypersnap_proto::CertifiedBlocksRequest {
                shard_id,
                start_height: from_height,
                stop_height: None,
            });
            let rpc_error = |pool: &EndpointPool, index: usize, url: String, status| {
                // A transport error or a pruned height: the next node may
                // have it.
                pool.failover(index);
                SourceError::Rpc {
                    endpoint: url,
                    status: Box::new(status),
                }
            };
            match client.get_certified_blocks(request).await {
                Ok(response) => {
                    let (index, url) = (ep.index, ep.url.clone());
                    response
                        .into_inner()
                        .map(move |item| {
                            item.map_err(|status| rpc_error(&pool, index, url.clone(), status))
                        })
                        .boxed()
                }
                Err(status) => {
                    let err = rpc_error(&pool, ep.index, ep.url, status);
                    futures::stream::once(async move { Err(err) }).boxed()
                }
            }
        })
        .flatten()
        .boxed()
    }

    async fn certified_tip(&self, shard_id: u32) -> Result<Option<u64>, SourceError> {
        let info = self
            .pool
            .get_info()
            .await
            .map_err(|status| SourceError::Rpc {
                endpoint: self.pool.current().url,
                status: Box::new(status),
            })?;
        Ok(info
            .shard_infos
            .iter()
            .find(|s| s.shard_id == shard_id)
            .map(|s| s.max_height))
    }
}

/// In-memory certified blocks. Tests push blocks; streams follow the tip.
#[derive(Clone, Default)]
pub struct MemoryHypersnapSource {
    inner: Arc<MemoryInner>,
}

#[derive(Default)]
struct MemoryInner {
    blocks: Mutex<BTreeMap<(u32, u64), HypersnapBlock>>,
    notify: tokio::sync::Notify,
    fail_next: AtomicU32,
}

impl MemoryHypersnapSource {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&self, block: HypersnapBlock) {
        let header = block.header.as_ref().expect("header");
        let key = (header.shard_id, header.height);
        self.inner.blocks.lock().unwrap().insert(key, block);
        self.inner.notify.notify_waiters();
    }

    /// Builds and pushes a certified block. The block hash is BLAKE3 of the
    /// encoded header here (Keccak-256 on the real chain, FIP §17.7).
    pub fn push_messages(
        &self,
        shard_id: u32,
        height: u64,
        messages: Vec<Message>,
    ) -> HypersnapBlock {
        let block = certified_block(shard_id, height, messages);
        self.push(block.clone());
        block
    }

    /// The next `n` item reads fail (to test reopen and backoff).
    pub fn fail_next(&self, n: u32) {
        self.inner.fail_next.store(n, Ordering::SeqCst);
    }

    /// The next height after the highest block of `shard_id`, or `first`.
    pub fn next_height(&self, shard_id: u32, first: u64) -> u64 {
        self.inner
            .blocks
            .lock()
            .unwrap()
            .range((shard_id, 0)..=(shard_id, u64::MAX))
            .next_back()
            .map(|((_, h), _)| h + 1)
            .unwrap_or(first)
    }
}

/// A certified block in the layout of FIP §17.7: shard 0 lists the user
/// messages, shards 1 and 2 group them into one transaction per message here.
pub fn certified_block(shard_id: u32, height: u64, messages: Vec<Message>) -> HypersnapBlock {
    let (messages, transactions) = if shard_id == 0 {
        (messages, vec![])
    } else {
        let txns = messages
            .into_iter()
            .map(|m| Transaction {
                fid: m.data.as_ref().map(|d| d.fid).unwrap_or(0),
                user_messages: vec![m],
                ..Default::default()
            })
            .collect();
        (vec![], txns)
    };
    let header = HypersnapBlockHeader {
        shard_id,
        height,
        timestamp: height,
        ..Default::default()
    };
    let hash = blake3::hash(&header.encode_to_vec()).as_bytes().to_vec();
    HypersnapBlock {
        certificate: Some(CommitCertificate {
            shard_id,
            height,
            block_hash: hash.clone(),
            ..Default::default()
        }),
        header: Some(header),
        hash,
        messages,
        transactions,
        ..Default::default()
    }
}

#[async_trait::async_trait]
impl HypersnapBlockSource for MemoryHypersnapSource {
    fn certified_blocks(&self, shard_id: u32, from_height: u64) -> HypersnapBlockStream {
        let inner = self.inner.clone();
        futures::stream::unfold((inner, from_height), move |(inner, next)| async move {
            loop {
                let fail = inner
                    .fail_next
                    .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
                    .is_ok();
                if fail {
                    let err = SourceError::Invalid("injected failure".into());
                    return Some((Err(err), (inner, next)));
                }
                let block = {
                    // Register for the wakeup before the lookup, so a push
                    // between the two is not missed.
                    let notified = inner.notify.notified();
                    tokio::pin!(notified);
                    notified.as_mut().enable();
                    let block = inner.blocks.lock().unwrap().get(&(shard_id, next)).cloned();
                    if block.is_none() {
                        let _ = tokio::time::timeout(Duration::from_millis(250), notified).await;
                    }
                    block
                };
                if let Some(block) = block {
                    return Some((Ok(block), (inner, next + 1)));
                }
            }
        })
        .boxed()
    }

    async fn certified_tip(&self, shard_id: u32) -> Result<Option<u64>, SourceError> {
        Ok(self
            .inner
            .blocks
            .lock()
            .unwrap()
            .range((shard_id, 0)..=(shard_id, u64::MAX))
            .next_back()
            .map(|((_, h), _)| *h))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn memory_source_follows_tip_and_checks_certificates() {
        let mem = MemoryHypersnapSource::new();
        let source = CertifiedSource::new(mem.clone());
        mem.push_messages(1, 10, vec![]);
        let mut stream = source.open(1, 10);
        assert_eq!(stream.next().await.unwrap().unwrap().height, 10);
        let pusher = mem.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(30)).await;
            pusher.push_messages(1, 11, vec![]);
        });
        assert_eq!(stream.next().await.unwrap().unwrap().height, 11);
        assert_eq!(source.tip(1).await.unwrap(), Some(11));
        assert_eq!(source.tip(2).await.unwrap(), None);

        // Shard 0 (messages) and shard 1 (transactions) layouts both yield the
        // user messages in order.
        let m = |n: u8| Message {
            hash: vec![n; 20],
            ..Default::default()
        };
        let b0 = certified_to_relay_block(0, certified_block(0, 1, vec![m(1), m(2)])).unwrap();
        assert_eq!(b0.messages, vec![m(1), m(2)]);
        let mut raw1 = certified_block(1, 1, vec![m(3), m(4)]);
        assert!(raw1.messages.is_empty());
        raw1.transactions[0]
            .system_messages
            .push(Default::default());
        let b1 = certified_to_relay_block(1, raw1).unwrap();
        assert_eq!(b1.messages, vec![m(3), m(4)]);
        assert_eq!(b1.system_messages, 1);

        let mut uncertified = certified_block(2, 5, vec![]);
        uncertified.certificate = None;
        assert!(certified_to_relay_block(2, uncertified).is_err());
        let mut wrong = certified_block(2, 5, vec![]);
        wrong.certificate.as_mut().unwrap().height = 6;
        assert!(certified_to_relay_block(2, wrong).is_err());
        assert!(certified_to_relay_block(1, certified_block(2, 5, vec![])).is_err());
    }

    #[tokio::test]
    async fn grpc_source_reports_an_unreachable_node() {
        let metrics: Arc<dyn crate::metrics::RelayMetrics> = Arc::new(crate::metrics::NoopMetrics);
        let pool = EndpointPool::new(
            Network::Hypersnap,
            &["http://127.0.0.1:1".to_string()],
            crate::endpoints::EndpointOptions {
                connect_timeout: Duration::from_millis(100),
                request_timeout: Duration::from_millis(100),
                max_message_bytes: 1 << 20,
                auth: None,
                rpcs_per_minute: 0,
            },
            metrics,
        )
        .unwrap();
        let src = GrpcHypersnapBlockSource::new(Arc::new(pool));
        assert!(matches!(
            src.certified_tip(0).await,
            Err(SourceError::Rpc { .. })
        ));
        let mut s = src.certified_blocks(0, 1);
        assert!(matches!(s.next().await, Some(Err(SourceError::Rpc { .. }))));
    }
}
