//! In-process fake snapchain / Hypersnap nodes for the end-to-end tests.
//!
//! The fake serves only the `HubService` methods that the relay calls
//! (`GetShardChunks`, `GetBlocks`, `GetCertifiedBlocks`, `GetInfo`,
//! `SubmitBulkMessages`, `SubmitMessage`) through a hand-written tonic router, so it does not break
//! when the proto gains RPCs. Every other method answers `Unimplemented`.
#![allow(dead_code)]
// The fake mirrors tonic's handler signatures, which return `Status`.
#![allow(clippy::result_large_err)]

pub mod messages;

use hypersnap_proto::{
    bulk_message_response, Block, BlockHeader, BlocksRequest, BulkMessageResponse,
    CertifiedBlocksRequest, CommitCertificate, GetInfoRequest, GetInfoResponse,
    GetPivotRecordRequest, Height, HypersnapBlock, HypersnapBlockHeader, Message, MessageError,
    OnChainEvent, PivotRecord, ShardChunk, ShardChunksRequest, ShardChunksResponse, ShardHeader,
    ShardInfo, SubmitBulkMessagesRequest, SubmitBulkMessagesResponse, Transaction,
    ValidatorMessage,
};
use std::collections::{BTreeMap, HashMap};
use std::convert::Infallible;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tonic::body::BoxBody;
use tonic::codec::ProstCodec;
use tonic::codegen::{http, Body, BoxFuture, Context, Poll, Service, StdError};
use tonic::metadata::MetadataValue;
use tonic::server::{Grpc, NamedService};
use tonic::{Request, Response, Status};

/// Decides an error for a submitted message: `(message, nth submission of its
/// hash)` -> `Some((err_code, message))`.
pub type Responder = Box<dyn Fn(&Message, u32) -> Option<(String, String)> + Send + Sync>;
pub type AcceptHook = Box<dyn Fn(&Message) + Send + Sync>;

pub struct FakeHub {
    pub name: String,
    pub version: Mutex<String>,
    chunks: Mutex<BTreeMap<(u32, u64), ShardChunk>>,
    blocks: Mutex<BTreeMap<u64, Block>>,
    /// Certified Hypersnap blocks by (shard, height).
    certified: Mutex<BTreeMap<(u32, u64), HypersnapBlock>>,
    merged: Mutex<HashMap<Vec<u8>, Message>>,
    /// Every submitted hash, in order (duplicates included).
    submissions: Mutex<Vec<Vec<u8>>>,
    attempts: Mutex<HashMap<Vec<u8>, u32>>,
    responders: Mutex<Vec<Responder>>,
    on_accept: Mutex<Option<AcceptHook>>,
    /// Every RPC fails with `Unavailable`.
    pub fail_all: AtomicBool,
    /// `SubmitBulkMessages` answers `Unimplemented`.
    pub bulk_unimplemented: AtomicBool,
    pub bulk_calls: AtomicUsize,
    pub single_calls: AtomicUsize,
    pub fetch_calls: AtomicUsize,
    /// Delay of each submission RPC.
    pub submit_delay_ms: AtomicUsize,
    /// `GetPivotRecord` answers this, or `Unimplemented` (a snapchain node).
    pub pivot: Mutex<Option<PivotRecord>>,
}

impl FakeHub {
    pub fn new(name: &str) -> Arc<Self> {
        Arc::new(Self {
            name: name.to_string(),
            version: Mutex::new("0.13.3".into()),
            chunks: Mutex::default(),
            blocks: Mutex::default(),
            certified: Mutex::default(),
            merged: Mutex::default(),
            submissions: Mutex::default(),
            attempts: Mutex::default(),
            responders: Mutex::default(),
            on_accept: Mutex::default(),
            fail_all: AtomicBool::new(false),
            bulk_unimplemented: AtomicBool::new(false),
            bulk_calls: AtomicUsize::new(0),
            single_calls: AtomicUsize::new(0),
            fetch_calls: AtomicUsize::new(0),
            submit_delay_ms: AtomicUsize::new(0),
            pivot: Mutex::default(),
        })
    }

    /// A certified Hypersnap block of shard 1/2 with the user messages in one
    /// transaction each.
    pub fn add_certified(&self, shard: u32, height: u64, user: Vec<Message>) {
        let hash = blake3::hash(&[shard as u8, height as u8])
            .as_bytes()
            .to_vec();
        let block = HypersnapBlock {
            header: Some(HypersnapBlockHeader {
                shard_id: shard,
                height,
                ..Default::default()
            }),
            transactions: user
                .into_iter()
                .map(|m| Transaction {
                    fid: m.data.as_ref().map(|d| d.fid).unwrap_or(0),
                    user_messages: vec![m],
                    ..Default::default()
                })
                .collect(),
            certificate: Some(CommitCertificate {
                shard_id: shard,
                height,
                block_hash: hash.clone(),
                ..Default::default()
            }),
            hash,
            ..Default::default()
        };
        self.certified
            .lock()
            .unwrap()
            .insert((shard, height), block);
    }

    fn certified_from(&self, r: CertifiedBlocksRequest) -> Vec<HypersnapBlock> {
        let stop = r.stop_height.unwrap_or(u64::MAX);
        self.certified
            .lock()
            .unwrap()
            .range((r.shard_id, r.start_height)..(r.shard_id, stop))
            .map(|(_, b)| b.clone())
            .collect()
    }

    /// A shard-1/2 chunk with the user messages in one transaction each and
    /// `system` on-chain-event system messages.
    pub fn add_chunk(&self, shard: u32, height: u64, user: Vec<Message>, system: usize) {
        let mut transactions: Vec<Transaction> = user
            .into_iter()
            .map(|m| Transaction {
                fid: m.data.as_ref().map(|d| d.fid).unwrap_or(0),
                user_messages: vec![m],
                ..Default::default()
            })
            .collect();
        for i in 0..system {
            transactions.push(Transaction {
                fid: 1_000 + i as u64,
                system_messages: vec![ValidatorMessage {
                    on_chain_event: Some(OnChainEvent {
                        fid: 1_000 + i as u64,
                        ..Default::default()
                    }),
                    ..Default::default()
                }],
                ..Default::default()
            });
        }
        let chunk = ShardChunk {
            header: Some(ShardHeader {
                height: Some(Height {
                    shard_index: shard,
                    block_number: height,
                }),
                ..Default::default()
            }),
            hash: format!("{shard}-{height}").into_bytes(),
            transactions,
            ..Default::default()
        };
        self.chunks.lock().unwrap().insert((shard, height), chunk);
    }

    /// Appends a chunk after the highest one of `shard` (or at `first`).
    pub fn append_chunk(&self, shard: u32, first: u64, user: Vec<Message>) -> u64 {
        let height = self.next_chunk_height(shard, first);
        self.add_chunk(shard, height, user, 0);
        height
    }

    pub fn next_chunk_height(&self, shard: u32, first: u64) -> u64 {
        self.chunks
            .lock()
            .unwrap()
            .range((shard, 0)..=(shard, u64::MAX))
            .next_back()
            .map(|((_, h), _)| h + 1)
            .unwrap_or(first)
    }

    /// A shard-0 block with user messages and `events` block events.
    pub fn add_block(&self, height: u64, user: Vec<Message>, events: usize) {
        let block = Block {
            header: Some(BlockHeader {
                height: Some(Height {
                    shard_index: 0,
                    block_number: height,
                }),
                ..Default::default()
            }),
            hash: format!("0-{height}").into_bytes(),
            transactions: vec![Transaction {
                user_messages: user,
                ..Default::default()
            }],
            events: (0..events).map(|_| Default::default()).collect(),
            ..Default::default()
        };
        self.blocks.lock().unwrap().insert(height, block);
    }

    pub fn respond_with(&self, responder: Responder) {
        self.responders.lock().unwrap().push(responder);
    }

    pub fn on_accept(&self, hook: AcceptHook) {
        *self.on_accept.lock().unwrap() = Some(hook);
    }

    /// Marks a message as already on this network.
    pub fn premerge(&self, message: &Message) {
        self.merged
            .lock()
            .unwrap()
            .insert(message.hash.clone(), message.clone());
    }

    pub fn merged(&self) -> HashMap<Vec<u8>, Message> {
        self.merged.lock().unwrap().clone()
    }

    pub fn merged_count(&self) -> usize {
        self.merged.lock().unwrap().len()
    }

    pub fn submissions_of(&self, hash: &[u8]) -> usize {
        self.submissions
            .lock()
            .unwrap()
            .iter()
            .filter(|h| h.as_slice() == hash)
            .count()
    }

    pub fn total_submissions(&self) -> usize {
        self.submissions.lock().unwrap().len()
    }

    fn submit_one(&self, message: &Message) -> Result<Message, (String, String)> {
        self.submissions.lock().unwrap().push(message.hash.clone());
        let nth = {
            let mut attempts = self.attempts.lock().unwrap();
            let n = attempts.entry(message.hash.clone()).or_insert(0);
            *n += 1;
            *n
        };
        for responder in self.responders.lock().unwrap().iter() {
            if let Some(err) = responder(message, nth) {
                return Err(err);
            }
        }
        {
            let mut merged = self.merged.lock().unwrap();
            if merged.contains_key(&message.hash) {
                return Err((
                    "bad_request.duplicate".into(),
                    "message has already been merged".into(),
                ));
            }
            merged.insert(message.hash.clone(), message.clone());
        }
        if let Some(hook) = self.on_accept.lock().unwrap().as_ref() {
            hook(message);
        }
        Ok(message.clone())
    }

    async fn submit_delay(&self) {
        let ms = self.submit_delay_ms.load(Ordering::Relaxed);
        if ms > 0 {
            tokio::time::sleep(Duration::from_millis(ms as u64)).await;
        }
    }

    fn check_up(&self) -> Result<(), Status> {
        if self.fail_all.load(Ordering::SeqCst) {
            Err(Status::unavailable(format!("{} is down", self.name)))
        } else {
            Ok(())
        }
    }

    async fn submit_bulk(
        &self,
        req: SubmitBulkMessagesRequest,
    ) -> Result<SubmitBulkMessagesResponse, Status> {
        self.check_up()?;
        if self.bulk_unimplemented.load(Ordering::SeqCst) {
            return Err(Status::unimplemented("SubmitBulkMessages"));
        }
        self.bulk_calls.fetch_add(1, Ordering::SeqCst);
        self.submit_delay().await;
        let mut messages: Vec<BulkMessageResponse> = req
            .messages
            .iter()
            .map(|m| BulkMessageResponse {
                response: Some(match self.submit_one(m) {
                    Ok(m) => bulk_message_response::Response::Message(m),
                    Err((code, message)) => {
                        bulk_message_response::Response::MessageError(MessageError {
                            hash: m.hash.clone(),
                            err_code: code,
                            message,
                        })
                    }
                }),
            })
            .collect();
        // The node answers in shard-group order, not request order.
        messages.reverse();
        Ok(SubmitBulkMessagesResponse { messages })
    }

    async fn submit_message(&self, message: Message) -> Result<Message, Status> {
        self.check_up()?;
        self.single_calls.fetch_add(1, Ordering::SeqCst);
        self.submit_delay().await;
        self.submit_one(&message).map_err(|(code, msg)| {
            // The shape of `submit_message` in src/network/server.rs.
            let text = format!("{code}/{msg}");
            let mut status = if code.starts_with("bad_request") {
                Status::invalid_argument(text)
            } else if code.starts_with("db") || code.starts_with("internal") {
                Status::internal(text)
            } else if code.starts_with("unavailable") {
                Status::unavailable(text)
            } else {
                Status::unknown(text)
            };
            status.metadata_mut().insert(
                "x-err-code",
                MetadataValue::try_from(code.as_str()).unwrap(),
            );
            status
        })
    }

    fn shard_chunks(&self, req: ShardChunksRequest) -> Result<ShardChunksResponse, Status> {
        self.check_up()?;
        self.fetch_calls.fetch_add(1, Ordering::SeqCst);
        let stop = req.stop_block_number.unwrap_or(u64::MAX);
        let shard_chunks = self
            .chunks
            .lock()
            .unwrap()
            .range((req.shard_id, req.start_block_number)..(req.shard_id, stop))
            .map(|(_, c)| c.clone())
            .collect();
        Ok(ShardChunksResponse { shard_chunks })
    }

    fn blocks_in(&self, req: BlocksRequest) -> Result<Vec<Block>, Status> {
        self.check_up()?;
        self.fetch_calls.fetch_add(1, Ordering::SeqCst);
        let stop = req.stop_block_number.unwrap_or(u64::MAX);
        Ok(self
            .blocks
            .lock()
            .unwrap()
            .range(req.start_block_number..stop)
            .map(|(_, b)| b.clone())
            .collect())
    }

    fn info(&self) -> Result<GetInfoResponse, Status> {
        self.check_up()?;
        let chunks = self.chunks.lock().unwrap();
        let mut shard_infos = vec![ShardInfo {
            shard_id: 0,
            max_height: self
                .blocks
                .lock()
                .unwrap()
                .keys()
                .next_back()
                .copied()
                .unwrap_or(0),
            ..Default::default()
        }];
        for shard in [1u32, 2] {
            let max_height = chunks
                .range((shard, 0)..=(shard, u64::MAX))
                .next_back()
                .map(|((_, h), _)| *h)
                .unwrap_or(0);
            shard_infos.push(ShardInfo {
                shard_id: shard,
                max_height,
                ..Default::default()
            });
        }
        Ok(GetInfoResponse {
            version: self.version.lock().unwrap().clone(),
            num_shards: 2,
            shard_infos,
            ..Default::default()
        })
    }
}

/// One explicit service type per method, as tonic's generated code does.
macro_rules! unary_svc {
    ($name:ident, $req:ty, $res:ty, |$hub:ident, $r:ident| $body:expr) => {
        struct $name(Arc<FakeHub>);
        impl tonic::server::UnaryService<$req> for $name {
            type Response = $res;
            type Future = BoxFuture<Response<$res>, Status>;
            fn call(&mut self, request: Request<$req>) -> Self::Future {
                let $hub = self.0.clone();
                let $r = request.into_inner();
                Box::pin(async move { $body.map(Response::new) })
            }
        }
    };
}

unary_svc!(
    SubmitBulkSvc,
    SubmitBulkMessagesRequest,
    SubmitBulkMessagesResponse,
    |hub, r| hub.submit_bulk(r).await
);
unary_svc!(SubmitMessageSvc, Message, Message, |hub, r| hub
    .submit_message(r)
    .await);
unary_svc!(
    ShardChunksSvc,
    ShardChunksRequest,
    ShardChunksResponse,
    |hub, r| hub.shard_chunks(r)
);
unary_svc!(GetInfoSvc, GetInfoRequest, GetInfoResponse, |hub, _r| hub
    .info());
unary_svc!(
    GetPivotRecordSvc,
    GetPivotRecordRequest,
    PivotRecord,
    |hub, _r| hub
        .pivot
        .lock()
        .unwrap()
        .clone()
        .ok_or_else(|| Status::unimplemented("not a Hypersnap node"))
);

type BlockStream = futures::stream::BoxStream<'static, Result<Block, Status>>;

struct GetBlocksSvc(Arc<FakeHub>);

impl tonic::server::ServerStreamingService<BlocksRequest> for GetBlocksSvc {
    type Response = Block;
    type ResponseStream = BlockStream;
    type Future = BoxFuture<Response<BlockStream>, Status>;

    fn call(&mut self, request: Request<BlocksRequest>) -> Self::Future {
        let hub = self.0.clone();
        Box::pin(async move {
            let blocks = hub.blocks_in(request.into_inner())?;
            let stream: BlockStream = Box::pin(futures::stream::iter(blocks.into_iter().map(Ok)));
            Ok(Response::new(stream))
        })
    }
}

type CertifiedStream = futures::stream::BoxStream<'static, Result<HypersnapBlock, Status>>;

struct GetCertifiedBlocksSvc(Arc<FakeHub>);

impl tonic::server::ServerStreamingService<CertifiedBlocksRequest> for GetCertifiedBlocksSvc {
    type Response = HypersnapBlock;
    type ResponseStream = CertifiedStream;
    type Future = BoxFuture<Response<CertifiedStream>, Status>;

    fn call(&mut self, request: Request<CertifiedBlocksRequest>) -> Self::Future {
        let hub = self.0.clone();
        Box::pin(async move {
            if hub.fail_all.load(Ordering::Relaxed) {
                return Err(Status::unavailable("fail_all"));
            }
            let blocks = hub.certified_from(request.into_inner());
            let stream: CertifiedStream =
                Box::pin(futures::stream::iter(blocks.into_iter().map(Ok)));
            Ok(Response::new(stream))
        })
    }
}

#[derive(Clone)]
pub struct FakeHubServer {
    hub: Arc<FakeHub>,
}

impl NamedService for FakeHubServer {
    const NAME: &'static str = "HubService";
}

impl<B> Service<http::Request<B>> for FakeHubServer
where
    B: Body + Send + 'static,
    B::Error: Into<StdError> + Send + 'static,
{
    type Response = http::Response<BoxBody>;
    type Error = Infallible;
    type Future = BoxFuture<Self::Response, Infallible>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: http::Request<B>) -> Self::Future {
        let hub = self.hub.clone();
        match req.uri().path() {
            "/HubService/SubmitBulkMessages" => Box::pin(async move {
                Ok(Grpc::new(ProstCodec::default())
                    .unary(SubmitBulkSvc(hub), req)
                    .await)
            }),
            "/HubService/SubmitMessage" => Box::pin(async move {
                Ok(Grpc::new(ProstCodec::default())
                    .unary(SubmitMessageSvc(hub), req)
                    .await)
            }),
            "/HubService/GetShardChunks" => Box::pin(async move {
                Ok(Grpc::new(ProstCodec::default())
                    .unary(ShardChunksSvc(hub), req)
                    .await)
            }),
            "/HubService/GetInfo" => Box::pin(async move {
                Ok(Grpc::new(ProstCodec::default())
                    .unary(GetInfoSvc(hub), req)
                    .await)
            }),
            "/HubService/GetPivotRecord" => Box::pin(async move {
                Ok(Grpc::new(ProstCodec::default())
                    .unary(GetPivotRecordSvc(hub), req)
                    .await)
            }),
            "/HubService/GetBlocks" => Box::pin(async move {
                Ok(Grpc::new(ProstCodec::default())
                    .server_streaming(GetBlocksSvc(hub), req)
                    .await)
            }),
            "/HubService/GetCertifiedBlocks" => Box::pin(async move {
                Ok(Grpc::new(ProstCodec::default())
                    .server_streaming(GetCertifiedBlocksSvc(hub), req)
                    .await)
            }),
            _ => Box::pin(async move {
                Ok(http::Response::builder()
                    .status(200)
                    .header("grpc-status", "12")
                    .header("content-type", "application/grpc")
                    .body(tonic::codegen::empty_body())
                    .unwrap())
            }),
        }
    }
}

pub struct ServerHandle {
    pub url: String,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<()>,
}

impl ServerHandle {
    pub async fn stop(mut self) {
        if let Some(tx) = self.stop.take() {
            let _ = tx.send(());
        }
        let _ = self.task.await;
    }
}

pub async fn spawn_server(hub: Arc<FakeHub>) -> ServerHandle {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let task = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(FakeHubServer { hub })
            .serve_with_incoming_shutdown(
                tokio_stream::wrappers::TcpListenerStream::new(listener),
                async {
                    let _ = rx.await;
                },
            )
            .await
            .unwrap();
    });
    ServerHandle {
        url,
        stop: Some(tx),
        task,
    }
}

/// An address with nothing listening (connection refused).
pub async fn dead_url() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    drop(listener);
    url
}

/// A relay config with short timeouts for tests.
pub fn test_config(
    state_dir: &Path,
    snapchain: Vec<String>,
    hypersnap: Vec<String>,
) -> hypersnap_relay::RelayConfig {
    let mut cfg = hypersnap_relay::RelayConfig {
        snapchain_endpoints: snapchain,
        hypersnap_endpoints: hypersnap,
        state_dir: state_dir.to_path_buf(),
        seen_set_capacity: 100_000,
        retry_initial_ms: 10,
        retry_max_ms: 100,
        max_message_attempts: 5,
        poll_interval_ms: 20,
        request_timeout_ms: 2_000,
        connect_timeout_ms: 500,
        tip_interval_ms: 100,
        metrics_log_interval_secs: 0,
        snapchain_version: "auto".into(),
        ..Default::default()
    };
    cfg.deferred.retry_ms = 50;
    cfg
}

pub async fn wait_until(what: &str, timeout: Duration, mut cond: impl FnMut() -> bool) {
    let deadline = tokio::time::Instant::now() + timeout;
    while !cond() {
        if tokio::time::Instant::now() > deadline {
            panic!("timed out waiting for: {what}");
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

pub fn read_cursor(state_dir: &Path, network: &str, shard: u32) -> Option<u64> {
    let path = state_dir
        .join("cursors")
        .join(format!("{network}-shard-{shard}.json"));
    let bytes = std::fs::read(path).ok()?;
    let v: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    v["next_height"].as_u64()
}
