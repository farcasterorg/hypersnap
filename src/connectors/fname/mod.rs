use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::{
    sync::{broadcast, mpsc},
    time::{sleep, Duration},
};
use tracing::{debug, error, info, warn};

use crate::mempool::mempool::{MempoolRequest, MempoolSource};
use crate::{
    proto::{FnameTransfer, UserNameProof, UserNameType},
    storage::store::mempool_poller::MempoolMessage,
    storage::store::node_local_state::LocalStateStore,
    utils::statsd_wrapper::StatsdClientWrapper,
};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub start_from: Option<u64>,
    pub stop_at: Option<u64>,
    pub url: String,
    pub disable: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            start_from: None,
            stop_at: None,
            url: "https://fnames.farcaster.xyz/transfers".to_string(),
            disable: false,
        }
    }
}

#[derive(Clone)]
pub enum FnameRequest {
    RetryFid(u64),
    RetryFname(String),
}

#[derive(Deserialize, Debug)]
struct TransfersData {
    transfers: Vec<Transfer>,
}

#[derive(Deserialize, Debug)]
struct CurrentTransfer {
    transfer: Transfer,
}

#[derive(Deserialize, Debug, Clone)]
struct Transfer {
    id: u64,

    #[allow(dead_code)] // TODO
    timestamp: u64,

    #[allow(dead_code)] // TODO
    username: String,

    #[allow(dead_code)] // TODO
    owner: String,

    #[allow(dead_code)] // TODO
    from: u64,

    #[allow(dead_code)] // TODO
    to: u64,

    #[allow(dead_code)] // TODO
    user_signature: String,

    #[allow(dead_code)] // TODO
    server_signature: String,
}

#[derive(Error, Debug)]
pub enum FetchError {
    #[error("non-sequential IDs found")]
    NonSequentialIds { position: u64, id: u64 },

    #[error("stop fetching")]
    Stop,

    #[error(transparent)]
    Reqwest(#[from] reqwest::Error),

    #[error("invalid format")]
    InvalidFormat,
}

fn transfer_to_fname_transfer(t: &Transfer) -> Result<FnameTransfer, FetchError> {
    // The fname registry currently emits hex strings prefixed with `0x`. Be
    // explicit about that contract — silently slicing the first two chars off
    // an unprefixed value would decode different bytes rather than fail loudly.
    if !t.owner.starts_with("0x")
        || t.owner.len() <= 2
        || !t.server_signature.starts_with("0x")
        || t.server_signature.len() <= 2
    {
        return Err(FetchError::InvalidFormat);
    }
    let owner = hex::decode(&t.owner[2..]).map_err(|_| FetchError::InvalidFormat)?;
    let signature = hex::decode(&t.server_signature[2..]).map_err(|_| FetchError::InvalidFormat)?;
    Ok(FnameTransfer {
        id: t.id,
        from_fid: t.from,
        proof: Some(UserNameProof {
            timestamp: t.timestamp,
            name: t.username.clone().into_bytes(),
            owner,
            signature,
            fid: t.to,
            r#type: UserNameType::UsernameTypeFname as i32,
        }),
    })
}

/// Synchronously fetch all transfers for a given fname from the fname registry.
///
/// Used by both the background `Fetcher` retry path and the gRPC server's on-demand
/// recovery path when a `UserDataAdd` for a username arrives before the registry
/// poll has produced the corresponding proof.
pub async fn fetch_transfers_for_fname(
    base_url: &str,
    fname: &str,
) -> Result<Vec<FnameTransfer>, FetchError> {
    // Build the URL via `query_pairs_mut` so that fname values containing `&`,
    // `=`, or other reserved characters can't be smuggled into adjacent
    // parameters (`fname=foo&from_id=0`-style injection). Untrusted fnames flow
    // here from the gRPC recovery path.
    let mut url = reqwest::Url::parse(base_url).map_err(|_| FetchError::InvalidFormat)?;
    url.query_pairs_mut().append_pair("fname", fname);
    let response = reqwest::get(url).await?.json::<TransfersData>().await?;
    response
        .transfers
        .iter()
        .map(transfer_to_fname_transfer)
        .collect()
}

/// Lookup transfers for a single fname from an fname registry.
///
/// Implemented by [`HttpFnameTransferLookup`] in production; tests inject a mock to
/// drive the gRPC server's on-demand recovery flow without spinning up an HTTP server.
#[async_trait]
pub trait FnameTransferLookup: Send + Sync {
    async fn lookup_fname(&self, fname: &str) -> Result<Vec<FnameTransfer>, FetchError>;
}

pub struct HttpFnameTransferLookup {
    base_url: String,
}

impl HttpFnameTransferLookup {
    pub fn new(base_url: String) -> Self {
        Self { base_url }
    }
}

#[async_trait]
impl FnameTransferLookup for HttpFnameTransferLookup {
    async fn lookup_fname(&self, fname: &str) -> Result<Vec<FnameTransfer>, FetchError> {
        fetch_transfers_for_fname(&self.base_url, fname).await
    }
}

pub struct Fetcher {
    position: u64,
    cfg: Config,
    mempool_tx: mpsc::Sender<MempoolRequest>,
    statsd_client: StatsdClientWrapper,
    local_state_store: LocalStateStore,
    fname_request_rx: broadcast::Receiver<FnameRequest>,
}

impl Fetcher {
    pub fn new(
        cfg: Config,
        mempool_tx: mpsc::Sender<MempoolRequest>,
        statsd_client: StatsdClientWrapper,
        local_state_store: LocalStateStore,
        fname_request_rx: broadcast::Receiver<FnameRequest>,
    ) -> Self {
        Fetcher {
            position: 0,
            cfg,
            mempool_tx,
            statsd_client,
            local_state_store,
            fname_request_rx,
        }
    }

    fn record_username_proof(&self, transfer_id: u64) {
        match self
            .local_state_store
            .set_latest_fname_transfer_id(transfer_id)
        {
            Err(err) => {
                error!(
                    transfer_id,
                    err = err.to_string(),
                    "Unable to store last username proof",
                );
            }
            _ => {}
        }
    }

    fn latest_fname_transfer_in_db(&self) -> u64 {
        match self.local_state_store.get_latest_fname_transfer_id() {
            Ok(id) => id.unwrap_or(0),
            Err(err) => {
                error!(
                    err = err.to_string(),
                    "Unable to retrieve last username proof",
                );
                0
            }
        }
    }

    fn count(&self, key: &str, value: i64) {
        self.statsd_client
            .count(format!("fnames.{}", key).as_str(), value, vec![]);
    }

    fn gauge(&self, key: &str, value: u64) {
        self.statsd_client
            .gauge(format!("fnames.{}", key).as_str(), value, vec![]);
    }

    async fn fetch(&mut self) -> Result<(), FetchError> {
        loop {
            let url = format!("{}?from_id={}", self.cfg.url, self.position);
            debug!(%url, "fetching transfers");

            let response = reqwest::get(&url).await?.json::<TransfersData>().await?;

            let count = response.transfers.len();

            if count == 0 {
                return Ok(());
            }

            info!(count, position = self.position, "found new transfers");

            let mut last_transfer_id = 0;
            for t in response.transfers {
                if t.id <= self.position {
                    return Err(FetchError::NonSequentialIds {
                        id: t.id,
                        position: self.position,
                    });
                }
                if self.cfg.stop_at.is_some() && t.id >= self.cfg.stop_at.unwrap() {
                    return Err(FetchError::Stop);
                }
                self.position = t.id;
                let res = self.submit_transfer(&t).await;
                if let Err(err) = res {
                    error!(
                        transfer_id = t.id,
                        err = err.to_string(),
                        "Error processing fname transfer"
                    );
                }
                self.gauge("latest_transfer_id", t.id);
                last_transfer_id = t.id;
            }
            if last_transfer_id > 0 {
                self.record_username_proof(last_transfer_id);
            }
        }
    }

    async fn submit_transfer(&mut self, t: &Transfer) -> Result<(), FetchError> {
        let fname_transfer = transfer_to_fname_transfer(t)?;
        self.count("num_transfers", 1);
        if let Err(err) = self
            .mempool_tx
            .send(MempoolRequest::AddMessage(
                MempoolMessage::FnameTransfer(fname_transfer),
                MempoolSource::Local,
                None,
            ))
            .await
        {
            error!(
                from = t.from,
                to = t.to,
                err = err.to_string(),
                "Unable to send fname transfer to mempool"
            )
        }
        info!(
            from = t.from,
            fid = t.to,
            name = t.username.clone(),
            "Processed fname transfer"
        );
        Ok(())
    }

    async fn set_initial_position(&mut self) -> Result<(), FetchError> {
        match self.cfg.start_from {
            None => {
                let url = format!("{}/current", self.cfg.url);
                debug!(%url, "fetching transfers");

                let response = reqwest::get(&url)
                    .await?
                    .error_for_status()?
                    .json::<CurrentTransfer>()
                    .await?;

                self.position = response.transfer.id;
            }
            Some(start_from) => {
                self.position = start_from.max(self.latest_fname_transfer_in_db());
            }
        };
        Ok(())
    }

    async fn retry_fid(&mut self, fid: u64) -> Result<(), FetchError> {
        info!(fid, "Retrying fname events for fid");

        let url = format!("{}?fid={}", self.cfg.url, fid);
        debug!(%url, "fetching current transfer for retry");

        let response = reqwest::get(&url).await?.json::<TransfersData>().await?;

        for t in response.transfers {
            info!(
                fid,
                transfer_id = t.id,
                username = t.username,
                "Retrying fname transfer"
            );
            if let Err(e) = self.submit_transfer(&t).await {
                error!(
                    fid,
                    transfer_id = t.id,
                    err = e.to_string(),
                    "Error processing fname transfer during retry"
                );
            }
        }

        Ok(())
    }

    async fn retry_fname(&mut self, fname: &str) -> Result<(), FetchError> {
        info!(fname, "Retrying fname events for fname");

        let url = format!("{}?fname={}", self.cfg.url, fname);
        debug!(%url, "fetching current transfer for retry");

        let response = reqwest::get(&url).await?.json::<TransfersData>().await?;

        for t in response.transfers {
            info!(
                fid = t.to,
                transfer_id = t.id,
                username = t.username,
                "Retrying fname transfer"
            );
            if let Err(e) = self.submit_transfer(&t).await {
                error!(
                    fid = t.to,
                    transfer_id = t.id,
                    err = e.to_string(),
                    "Error processing fname transfer during retry"
                );
            }
        }

        Ok(())
    }

    pub async fn run(&mut self) -> () {
        loop {
            match self.set_initial_position().await {
                Ok(()) => break,
                Err(err) => {
                    warn!(error = %err, "Unable to set initial position for fname ingest; retrying before polling transfers");
                    sleep(Duration::from_secs(5)).await;
                }
            }
        }
        info!(start_id = self.position, "Starting fname ingest");

        loop {
            tokio::select! {
                biased;

                request = self.fname_request_rx.recv() => {
                    match request {
                        Err(_) => {
                            // Ignore, this can happen if we don't run an admin server
                        },
                        Ok(request) => {
                            match request {
                                FnameRequest::RetryFid(retry_fid) => {
                                    if let Err(err) = self.retry_fid(retry_fid).await {
                                        error!(fid = retry_fid, "Unable to retry fid: {}", err.to_string())
                                    }
                                },
                                FnameRequest::RetryFname(fname) => {
                                    if let Err(err) = self.retry_fname(fname.as_str()).await {
                                        error!(fname, "Unable to retry fname: {}", err.to_string())
                                    }
                                }
                            }
                        }
                    }
                }

                _ = sleep(Duration::from_secs(5)) => {
                    let result = self.fetch().await;

                    if let Err(e) = result {
                        match e {
                            FetchError::NonSequentialIds { id, position } => {
                                error!(id, position, %e);
                            }
                            FetchError::Reqwest(request_error) => {
                                warn!(error = %request_error, "reqwest error fetching transfers");
                            }
                            FetchError::Stop => {
                                info!(position = self.position, "stopped fetching transfers");
                                return;
                            }
                            FetchError::InvalidFormat => {
                                error!("fname server returning different format than expected");
                            }
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{db::RocksDB, store::test_helper};
    use std::sync::Arc;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    #[tokio::test]
    async fn failed_initial_position_retries_without_replaying_history() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (requests_tx, mut requests_rx) = mpsc::channel(8);
        let server = tokio::spawn(async move {
            let mut current_requests = 0;
            loop {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut buffer = vec![0; 4096];
                let len = socket.read(&mut buffer).await.unwrap();
                let request = String::from_utf8_lossy(&buffer[..len]);
                let path = request.split_whitespace().nth(1).unwrap().to_string();
                requests_tx.send(path.clone()).await.unwrap();
                let transfer = |id| {
                    serde_json::json!({
                        "id": id, "timestamp": 1, "username": "example", "owner": "0x01",
                        "from": 0, "to": 42, "user_signature": "0x01", "server_signature": "0x01"
                    })
                };
                let (status, body) = if path.ends_with("/current") {
                    current_requests += 1;
                    if current_requests == 1 {
                        ("503 Service Unavailable", "{}".to_string())
                    } else {
                        (
                            "200 OK",
                            serde_json::json!({"transfer": transfer(1000)}).to_string(),
                        )
                    }
                } else if path.ends_with("from_id=0") {
                    (
                        "200 OK",
                        serde_json::json!({"transfers": [transfer(1)]}).to_string(),
                    )
                } else {
                    ("200 OK", "{\"transfers\":[]}".to_string())
                };
                socket.write_all(format!("HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes()).await.unwrap();
            }
        });
        let dir = tempfile::TempDir::new().unwrap();
        let db = RocksDB::new(dir.path().join("local.db").to_str().unwrap());
        db.open().unwrap();
        let (mempool_tx, mut mempool_rx) = mpsc::channel(8);
        let (_retry_tx, retry_rx) = broadcast::channel(8);
        let mut fetcher = Fetcher::new(
            Config {
                url: format!("http://{address}/transfers"),
                ..Config::default()
            },
            mempool_tx,
            test_helper::statsd_client(),
            LocalStateStore::new(Arc::new(db)),
            retry_rx,
        );
        let worker = tokio::spawn(async move { fetcher.run().await });
        let paths = tokio::time::timeout(Duration::from_secs(15), async {
            let mut paths = Vec::new();
            for _ in 0..3 {
                paths.push(requests_rx.recv().await.unwrap());
            }
            paths
        })
        .await;
        worker.abort();
        server.abort();
        assert_eq!(
            paths.unwrap(),
            vec![
                "/transfers/current",
                "/transfers/current",
                "/transfers?from_id=1000"
            ]
        );
        assert!(
            mempool_rx.try_recv().is_err(),
            "failed initialization must not enqueue historical transfers"
        );
    }
}
