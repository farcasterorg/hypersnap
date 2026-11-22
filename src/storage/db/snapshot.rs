use super::snapshot_restore::RestoreSession;
pub use super::snapshot_restore::{has_pending_snapshot_restore, needs_snapshot_restore};
use super::{snapshot_stream, RocksDB, RocksdbError};
use crate::proto::FarcasterNetwork;
use crate::utils::statsd_wrapper::StatsdClientWrapper;
use aws_config::Region;
use aws_sdk_s3::config::http::HttpResponse;
use aws_sdk_s3::config::Credentials;
use aws_sdk_s3::error::{BuildError, SdkError};
use aws_sdk_s3::operation::abort_multipart_upload::AbortMultipartUploadError;
use aws_sdk_s3::operation::complete_multipart_upload::CompleteMultipartUploadError;
use aws_sdk_s3::operation::create_multipart_upload::CreateMultipartUploadError;
use aws_sdk_s3::operation::delete_objects::DeleteObjectsError;
use aws_sdk_s3::operation::list_objects_v2::ListObjectsV2Error;
use aws_sdk_s3::operation::put_object::PutObjectError;
use aws_sdk_s3::operation::upload_part::UploadPartError;
use aws_sdk_s3::primitives::{ByteStream, ByteStreamError};
use aws_sdk_s3::types::{Delete, ObjectIdentifier};
use aws_sdk_s3::Client;
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io;
use std::sync::Arc;
use std::time::Duration;
use std::time::{SystemTime, SystemTimeError, UNIX_EPOCH};
use thiserror::Error;
use tokio_retry2::{Retry, RetryError};
use tracing::{info, warn};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum BootstrapMethod {
    Snapshot,
    /// Copies state and the tip chunk but not a data shard's consumed shard-zero event rows,
    /// so it cannot bootstrap a data shard past its fork. See docs/snapshots.md.
    Replicate,
}

impl Default for BootstrapMethod {
    fn default() -> Self {
        BootstrapMethod::Snapshot
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub endpoint_url: String,
    pub s3_bucket: String,
    pub backup_dir: String,
    pub backup_on_startup: bool,
    pub load_db_from_snapshot: bool,
    pub force_load_db_from_snapshot: bool,
    pub snapshot_download_url: String,
    pub snapshot_download_dir: String,
    pub aws_access_key_id: String,
    pub aws_secret_access_key: String,
    pub bootstrap_method: BootstrapMethod,
    pub replication_peers: Vec<String>,
    /// Abort snapshots before free space on the source or restore disk falls below this reserve.
    #[serde(default = "default_min_free_bytes")]
    pub min_free_disk_bytes: u64,
    /// Grace period after a generation stops being latest, including manual uploads.
    #[serde(default = "default_retention_secs")]
    pub min_retention_secs: u64,
    #[serde(default = "default_connect_timeout_secs")]
    pub connect_timeout_secs: u64,
    #[serde(default = "default_read_timeout_secs")]
    pub read_timeout_secs: u64,
    #[serde(default = "default_request_timeout_secs")]
    pub request_timeout_secs: u64,
}

fn default_retention_secs() -> u64 {
    7 * 24 * 60 * 60
}
fn default_connect_timeout_secs() -> u64 {
    10
}
fn default_read_timeout_secs() -> u64 {
    60
}
fn default_request_timeout_secs() -> u64 {
    600
}

fn default_min_free_bytes() -> u64 {
    10 * 1024 * 1024 * 1024
}

impl Default for Config {
    fn default() -> Self {
        Config {
            endpoint_url: "https://5400535f796c891e31be1f53f6d89dc0.r2.cloudflarestorage.com"
                .to_string(),
            s3_bucket: "snapshots".to_string(),
            backup_dir: ".rocks.backup".to_string(),
            snapshot_download_dir: ".rocks.snapshot".to_string(),
            backup_on_startup: false,
            load_db_from_snapshot: true,
            force_load_db_from_snapshot: false,
            snapshot_download_url: "https://snapshots.hypria.app".to_string(),
            aws_access_key_id: "".to_string(),
            aws_secret_access_key: "".to_string(),
            bootstrap_method: BootstrapMethod::default(),
            replication_peers: vec![],
            min_free_disk_bytes: default_min_free_bytes(),
            min_retention_secs: default_retention_secs(),
            connect_timeout_secs: default_connect_timeout_secs(),
            read_timeout_secs: default_read_timeout_secs(),
            request_timeout_secs: default_request_timeout_secs(),
        }
    }
}

impl Config {
    pub fn snapshot_upload_enabled(&self) -> bool {
        !self.aws_access_key_id.is_empty() && !self.aws_secret_access_key.is_empty()
    }

    fn validate_timeouts(&self) -> io::Result<()> {
        if self.connect_timeout_secs == 0
            || self.read_timeout_secs == 0
            || self.request_timeout_secs == 0
        {
            return Err(io::Error::other(
                "snapshot timeout values must be greater than zero",
            ));
        }
        Ok(())
    }
}

fn download_client(config: &Config) -> Result<reqwest::Client, SnapshotError> {
    config.validate_timeouts()?;
    Ok(reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(config.connect_timeout_secs))
        .read_timeout(Duration::from_secs(config.read_timeout_secs))
        .timeout(Duration::from_secs(config.request_timeout_secs))
        .no_gzip()
        .no_brotli()
        .no_deflate()
        .no_zstd()
        .build()?)
}

fn snapshot_directory(network: FarcasterNetwork, shard_id: u32) -> String {
    return format!("{}/{}", network.as_str_name(), shard_id);
}

#[derive(Error, Debug)]
pub enum SnapshotError {
    #[error(transparent)]
    SystemTimeError(#[from] SystemTimeError),

    #[error(transparent)]
    IoError(#[from] io::Error),

    #[error(transparent)]
    ByteStreamError(#[from] ByteStreamError),

    #[error(transparent)]
    PutError(#[from] SdkError<PutObjectError, HttpResponse>),

    #[error(transparent)]
    CreateMultipartUploadError(#[from] SdkError<CreateMultipartUploadError, HttpResponse>),

    #[error(transparent)]
    CompleteMultipartUploadError(#[from] SdkError<CompleteMultipartUploadError, HttpResponse>),

    #[error(transparent)]
    AbortMultipartUploadError(#[from] SdkError<AbortMultipartUploadError, HttpResponse>),

    #[error(transparent)]
    UploadPartError(#[from] SdkError<UploadPartError, HttpResponse>),

    #[error(transparent)]
    DeleteObjectsError(#[from] SdkError<DeleteObjectsError, HttpResponse>),

    #[error(transparent)]
    ListObjectsError(#[from] SdkError<ListObjectsV2Error, HttpResponse>),

    #[error(transparent)]
    BuildError(#[from] BuildError),

    #[error(transparent)]
    ReqwestError(#[from] reqwest::Error),

    #[error(transparent)]
    SerdeJsonError(#[from] serde_json::Error),

    #[error("unable to convert time to date")]
    DateError,

    #[error("unable to find parent directory")]
    MissingParentDirectory,

    #[error("unable to convert file name to string")]
    UnableToParseFileName,

    #[error("upload already in progress")]
    UploadAlreadyInProgress,

    #[error("snapshot job failed: {0}")]
    UploadFailures(String),

    #[error(transparent)]
    RocksDbError(#[from] RocksdbError),
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
#[serde(rename_all = "snake_case")]
enum SnapshotFormat {
    KeyValueV1,
}

#[derive(Serialize, Deserialize)]
struct SnapshotMetadata {
    key_base: String,
    chunks: Vec<String>,
    timestamp: i64,
    format: SnapshotFormat,
    #[serde(default)]
    sha256: Vec<String>,
    #[serde(default)]
    records: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    previous_key_base: Option<String>,
}

async fn create_s3_client(snapshot_config: &Config) -> Result<aws_sdk_s3::Client, SnapshotError> {
    snapshot_config.validate_timeouts()?;
    // AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, and AWS_REGION are loaded from envvars
    let credentials = Credentials::new(
        snapshot_config.aws_access_key_id.clone(),
        snapshot_config.aws_secret_access_key.clone(),
        None,
        None,
        "manual",
    );
    let s3_config = aws_sdk_s3::config::Config::builder()
        .force_path_style(true)
        .endpoint_url(snapshot_config.endpoint_url.clone())
        .credentials_provider(credentials)
        .region(Some(Region::new("auto")))
        .timeout_config(
            aws_sdk_s3::config::timeout::TimeoutConfig::builder()
                .connect_timeout(Duration::from_secs(snapshot_config.connect_timeout_secs))
                .read_timeout(Duration::from_secs(snapshot_config.read_timeout_secs))
                .operation_attempt_timeout(Duration::from_secs(
                    snapshot_config.request_timeout_secs,
                ))
                .operation_timeout(Duration::from_secs(snapshot_config.request_timeout_secs))
                .build(),
        )
        .build();
    Ok(aws_sdk_s3::Client::from_conf(s3_config))
}

async fn get_objects_under_key(
    s3_client: &Client,
    snapshot_config: &Config,
    prefix: String,
) -> Result<Vec<ObjectIdentifier>, SnapshotError> {
    let mut objects = Vec::new();
    let mut continuation = None;
    loop {
        let page = s3_client
            .list_objects_v2()
            .bucket(&snapshot_config.s3_bucket)
            .prefix(&prefix)
            .set_continuation_token(continuation)
            .send()
            .await?;
        for object in page.contents.unwrap_or_default() {
            if let Some(key) = object.key {
                objects.push(ObjectIdentifier::builder().key(key).build()?);
            }
        }
        if page.is_truncated != Some(true) {
            break;
        }
        continuation = Some(
            page.next_continuation_token
                .ok_or_else(|| io::Error::other("S3 listing omitted continuation token"))?,
        );
    }
    Ok(objects)
}

async fn read_snapshot_object(
    client: &Client,
    config: &Config,
    key: &str,
) -> Result<Option<bytes::Bytes>, SnapshotError> {
    // SDK operation deadlines stop at response headers; include body consumption.
    tokio::time::timeout(Duration::from_secs(config.request_timeout_secs), async {
        match client
            .get_object()
            .bucket(&config.s3_bucket)
            .key(key)
            .send()
            .await
        {
            Ok(response) => Ok(Some(response.body.collect().await?.into_bytes())),
            Err(error)
                if error
                    .raw_response()
                    .is_some_and(|r| r.status().as_u16() == 404) =>
            {
                Ok(None)
            }
            Err(error) => Err(SnapshotError::from(io::Error::other(error.to_string()))),
        }
    })
    .await
    .map_err(|_| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            "snapshot object download timed out",
        )
    })?
}

async fn read_published_metadata(
    client: &Client,
    config: &Config,
    network: FarcasterNetwork,
    shard_id: u32,
) -> Result<Option<SnapshotMetadata>, SnapshotError> {
    read_snapshot_object(client, config, &metadata_path(network, shard_id))
        .await?
        .map(|body| serde_json::from_slice(&body).map_err(SnapshotError::from))
        .transpose()
}

#[derive(Serialize, Deserialize)]
struct Retirement {
    retired_at_ms: u64,
}

fn now_millis() -> Result<u64, SnapshotError> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as u64)
}

async fn retire_generation(
    client: &Client,
    config: &Config,
    key_base: &str,
) -> Result<(), SnapshotError> {
    client
        .put_object()
        .bucket(&config.s3_bucket)
        .key(format!("{key_base}/retired.json"))
        .content_type("application/json")
        .cache_control("no-store")
        .body(ByteStream::from(serde_json::to_vec(&Retirement {
            retired_at_ms: now_millis()?,
        })?))
        .send()
        .await?;
    Ok(())
}

pub async fn clear_old_snapshots(
    network: FarcasterNetwork,
    snapshot_config: &Config,
    shard_id: u32,
) -> Result<(), SnapshotError> {
    let s3_client = create_s3_client(&snapshot_config).await?;
    let snapshot_dir = format!("{}/", snapshot_directory(network, shard_id));
    // Read the authoritative pointer from S3, never a possibly cached public URL.
    let metadata = read_published_metadata(&s3_client, snapshot_config, network, shard_id)
        .await?
        .ok_or_else(|| io::Error::other("snapshot metadata missing during cleanup"))?;
    let objects = get_objects_under_key(&s3_client, snapshot_config, snapshot_dir.clone()).await?;
    let active_prefix = format!("{}/", metadata.key_base);
    if !active_prefix.starts_with(&snapshot_dir) {
        return Err(io::Error::other("snapshot metadata points outside the shard prefix").into());
    }
    let mut generations: HashMap<String, Vec<ObjectIdentifier>> = HashMap::new();
    for object in objects {
        let Some(relative) = object.key().strip_prefix(&snapshot_dir) else {
            continue;
        };
        let Some((generation, _)) = relative.split_once('/') else {
            continue;
        };
        if generation.is_empty() {
            continue;
        }
        generations
            .entry(format!("{snapshot_dir}{generation}"))
            .or_default()
            .push(object);
    }
    let now = now_millis()?;
    let grace_ms = snapshot_config.min_retention_secs.saturating_mul(1000);
    let mut old_objects = Vec::new();
    for (generation, objects) in generations {
        if generation == metadata.key_base
            || metadata.previous_key_base.as_ref() == Some(&generation)
        {
            continue;
        }
        let retirement = read_snapshot_object(
            &s3_client,
            snapshot_config,
            &format!("{generation}/retired.json"),
        )
        .await?;
        let Some(retirement) = retirement else {
            // Unknown/legacy generations and abandoned uploads get a full grace
            // period starting at discovery, never deletion based on creation age.
            retire_generation(&s3_client, snapshot_config, &generation).await?;
            continue;
        };
        let retirement: Retirement = serde_json::from_slice(&retirement)?;
        if now.saturating_sub(retirement.retired_at_ms) >= grace_ms {
            old_objects.extend(objects);
        }
    }
    for batch in old_objects.chunks(1000) {
        let delete = Delete::builder()
            .set_objects(Some(batch.to_vec()))
            .build()?;
        let result = s3_client
            .delete_objects()
            .bucket(&snapshot_config.s3_bucket)
            .delete(delete)
            .send()
            .await?;
        if !result.errors().is_empty() {
            return Err(io::Error::other(format!(
                "snapshot cleanup failed: {:?}",
                result.errors()
            ))
            .into());
        }
    }
    Ok(())
}

fn metadata_path(network: FarcasterNetwork, shard_id: u32) -> String {
    format!(
        "{}/{}",
        snapshot_directory(network, shard_id),
        "latest.json"
    )
}

async fn download_metadata(
    client: &reqwest::Client,
    network: FarcasterNetwork,
    shard_id: u32,
    snapshot_config: &Config,
) -> Result<SnapshotMetadata, SnapshotError> {
    let metadata_url = format!(
        "{}/{}",
        snapshot_config.snapshot_download_url,
        metadata_path(network, shard_id)
    );
    info!("Retrieving metadata from {}", metadata_url);
    let metadata = client
        .get(metadata_url)
        .send()
        .await?
        .error_for_status()?
        .json::<SnapshotMetadata>()
        .await?;
    Ok(metadata)
}

pub async fn download_snapshots(
    network: FarcasterNetwork,
    snapshot_config: &Config,
    db_dir: String,
    mut shard_ids: Vec<u32>,
) -> Result<(), SnapshotError> {
    shard_ids.sort_unstable();
    shard_ids.dedup();
    let client = download_client(snapshot_config)?;
    let mut session = RestoreSession::begin(
        &db_dir,
        network as i32,
        &snapshot_config.snapshot_download_url,
        &shard_ids,
        snapshot_config.force_load_db_from_snapshot,
    )?;
    let snapshot_dir = &snapshot_config.snapshot_download_dir;
    let mut all_metadata = HashMap::new();
    for &id in &shard_ids {
        if session.completed(id) {
            continue;
        }
        let strategy = tokio_retry2::strategy::FixedInterval::from_millis(1000).take(5);
        let metadata = Retry::spawn(strategy, || async {
            download_metadata(&client, network, id, snapshot_config)
                .await
                .map_err(RetryError::transient)
        })
        .await?;
        all_metadata.insert(id, metadata);
    }
    let total = all_metadata.values().map(|m| m.chunks.len() as u64).sum();
    let main_pb = indicatif::ProgressBar::new(total);
    for id in shard_ids {
        if session.completed(id) {
            info!(shard_id = id, "Keeping previously restored snapshot shard");
            continue;
        }
        let metadata = &all_metadata[&id];
        session.prepare(id)?;
        info!(
            shard_id = id,
            chunks = metadata.chunks.len(),
            "Restoring snapshot shard"
        );
        let result = download_streaming_snapshot(
            &client,
            snapshot_config,
            &db_dir,
            &session.staged_db(id),
            metadata,
            &main_pb,
        )
        .await;
        if let Err(error) = result {
            session.discard_import(id)?;
            return Err(error);
        }
        session.install(id)?;
        info!(shard_id = id, "Installed snapshot shard");
    }
    // Installed databases are durable. Scratch cleanup must not leave a completed
    // restore marked pending, nor remove a download directory mounted by Compose.
    session.finish()?;
    cleanup_snapshot_downloads(snapshot_dir);
    main_pb.finish_with_message("All snapshots downloaded successfully!");
    Ok(())
}

fn cleanup_snapshot_downloads(snapshot_dir: &str) {
    let entries = match std::fs::read_dir(snapshot_dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return,
        Err(error) => {
            warn!(path = snapshot_dir, %error, "Snapshot restored, but unable to inspect download scratch files");
            return;
        }
    };
    for entry in entries {
        let result = entry.and_then(|entry| {
            let path = entry.path();
            let result = if entry.file_type()?.is_dir() {
                std::fs::remove_dir_all(&path)
            } else {
                // Remove symlinks themselves, never their targets.
                std::fs::remove_file(&path)
            };
            result.map_err(|error| {
                io::Error::new(error.kind(), format!("{}: {error}", path.display()))
            })
        });
        if let Err(error) = result {
            warn!(path = snapshot_dir, %error, "Snapshot restored, but unable to remove download scratch files");
        }
    }
}

async fn put_snapshot_object(
    client: &Client,
    config: &Config,
    key: &str,
    body: bytes::Bytes,
    content_type: &str,
    source_path: &str,
) -> Result<(), SnapshotError> {
    let strategy = tokio_retry2::strategy::FixedInterval::from_millis(10_000).take(5);
    Retry::spawn(strategy, || async {
        snapshot_stream::check_space(source_path, config.min_free_disk_bytes)
            .map_err(|e| RetryError::permanent(SnapshotError::IoError(e)))?;
        client
            .put_object()
            .cache_control(if content_type == "application/json" {
                "no-store"
            } else {
                "public, max-age=31536000, immutable"
            })
            .bucket(&config.s3_bucket)
            .key(key)
            .content_type(content_type)
            .body(ByteStream::from(body.clone()))
            .send()
            .await
            .map(|_| ())
            .map_err(|e| {
                let permanent = e.raw_response().is_some_and(|response| {
                    let status = response.status().as_u16();
                    (400..500).contains(&status) && status != 429
                });
                if permanent {
                    RetryError::permanent(SnapshotError::from(e))
                } else {
                    RetryError::transient(SnapshotError::from(e))
                }
            })
    })
    .await
}

/// Export a consistent RocksDB read snapshot directly to bounded S3 objects.
/// A one-slot channel applies backpressure; no database/archive copy is written.
/// `latest.json` is published only after the producer and all uploads succeed.
pub async fn upload_streaming_snapshot(
    network: FarcasterNetwork,
    db: Arc<RocksDB>,
    config: &Config,
    shard_id: u32,
    stats: &StatsdClientWrapper,
) -> Result<(), SnapshotError> {
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as i64;
    let key_base = format!(
        "{}/snapshot-{}-{}",
        snapshot_directory(network, shard_id),
        timestamp,
        uuid::Uuid::new_v4()
    );
    let client = create_s3_client(config).await?;
    let source_path = db.path.clone();
    let minimum = config.min_free_disk_bytes;
    let (tx, mut rx) = tokio::sync::mpsc::channel(1);
    let producer = tokio::task::spawn_blocking(move || snapshot_stream::export(&db, minimum, tx));
    let mut chunks = Vec::new();
    let mut hashes = Vec::new();
    let upload = async {
        while let Some(chunk) = rx.recv().await {
            let name = format!("chunk_{:08}.bin", chunks.len());
            let key = format!("{key_base}/{name}");
            let compressed_bytes = chunk.len();
            let hash = hex::encode(Sha256::digest(&chunk));
            put_snapshot_object(
                &client,
                config,
                &key,
                chunk.into(),
                "application/gzip",
                &source_path,
            )
            .await?;
            info!(
                shard_id,
                key, compressed_bytes, "Uploaded streaming snapshot chunk"
            );
            stats.count_with_shard(shard_id, "snapshots.successful_upload", 1, vec![]);
            chunks.push(name);
            hashes.push(hash);
        }
        Ok::<_, SnapshotError>(())
    };
    let monitor = async {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(2));
        loop {
            interval.tick().await;
            snapshot_stream::check_space(&source_path, minimum)?;
        }
        #[allow(unreachable_code)]
        Ok::<(), io::Error>(())
    };
    let upload_result = tokio::select! {
        result = upload => result,
        result = monitor => result.map_err(SnapshotError::from),
    };
    // On any upload failure, unblock the producer and release its read snapshot.
    drop(rx);
    let produced = producer
        .await
        .map_err(|e| io::Error::other(e.to_string()))?;
    upload_result?;
    let records = produced?;
    let previous = read_published_metadata(&client, config, network, shard_id).await?;
    if let Some(previous) = &previous {
        let shard_prefix = format!("{}/", snapshot_directory(network, shard_id));
        if !previous.key_base.starts_with(&shard_prefix) {
            return Err(
                io::Error::other("previous snapshot points outside the shard prefix").into(),
            );
        }
    }
    let metadata = SnapshotMetadata {
        key_base,
        chunks,
        timestamp,
        format: SnapshotFormat::KeyValueV1,
        sha256: hashes,
        records,
        previous_key_base: previous.as_ref().map(|metadata| metadata.key_base.clone()),
    };
    let body = serde_json::to_vec(&metadata)?;
    put_snapshot_object(
        &client,
        config,
        &metadata_path(network, shard_id),
        body.into(),
        "application/json",
        &source_path,
    )
    .await?;
    if let Some(previous) = previous {
        // If this write fails, cleanup discovers the missing marker and starts
        // a fresh grace period. The latest and previous generations are always kept.
        retire_generation(&client, config, &previous.key_base).await?;
    }
    info!(
        shard_id,
        records,
        chunks = metadata.chunks.len(),
        "Published streaming snapshot"
    );
    Ok(())
}

async fn fetch_streaming_chunk(
    client: &reqwest::Client,
    url: &str,
    expected_hash: &str,
) -> Result<Vec<u8>, SnapshotError> {
    let response = client.get(url).send().await?.error_for_status()?;
    let mut stream = response.bytes_stream();
    let mut bytes = Vec::new();
    while let Some(part) = stream.next().await {
        let part = part?;
        if bytes.len().saturating_add(part.len()) > snapshot_stream::MAX_COMPRESSED_CHUNK {
            return Err(io::Error::other("streaming snapshot chunk exceeds size limit").into());
        }
        bytes.extend_from_slice(&part);
    }
    if hex::encode(Sha256::digest(&bytes)) != expected_hash {
        return Err(io::Error::other("streaming snapshot chunk checksum mismatch").into());
    }
    Ok(bytes)
}

async fn download_streaming_snapshot(
    client: &reqwest::Client,
    config: &Config,
    db_dir: &str,
    staged_db: &std::path::Path,
    metadata: &SnapshotMetadata,
    progress: &indicatif::ProgressBar,
) -> Result<(), SnapshotError> {
    if metadata.chunks.is_empty() || metadata.chunks.len() != metadata.sha256.len() {
        return Err(io::Error::other("invalid streaming snapshot manifest").into());
    }
    std::fs::create_dir_all(db_dir)?;
    snapshot_stream::check_space(db_dir, config.min_free_disk_bytes)?;
    let path = staged_db.to_string_lossy().into_owned();
    let (tx, rx) = tokio::sync::mpsc::channel(1);
    let importer = tokio::task::spawn_blocking(move || snapshot_stream::restore(&path, rx));
    let download_result = async {
        for (chunk, checksum) in metadata.chunks.iter().zip(&metadata.sha256) {
            snapshot_stream::check_space(db_dir, config.min_free_disk_bytes)?;
            let url = format!(
                "{}/{}/{}",
                config.snapshot_download_url, metadata.key_base, chunk
            );
            let strategy = tokio_retry2::strategy::FixedInterval::from_millis(1000).take(5);
            let bytes = Retry::spawn(strategy, || async {
                fetch_streaming_chunk(client, &url, checksum)
                    .await
                    .map_err(RetryError::transient)
            })
            .await?;
            tx.send(bytes)
                .await
                .map_err(|_| io::Error::other("snapshot importer stopped"))?;
            progress.inc(1);
        }
        Ok::<_, SnapshotError>(())
    }
    .await;
    drop(tx);
    let imported = importer
        .await
        .map_err(|e| io::Error::other(e.to_string()))?;
    download_result?;
    if imported? != metadata.records {
        return Err(io::Error::other("streaming snapshot manifest record count mismatch").into());
    }
    Ok(())
}

#[cfg(test)]
mod streaming_tests {
    use super::*;
    use http_body_util::{BodyExt, Full};
    use hyper::{body::Incoming, Request, Response, StatusCode};
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Mutex,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    struct Store {
        url: String,
        objects: Arc<Mutex<HashMap<String, Vec<u8>>>>,
        writes: Arc<Mutex<Vec<String>>>,
        reject: Arc<AtomicBool>,
        task: tokio::task::JoinHandle<()>,
    }
    impl Drop for Store {
        fn drop(&mut self) {
            self.task.abort();
        }
    }
    fn decode_body(body: &[u8], chunked: bool) -> Vec<u8> {
        if !chunked {
            return body.to_vec();
        }
        let mut remaining = body;
        let mut decoded = Vec::new();
        loop {
            let end = remaining.windows(2).position(|w| w == b"\r\n").unwrap();
            let length = std::str::from_utf8(&remaining[..end])
                .unwrap()
                .split(';')
                .next()
                .unwrap();
            let length = usize::from_str_radix(length, 16).unwrap();
            if length == 0 {
                break;
            }
            remaining = &remaining[end + 2..];
            decoded.extend_from_slice(&remaining[..length]);
            remaining = &remaining[length + 2..];
        }
        decoded
    }
    impl Store {
        async fn new() -> Self {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            let objects: Arc<Mutex<HashMap<String, Vec<u8>>>> = Arc::default();
            let writes: Arc<Mutex<Vec<String>>> = Arc::default();
            let reject = Arc::new(AtomicBool::new(false));
            let (o, w, r) = (objects.clone(), writes.clone(), reject.clone());
            let task = tokio::spawn(async move {
                while let Ok((stream, _)) = listener.accept().await {
                    let (objects, writes, reject) = (o.clone(), w.clone(), r.clone());
                    tokio::spawn(async move {
                        let service = hyper::service::service_fn(
                            move |request: Request<Incoming>| {
                                let (objects, writes, reject) =
                                    (objects.clone(), writes.clone(), reject.clone());
                                async move {
                                    let path = request.uri().path().to_string();
                                    let method = request.method().clone();
                                    let query: HashMap<String, String> =
                                        url::form_urlencoded::parse(
                                            request.uri().query().unwrap_or("").as_bytes(),
                                        )
                                        .into_owned()
                                        .collect();
                                    let aws_chunked =
                                        request.headers().get("content-encoding").is_some_and(
                                            |h| h.to_str().unwrap().contains("aws-chunked"),
                                        );
                                    let body =
                                        request.into_body().collect().await.unwrap().to_bytes();
                                    let mut response =
                                        Response::new(Full::new(bytes::Bytes::new()));
                                    if method == hyper::Method::PUT {
                                        writes.lock().unwrap().push(path.clone());
                                        if reject.load(Ordering::SeqCst) {
                                            *response.status_mut() = StatusCode::FORBIDDEN;
                                            *response.body_mut() =
                                                Full::new(bytes::Bytes::from_static(
                                                    b"<Error><Code>AccessDenied</Code></Error>",
                                                ));
                                        } else {
                                            objects
                                                .lock()
                                                .unwrap()
                                                .insert(path, decode_body(&body, aws_chunked));
                                        }
                                    } else if query.get("list-type").is_some() {
                                        let objects = objects.lock().unwrap();
                                        let prefix = query.get("prefix").unwrap();
                                        let mut keys: Vec<_> = objects
                                            .keys()
                                            .filter_map(|key| key.strip_prefix("/bucket/"))
                                            .filter(|key| key.starts_with(prefix))
                                            .collect();
                                        keys.sort();
                                        let from = query
                                            .get("continuation-token")
                                            .and_then(|s| s.parse::<usize>().ok())
                                            .unwrap_or(0);
                                        let to = (from + 1000).min(keys.len());
                                        let truncated = to < keys.len();
                                        let mut xml = format!("<ListBucketResult><IsTruncated>{truncated}</IsTruncated>");
                                        if truncated {
                                            xml.push_str(&format!("<NextContinuationToken>{to}</NextContinuationToken>"));
                                        }
                                        for key in &keys[from..to] {
                                            xml.push_str(&format!(
                                                "<Contents><Key>{key}</Key></Contents>"
                                            ));
                                        }
                                        xml.push_str("</ListBucketResult>");
                                        *response.body_mut() = Full::new(xml.into());
                                    } else if method == hyper::Method::POST
                                        && query.contains_key("delete")
                                    {
                                        let body = decode_body(&body, aws_chunked);
                                        let xml = std::str::from_utf8(&body).unwrap();
                                        for key in xml
                                            .split("<Key>")
                                            .skip(1)
                                            .filter_map(|s| s.split("</Key>").next())
                                        {
                                            objects
                                                .lock()
                                                .unwrap()
                                                .remove(&format!("/bucket/{key}"));
                                        }
                                        *response.body_mut() = Full::new(
                                            bytes::Bytes::from_static(b"<DeleteResult/>"),
                                        );
                                    } else if let Some(body) =
                                        objects.lock().unwrap().get(&path).cloned()
                                    {
                                        *response.body_mut() = Full::new(body.into());
                                    } else {
                                        *response.status_mut() = StatusCode::NOT_FOUND;
                                    }
                                    Ok::<_, std::convert::Infallible>(response)
                                }
                            },
                        );
                        let _ = hyper::server::conn::http1::Builder::new()
                            .serve_connection(hyper_util::rt::TokioIo::new(stream), service)
                            .await;
                    });
                }
            });
            Self {
                url,
                objects,
                writes,
                reject,
                task,
            }
        }
        fn config(&self, dir: &std::path::Path) -> Config {
            Config {
                endpoint_url: self.url.clone(),
                snapshot_download_url: format!("{}/bucket", self.url),
                s3_bucket: "bucket".into(),
                aws_access_key_id: "test".into(),
                aws_secret_access_key: "test".into(),
                backup_dir: dir.join("backup").to_string_lossy().into_owned(),
                snapshot_download_dir: dir.join("downloads").to_string_lossy().into_owned(),
                min_free_disk_bytes: 0,
                ..Default::default()
            }
        }
    }
    fn source(dir: &std::path::Path) -> Arc<RocksDB> {
        let db = Arc::new(RocksDB::new(dir.join("source").to_str().unwrap()));
        db.open().unwrap();
        db.put(b"height", b"51250009").unwrap();
        db.put(&[0, 0, 0, 0, 1, 0, 0, 0, 0], b"native account")
            .unwrap();
        db
    }
    fn pointer() -> String {
        format!("/bucket/{}", metadata_path(FarcasterNetwork::Devnet, 1))
    }

    #[tokio::test]
    async fn streaming_upload_download_roundtrip_publishes_last_and_creates_no_backup_copy() {
        use std::os::unix::fs::MetadataExt;
        let store = Store::new().await;
        let dir = tempfile::TempDir::new().unwrap();
        let db = source(dir.path());
        let config = store.config(dir.path());
        // Compose mounts this directory. Cleanup must preserve the directory
        // itself, including its inode, while reclaiming legacy scratch contents.
        let downloads = std::path::Path::new(&config.snapshot_download_dir);
        std::fs::create_dir_all(downloads.join("shard-1")).unwrap();
        std::fs::write(downloads.join("shard-1/chunk.bin"), b"old chunk").unwrap();
        std::fs::write(downloads.join("shard_1_snapshot.tar"), b"old archive").unwrap();
        let download_inode = std::fs::metadata(downloads).unwrap().ino();
        let outside = dir.path().join("keep");
        std::fs::create_dir(&outside).unwrap();
        std::fs::write(outside.join("data"), b"keep").unwrap();
        std::os::unix::fs::symlink(&outside, downloads.join("link")).unwrap();
        upload_streaming_snapshot(
            FarcasterNetwork::Devnet,
            db,
            &config,
            1,
            &StatsdClientWrapper::new(
                cadence::StatsdClient::builder("", cadence::NopMetricSink).build(),
                true,
            ),
        )
        .await
        .unwrap();
        assert!(!std::path::Path::new(&config.backup_dir).exists());
        let writes = store.writes.lock().unwrap().clone();
        assert!(writes.len() >= 2);
        assert_eq!(writes.last().unwrap(), &pointer());
        let metadata: SnapshotMetadata =
            serde_json::from_slice(&store.objects.lock().unwrap()[&pointer()]).unwrap();
        assert_eq!(metadata.format, SnapshotFormat::KeyValueV1);
        assert_eq!(metadata.records, 2);
        let restored = dir.path().join("restored");
        download_snapshots(
            FarcasterNetwork::Devnet,
            &config,
            restored.to_string_lossy().into_owned(),
            vec![1],
        )
        .await
        .unwrap();
        let db = RocksDB::new(restored.join("shard-1").to_str().unwrap());
        db.open().unwrap();
        assert_eq!(db.get(b"height").unwrap(), Some(b"51250009".to_vec()));
        assert_eq!(std::fs::read_dir(&restored).unwrap().count(), 1);
        assert_eq!(std::fs::metadata(downloads).unwrap().ino(), download_inode);
        assert_eq!(std::fs::read_dir(downloads).unwrap().count(), 0);
        assert_eq!(std::fs::read(outside.join("data")).unwrap(), b"keep");
        assert!(!needs_snapshot_restore(restored.to_str().unwrap(), &[1]).unwrap());
    }

    #[tokio::test]
    async fn streaming_restore_and_completed_journal_recovery_ignore_scratch_cleanup_errors() {
        let store = Store::new().await;
        let dir = tempfile::TempDir::new().unwrap();
        let config = store.config(dir.path());
        upload_streaming_snapshot(
            FarcasterNetwork::Devnet,
            source(dir.path()),
            &config,
            1,
            &crate::storage::store::test_helper::statsd_client(),
        )
        .await
        .unwrap();
        // A regular file guarantees read_dir fails even when tests run as root.
        // Streaming imports do not need this legacy scratch location at all.
        std::fs::write(&config.snapshot_download_dir, b"unusable scratch path").unwrap();
        let restored = dir.path().join("restored");
        download_snapshots(
            FarcasterNetwork::Devnet,
            &config,
            restored.to_string_lossy().into_owned(),
            vec![1],
        )
        .await
        .unwrap();
        assert!(!needs_snapshot_restore(restored.to_str().unwrap(), &[1]).unwrap());

        // Simulate the previous version's state: all databases installed, but a
        // journal still pending after scratch cleanup failed. No download needed.
        let session = RestoreSession::begin(
            restored.to_str().unwrap(),
            FarcasterNetwork::Devnet as i32,
            &config.snapshot_download_url,
            &[1],
            false,
        )
        .unwrap();
        assert!(session.completed(1));
        drop(session);
        assert!(has_pending_snapshot_restore(restored.to_str().unwrap()).unwrap());
        store.objects.lock().unwrap().remove(&pointer());
        download_snapshots(
            FarcasterNetwork::Devnet,
            &config,
            restored.to_string_lossy().into_owned(),
            vec![1],
        )
        .await
        .unwrap();
        assert!(!needs_snapshot_restore(restored.to_str().unwrap(), &[1]).unwrap());
        let db = RocksDB::new(restored.join("shard-1").to_str().unwrap());
        db.open().unwrap();
        assert_eq!(db.get(b"height").unwrap().unwrap(), b"51250009");
        assert_eq!(
            std::fs::read(&config.snapshot_download_dir).unwrap(),
            b"unusable scratch path"
        );
    }
    #[tokio::test]
    async fn failed_upload_and_low_disk_leave_previous_pointer_and_release_the_source() {
        let store = Store::new().await;
        let dir = tempfile::TempDir::new().unwrap();
        let db = source(dir.path());
        store
            .objects
            .lock()
            .unwrap()
            .insert(pointer(), b"previous".to_vec());
        let mut config = store.config(dir.path());
        let stats = crate::storage::store::test_helper::statsd_client();
        config.min_free_disk_bytes = u64::MAX;
        assert!(upload_streaming_snapshot(
            FarcasterNetwork::Devnet,
            db.clone(),
            &config,
            1,
            &stats
        )
        .await
        .is_err());
        assert!(store.writes.lock().unwrap().is_empty());
        config.min_free_disk_bytes = 0;
        store.reject.store(true, Ordering::SeqCst);
        // Force several chunks so the producer can be blocked on backpressure.
        db.put(b"large", &vec![7; snapshot_stream::CHUNK_BYTES * 3])
            .unwrap();
        assert!(tokio::time::timeout(
            std::time::Duration::from_secs(20),
            upload_streaming_snapshot(FarcasterNetwork::Devnet, db.clone(), &config, 1, &stats)
        )
        .await
        .unwrap()
        .is_err());
        assert_eq!(store.objects.lock().unwrap()[&pointer()], b"previous");
        assert!(store.writes.lock().unwrap().iter().all(|p| p != &pointer()));
        // This takes the DB's exclusive lock: a leaked snapshot would deadlock.
        db.close();
    }
    #[tokio::test]
    async fn invalid_restore_preserves_existing_db_and_removes_partial_import() {
        let store = Store::new().await;
        let dir = tempfile::TempDir::new().unwrap();
        let mut config = store.config(dir.path());
        config.force_load_db_from_snapshot = true;
        upload_streaming_snapshot(
            FarcasterNetwork::Devnet,
            source(dir.path()),
            &config,
            1,
            &crate::storage::store::test_helper::statsd_client(),
        )
        .await
        .unwrap();
        {
            let mut objects = store.objects.lock().unwrap();
            let mut metadata: SnapshotMetadata =
                serde_json::from_slice(&objects[&pointer()]).unwrap();
            metadata.records += 1;
            objects.insert(pointer(), serde_json::to_vec(&metadata).unwrap());
        }
        let restored = dir.path().join("restored");
        std::fs::create_dir_all(restored.join("shard-1")).unwrap();
        std::fs::write(restored.join("shard-1/keep"), b"original").unwrap();
        assert!(download_snapshots(
            FarcasterNetwork::Devnet,
            &config,
            restored.to_string_lossy().into_owned(),
            vec![1]
        )
        .await
        .is_err());
        assert_eq!(
            std::fs::read(restored.join("shard-1/keep")).unwrap(),
            b"original"
        );
        assert!(has_pending_snapshot_restore(restored.to_str().unwrap()).unwrap());
        assert!(!restored.join(".snapshot-restore-shard-1").exists());
    }
    #[tokio::test]
    async fn retains_old_reader_across_multiple_publications_until_grace_expires() {
        let store = Store::new().await;
        let dir = tempfile::TempDir::new().unwrap();
        let config = store.config(dir.path());
        let db = source(dir.path());
        let mut generations = Vec::new();
        for _ in 0..3 {
            upload_streaming_snapshot(
                FarcasterNetwork::Devnet,
                db.clone(),
                &config,
                1,
                &crate::storage::store::test_helper::statsd_client(),
            )
            .await
            .unwrap();
            let metadata: SnapshotMetadata =
                serde_json::from_slice(&store.objects.lock().unwrap()[&pointer()]).unwrap();
            assert_eq!(metadata.previous_key_base.as_ref(), generations.last());
            generations.push(metadata.key_base);
            clear_old_snapshots(FarcasterNetwork::Devnet, &config, 1)
                .await
                .unwrap();
        }
        let old_chunk = format!(
            "{}/{}/chunk_00000000.bin",
            config.snapshot_download_url, generations[0]
        );
        let client = download_client(&config).unwrap();
        assert!(client
            .get(&old_chunk)
            .send()
            .await
            .unwrap()
            .status()
            .is_success());
        {
            let mut objects = store.objects.lock().unwrap();
            // Creation timestamp is irrelevant: retention starts at replacement.
            objects.insert(
                format!("/bucket/{}/retired.json", generations[0]),
                serde_json::to_vec(&Retirement {
                    retired_at_ms: now_millis().unwrap() - config.min_retention_secs * 1000 - 1,
                })
                .unwrap(),
            );
        }
        clear_old_snapshots(FarcasterNetwork::Devnet, &config, 1)
            .await
            .unwrap();
        assert_eq!(
            client.get(&old_chunk).send().await.unwrap().status(),
            reqwest::StatusCode::NOT_FOUND
        );
        let objects = store.objects.lock().unwrap();
        assert!(objects.keys().any(|key| key.contains(&generations[1])));
        assert!(objects.keys().any(|key| key.contains(&generations[2])));
    }

    #[tokio::test]
    async fn cleanup_pages_large_buckets_and_keeps_active_snapshot_and_other_shards() {
        let store = Store::new().await;
        let dir = tempfile::TempDir::new().unwrap();
        let mut config = store.config(dir.path());
        config.snapshot_download_url = "http://127.0.0.1:9/unreachable-public-cache".into();
        let base = snapshot_directory(FarcasterNetwork::Devnet, 1);
        let metadata = SnapshotMetadata {
            key_base: format!("{base}/active"),
            chunks: vec!["chunk.bin".into()],
            timestamp: 1,
            format: SnapshotFormat::KeyValueV1,
            sha256: vec![],
            records: 0,
            previous_key_base: None,
        };
        {
            let mut objects = store.objects.lock().unwrap();
            objects.insert(pointer(), serde_json::to_vec(&metadata).unwrap());
            objects.insert(format!("/bucket/{base}/active/chunk.bin"), vec![]);
            objects.insert(format!("/bucket/{}0/keep", base), vec![]);
            objects.insert(
                format!("/bucket/{base}/old/retired.json"),
                serde_json::to_vec(&Retirement { retired_at_ms: 0 }).unwrap(),
            );
            for n in 0..1501 {
                objects.insert(format!("/bucket/{base}/old/chunk_{n}"), vec![]);
            }
        }
        clear_old_snapshots(FarcasterNetwork::Devnet, &config, 1)
            .await
            .unwrap();
        let objects = store.objects.lock().unwrap();
        assert_eq!(objects.len(), 3);
        assert!(objects.contains_key(&pointer()));
        assert!(objects.contains_key(&format!("/bucket/{base}/active/chunk.bin")));
        assert!(objects.contains_key(&format!("/bucket/{base}0/keep")));
    }

    fn snapshot_job_stores(
        dir: &std::path::Path,
    ) -> (
        crate::storage::store::block_engine::BlockStores,
        HashMap<u32, crate::storage::store::stores::Stores>,
    ) {
        use crate::storage::store::{block_engine::BlockStores, stores::Stores, test_helper};
        use crate::storage::trie::merkle_trie::MerkleTrie;
        let blocks = BlockStores::new(
            source(dir),
            MerkleTrie::new().unwrap(),
            FarcasterNetwork::Devnet,
        );
        let shards = (1u32..=2)
            .map(|id| {
                let db = Arc::new(RocksDB::new(
                    dir.join(format!("shard-{id}")).to_str().unwrap(),
                ));
                db.open().unwrap();
                db.put(b"shard", &id.to_be_bytes()).unwrap();
                (
                    id,
                    Stores::new(
                        db,
                        id,
                        MerkleTrie::new().unwrap(),
                        test_helper::limits::test_store_limits(),
                        FarcasterNetwork::Devnet,
                        test_helper::statsd_client(),
                    ),
                )
            })
            .collect();
        (blocks, shards)
    }

    #[test]
    fn rejects_legacy_snapshot_metadata() {
        for json in [
            r#"{"key_base":"legacy","chunks":["../../outside"],"timestamp":1}"#,
            r#"{"key_base":"legacy","chunks":["../../outside"],"timestamp":1,"format":"tar_gzip"}"#,
        ] {
            assert!(serde_json::from_str::<SnapshotMetadata>(json).is_err());
        }
    }

    #[tokio::test]
    #[serial_test::serial(snapshot_upload)]
    async fn snapshot_job_publishes_remaining_shards_after_cleanup_failure() {
        let store = Store::new().await;
        let dir = tempfile::TempDir::new().unwrap();
        let config = store.config(dir.path());
        let (blocks, shards) = snapshot_job_stores(dir.path());
        let stats = crate::storage::store::test_helper::statsd_client();
        let retirement = format!(
            "/bucket/{}/old/retired.json",
            snapshot_directory(FarcasterNetwork::Devnet, 0)
        );
        store
            .objects
            .lock()
            .unwrap()
            .insert(retirement, b"invalid retirement record".to_vec());
        let mut previous = Vec::new();
        for _ in 0..2 {
            let error = crate::jobs::snapshot_upload::upload_snapshot(
                config.clone(),
                FarcasterNetwork::Devnet,
                blocks.clone(),
                shards.clone(),
                stats.clone(),
                None,
            )
            .await
            .unwrap_err();
            let SnapshotError::UploadFailures(error) = error else {
                panic!("expected aggregate error");
            };
            assert!(error.contains("shard 0 cleanup:"), "{error}");
            assert!(!error.contains("shard 1"), "{error}");
            assert!(!error.contains("shard 2"), "{error}");
            let generations: Vec<_> = (0..=2)
                .map(|id| {
                    let key = format!("/bucket/{}", metadata_path(FarcasterNetwork::Devnet, id));
                    let metadata: SnapshotMetadata =
                        serde_json::from_slice(&store.objects.lock().unwrap()[&key]).unwrap();
                    metadata.key_base
                })
                .collect();
            for (old, new) in previous.iter().zip(&generations) {
                assert_ne!(old, new, "later jobs must publish every shard again");
            }
            previous = generations;
        }
        let restored = dir.path().join("restored");
        download_snapshots(
            FarcasterNetwork::Devnet,
            &config,
            restored.to_string_lossy().into_owned(),
            vec![1, 2],
        )
        .await
        .unwrap();
        for id in 1u32..=2 {
            let db = RocksDB::new(restored.join(format!("shard-{id}")).to_str().unwrap());
            db.open().unwrap();
            assert_eq!(db.get(b"shard").unwrap().unwrap(), id.to_be_bytes());
        }
    }

    #[tokio::test]
    #[serial_test::serial(snapshot_upload)]
    async fn snapshot_job_reports_upload_and_cleanup_errors_after_attempting_all_shards() {
        let store = Store::new().await;
        let dir = tempfile::TempDir::new().unwrap();
        let config = store.config(dir.path());
        let (blocks, shards) = snapshot_job_stores(dir.path());
        // Fail shard 0's exporter, then fail only shard 1's remote cleanup.
        blocks.db.close();
        let block_pointer = format!("/bucket/{}", metadata_path(FarcasterNetwork::Devnet, 0));
        let retirement = format!(
            "/bucket/{}/old/retired.json",
            snapshot_directory(FarcasterNetwork::Devnet, 1)
        );
        {
            let mut objects = store.objects.lock().unwrap();
            objects.insert(
                block_pointer.clone(),
                b"preserve previous snapshot".to_vec(),
            );
            objects.insert(retirement, b"invalid retirement record".to_vec());
        }
        let error = crate::jobs::snapshot_upload::upload_snapshot(
            config,
            FarcasterNetwork::Devnet,
            blocks,
            shards,
            crate::storage::store::test_helper::statsd_client(),
            None,
        )
        .await
        .unwrap_err();
        let SnapshotError::UploadFailures(error) = error else {
            panic!("expected aggregate error");
        };
        assert!(error.contains("shard 0 upload:"), "{error}");
        assert!(error.contains("shard 1 cleanup:"), "{error}");
        assert!(!error.contains("shard 2"), "{error}");
        let objects = store.objects.lock().unwrap();
        assert_eq!(objects[&block_pointer], b"preserve previous snapshot");
        for id in [1, 2] {
            assert!(objects.contains_key(&format!(
                "/bucket/{}",
                metadata_path(FarcasterNetwork::Devnet, id)
            )));
        }
    }

    #[tokio::test]
    async fn interrupted_multishard_restore_resumes_only_unfinished_shards() {
        let store = Store::new().await;
        let dir = tempfile::TempDir::new().unwrap();
        let config = store.config(dir.path());
        let db = source(dir.path());
        let stats = crate::storage::store::test_helper::statsd_client();
        for id in [1, 2] {
            upload_streaming_snapshot(FarcasterNetwork::Devnet, db.clone(), &config, id, &stats)
                .await
                .unwrap();
        }
        let pointer2 = format!("/bucket/{}", metadata_path(FarcasterNetwork::Devnet, 2));
        let good = store.objects.lock().unwrap()[&pointer2].clone();
        {
            let mut objects = store.objects.lock().unwrap();
            let mut metadata: SnapshotMetadata = serde_json::from_slice(&good).unwrap();
            metadata.records += 1;
            objects.insert(pointer2.clone(), serde_json::to_vec(&metadata).unwrap());
        }
        let restored = dir.path().join("restored");
        assert!(download_snapshots(
            FarcasterNetwork::Devnet,
            &config,
            restored.to_string_lossy().into_owned(),
            vec![1, 2]
        )
        .await
        .is_err());
        assert!(restored.join("shard-1/CURRENT").is_file());
        assert!(needs_snapshot_restore(restored.to_str().unwrap(), &[1, 2]).unwrap());
        // A finished shard must not depend on its old remote manifest or be redownloaded.
        store.objects.lock().unwrap().remove(&pointer());
        store.objects.lock().unwrap().insert(pointer2, good);
        let saved = RocksDB::new(restored.join("shard-1").to_str().unwrap());
        saved.open().unwrap();
        saved.put(b"keep", b"finished shard").unwrap();
        saved.close();
        download_snapshots(
            FarcasterNetwork::Devnet,
            &config,
            restored.to_string_lossy().into_owned(),
            vec![1, 2],
        )
        .await
        .unwrap();
        assert!(!needs_snapshot_restore(restored.to_str().unwrap(), &[1, 2]).unwrap());
        saved.open().unwrap();
        assert_eq!(saved.get(b"keep").unwrap().unwrap(), b"finished shard");
    }

    #[tokio::test]
    async fn unknown_generation_receives_full_retention_window() {
        let store = Store::new().await;
        let dir = tempfile::TempDir::new().unwrap();
        let config = store.config(dir.path());
        upload_streaming_snapshot(
            FarcasterNetwork::Devnet,
            source(dir.path()),
            &config,
            1,
            &crate::storage::store::test_helper::statsd_client(),
        )
        .await
        .unwrap();
        let old = format!(
            "/bucket/{}/legacy",
            snapshot_directory(FarcasterNetwork::Devnet, 1)
        );
        store
            .objects
            .lock()
            .unwrap()
            .insert(format!("{old}/chunk.bin"), vec![1]);
        clear_old_snapshots(FarcasterNetwork::Devnet, &config, 1)
            .await
            .unwrap();
        assert!(store
            .objects
            .lock()
            .unwrap()
            .contains_key(&format!("{old}/chunk.bin")));
        let bytes = store.objects.lock().unwrap()[&format!("{old}/retired.json")].clone();
        clear_old_snapshots(FarcasterNetwork::Devnet, &config, 1)
            .await
            .unwrap();
        assert_eq!(
            store.objects.lock().unwrap()[&format!("{old}/retired.json")],
            bytes
        );
    }

    // Serve one hung response, then valid responses, exercising both header and
    // mid-body stalls without a real bucket or unbounded waits.
    async fn stall_once(body: Vec<u8>, headers: bool) -> (String, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            let mut first = true;
            while let Ok((mut socket, _)) = listener.accept().await {
                let stalled = first;
                first = false;
                let body = body.clone();
                tokio::spawn(async move {
                    let mut request = [0; 8192];
                    let _ = socket.read(&mut request).await;
                    if !stalled || headers {
                        let header = format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            body.len()
                        );
                        let _ = socket.write_all(header.as_bytes()).await;
                    }
                    if stalled {
                        tokio::time::sleep(Duration::from_secs(4)).await;
                    } else {
                        let _ = socket.write_all(&body).await;
                    }
                });
            }
        });
        (url, task)
    }

    #[tokio::test]
    async fn stalled_snapshot_headers_and_bodies_timeout_then_retry() {
        for headers in [false, true] {
            let payload = b"compressed payload".to_vec();
            let hash = hex::encode(Sha256::digest(&payload));
            let (url, server) = stall_once(payload.clone(), headers).await;
            let config = Config {
                connect_timeout_secs: 1,
                read_timeout_secs: 1,
                request_timeout_secs: 2,
                ..Default::default()
            };
            let client = download_client(&config).unwrap();
            let start = std::time::Instant::now();
            let result = Retry::spawn(
                tokio_retry2::strategy::FixedInterval::from_millis(1).take(1),
                || async {
                    fetch_streaming_chunk(&client, &url, &hash)
                        .await
                        .map_err(RetryError::transient)
                },
            )
            .await
            .unwrap();
            assert_eq!(result, payload);
            assert!(start.elapsed() < Duration::from_secs(3));
            server.abort();
        }
    }

    #[tokio::test]
    async fn s3_snapshot_deadlines_include_waiting_for_headers_and_body() {
        for headers in [false, true] {
            let (url, server) = stall_once(b"{}".to_vec(), headers).await;
            let config = Config {
                endpoint_url: url,
                s3_bucket: "bucket".into(),
                aws_access_key_id: "test".into(),
                aws_secret_access_key: "test".into(),
                connect_timeout_secs: 1,
                read_timeout_secs: 1,
                request_timeout_secs: 1,
                ..Default::default()
            };
            let client = create_s3_client(&config).await.unwrap();
            let result = tokio::time::timeout(
                Duration::from_secs(3),
                read_snapshot_object(&client, &config, "latest.json"),
            )
            .await
            .unwrap();
            assert!(result.is_err());
            server.abort();
        }
    }

    #[tokio::test]
    async fn snapshot_crash_during_import_child() {
        let Ok(root) = std::env::var("HYPERSNAP_SNAPSHOT_CRASH_TEST_ROOT") else {
            return;
        };
        let session = RestoreSession::begin(&root, 1, "test-source", &[1], false).unwrap();
        session.prepare(1).unwrap();
        let (url, _server) = stall_once(b"unused".to_vec(), true).await;
        let config = Config {
            snapshot_download_url: url,
            min_free_disk_bytes: 0,
            ..Default::default()
        };
        let client = download_client(&config).unwrap();
        let metadata = SnapshotMetadata {
            key_base: "snapshot".into(),
            chunks: vec!["chunk.bin".into()],
            timestamp: 0,
            format: SnapshotFormat::KeyValueV1,
            sha256: vec!["0".repeat(64)],
            records: 1,
            previous_key_base: None,
        };
        let staged = session.staged_db(1);
        tokio::spawn(async move {
            // Exit from another task: cancellation would run destructors and is not a crash.
            for _ in 0..100 {
                if staged.join("CURRENT").exists() {
                    std::process::exit(77);
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            std::process::exit(78);
        });
        download_streaming_snapshot(
            &client,
            &config,
            &root,
            &session.staged_db(1),
            &metadata,
            &indicatif::ProgressBar::hidden(),
        )
        .await
        .unwrap();
        panic!("expected child termination");
    }

    #[test]
    fn snapshot_crash_during_import_is_recognized_and_partial_files_are_reclaimed() {
        let dir = tempfile::TempDir::new().unwrap();
        let root = dir.path().join("restore");
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "storage::db::snapshot::streaming_tests::snapshot_crash_during_import_child",
                "--nocapture",
            ])
            .env("HYPERSNAP_SNAPSHOT_CRASH_TEST_ROOT", &root)
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(77),
            "{} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!root.join("shard-1").exists());
        assert!(needs_snapshot_restore(root.to_str().unwrap(), &[1]).unwrap());
        let session =
            RestoreSession::begin(root.to_str().unwrap(), 1, "test-source", &[1], false).unwrap();
        assert!(!session.stage(1).exists());
        assert!(!session.completed(1));
    }
}
