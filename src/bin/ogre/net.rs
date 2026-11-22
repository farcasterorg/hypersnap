//! A local devnet of hypersnap nodes, each one either the release under test
//! or the base release, as a native binary or a docker image.

use crate::convert::Error;
use libp2p::identity::ed25519::{Keypair, SecretKey};
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

pub const VALIDATORS: usize = 7;
pub const NODES: usize = 10;
/// The read node a client like haatz would be: API on, reached over HTTP.
pub const API: usize = 9;
/// A read node on the base release, to compare the API under test against.
pub const REFERENCE: usize = 8;
/// A read node that joins with an empty database and syncs everything.
pub const FRESH: usize = 10;
pub const ADMIN_AUTH: &str = "ogre:ogre";

/// How a node is started: a hypersnap binary, or an image whose `/app/hypersnap`
/// is run with this machine's network and the work directory mounted at the
/// same path.
#[derive(Clone, Debug)]
pub enum Build {
    Binary(PathBuf),
    Image(String),
}

impl std::str::FromStr for Build {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        Ok(match s.strip_prefix("docker:") {
            Some(image) => Build::Image(image.to_string()),
            None => Build::Binary(PathBuf::from(s)),
        })
    }
}

fn secret(i: usize) -> SecretKey {
    // Fixed keys, so a cached chain restarts with the validator set it was built with.
    let seed = blake3::hash(format!("ogre node {i}").as_bytes());
    SecretKey::try_from_bytes(seed.as_bytes().to_vec()).unwrap()
}

fn public_key(i: usize) -> String {
    hex::encode(Keypair::from(secret(i)).public().to_bytes())
}

fn peer_id(i: usize) -> String {
    libp2p::identity::PublicKey::from(Keypair::from(secret(i)).public())
        .to_peer_id()
        .to_base58()
}

pub fn rpc_port(i: usize) -> u16 {
    4000 + 10 * i as u16
}
pub fn http_port(i: usize) -> u16 {
    rpc_port(i) + 1
}
fn gossip_port(i: usize) -> u16 {
    rpc_port(i) + 2
}

pub fn is_api(i: usize) -> bool {
    i > VALIDATORS
}

fn config(dir: &Path, i: usize, block_time: &str) -> String {
    let others = |f: &dyn Fn(usize) -> String| {
        (1..=NODES)
            .filter(|&n| n != i)
            .map(f)
            .collect::<Vec<_>>()
            .join(",")
    };
    let bootstrap = others(&|n| format!("/ip4/127.0.0.1/udp/{}/quic-v1", gossip_port(n)));
    let direct = others(&peer_id);
    let validators = (1..=VALIDATORS)
        .map(|n| format!("\"{}\"", public_key(n)))
        .collect::<Vec<_>>()
        .join(", ");
    let d = dir.display();
    // The API sections are haatz's (docker-compose.mainnet.yml), on read nodes only.
    let api = if is_api(i) {
        format!(
            r#"
[api]
enabled = true
[api.social_graph]
enabled = true
backfill_on_startup = true
[api.channels]
enabled = true
backfill_on_startup = true
[api.metrics]
enabled = true
backfill_on_startup = true
[api.feeds]
enabled = true
[api.search]
enabled = true
backfill_on_startup = true
index_path = "{d}/.rocks/search_index"
[api.conversations]
enabled = true
"#
        )
    } else {
        String::new()
    };
    format!(
        r#"rpc_address = "127.0.0.1:{rpc}"
http_address = "127.0.0.1:{http}"
admin_rpc_auth = "{ADMIN_AUTH}"
rocksdb_dir = "{d}/.rocks"
fc_network = "Devnet"

[statsd]
prefix = "ogre{i}"
addr = "127.0.0.1:8125"

[gossip]
address = "/ip4/127.0.0.1/udp/{gossip}/quic-v1"
bootstrap_peers = "{bootstrap}"
direct_peers = "{direct}"

[consensus]
private_key = "{key}"
block_time = "{block_time}"
shard_ids = [1, 2]
num_shards = 2
validator_sets = [{{ effective_at = 0, validator_public_keys = [{validators}], shard_ids = [0, 1, 2] }}]

[consensus.native_registration.activation_heights]
"0" = 0
"1" = 0
"2" = 0

[consensus.native_registration.api_activation_heights]
"1" = 0
"2" = 0

[gossip.topic_cutovers]
"0" = 0
"1" = 0
"2" = 0

[snapshot]
load_db_from_snapshot = false
backup_dir = "{d}/.rocks.backup"
snapshot_download_dir = "{d}/.rocks.snapshot"

[hyper]
enabled = true
{api}"#,
        rpc = rpc_port(i),
        http = http_port(i),
        gossip = gossip_port(i),
        key = hex::encode(secret(i).as_ref()),
    )
}

pub struct Node {
    pub i: usize,
    pub dir: PathBuf,
    pub build: Option<Build>,
    child: Option<Child>,
    log: PathBuf,
    /// Panics logged while the node was being stopped.
    pub shutdown_panics: Vec<String>,
    /// How the node exited on its own, found when it was next stopped.
    pub crashes: Vec<String>,
}

impl Node {
    pub fn running(&self) -> bool {
        self.child.is_some()
    }

    pub fn url(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{}", http_port(self.i), path)
    }

    pub fn rpc(&self) -> String {
        format!("http://127.0.0.1:{}", rpc_port(self.i))
    }

    fn container(&self) -> String {
        format!("ogre-node-{}", self.i)
    }

    pub fn start(&mut self, build: &Build, block_time: &str) -> Result<(), Error> {
        std::fs::create_dir_all(&self.dir)?;
        let cfg = self.dir.join("hypersnap.toml");
        std::fs::write(&cfg, config(&self.dir, self.i, block_time))?;
        let log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log)?;
        const ENV: [(&str, &str); 3] = [
            ("RUST_LOG", "warn,snapchain=info"),
            ("RUST_BACKTRACE", "1"),
            ("NO_COLOR", "1"),
        ];
        let mut cmd = match build {
            Build::Binary(bin) => {
                let mut c = Command::new(bin);
                c.arg("--config-path").arg(&cfg).envs(ENV);
                c
            }
            Build::Image(image) => {
                let _ = Command::new("docker")
                    .args(["rm", "-f", &self.container()])
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status();
                let work = self.dir.parent().unwrap().display().to_string();
                let mut c = Command::new("docker");
                c.args([
                    "run",
                    "--rm",
                    "--init",
                    "--sig-proxy=true",
                    "--network=host",
                ])
                .args(["--name", &self.container()])
                .args(["--user", &format!("{}:{}", uid(), gid())])
                .args(["-v", &format!("{work}:{work}"), "-w", &work])
                .args(["--ulimit", "nofile=65535:65535"])
                .args(
                    ENV.iter()
                        .flat_map(|(k, v)| ["-e".to_string(), format!("{k}={v}")]),
                )
                .args(["--entrypoint", "/app/hypersnap", image, "--config-path"])
                .arg(&cfg);
                c
            }
        };
        cmd.stdout(log.try_clone()?).stderr(log);
        self.child = Some(cmd.spawn()?);
        self.build = Some(build.clone());
        Ok(())
    }

    /// Stops the node the way an operator's restart does (SIGTERM), or kills it.
    pub fn stop(&mut self, kill: bool) {
        let Some(mut child) = self.child.take() else {
            return;
        };
        if let Ok(Some(status)) = child.try_wait() {
            self.crashes.push(format!("exited on its own: {status}"));
        }
        let before = self.panics().len();
        let image = matches!(self.build, Some(Build::Image(_)));
        if image {
            let sig = if kill { "KILL" } else { "TERM" };
            let _ = Command::new("docker")
                .args(["kill", "-s", sig, &self.container()])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        } else {
            let sig = if kill { "-KILL" } else { "-TERM" };
            let _ = Command::new("kill")
                .args([sig, &child.id().to_string()])
                .status();
        }
        let deadline = Instant::now() + Duration::from_secs(30);
        while Instant::now() < deadline {
            if let Ok(Some(_)) = child.try_wait() {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        if image {
            // Killing the `docker run` client would leave the container running.
            let _ = Command::new("docker")
                .args(["rm", "-f", &self.container()])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
        if child.try_wait().ok().flatten().is_none() {
            let _ = child.kill();
        }
        let _ = child.wait();
        let after = self.panics();
        self.shutdown_panics.extend(after.into_iter().skip(before));
    }

    /// Panics logged while the node was running.
    pub fn running_panics(&self) -> Vec<String> {
        self.panics()
            .into_iter()
            .filter(|p| !self.shutdown_panics.contains(p))
            .collect()
    }

    pub fn log_tail(&self, lines: usize) -> String {
        let text = std::fs::read_to_string(&self.log).unwrap_or_default();
        let all: Vec<&str> = text.lines().collect();
        all[all.len().saturating_sub(lines)..].join("\n")
    }

    /// Panic messages in the log, each with the line that follows (the message).
    pub fn panics(&self) -> Vec<String> {
        let text = std::fs::read_to_string(&self.log).unwrap_or_default();
        let lines: Vec<&str> = text.lines().collect();
        lines
            .iter()
            .enumerate()
            .filter(|(_, l)| l.contains("panicked at"))
            .map(|(n, l)| format!("{} {}", l.trim(), lines.get(n + 1).unwrap_or(&"").trim()))
            .collect()
    }
}

fn uid() -> String {
    String::from_utf8(Command::new("id").arg("-u").output().unwrap().stdout)
        .unwrap()
        .trim()
        .to_string()
}

fn gid() -> String {
    String::from_utf8(Command::new("id").arg("-g").output().unwrap().stdout)
        .unwrap()
        .trim()
        .to_string()
}

pub struct Net {
    pub nodes: Vec<Node>,
    pub block_time: String,
    pub http: reqwest::Client,
}

impl Net {
    pub fn new(work: &Path, logs: &Path, block_time: &str) -> Result<Net, Error> {
        std::fs::create_dir_all(logs)?;
        // Configs and docker mounts need absolute paths.
        let (work, logs) = (std::path::absolute(work)?, std::path::absolute(logs)?);
        let nodes = (1..=NODES)
            .map(|i| Node {
                i,
                dir: work.join(format!("node-{i}")),
                build: None,
                child: None,
                log: logs.join(format!("node-{i}.log")),
                shutdown_panics: Vec::new(),
                crashes: Vec::new(),
            })
            .collect();
        Ok(Net {
            nodes,
            block_time: block_time.to_string(),
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()?,
        })
    }

    pub fn node(&mut self, i: usize) -> &mut Node {
        &mut self.nodes[i - 1]
    }

    pub fn start(&mut self, i: usize, build: &Build) -> Result<(), Error> {
        let block_time = self.block_time.clone();
        self.node(i).start(build, &block_time)
    }

    pub fn stop_all(&mut self) {
        // In parallel: a graceful stop can take a few seconds per node.
        std::thread::scope(|s| {
            for n in &mut self.nodes {
                s.spawn(move || n.stop(false));
            }
        });
    }

    pub async fn get(&self, i: usize, path: &str) -> Result<(u16, Value), Error> {
        self.send(self.http.get(self.nodes[i - 1].url(path))).await
    }

    /// GETs `path`, or for `POST <path> <json>` posts the body.
    pub async fn read(&self, i: usize, spec: &str) -> Result<(u16, Value), Error> {
        match spec.strip_prefix("POST ").and_then(|s| s.split_once(' ')) {
            Some((path, body)) => {
                let url = self.nodes[i - 1].url(path);
                let req = self
                    .http
                    .post(url)
                    .header("content-type", "application/json");
                self.send(req.body(body.to_string())).await
            }
            None => self.get(i, spec).await,
        }
    }

    async fn send(&self, req: reqwest::RequestBuilder) -> Result<(u16, Value), Error> {
        let r = req.send().await?;
        let status = r.status().as_u16();
        let text = r.text().await?;
        Ok((
            status,
            serde_json::from_str(&text).unwrap_or(Value::String(text)),
        ))
    }

    /// Heights of shards 0, 1 and 2, if the node answers.
    pub async fn heights(&self, i: usize) -> Option<[u64; 3]> {
        let (status, info) = self.get(i, "/v1/info").await.ok()?;
        if status != 200 {
            return None;
        }
        let mut h = [0; 3];
        for s in info["shardInfos"].as_array()? {
            let id = s["shardId"].as_u64()? as usize;
            if id < 3 {
                h[id] = s["maxHeight"].as_u64()?;
            }
        }
        Some(h)
    }

    /// Waits until the node answers, and returns how long that took.
    pub async fn wait_up(&self, i: usize, timeout: Duration) -> Result<Duration, Error> {
        let t = Instant::now();
        while t.elapsed() < timeout {
            if self.heights(i).await.is_some() {
                return Ok(t.elapsed());
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        Err(format!("node {i} didn't answer within {timeout:?}").into())
    }

    /// Waits until every shard on node `i` has made a block, and returns how long that took.
    pub async fn wait_blocks(&self, i: usize, timeout: Duration) -> Result<Duration, Error> {
        let t = Instant::now();
        let start = loop {
            if let Some(h) = self.heights(i).await {
                break h;
            }
            if t.elapsed() > timeout {
                return Err(format!("node {i} didn't answer within {timeout:?}").into());
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        };
        while t.elapsed() < timeout {
            if let Some(h) = self.heights(i).await {
                if (0..3).all(|s| h[s] > start[s]) {
                    return Ok(t.elapsed());
                }
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        Err(format!("node {i}: a shard made no block within {timeout:?}").into())
    }

    /// Waits until every shard on node `i` is within `slack` blocks of the
    /// highest height any running node reports.
    pub async fn wait_caught_up(
        &self,
        i: usize,
        slack: u64,
        timeout: Duration,
    ) -> Result<Duration, Error> {
        let t = Instant::now();
        while t.elapsed() < timeout {
            if let Some(h) = self.heights(i).await {
                let mut tip = [0u64; 3];
                for n in self.nodes.iter().filter(|n| n.running() && n.i != i) {
                    if let Some(o) = self.heights(n.i).await {
                        for s in 0..3 {
                            tip[s] = tip[s].max(o[s]);
                        }
                    }
                }
                if (0..3).all(|s| h[s] + slack >= tip[s]) {
                    return Ok(t.elapsed());
                }
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        Err(format!("node {i} didn't catch up within {timeout:?}").into())
    }
}
