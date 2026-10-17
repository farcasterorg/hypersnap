//! Configuration (FIP Appendix A.8), from a TOML file and the environment.
//!
//! Layers, lowest first: built-in defaults, the TOML file, then environment
//! variables. A variable `HYPERSNAP_RELAY_<KEY>` sets `relay.<key>`. A double
//! underscore selects a nested key:
//!
//! ```text
//! HYPERSNAP_RELAY_STATE_DIR=/data
//! HYPERSNAP_RELAY_SNAPCHAIN_ENDPOINTS='["http://a:3383","http://b:3383"]'
//! HYPERSNAP_RELAY_START_HEIGHTS__SNAPCHAIN__SHARD_1=1234
//! HYPERSNAP_RELAY_RATE_LIMITS__SNAPCHAIN_RPCS_PER_MINUTE=100
//! ```

use crate::types::Network;
use figment::providers::{Env, Format, Serialized, Toml};
use figment::Figment;
use hypersnap_proto::FarcasterNetwork;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::Duration;

pub const ENV_PREFIX: &str = "HYPERSNAP_RELAY_";

/// Hypersnap and snapchain both have shards 0, 1 and 2.
pub const SHARDS: [u32; 3] = [0, 1, 2];

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("config file not found: {0}")]
    NotFound(PathBuf),
    #[error("config: {0}")]
    Parse(#[from] Box<figment::Error>),
    #[error("config: {0}")]
    Invalid(String),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NetworkName {
    Mainnet,
    Testnet,
    Devnet,
}

impl NetworkName {
    pub fn farcaster_network(self) -> FarcasterNetwork {
        match self {
            NetworkName::Mainnet => FarcasterNetwork::Mainnet,
            NetworkName::Testnet => FarcasterNetwork::Testnet,
            NetworkName::Devnet => FarcasterNetwork::Devnet,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            NetworkName::Mainnet => "mainnet",
            NetworkName::Testnet => "testnet",
            NetworkName::Devnet => "devnet",
        }
    }
}

/// Where the outbound path gets Hypersnap blocks.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HypersnapBlockSourceKind {
    /// The certified-block stream of a Hypersnap node (FIP A.4 step 3). The
    /// node does not expose it yet; see `source::hypersnap`.
    Certified,
    /// Interim, for devnets and tests: `GetShardChunks` / `GetBlocks` of the
    /// Hypersnap node, which return snapchain-format chunks today.
    ShardChunks,
}

/// Start heights per shard. A persisted cursor always wins over these.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ShardHeights {
    pub shard_0: Option<u64>,
    pub shard_1: Option<u64>,
    pub shard_2: Option<u64>,
}

impl ShardHeights {
    pub fn get(&self, shard: u32) -> Option<u64> {
        match shard {
            0 => self.shard_0,
            1 => self.shard_1,
            2 => self.shard_2,
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct StartHeights {
    /// Inbound: snapchain heights.
    pub snapchain: ShardHeights,
    /// Outbound: Hypersnap heights.
    pub hypersnap: ShardHeights,
}

/// The fork points of FIP §17.2, copied from the `PivotRecord`. From them the
/// relay derives the first height of each cursor:
///
/// | cursor              | first height     |
/// |---------------------|------------------|
/// | snapchain shard 0   | `pivot_height`   |
/// | snapchain shard s   | `H_s + 1`        |
/// | Hypersnap shard 0   | `pivot_height`   |
/// | Hypersnap shard s   | `H_s + 1`        |
///
/// Without this table, the relay reads the `PivotRecord` of a Hypersnap node
/// (`GetPivotRecord`) at start.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PivotConfig {
    /// `PIVOT_HEIGHT`: the shard-0 pivot block height.
    pub pivot_height: u64,
    /// `H_s` for shards 1 and 2 (`shard_0` is ignored).
    pub fork_heights: ShardHeights,
}

impl PivotConfig {
    pub fn from_record(record: &hypersnap_proto::PivotRecord) -> Self {
        let fork = |shard: u32| {
            record
                .shard_forks
                .iter()
                .find(|p| p.shard_id == shard)
                .map(|p| p.fork_height)
        };
        PivotConfig {
            pivot_height: record.pivot_height,
            fork_heights: ShardHeights {
                shard_0: None,
                shard_1: fork(1),
                shard_2: fork(2),
            },
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct RateLimits {
    /// RPCs per minute to the snapchain pool, fetches included. 0 = no limit.
    /// A node limits each IP to 120 RPCs per minute unless it exempts the relay.
    pub snapchain_rpcs_per_minute: u32,
    pub hypersnap_rpcs_per_minute: u32,
    /// Messages per second that the relay submits. 0 = no limit.
    pub snapchain_messages_per_second: u32,
    pub hypersnap_messages_per_second: u32,
}

/// The deferred queue holds messages that the target rejected for state that
/// it can still get: an FID, a signer or an fname that the target network has
/// not ingested yet (FIP A.6, "Time of on-chain events"), or a `KEY_ADD` that
/// another shard worker has not relayed yet.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct DeferredConfig {
    /// Entries per shard worker. When the queue is full, a new deferral is a
    /// rule rejection.
    pub capacity: usize,
    /// Submissions in total, the first one included. Then a rule rejection.
    pub max_attempts: u32,
    /// Delay before the first retry. It doubles after each retry.
    pub retry_ms: u64,
    /// Case-insensitive substrings of a `bad_request.validation_failure`
    /// message that make the rejection state-dependent.
    pub error_patterns: Vec<String>,
}

impl Default for DeferredConfig {
    fn default() -> Self {
        Self {
            capacity: 1024,
            max_attempts: 5,
            retry_ms: 30_000,
            error_patterns: vec![
                "unknown fid".into(),
                "invalid signer".into(),
                "fname is not registered for fid".into(),
            ],
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct RelayConfig {
    /// Farcaster network of both sides. Messages of another network are dropped.
    pub network: NetworkName,
    /// Snapchain nodes (gRPC), in failover order.
    pub snapchain_endpoints: Vec<String>,
    /// Hypersnap nodes (gRPC), in failover order.
    pub hypersnap_endpoints: Vec<String>,
    /// Optional `user:password` for nodes that require RPC auth.
    pub snapchain_auth: Option<String>,
    pub hypersnap_auth: Option<String>,

    pub inbound_enabled: bool,
    pub outbound_enabled: bool,
    /// Snapchain shards that the inbound path reads. Shard 0 carries `KEY_ADD`,
    /// `KEY_REMOVE` and `LEND_STORAGE` on snapchain.
    pub inbound_shards: Vec<u32>,
    /// Hypersnap shards that the outbound path reads.
    pub outbound_shards: Vec<u32>,

    /// `auto` asks the snapchain node (`GetInfo.version`), or a version such as
    /// `0.13.3`. It selects the outbound `MessageType` allowlist.
    pub snapchain_version: String,
    pub hypersnap_block_source: HypersnapBlockSourceKind,

    /// Cursor and seen-set storage.
    pub state_dir: PathBuf,
    /// Maximum entries of each seen set (inbound and outbound).
    pub seen_set_capacity: usize,

    /// Retry policy for transient errors and rate limits.
    pub retry_initial_ms: u64,
    pub retry_max_ms: u64,
    /// Submissions of one message after per-message transient or rate-limit
    /// errors before the relay gives up on it. RPC-level outages do not count.
    pub max_message_attempts: u32,

    /// Wait between polls when a source has no new block.
    pub poll_interval_ms: u64,
    /// Blocks per fetch RPC. The relay halves it when a page is too large.
    pub fetch_page_size: u32,
    /// Messages per `SubmitBulkMessages` call.
    pub submit_batch_size: usize,
    pub request_timeout_ms: u64,
    pub connect_timeout_ms: u64,
    /// gRPC decode/encode limit. Blocks with Falcon-512 keys and signatures
    /// are large.
    pub max_grpc_message_bytes: usize,
    /// Interval of the cursor-lag gauges.
    pub tip_interval_ms: u64,
    /// Interval of the snapchain version check when `snapchain_version = "auto"`.
    pub version_refresh_secs: u64,
    /// Interval of the metrics summary log line (0 = off).
    pub metrics_log_interval_secs: u64,

    pub pivot: Option<PivotConfig>,
    pub start_heights: StartHeights,
    pub rate_limits: RateLimits,
    pub deferred: DeferredConfig,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            network: NetworkName::Mainnet,
            snapchain_endpoints: vec![],
            hypersnap_endpoints: vec![],
            snapchain_auth: None,
            hypersnap_auth: None,
            inbound_enabled: true,
            outbound_enabled: true,
            inbound_shards: SHARDS.to_vec(),
            outbound_shards: SHARDS.to_vec(),
            snapchain_version: "auto".into(),
            hypersnap_block_source: HypersnapBlockSourceKind::Certified,
            state_dir: PathBuf::from("/var/lib/hypersnap-relay"),
            seen_set_capacity: 10_000_000,
            retry_initial_ms: 500,
            retry_max_ms: 60_000,
            max_message_attempts: 20,
            poll_interval_ms: 1_000,
            fetch_page_size: 50,
            submit_batch_size: 100,
            request_timeout_ms: 15_000,
            connect_timeout_ms: 5_000,
            max_grpc_message_bytes: 64 * 1024 * 1024,
            tip_interval_ms: 15_000,
            version_refresh_secs: 300,
            metrics_log_interval_secs: 60,
            pivot: None,
            start_heights: StartHeights::default(),
            rate_limits: RateLimits::default(),
            deferred: DeferredConfig::default(),
        }
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
struct FileConfig {
    relay: RelayConfig,
}

impl RelayConfig {
    /// Loads defaults, then `path` (if given), then `HYPERSNAP_RELAY_*`.
    pub fn load(path: Option<&Path>) -> Result<Self, ConfigError> {
        Self::load_with_env_prefix(path, ENV_PREFIX)
    }

    /// As [`RelayConfig::load`], with another environment prefix (for tests).
    pub fn load_with_env_prefix(path: Option<&Path>, prefix: &str) -> Result<Self, ConfigError> {
        let mut figment = Figment::from(Serialized::defaults(FileConfig::default()));
        if let Some(path) = path {
            if !path.exists() {
                return Err(ConfigError::NotFound(path.to_path_buf()));
            }
            figment = figment.merge(Toml::file(path));
        }
        figment = figment.merge(
            Env::prefixed(prefix)
                // Read by the CLI, not by the config.
                .ignore(&["config", "log_format"])
                .map(|key| format!("relay.{}", key.as_str().replace("__", ".")).into()),
        );
        let file: FileConfig = figment.extract().map_err(Box::new)?;
        file.relay.validate()?;
        Ok(file.relay)
    }

    /// Parses a TOML document (no environment layer).
    pub fn from_toml_str(toml: &str) -> Result<Self, ConfigError> {
        let file: FileConfig = Figment::from(Serialized::defaults(FileConfig::default()))
            .merge(Toml::string(toml))
            .extract()
            .map_err(Box::new)?;
        file.relay.validate()?;
        Ok(file.relay)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        let invalid = |m: String| Err(ConfigError::Invalid(m));
        if !self.inbound_enabled && !self.outbound_enabled {
            return invalid("inbound_enabled and outbound_enabled are both false".into());
        }
        if self.snapchain_endpoints.is_empty() {
            return invalid("snapchain_endpoints is empty".into());
        }
        if self.hypersnap_endpoints.is_empty() {
            return invalid("hypersnap_endpoints is empty".into());
        }
        for url in self
            .snapchain_endpoints
            .iter()
            .chain(self.hypersnap_endpoints.iter())
        {
            if !(url.starts_with("http://") || url.starts_with("https://")) {
                return invalid(format!(
                    "endpoint {url:?} must start with http:// or https://"
                ));
            }
        }
        for (name, shards) in [
            ("inbound_shards", &self.inbound_shards),
            ("outbound_shards", &self.outbound_shards),
        ] {
            for s in shards {
                if !SHARDS.contains(s) {
                    return invalid(format!("{name} contains {s}; shards are 0, 1 and 2"));
                }
            }
            let mut sorted = shards.clone();
            sorted.sort();
            sorted.dedup();
            if sorted.len() != shards.len() {
                return invalid(format!("{name} has a repeated shard"));
            }
        }
        if self.snapchain_version != "auto"
            && crate::filter::SnapchainVersion::parse(&self.snapchain_version).is_none()
        {
            return invalid(format!(
                "snapchain_version {:?} is not \"auto\" or a version such as \"0.13.3\"",
                self.snapchain_version
            ));
        }
        if self.seen_set_capacity == 0 {
            return invalid("seen_set_capacity must be > 0".into());
        }
        if self.retry_initial_ms == 0 || self.retry_initial_ms > self.retry_max_ms {
            return invalid("need 0 < retry_initial_ms <= retry_max_ms".into());
        }
        if self.max_message_attempts == 0 {
            return invalid("max_message_attempts must be > 0".into());
        }
        if self.fetch_page_size == 0 {
            return invalid("fetch_page_size must be > 0".into());
        }
        if self.submit_batch_size == 0 || self.submit_batch_size > 1_000 {
            return invalid("submit_batch_size must be in 1..=1000".into());
        }
        if self.deferred.max_attempts == 0 {
            return invalid("deferred.max_attempts must be > 0".into());
        }
        for (name, auth) in [
            ("snapchain_auth", &self.snapchain_auth),
            ("hypersnap_auth", &self.hypersnap_auth),
        ] {
            if let Some(auth) = auth {
                if auth.split(':').count() != 2 {
                    return invalid(format!("{name} must be \"user:password\""));
                }
            }
        }
        Ok(())
    }

    /// The first height of the cursor of (`network`, `shard`) when no cursor is
    /// persisted. An explicit `start_heights` entry wins over the pivot table.
    pub fn start_height(&self, network: Network, shard: u32) -> Option<u64> {
        let explicit = match network {
            Network::Snapchain => self.start_heights.snapchain.get(shard),
            Network::Hypersnap => self.start_heights.hypersnap.get(shard),
        };
        explicit.or_else(|| {
            let pivot = self.pivot.as_ref()?;
            if shard == 0 {
                Some(pivot.pivot_height)
            } else {
                pivot.fork_heights.get(shard).map(|h| h + 1)
            }
        })
    }

    pub fn retry_initial(&self) -> Duration {
        Duration::from_millis(self.retry_initial_ms)
    }

    pub fn retry_max(&self) -> Duration {
        Duration::from_millis(self.retry_max_ms)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A8: &str = r#"
[relay]
# Snapchain nodes (gRPC)
snapchain_endpoints = ["https://snapchain-a.example:3383", "https://snapchain-b.example:3383"]

# Hypersnap nodes (gRPC)
hypersnap_endpoints = ["https://hypersnap-a.example:3383"]

# Directions
inbound_enabled = true
outbound_enabled = true

# Cursor and seen-set storage
state_dir = "/var/lib/hypersnap-relay"
seen_set_capacity = 10_000_000

# Retry policy for transient errors and rate limits
retry_initial_ms = 500
retry_max_ms = 60_000
"#;

    #[test]
    fn fip_a8_example_parses() {
        let cfg = RelayConfig::from_toml_str(A8).unwrap();
        assert_eq!(cfg.snapchain_endpoints.len(), 2);
        assert_eq!(
            cfg.hypersnap_endpoints,
            vec!["https://hypersnap-a.example:3383"]
        );
        assert_eq!(cfg.seen_set_capacity, 10_000_000);
        assert_eq!(cfg.retry_initial_ms, 500);
        assert_eq!(cfg.retry_max_ms, 60_000);
        assert_eq!(cfg.inbound_shards, vec![0, 1, 2]);
        assert_eq!(cfg.snapchain_version, "auto");
        assert_eq!(cfg.network, NetworkName::Mainnet);
    }

    #[test]
    fn example_config_parses() {
        let example = include_str!("../relay.example.toml");
        let cfg = RelayConfig::from_toml_str(example).unwrap();
        assert_eq!(cfg, {
            // The example spells out the defaults, apart from the endpoints.
            let mut d = RelayConfig {
                snapchain_endpoints: cfg.snapchain_endpoints.clone(),
                hypersnap_endpoints: cfg.hypersnap_endpoints.clone(),
                ..RelayConfig::default()
            };
            d.deferred = DeferredConfig::default();
            d
        });
        // Uncommenting the pivot block gives the derived start heights.
        let with_pivot = example
            .replace("# [relay.pivot]", "[relay.pivot]")
            .replace("# pivot_height", "pivot_height")
            .replace("# fork_heights", "fork_heights");
        let cfg = RelayConfig::from_toml_str(&with_pivot).unwrap();
        assert_eq!(cfg.start_height(Network::Snapchain, 1), Some(9_876_544));
        assert_eq!(cfg.start_height(Network::Hypersnap, 0), Some(12_345_678));
    }

    #[test]
    fn start_heights_from_pivot_and_overrides() {
        let toml = format!(
            "{A8}\n[relay.pivot]\npivot_height = 1000\nfork_heights = {{ shard_1 = 500, shard_2 = 700 }}\n\
             [relay.start_heights.hypersnap]\nshard_2 = 42\n"
        );
        let cfg = RelayConfig::from_toml_str(&toml).unwrap();
        assert_eq!(cfg.start_height(Network::Snapchain, 0), Some(1000));
        assert_eq!(cfg.start_height(Network::Snapchain, 1), Some(501));
        assert_eq!(cfg.start_height(Network::Snapchain, 2), Some(701));
        assert_eq!(cfg.start_height(Network::Hypersnap, 0), Some(1000));
        assert_eq!(cfg.start_height(Network::Hypersnap, 1), Some(501));
        assert_eq!(cfg.start_height(Network::Hypersnap, 2), Some(42));
        assert_eq!(
            RelayConfig::from_toml_str(A8)
                .unwrap()
                .start_height(Network::Snapchain, 1),
            None
        );
    }

    #[test]
    fn env_overrides_toml() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("relay.toml");
        std::fs::write(&path, A8).unwrap();
        // A unique prefix keeps this test independent of the others.
        let p = "RELAYCFGTEST_";
        std::env::set_var(format!("{p}STATE_DIR"), "/tmp/relay-env");
        std::env::set_var(
            format!("{p}HYPERSNAP_ENDPOINTS"),
            "[\"http://h1:3383\",\"http://h2:3383\"]",
        );
        std::env::set_var(format!("{p}START_HEIGHTS__SNAPCHAIN__SHARD_1"), "77");
        std::env::set_var(format!("{p}RATE_LIMITS__SNAPCHAIN_RPCS_PER_MINUTE"), "100");
        std::env::set_var(format!("{p}NETWORK"), "devnet");
        let cfg = RelayConfig::load_with_env_prefix(Some(&path), p).unwrap();
        assert_eq!(cfg.state_dir, PathBuf::from("/tmp/relay-env"));
        assert_eq!(
            cfg.hypersnap_endpoints,
            vec!["http://h1:3383", "http://h2:3383"]
        );
        assert_eq!(cfg.start_height(Network::Snapchain, 1), Some(77));
        assert_eq!(cfg.rate_limits.snapchain_rpcs_per_minute, 100);
        assert_eq!(cfg.network, NetworkName::Devnet);
        // Untouched values keep the file value.
        assert_eq!(cfg.snapchain_endpoints.len(), 2);
    }

    #[test]
    fn rejects_bad_values() {
        let bad = [
            "[relay]\nsnapchain_endpoints=[]\nhypersnap_endpoints=[\"http://h:1\"]",
            "[relay]\nsnapchain_endpoints=[\"grpc://s:1\"]\nhypersnap_endpoints=[\"http://h:1\"]",
            "[relay]\nsnapchain_endpoints=[\"http://s:1\"]\nhypersnap_endpoints=[\"http://h:1\"]\ninbound_shards=[3]",
            "[relay]\nsnapchain_endpoints=[\"http://s:1\"]\nhypersnap_endpoints=[\"http://h:1\"]\nsnapchain_version=\"latest\"",
            "[relay]\nsnapchain_endpoints=[\"http://s:1\"]\nhypersnap_endpoints=[\"http://h:1\"]\nretry_initial_ms=10\nretry_max_ms=5",
            "[relay]\nsnapchain_endpoints=[\"http://s:1\"]\nhypersnap_endpoints=[\"http://h:1\"]\nunknown_key=1",
        ];
        for toml in bad {
            assert!(
                RelayConfig::from_toml_str(toml).is_err(),
                "accepted: {toml}"
            );
        }
    }
}
