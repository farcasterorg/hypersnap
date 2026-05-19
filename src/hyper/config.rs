//! Operator-facing configuration for `HyperRuntime`.
//!
//! TOML schema:
//!
//! ```toml
//! [hyper]
//! enabled = true
//! mempool_capacity = 10000
//!
//! [hyper.score_weights]
//! proposal = 100
//! participation = 1
//! miss_penalty = 50
//! invalid_penalty = 1000
//!
//! # Path to the KZG ceremony trusted-setup file.
//! kzg_setup_path = "/etc/hypersnap/trusted_setup.txt"
//! ```

use crate::hyper::runtime::{
    HyperRuntime, HyperRuntimeConfig, RETRO_VESTING_ON_PROTOCOL_EPOCHS_DEFAULT,
};
use crate::hyper::validator_score::ScoreWeights;
use crate::storage::db::RocksDB;
use hypersnap_crypto::kzg::KzgSrs;
use hypersnap_crypto::kzg_loader::{parse_trusted_setup_text, LoaderError};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Arc;

/// Serializable hyper runtime configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HyperRuntimeFileConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_mempool_capacity")]
    pub mempool_capacity: usize,
    #[serde(default)]
    pub score_weights: ScoreWeightsConfig,
    /// Optional path to a KZG ceremony trusted-setup text file. If `None`, the
    /// runtime is constructed with a randomly-sampled SRS — fine for testing
    /// but unsafe for production.
    #[serde(default)]
    pub kzg_setup_path: Option<String>,
    /// SRS max degree when loading from a ceremony file. Defaults to the
    /// verkle domain size (256).
    #[serde(default = "default_srs_max_degree")]
    pub srs_max_degree: usize,
    /// Optional path to a genesis state TOML file. When present and chain has
    /// no prior history, `build_runtime` applies it during initialization.
    #[serde(default)]
    pub genesis_path: Option<String>,

    /// Hyper-side recovery watcher config. If `rpc_url` is non-empty,
    /// the snapchain main binary spawns a long-running task that
    /// subscribes to IdRegistry Recover events on Optimism and
    /// persists them in the hyper recovery store. Used by the
    /// deterministic retro distribution to distinguish forced
    /// recoveries from real ownership changes.
    #[serde(default)]
    pub recovery_watcher: RecoveryWatcherFileConfig,

    /// FIP §10.5 vesting cadence: number of on-protocol epochs over
    /// which the retro distribution vests. Defaults to 29 (the
    /// remaining tranches after 7 paid out off-protocol on the §10.5
    /// 36-tranche schedule). Testnets and devnets can shorten this.
    #[serde(default = "default_retro_vesting_on_protocol_epochs")]
    pub retro_vesting_on_protocol_epochs: u64,

    /// FIP §13.5 DKLS gossip E2EE: path to the operator's X25519
    /// transport secret on disk. The file holds exactly 32 raw
    /// bytes (no encoding — `cat /dev/urandom | head -c 32 > path`
    /// produces a valid file).
    ///
    /// If the path is `None`, the runtime starts with a zero secret
    /// (`[0u8; 32]`) — this is a hard-compromised placeholder that
    /// any observer can derive. Acceptable for ephemeral tests; in
    /// production, every validator MUST set this to a long-lived
    /// secret unique to that node. The public half is what gets
    /// announced via `HyperValidatorEventBody.transport_pubkey` —
    /// rotating the secret requires re-registering with the new
    /// pubkey.
    ///
    /// If the path is set but the file is missing AND
    /// `auto_generate_transport_secret` is true, the runtime
    /// generates a fresh 32-byte secret and writes it. Convenient
    /// for first-boot devnets; production loaders should pre-
    /// populate the file out-of-band.
    #[serde(default)]
    pub transport_secret_path: Option<String>,

    /// If `transport_secret_path` is set and the file does not
    /// exist, generate a fresh random secret and write it.
    /// Defaults to `true` for ergonomic first-boot. Set to
    /// `false` in production so a missing keyfile is a hard
    /// error rather than silently creating one.
    #[serde(default = "default_auto_generate_transport_secret")]
    pub auto_generate_transport_secret: bool,

    /// FIP §13.6 inbound bridge: per-destination-chain watchers
    /// for `HypersnapBridge.Burned` events. Empty list disables
    /// the inbound bridge entirely. One entry per bridge
    /// deployment (one per chain the node should accept burns
    /// from).
    #[serde(default)]
    pub bridge_burn_watchers: Vec<BridgeBurnWatcherFileConfig>,

    /// Path to this validator's bincode-serialized epoch-0
    /// `Party<Secp256k1>` from the offline DKG. Unset on non-
    /// signing validators.
    #[serde(default)]
    pub local_dkls_share_path: Option<String>,
    /// 1-based party index matching the share file. Required when
    /// `local_dkls_share_path` is set.
    #[serde(default)]
    pub local_dkls_share_party_index: Option<u64>,

    /// DA-response operator identity. All three fields together
    /// enable the auto DA-response producer. Path: 32-byte raw
    /// ed25519 signing key, registered as an active signer for
    /// `operator_fid`. `operator_validator_pubkey_hex` defaults
    /// to the signer pubkey when omitted.
    #[serde(default)]
    pub operator_signer_secret_path: Option<String>,
    #[serde(default)]
    pub operator_fid: Option<u64>,
    #[serde(default)]
    pub operator_validator_pubkey_hex: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct BridgeBurnWatcherFileConfig {
    /// Destination-chain RPC URL. Empty entry is ignored.
    #[serde(default)]
    pub rpc_url: String,
    /// EIP-155 chain id of the source chain.
    #[serde(default)]
    pub source_chain_id: u32,
    /// 20-byte EVM address of the deployed bridge contract on
    /// the source chain, 0x-prefixed hex.
    #[serde(default)]
    pub bridge_contract_address_hex: String,
    /// First block to scan if the local store has no record for
    /// this chain.
    #[serde(default)]
    pub start_block: u64,
    /// Poll interval in seconds (default 30).
    #[serde(default = "default_bridge_burn_poll_secs")]
    pub poll_interval_secs: u64,
    /// Block batch per `eth_getLogs` call (default 8000).
    #[serde(default = "default_bridge_burn_block_batch")]
    pub block_batch: u64,
    /// Finality confirmations before persisting a burn (default
    /// 64, matches FIP §13.8).
    #[serde(default = "default_bridge_burn_finality")]
    pub finality_confirmations: u64,
}

fn default_bridge_burn_poll_secs() -> u64 {
    30
}

fn default_bridge_burn_block_batch() -> u64 {
    8_000
}

fn default_bridge_burn_finality() -> u64 {
    64
}

fn default_auto_generate_transport_secret() -> bool {
    true
}

fn default_retro_vesting_on_protocol_epochs() -> u64 {
    RETRO_VESTING_ON_PROTOCOL_EPOCHS_DEFAULT
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RecoveryWatcherFileConfig {
    #[serde(default)]
    pub rpc_url: String,
    #[serde(default = "default_recovery_start_block")]
    pub start_block: u64,
    #[serde(default = "default_recovery_poll_secs")]
    pub poll_interval_secs: u64,
    #[serde(default = "default_recovery_block_batch")]
    pub block_batch: u64,
}

fn default_recovery_start_block() -> u64 {
    108_864_739
}

fn default_recovery_poll_secs() -> u64 {
    30
}

fn default_recovery_block_batch() -> u64 {
    8_000
}

/// Genesis state declared in TOML. The DKLS23 group address is
/// hex-encoded 20-byte secp256k1; bootstrap validators carry
/// hex-encoded keys.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GenesisFileConfig {
    pub bootstrap_validators: Vec<BootstrapValidatorConfig>,
    /// 20-byte secp256k1 group address (hex, with or without 0x).
    pub genesis_group_address_hex: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BootstrapValidatorConfig {
    /// 32-byte Ed25519 identity public key (hex).
    pub validator_key_hex: String,
    /// 32-byte X25519 transport public key (hex).
    pub transport_pubkey_hex: String,
    /// 20-byte secp256k1 individual validator address (hex).
    pub validator_address_hex: String,
}

fn default_mempool_capacity() -> usize {
    crate::hyper::mempool::DEFAULT_MEMPOOL_CAPACITY
}

fn default_srs_max_degree() -> usize {
    hypersnap_crypto::kzg_lagrange::VERKLE_DOMAIN
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScoreWeightsConfig {
    pub proposal: i64,
    pub participation: i64,
    pub miss_penalty: i64,
    pub invalid_penalty: i64,
}

impl Default for ScoreWeightsConfig {
    fn default() -> Self {
        let w = ScoreWeights::default();
        Self {
            proposal: w.proposal,
            participation: w.participation,
            miss_penalty: w.miss_penalty,
            invalid_penalty: w.invalid_penalty,
        }
    }
}

impl From<ScoreWeightsConfig> for ScoreWeights {
    fn from(c: ScoreWeightsConfig) -> Self {
        Self {
            proposal: c.proposal,
            participation: c.participation,
            miss_penalty: c.miss_penalty,
            invalid_penalty: c.invalid_penalty,
        }
    }
}

#[derive(thiserror::Error, Debug)]
pub enum ConfigError {
    #[error("failed to read KZG setup file: {0}")]
    ReadSetup(#[from] std::io::Error),
    #[error(transparent)]
    Loader(#[from] LoaderError),
    #[error("invalid hex in genesis config: {0}")]
    HexDecode(#[from] hex::FromHexError),
    #[error("invalid genesis group address: expected 20 bytes")]
    BadGroupAddress,
    #[error("invalid bootstrap validator_address: expected 20 bytes")]
    BadValidatorAddress,
    #[error("genesis TOML parse error: {0}")]
    TomlParse(#[from] toml::de::Error),
    #[error(transparent)]
    Genesis(#[from] crate::hyper::genesis::GenesisError),
    #[error("transport secret file at {path:?} is the wrong size: expected 32 bytes, got {got}")]
    BadTransportSecretSize { path: String, got: usize },
    #[error(
        "transport secret file at {0:?} does not exist and auto_generate_transport_secret = false"
    )]
    MissingTransportSecret(String),
    #[error("bridge burn watcher misconfigured: {0}")]
    BridgeBurnWatcher(String),
    #[error("failed to read local DKLS share file at {path:?}: {source}")]
    DklsShareIo {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to deserialize local DKLS share at {path:?}: {source}")]
    DklsShareDecode {
        path: String,
        #[source]
        source: bincode::Error,
    },
    #[error(
        "local_dkls_share_path set but local_dkls_share_party_index missing — both are required"
    )]
    DklsShareIndexMissing,
    #[error(
        "local_dkls_share_party_index ({configured}) does not match share file's party_index ({on_disk})"
    )]
    DklsShareIndexMismatch { configured: u64, on_disk: u64 },
}

impl BridgeBurnWatcherFileConfig {
    /// Translate the file-config row into the runtime
    /// `BridgeBurnWatcherConfig` the watcher consumes. Validates
    /// the hex-encoded contract address.
    pub fn into_runtime_config(
        self,
    ) -> Result<crate::hyper::bridge_burn_watcher::BridgeBurnWatcherConfig, ConfigError> {
        let stripped = self
            .bridge_contract_address_hex
            .strip_prefix("0x")
            .unwrap_or(&self.bridge_contract_address_hex);
        let bytes = if stripped.is_empty() {
            // Allow empty address only when the rpc_url is also
            // empty (i.e. the entry is fully disabled).
            if self.rpc_url.is_empty() {
                [0u8; 20]
            } else {
                return Err(ConfigError::BridgeBurnWatcher(format!(
                    "chain {}: bridge_contract_address_hex required when rpc_url is set",
                    self.source_chain_id
                )));
            }
        } else {
            let raw = hex::decode(stripped)?;
            if raw.len() != 20 {
                return Err(ConfigError::BridgeBurnWatcher(format!(
                    "chain {}: bridge_contract_address_hex must decode to 20 bytes (got {})",
                    self.source_chain_id,
                    raw.len()
                )));
            }
            let mut a = [0u8; 20];
            a.copy_from_slice(&raw);
            a
        };
        Ok(crate::hyper::bridge_burn_watcher::BridgeBurnWatcherConfig {
            rpc_url: self.rpc_url,
            source_chain_id: self.source_chain_id,
            bridge_contract_address: alloy_primitives::Address::from(bytes),
            start_block: self.start_block,
            poll_interval: std::time::Duration::from_secs(self.poll_interval_secs),
            block_batch: self.block_batch,
            finality_confirmations: self.finality_confirmations,
        })
    }
}

/// Read (or, if absent and `auto_generate` is true, generate) a
/// 32-byte X25519 transport secret at `path`. Returns the secret
/// bytes ready for `HyperRuntimeConfig.local_transport_secret_bytes`.
///
/// File format: raw 32 bytes — no encoding. `chmod 0600` is the
/// operator's responsibility; this loader doesn't enforce
/// permissions but a future hardening pass should.
pub fn load_or_generate_transport_secret(
    path: &Path,
    auto_generate: bool,
) -> Result<[u8; 32], ConfigError> {
    use std::io::{Read, Write};
    if path.exists() {
        let mut file = std::fs::File::open(path)?;
        let mut buf = Vec::with_capacity(32);
        file.read_to_end(&mut buf)?;
        if buf.len() != 32 {
            return Err(ConfigError::BadTransportSecretSize {
                path: path.display().to_string(),
                got: buf.len(),
            });
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&buf);
        return Ok(out);
    }
    if !auto_generate {
        return Err(ConfigError::MissingTransportSecret(
            path.display().to_string(),
        ));
    }
    // Generate + write. The transport key is symmetric in size to
    // any other 32-byte random secret; `OsRng` is the right entropy
    // source.
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let mut file = std::fs::File::create(path)?;
    file.write_all(&bytes)?;
    Ok(bytes)
}

impl HyperRuntimeFileConfig {
    /// Build an SRS from this config — either by loading the ceremony file or
    /// (test-only) by sampling a random τ.
    pub fn build_srs(&self) -> Result<Arc<KzgSrs>, ConfigError> {
        match &self.kzg_setup_path {
            Some(path) => {
                let text = std::fs::read_to_string(Path::new(path))?;
                let parsed = parse_trusted_setup_text(&text)?;
                Ok(Arc::new(parsed.into_srs_monomial(self.srs_max_degree)?))
            }
            None => {
                let mut rng = rand::rngs::OsRng;
                Ok(Arc::new(KzgSrs::random_unsafe(
                    &mut rng,
                    self.srs_max_degree,
                )))
            }
        }
    }

    /// Construct a `HyperRuntime` from this config + an existing RocksDB.
    /// If `genesis_path` is set, the genesis state is applied to the runtime.
    pub fn build_runtime(&self, db: Arc<RocksDB>) -> Result<HyperRuntime, ConfigError> {
        let srs = self.build_srs()?;
        let local_transport_secret_bytes = match &self.transport_secret_path {
            Some(path) => load_or_generate_transport_secret(
                Path::new(path),
                self.auto_generate_transport_secret,
            )?,
            // Missing path → fall back to the zero secret. This is
            // a hard-compromised placeholder; production operators
            // MUST set `transport_secret_path`. See the field doc on
            // `HyperRuntimeFileConfig::transport_secret_path`.
            None => [0u8; 32],
        };
        let runtime_config = HyperRuntimeConfig {
            db,
            srs,
            mempool_capacity: self.mempool_capacity,
            score_weights: self.score_weights.clone().into(),
            bootstrap_validators: vec![],
            max_reward_per_epoch: None,
            max_reward_per_epoch_per_market: std::collections::HashMap::new(),
            cutover_snapchain_block: 0,
            min_validator_trust_score: 0.0,
            protocol_chain_id: crate::hyper::DEFAULT_PROTOCOL_CHAIN_ID,
            scoring_params: proof_of_quality::ScoringParams::default(),
            seed_max_fid: 50_000,
            retro_vesting_on_protocol_epochs: self.retro_vesting_on_protocol_epochs,
            local_transport_secret_bytes,
        };
        let mut runtime = HyperRuntime::new(runtime_config);
        if let Some(fid) = self.operator_fid {
            runtime.set_operator_fid(fid);
        }

        if let Some(path) = &self.genesis_path {
            let text = std::fs::read_to_string(Path::new(path))?;
            let genesis_file: GenesisFileConfig = toml::from_str(&text)?;
            let mut genesis = genesis_file.into_runtime_config()?;
            if let Some(share_path) = &self.local_dkls_share_path {
                let party_index = self
                    .local_dkls_share_party_index
                    .ok_or(ConfigError::DklsShareIndexMissing)?;
                let bytes = std::fs::read(Path::new(share_path)).map_err(|source| {
                    ConfigError::DklsShareIo {
                        path: share_path.clone(),
                        source,
                    }
                })?;
                let party: hypersnap_crypto::dkls23::protocols::Party<
                    hypersnap_crypto::k256::Secp256k1,
                > = bincode::deserialize(&bytes).map_err(|source| {
                    ConfigError::DklsShareDecode {
                        path: share_path.clone(),
                        source,
                    }
                })?;
                if party.party_index as u64 != party_index {
                    return Err(ConfigError::DklsShareIndexMismatch {
                        configured: party_index,
                        on_disk: party.party_index as u64,
                    });
                }
                genesis.local_dkls_party = Some((party_index, Box::new(party)));
            }
            crate::hyper::genesis::bootstrap_runtime(&mut runtime, &genesis)?;
        }

        Ok(runtime)
    }
}

impl GenesisFileConfig {
    /// Parse the file config into a runtime-ready `GenesisConfig`.
    /// `local_share` is always `None` in this path — operators that want to
    /// install a local share at genesis must do so via the runtime API after
    /// `build_runtime` returns. This avoids storing share secrets in TOML.
    pub fn into_runtime_config(self) -> Result<crate::hyper::genesis::GenesisConfig, ConfigError> {
        use crate::hyper::genesis::{BootstrapValidator, GenesisConfig};

        let group_address_hex = self.genesis_group_address_hex.trim_start_matches("0x");
        let addr_bytes = hex::decode(group_address_hex)?;
        if addr_bytes.len() != 20 {
            return Err(ConfigError::BadGroupAddress);
        }
        let group_address = alloy_primitives::Address::from_slice(&addr_bytes);

        let mut validators = Vec::with_capacity(self.bootstrap_validators.len());
        for v in self.bootstrap_validators {
            let va_hex = v.validator_address_hex.trim_start_matches("0x");
            let va_bytes = hex::decode(va_hex)?;
            if va_bytes.len() != 20 {
                return Err(ConfigError::BadValidatorAddress);
            }
            validators.push(BootstrapValidator {
                validator_key: hex::decode(&v.validator_key_hex)?,
                transport_pubkey: hex::decode(&v.transport_pubkey_hex)?,
                validator_address: alloy_primitives::Address::from_slice(&va_bytes),
            });
        }

        Ok(GenesisConfig {
            bootstrap_validators: validators,
            genesis_group_address: group_address,
            local_dkls_party: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn loads_existing_transport_secret_unchanged() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("transport.key");
        let original = [0x42u8; 32];
        std::fs::write(&path, original).unwrap();
        let loaded = load_or_generate_transport_secret(&path, false).unwrap();
        assert_eq!(loaded, original);
    }

    #[test]
    fn auto_generates_when_missing_and_allowed() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("transport.key");
        let generated = load_or_generate_transport_secret(&path, true).unwrap();
        // File now exists with the generated bytes.
        let on_disk = std::fs::read(&path).unwrap();
        assert_eq!(on_disk.len(), 32);
        assert_eq!(on_disk.as_slice(), generated.as_slice());
        // Generated key is overwhelmingly unlikely to be all-zero.
        assert_ne!(generated, [0u8; 32]);
        // Second load returns the same bytes (idempotent — does
        // not re-generate).
        let loaded_again = load_or_generate_transport_secret(&path, false).unwrap();
        assert_eq!(loaded_again, generated);
    }

    #[test]
    fn refuses_to_generate_when_disabled() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("transport.key");
        let r = load_or_generate_transport_secret(&path, false);
        assert!(matches!(r, Err(ConfigError::MissingTransportSecret(_))));
        assert!(
            !path.exists(),
            "must not create the file when generation is disabled"
        );
    }

    #[test]
    fn rejects_wrong_size_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("transport.key");
        std::fs::write(&path, [0u8; 16]).unwrap();
        let r = load_or_generate_transport_secret(&path, false);
        assert!(matches!(
            r,
            Err(ConfigError::BadTransportSecretSize { got: 16, .. })
        ));
    }

    #[test]
    fn creates_parent_directories_on_auto_generate() {
        let dir = TempDir::new().unwrap();
        let path = dir
            .path()
            .join("nested")
            .join("subdir")
            .join("transport.key");
        let _ = load_or_generate_transport_secret(&path, true).unwrap();
        assert!(path.exists());
    }

    #[test]
    fn bridge_burn_watcher_config_parses_0x_address() {
        let cfg = BridgeBurnWatcherFileConfig {
            rpc_url: "http://op.example.com".into(),
            source_chain_id: 10,
            bridge_contract_address_hex: "0x0102030405060708090a0b0c0d0e0f1011121314".into(),
            start_block: 100,
            poll_interval_secs: 15,
            block_batch: 5_000,
            finality_confirmations: 32,
        };
        let runtime = cfg.into_runtime_config().unwrap();
        assert_eq!(runtime.source_chain_id, 10);
        assert_eq!(runtime.start_block, 100);
        assert_eq!(runtime.poll_interval.as_secs(), 15);
        assert_eq!(runtime.block_batch, 5_000);
        assert_eq!(runtime.finality_confirmations, 32);
        assert_eq!(
            runtime.bridge_contract_address.as_slice(),
            [
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
                0x0f, 0x10, 0x11, 0x12, 0x13, 0x14
            ]
        );
    }

    #[test]
    fn bridge_burn_watcher_config_rejects_bad_address_length() {
        let cfg = BridgeBurnWatcherFileConfig {
            rpc_url: "http://op.example.com".into(),
            source_chain_id: 10,
            // 19 bytes, not 20.
            bridge_contract_address_hex: "01020304050607080910111213141516171819".into(),
            ..Default::default()
        };
        let r = cfg.into_runtime_config();
        assert!(matches!(r, Err(ConfigError::BridgeBurnWatcher(_))));
    }

    #[test]
    fn bridge_burn_watcher_config_rejects_missing_address_when_rpc_set() {
        let cfg = BridgeBurnWatcherFileConfig {
            rpc_url: "http://op.example.com".into(),
            source_chain_id: 10,
            bridge_contract_address_hex: String::new(),
            ..Default::default()
        };
        let r = cfg.into_runtime_config();
        assert!(matches!(r, Err(ConfigError::BridgeBurnWatcher(_))));
    }

    #[test]
    fn bridge_burn_watcher_config_allows_empty_entry() {
        // Empty rpc_url + empty address: fully-disabled entry —
        // translator accepts so operator can leave placeholders.
        let cfg = BridgeBurnWatcherFileConfig::default();
        let runtime = cfg.into_runtime_config().unwrap();
        assert!(runtime.rpc_url.is_empty());
        assert_eq!(
            runtime.bridge_contract_address,
            alloy_primitives::Address::ZERO
        );
    }

    fn write_share_to_disk(
        party: &hypersnap_crypto::dkls23::protocols::Party<hypersnap_crypto::k256::Secp256k1>,
        path: &std::path::Path,
    ) {
        let bytes = bincode::serialize(party).expect("serialize party");
        std::fs::write(path, &bytes).expect("write share file");
    }

    fn minimal_genesis_toml(group_address: alloy_primitives::Address) -> String {
        format!(
            r#"genesis_group_address_hex = "0x{}"
bootstrap_validators = [
  {{ validator_key_hex = "{}", transport_pubkey_hex = "{}", validator_address_hex = "0x{}" }}
]
"#,
            hex::encode(group_address.as_slice()),
            hex::encode([0x01u8; 32]),
            hex::encode([0x02u8; 32]),
            hex::encode([0x03u8; 20]),
        )
    }

    fn make_file_config(
        rocksdb_dir: &TempDir,
        share_path: Option<String>,
        share_index: Option<u64>,
        genesis_path: Option<String>,
    ) -> HyperRuntimeFileConfig {
        let _ = rocksdb_dir;
        HyperRuntimeFileConfig {
            enabled: true,
            mempool_capacity: 100,
            score_weights: ScoreWeightsConfig::default(),
            kzg_setup_path: None,
            srs_max_degree: 256,
            genesis_path,
            recovery_watcher: RecoveryWatcherFileConfig::default(),
            retro_vesting_on_protocol_epochs: 29,
            transport_secret_path: None,
            auto_generate_transport_secret: true,
            bridge_burn_watchers: vec![],
            local_dkls_share_path: share_path,
            local_dkls_share_party_index: share_index,
            operator_signer_secret_path: None,
            operator_fid: None,
            operator_validator_pubkey_hex: None,
        }
    }

    fn fresh_db(dir: &TempDir) -> Arc<RocksDB> {
        let db = RocksDB::new(dir.path().to_str().unwrap());
        db.open().unwrap();
        Arc::new(db)
    }

    #[test]
    fn build_runtime_loads_local_dkls_share() {
        let db_dir = TempDir::new().unwrap();
        let share_dir = TempDir::new().unwrap();
        let dkg =
            hypersnap_crypto::dkls_threshold::run_honest_dkg(1, 1, [0xc1; 32]).expect("1-of-1 dkg");
        let share_path = share_dir.path().join("epoch0.share");
        write_share_to_disk(&dkg.parties[0], &share_path);

        let genesis_path = share_dir.path().join("genesis.toml");
        std::fs::write(&genesis_path, minimal_genesis_toml(dkg.group_address)).unwrap();

        let cfg = make_file_config(
            &db_dir,
            Some(share_path.to_str().unwrap().to_string()),
            Some(dkg.parties[0].party_index as u64),
            Some(genesis_path.to_str().unwrap().to_string()),
        );
        let runtime = cfg.build_runtime(fresh_db(&db_dir)).expect("build");
        let share = runtime
            .dkls_share_for_epoch(0)
            .expect("epoch-0 share installed");
        assert_eq!(share.party.party_index, dkg.parties[0].party_index);
        assert_eq!(
            share.party.parameters.share_count,
            dkg.parties[0].parameters.share_count
        );
    }

    #[test]
    fn build_runtime_rejects_share_path_without_index() {
        let db_dir = TempDir::new().unwrap();
        let share_dir = TempDir::new().unwrap();
        let dkg = hypersnap_crypto::dkls_threshold::run_honest_dkg(1, 1, [0xc2; 32]).unwrap();
        let share_path = share_dir.path().join("epoch0.share");
        write_share_to_disk(&dkg.parties[0], &share_path);
        let genesis_path = share_dir.path().join("genesis.toml");
        std::fs::write(&genesis_path, minimal_genesis_toml(dkg.group_address)).unwrap();

        let cfg = make_file_config(
            &db_dir,
            Some(share_path.to_str().unwrap().to_string()),
            None,
            Some(genesis_path.to_str().unwrap().to_string()),
        );
        let result = cfg.build_runtime(fresh_db(&db_dir));
        assert!(result.is_err());
        assert!(matches!(
            result.err().unwrap(),
            ConfigError::DklsShareIndexMissing
        ));
    }

    #[test]
    fn build_runtime_rejects_index_mismatch() {
        let db_dir = TempDir::new().unwrap();
        let share_dir = TempDir::new().unwrap();
        let dkg = hypersnap_crypto::dkls_threshold::run_honest_dkg(2, 3, [0xc3; 32]).unwrap();
        let share_path = share_dir.path().join("epoch0.share");
        write_share_to_disk(&dkg.parties[0], &share_path);
        let genesis_path = share_dir.path().join("genesis.toml");
        std::fs::write(&genesis_path, minimal_genesis_toml(dkg.group_address)).unwrap();

        let cfg = make_file_config(
            &db_dir,
            Some(share_path.to_str().unwrap().to_string()),
            Some(99),
            Some(genesis_path.to_str().unwrap().to_string()),
        );
        let result = cfg.build_runtime(fresh_db(&db_dir));
        assert!(result.is_err());
        let actual_index = dkg.parties[0].party_index as u64;
        assert!(matches!(
            result.err().unwrap(),
            ConfigError::DklsShareIndexMismatch { configured: 99, on_disk } if on_disk == actual_index
        ));
    }

    #[test]
    fn build_runtime_reports_missing_share_file() {
        let db_dir = TempDir::new().unwrap();
        let share_dir = TempDir::new().unwrap();
        let dkg = hypersnap_crypto::dkls_threshold::run_honest_dkg(1, 1, [0xc4; 32]).unwrap();
        let genesis_path = share_dir.path().join("genesis.toml");
        std::fs::write(&genesis_path, minimal_genesis_toml(dkg.group_address)).unwrap();

        let cfg = make_file_config(
            &db_dir,
            Some(
                share_dir
                    .path()
                    .join("nope.share")
                    .to_str()
                    .unwrap()
                    .to_string(),
            ),
            Some(1),
            Some(genesis_path.to_str().unwrap().to_string()),
        );
        let result = cfg.build_runtime(fresh_db(&db_dir));
        assert!(result.is_err());
        assert!(matches!(
            result.err().unwrap(),
            ConfigError::DklsShareIo { .. }
        ));
    }

    #[test]
    fn build_runtime_succeeds_without_share_path() {
        let db_dir = TempDir::new().unwrap();
        let share_dir = TempDir::new().unwrap();
        let group_address = alloy_primitives::Address::ZERO;
        let genesis_path = share_dir.path().join("genesis.toml");
        std::fs::write(&genesis_path, minimal_genesis_toml(group_address)).unwrap();
        let cfg = make_file_config(
            &db_dir,
            None,
            None,
            Some(genesis_path.to_str().unwrap().to_string()),
        );
        let runtime = cfg.build_runtime(fresh_db(&db_dir)).expect("build");
        assert!(runtime.dkls_share_for_epoch(0).is_none());
    }
}
