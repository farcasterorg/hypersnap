use super::Error;
use serde::Deserialize;
use std::{collections::BTreeMap, path::PathBuf};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side {
    Hypersnap = 0,
    Snapchain = 1,
}
impl Side {
    pub fn name(self) -> &'static str {
        match self {
            Self::Hypersnap => "hypersnap",
            Self::Snapchain => "snapchain",
        }
    }
    pub fn topic(self) -> &'static str {
        match self {
            Self::Hypersnap => snapchain_proto::topics::MEMPOOL,
            Self::Snapchain => snapchain_proto::topics::SNAPCHAIN_MEMPOOL,
        }
    }
    pub fn other(self) -> Self {
        match self {
            Self::Hypersnap => Self::Snapchain,
            Self::Snapchain => Self::Hypersnap,
        }
    }
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Network {
    pub rpc: String,
    pub peers: Vec<String>,
    #[serde(default = "listen")]
    pub listen: String,
    /// Absent cursors start at the current tip + 1; explicit heights are inclusive.
    #[serde(default)]
    pub start_blocks: BTreeMap<String, u64>,
    /// Restrict when the deployed destination supports fewer types than the schema.
    #[serde(default = "types")]
    pub message_types: Vec<i32>,
}
fn listen() -> String {
    "/ip4/0.0.0.0/udp/0/quic-v1".into()
}
fn types() -> Vec<i32> {
    (1..=8).chain(11..=21).collect()
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub state_dir: PathBuf,
    #[serde(default = "network")]
    pub network: i32,
    #[serde(default = "shards")]
    pub shards: Vec<u32>,
    #[serde(default = "poll")]
    pub poll_ms: u64,
    #[serde(default = "batch")]
    pub batch_blocks: u64,
    #[serde(default = "timeout")]
    pub rpc_timeout_secs: u64,
    /// Must match the Hypersnap validator fork schedule.
    pub topic_cutovers: BTreeMap<String, u64>,
    #[serde(default = "num_shards")]
    pub num_shards: u32,
    pub hypersnap: Network,
    pub snapchain: Network,
}
fn num_shards() -> u32 {
    2
}
fn network() -> i32 {
    1
}
fn shards() -> Vec<u32> {
    vec![0, 1, 2]
}
fn poll() -> u64 {
    500
}
fn batch() -> u64 {
    16
}
fn timeout() -> u64 {
    15
}
impl Config {
    pub fn load(path: &std::path::Path) -> Result<Self, Error> {
        let config: Self = toml::from_str(&std::fs::read_to_string(path)?)?;
        config.validate()?;
        Ok(config)
    }
    pub fn validate(&self) -> Result<(), Error> {
        if !(1..=3).contains(&self.network)
            || self.poll_ms == 0
            || self.rpc_timeout_secs == 0
            || !(1..=100).contains(&self.batch_blocks)
            || self.shards.is_empty()
        {
            return Err("invalid network, timing, batch size or empty shard list".into());
        }
        self.topic_schedule()?;
        if self.topic_cutovers.is_empty() {
            return Err("shuttle requires explicit Hypersnap topic_cutovers".into());
        }
        let unique: std::collections::HashSet<_> = self.shards.iter().collect();
        if unique.len() != self.shards.len() {
            return Err("duplicate shard IDs".into());
        }
        for side in [&self.hypersnap, &self.snapchain] {
            tonic::transport::Endpoint::new(side.rpc.clone())?;
            if side.peers.is_empty() {
                return Err("each destination needs at least one gossip peer".into());
            }
            side.listen.parse::<libp2p::Multiaddr>()?;
            for peer in &side.peers {
                peer.parse::<libp2p::Multiaddr>()?;
            }
            if side.message_types.iter().any(|t| !types().contains(t)) {
                return Err("unknown or non-user message type in allowlist".into());
            }
            if side
                .start_blocks
                .keys()
                .any(|s| s.parse::<u32>().map_or(true, |n| !self.shards.contains(&n)))
            {
                return Err("start_blocks contains an unconfigured shard".into());
            }
        }
        if self.hypersnap.rpc == self.snapchain.rpc {
            return Err("source RPCs must identify different networks".into());
        }
        Ok(())
    }
    pub fn topic_schedule(&self) -> Result<crate::network::topic_schedule::Schedule, Error> {
        let mut schedule = crate::network::topic_schedule::Schedule::new(
            &self.topic_cutovers,
            crate::proto::FarcasterNetwork::try_from(self.network)?,
        )
        .map_err(std::io::Error::other)?;
        schedule
            .set_num_shards(self.num_shards)
            .map_err(std::io::Error::other)?;
        Ok(schedule)
    }
    pub fn side(&self, side: Side) -> &Network {
        match side {
            Side::Hypersnap => &self.hypersnap,
            Side::Snapchain => &self.snapchain,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn example_and_explicit_start_blocks_parse_and_schedule_matches_validators() {
        let example = include_str!("../../shuttle.example.toml");
        let mut config: Config = toml::from_str(example).unwrap();
        config.validate().unwrap();
        let validators: toml::Value =
            toml::from_str(include_str!("../../validators.toml")).unwrap();
        let cutovers: BTreeMap<String, u64> = validators["gossip"]["topic_cutovers"]
            .clone()
            .try_into()
            .unwrap();
        assert_eq!(config.topic_cutovers, cutovers);
        for (shard, height) in &cutovers {
            assert!(
                validators["consensus"]["validator_sets"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|set| {
                        set["effective_at"].as_integer() == Some(*height as i64)
                            && set["shard_ids"]
                                .as_array()
                                .unwrap()
                                .iter()
                                .any(|id| id.as_integer() == shard.parse::<i64>().ok())
                    }),
                "topic cutoff must match a scheduled validator transition"
            );
        }
        let with_start = example.replace(
            "[snapchain]",
            "[hypersnap.start_blocks]\n\"0\" = 12\n\"1\" = 34\n[snapchain]",
        );
        let start: Config = toml::from_str(&with_start).unwrap();
        start.validate().unwrap();
        assert_eq!(start.hypersnap.start_blocks.get("0"), Some(&12));
        config.topic_cutovers.remove("1");
        assert!(config.validate().is_err());
    }
}
