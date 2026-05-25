use std::collections::BTreeMap;

use super::validator::StoredValidatorSets;
use crate::consensus::consensus::SystemMessage;
use crate::core::types::{CommitsExt, SnapchainValidatorContext};
use crate::core::util::{verify_signatures, FarcasterTime};
use crate::proto::{self, DecidedValue, FarcasterNetwork, Height};
use crate::storage::store::block_engine::BlockEngine;
use crate::storage::store::engine::ShardEngine;
use crate::utils::statsd_wrapper::StatsdClientWrapper;
use crate::version::version::EngineVersion;
use bytes::Bytes;
use informalsystems_malachitebft_sync::RawDecidedValue;
use prost::Message;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

pub enum Engine {
    ShardEngine(ShardEngine),
    BlockEngine(BlockEngine),
}
pub struct ReadValidator {
    pub engine: Engine,
    pub shard_id: u32,
    pub last_height: Height,
    pub max_num_buffered_blocks: u32,
    pub buffered_blocks: BTreeMap<Height, proto::DecidedValue>,
    pub statsd_client: StatsdClientWrapper,
    pub validator_sets: StoredValidatorSets,
    pub system_tx: mpsc::Sender<SystemMessage>,
}

impl ReadValidator {
    pub fn initialize_height(&mut self) {
        let height = match &self.engine {
            Engine::BlockEngine(engine) => engine.get_confirmed_height(),
            Engine::ShardEngine(engine) => engine.get_confirmed_height(),
        };
        self.last_height = height;
    }

    pub fn get_min_height(&self) -> Height {
        match &self.engine {
            Engine::BlockEngine(engine) => engine.get_min_height(),
            Engine::ShardEngine(engine) => engine.get_min_height(),
        }
    }

    async fn commit_decided_value(&mut self, value: &DecidedValue, height: Height) {
        // F005: peer-controlled `DecidedValue.value` oneof. Drop with
        // an error log instead of panicking when the variant doesn't
        // match the engine (e.g. forward-incompat protocol drift, an
        // unknown tag decoded by prost as `None`, or a HyperBlock
        // arriving on a non-hyper engine).
        match &mut self.engine {
            Engine::ShardEngine(shard_engine) => match &value.value {
                Some(proto::decided_value::Value::Shard(shard_chunk)) => {
                    shard_engine.commit_shard_chunk(&shard_chunk).await;
                    info!(
                        %height,
                        hash = hex::encode(&shard_chunk.hash),
                        "Processed decided shard chunk"
                    );
                    self.last_height = height;
                }
                other => {
                    error!(
                        %height,
                        variant = ?other.as_ref().map(|v| std::mem::discriminant(v)),
                        "Dropping DecidedValue: expected a ShardChunk for ShardEngine"
                    );
                }
            },
            Engine::BlockEngine(block_engine) => match &value.value {
                Some(proto::decided_value::Value::Block(block)) => {
                    block_engine.commit_block(&block);
                    info!(
                        %height,
                        hash = hex::encode(&block.hash),
                        "Processed decided block"
                    );
                    self.last_height = height;
                }
                other => {
                    error!(
                        %height,
                        variant = ?other.as_ref().map(|v| std::mem::discriminant(v)),
                        "Dropping DecidedValue: expected a Block for BlockEngine"
                    );
                }
            },
        };
    }

    async fn process_buffered_blocks(&mut self) -> u64 {
        let mut num_blocks_processed = 0;
        // This works only because [buffered_blocks] is ordered by height. It's important to maintain this property
        while let Some((height, value)) = self.buffered_blocks.pop_first() {
            if height == self.last_height.increment() {
                self.commit_decided_value(&value, height).await;
                num_blocks_processed += 1;
            } else if height > self.last_height.increment() {
                self.buffered_blocks.insert(height, value);
                break;
            }
        }

        num_blocks_processed
    }

    /// F005: returns `None` when the peer-controlled oneof is empty
    /// (unknown future variant decoded by prost) or when a nested
    /// `Option` (`header`, `header.height`) is missing. Callers must
    /// drop the message in that case, not unwrap.
    fn get_decided_value_height(value: &proto::DecidedValue) -> Option<Height> {
        match value.value.as_ref()? {
            proto::decided_value::Value::Shard(shard_chunk) => {
                shard_chunk.header.as_ref().and_then(|h| h.height)
            }

            proto::decided_value::Value::Block(block) => {
                block.header.as_ref().and_then(|h| h.height)
            }

            proto::decided_value::Value::HyperBlock(hb) => {
                // Hyperblocks have their own consensus path. This helper is not
                // meant to handle them, but we provide a best-effort height in
                // case of accidental routing.
                let canonical = hb
                    .envelope
                    .as_ref()
                    .and_then(|e| e.metadata.as_ref())
                    .map(|m| m.canonical_block_id)
                    .unwrap_or(0);
                Some(Height {
                    shard_index: 0,
                    block_number: canonical,
                })
            }
        }
    }

    fn verify_signatures(&self, value: &proto::DecidedValue) -> bool {
        // F005: `value.value` is peer-controlled; missing-or-unknown
        // variants are dropped rather than panicked on.
        let inner = match value.value.as_ref() {
            Some(v) => v,
            None => return false,
        };
        let commits = match inner {
            proto::decided_value::Value::Shard(shard_chunk) => match shard_chunk.commits.as_ref() {
                Some(c) => c,
                None => return false,
            },

            proto::decided_value::Value::Block(block) => match block.commits.as_ref() {
                Some(c) => c,
                None => return false,
            },

            proto::decided_value::Value::HyperBlock(_) => {
                // Hyperblocks carry threshold BLS signatures, not Ed25519
                // commits. They are verified against the per-epoch group public
                // key on a separate path; this Ed25519-quorum verifier is not
                // applicable.
                return false;
            }
        };

        verify_signatures(&commits, &self.validator_sets)
    }

    pub fn validate_protocol_version(&self, value: &DecidedValue) -> bool {
        match &value.value {
            Some(proto::decided_value::Value::Block(block)) => {
                // F005: peer-controlled — `header`, `chain_id`, and
                // nested `height` are all guarded.
                let header = match block.header.as_ref() {
                    Some(h) => h,
                    None => return false,
                };
                let network = match FarcasterNetwork::try_from(header.chain_id) {
                    Ok(n) => n,
                    Err(_) => return false,
                };
                let timestamp = FarcasterTime::new(header.timestamp);
                let expected_version =
                    EngineVersion::version_for(&timestamp, network).protocol_version();

                if header.version != expected_version {
                    let block_number = header.height.map(|h| h.block_number).unwrap_or(0);
                    let error_message = format!(
                        "Invalid protocol version in decided block at height {}: expected {}, got {}. Does your node need an upgrade?",
                        block_number,
                        expected_version, header.version
                    );
                    error!(%self.last_height, error_message);
                    self.system_tx
                        .try_send(SystemMessage::ExitWithError(error_message))
                        .unwrap_or_else(|e| {
                            error!(%self.last_height, "Failed to send system message: {}", e);
                        });
                    return false;
                }
            }
            _ => {
                // no-op. Only blocks have protocol version. Unknown
                // (None) variants are dropped earlier in process_decided_value.
            }
        }
        true
    }

    pub async fn process_decided_value(&mut self, value: DecidedValue) -> u64 {
        // F005: peer-controlled `value.value` may be `None` for
        // unknown future oneof variants. Drop the message rather than
        // panic on `.unwrap()`.
        let height = match Self::get_decided_value_height(&value) {
            Some(h) => h,
            None => {
                warn!(
                    last_height = %self.last_height,
                    "Dropping decided value: missing or unknown oneof variant (possible forward-protocol drift)"
                );
                return 0;
            }
        };
        let verified = self.verify_signatures(&value);
        if !verified {
            error!(%height, last_height = %self.last_height, "Dropping decided block because its signatures are invalid");
            return 0;
        }

        // Only validate the protocol version after verifying signatures so we know it's a valid block
        if !self.validate_protocol_version(&value) {
            error!(%height, last_height = %self.last_height, "Dropping decided block because its protocol version is invalid");
            return 0;
        }

        let num_committed_values = if height > self.last_height.increment() {
            if (self.buffered_blocks.len() as u32) < self.max_num_buffered_blocks {
                self.buffered_blocks.insert(height, value);
                0
            } else {
                warn!(%height, last_height = %self.last_height, "Dropping decided block because buffered block space is full");
                0
            }
        } else if height == self.last_height.increment() {
            self.commit_decided_value(&value, height).await;
            let num_buffered_blocks_processed = self.process_buffered_blocks().await;
            num_buffered_blocks_processed + 1
        } else {
            debug!(%height, last_height = %self.last_height, "Dropping decided block because height is too low");
            0
        };
        self.statsd_client.gauge_with_shard(
            self.shard_id,
            "read_validator.num_buffered_blocks",
            self.buffered_blocks.len() as u64,
        );
        self.statsd_client.count_with_shard(
            self.shard_id,
            "read_validator.num_commited_values",
            num_committed_values,
            vec![],
        );
        num_committed_values
    }

    pub fn get_decided_value(
        &mut self,
        height: Height,
    ) -> Option<RawDecidedValue<SnapchainValidatorContext>> {
        match &self.engine {
            Engine::ShardEngine(shard_engine) => {
                let shard_chunk = shard_engine.get_shard_chunk_by_height(height);
                match shard_chunk {
                    Some(chunk) => {
                        let commits = chunk.commits.clone().unwrap();
                        Some(RawDecidedValue {
                            certificate: commits.to_commit_certificate(),
                            value_bytes: Bytes::from(chunk.encode_to_vec()),
                        })
                    }
                    None => None,
                }
            }
            Engine::BlockEngine(block_engine) => {
                let block = block_engine.get_block_by_height(height);
                match block {
                    Some(block) => {
                        let commits = block.commits.clone().unwrap();
                        Some(RawDecidedValue {
                            certificate: commits.to_commit_certificate(),
                            value_bytes: Bytes::from(block.encode_to_vec()),
                        })
                    }
                    None => None,
                }
            }
        }
    }
}
