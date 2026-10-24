use std::collections::BTreeMap;

use super::pivot_guard::PivotGuard;
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
    /// Set when the release fixes `PIVOT_HEIGHT` for the network. Shard 1/2
    /// chunks then wait for a shard-0 witness (see `pivot_guard`).
    pub pivot_guard: Option<PivotGuard>,
}

impl ReadValidator {
    pub fn initialize_height(&mut self) {
        let height = match &self.engine {
            Engine::BlockEngine(engine) => engine.get_confirmed_height(),
            Engine::ShardEngine(engine) => engine.get_confirmed_height(),
        };
        self.last_height = height;
        // A shard that is already at its fork height reports it at start.
        self.after_commit(height);
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

    /// False if the pivot guard holds this value back for now.
    fn pivot_guard_allows(&self, height: Height) -> bool {
        match &self.pivot_guard {
            Some(guard) => guard.allows(self.shard_id, height.block_number),
            None => true,
        }
    }

    /// After a commit (FIP §17.5 steps 1-4): when shard 0 has applied the
    /// fork block and every shard is at its fork height, persist the marker
    /// and stop the process. The next start is a Hypersnap node.
    fn after_commit(&mut self, height: Height) {
        let Some(guard) = &self.pivot_guard else {
            return;
        };
        let Some(marker) = guard.record_height(self.shard_id, height.block_number) else {
            return;
        };
        if let Err(e) = crate::consensus::pivot_guard::write_marker(guard.db(), &marker) {
            error!("Cannot write the pivot marker: {}", e);
            return;
        }
        info!(
            fork_height = guard.fork_height(),
            "Applied the fork block and the fork heights; restart as a Hypersnap node"
        );
        let _ = self.system_tx.try_send(SystemMessage::ExitWithError(
            "pivot: the fork block is applied; restart as a Hypersnap node".to_string(),
        ));
    }

    async fn process_buffered_blocks(&mut self) -> u64 {
        let mut num_blocks_processed = 0;
        // This works only because [buffered_blocks] is ordered by height. It's important to maintain this property
        while let Some((height, value)) = self.buffered_blocks.pop_first() {
            if height == self.last_height.increment() {
                if !self.pivot_guard_allows(height) {
                    self.buffered_blocks.insert(height, value);
                    break;
                }
                self.commit_decided_value(&value, height).await;
                self.after_commit(height);
                num_blocks_processed += 1;
            } else if height > self.last_height.increment() {
                self.buffered_blocks.insert(height, value);
                break;
            }
        }

        num_blocks_processed
    }

    /// Returns the height in a decided value's header, or `None` if the value, header or height
    /// is missing.
    pub fn decided_value_height(value: &proto::DecidedValue) -> Option<Height> {
        match value.value.as_ref()? {
            proto::decided_value::Value::Shard(shard_chunk) => shard_chunk.header.as_ref()?.height,
            proto::decided_value::Value::Block(block) => block.header.as_ref()?.height,
            proto::decided_value::Value::HypersnapBlock(bytes) => {
                let view = proto::HypersnapBlockView::decode(bytes.as_slice()).ok()?;
                view.header.map(|h| Height {
                    shard_index: h.shard_id,
                    block_number: h.height,
                })
            }
        }
    }

    fn matches_engine(&self, value: &proto::DecidedValue) -> bool {
        matches!(
            (&self.engine, &value.value),
            (
                Engine::ShardEngine(_),
                Some(proto::decided_value::Value::Shard(_))
            ) | (
                Engine::BlockEngine(_),
                Some(proto::decided_value::Value::Block(_))
            )
        )
    }

    fn verify_signatures(&self, value: &proto::DecidedValue) -> bool {
        let commits = match value.value.as_ref() {
            Some(proto::decided_value::Value::Shard(shard_chunk)) => shard_chunk.commits.as_ref(),
            Some(proto::decided_value::Value::Block(block)) => block.commits.as_ref(),
            // Hypersnap blocks (after the pivot) are not part of the
            // snapchain read path.
            Some(proto::decided_value::Value::HypersnapBlock(_)) | None => None,
        };

        match commits {
            Some(commits) => verify_signatures(commits, &self.validator_sets),
            None => false,
        }
    }

    /// F012: re-derive `hash` from `blake3(header.encode_to_vec())` and
    /// compare against the proto field. The signed consensus value is
    /// `commits.value.hash`; once we've verified the quorum signed
    /// that, this check binds it to the actual `header` (and via the
    /// header's `state_root`/`events_hash`/`shard_witnesses_hash`, to
    /// the body).
    fn validate_block_hash_matches_header(&self, value: &DecidedValue) -> bool {
        use prost::Message;
        match value.value.as_ref() {
            Some(proto::decided_value::Value::Block(block)) => {
                let header = match block.header.as_ref() {
                    Some(h) => h,
                    None => return false,
                };
                let expected = blake3::hash(&header.encode_to_vec()).as_bytes().to_vec();
                block.hash == expected
            }
            Some(proto::decided_value::Value::Shard(chunk)) => {
                let header = match chunk.header.as_ref() {
                    Some(h) => h,
                    None => return false,
                };
                let expected = blake3::hash(&header.encode_to_vec()).as_bytes().to_vec();
                chunk.hash == expected
            }
            // Hyperblocks have their own integrity model (threshold-
            // signed state-root over a metadata payload). Not gated
            // by this check.
            _ => true,
        }
    }

    pub fn validate_protocol_version(&self, value: &DecidedValue) -> bool {
        match &value.value {
            Some(proto::decided_value::Value::Block(block)) => {
                let Some(header) = block.header.as_ref() else {
                    return false;
                };
                let Ok(network) = FarcasterNetwork::try_from(header.chain_id) else {
                    error!(%self.last_height, chain_id = header.chain_id, "Invalid chain id in decided block");
                    return false;
                };
                let timestamp = FarcasterTime::new(header.timestamp);
                let expected_version =
                    EngineVersion::version_for(&timestamp, network).protocol_version();

                if header.version != expected_version {
                    let error_message = format!(
                        "Invalid protocol version in decided block at height {}: expected {}, got {}. Does your node need an upgrade?",
                        header.height.unwrap_or_default().block_number,
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
            Some(proto::decided_value::Value::Shard(chunk)) => {
                // F011 fix: shard chunks have no header.version field
                // (ShardHeader carries only height/timestamp/parent_hash/
                // shard_root), so the old code returned `true` here —
                // letting a stale binary commit chunks under a
                // locally-derived `EngineVersion` and silently diverge
                // from the network state across a time-gated upgrade
                // boundary.
                //
                // Heuristic check: if `version_for(timestamp, network)`
                // maps to the binary's latest known version AND the
                // timestamp is past the latest schedule entry's
                // `active_at`, the binary may be missing newer
                // schedule entries. Halt rather than silently apply.
                if let Engine::ShardEngine(engine) = &self.engine {
                    // Devnet ships with a single-entry schedule; there's no
                    // upgrade cadence to stale against. Skip the heuristic.
                    if engine.network == FarcasterNetwork::Devnet {
                        return true;
                    }
                    let header = match chunk.header.as_ref() {
                        Some(h) => h,
                        None => return false,
                    };
                    let timestamp = FarcasterTime::new(header.timestamp);
                    let derived = EngineVersion::version_for(&timestamp, engine.network);
                    if derived == EngineVersion::latest()
                        && EngineVersion::next_version_timestamp_for(&timestamp, engine.network)
                            .is_none()
                    {
                        // Use the actual schedule horizon: the
                        // active_at of the latest entry the binary
                        // knows about. Any chunk timestamp far past
                        // that horizon is suspicious — the network
                        // has shipped a newer EngineVersion we don't
                        // know about. Grace period is intentionally
                        // long (60d) so routine off-cycle deploys
                        // don't trip the halt.
                        const SHARD_STALENESS_GRACE_SECS: u64 = 60 * 24 * 60 * 60;
                        if let Some(horizon) =
                            EngineVersion::latest_schedule_active_at(engine.network)
                        {
                            if timestamp.to_unix_seconds()
                                > horizon.saturating_add(SHARD_STALENESS_GRACE_SECS)
                            {
                                let block_number =
                                    header.height.map(|h| h.block_number).unwrap_or(0);
                                let error_message = format!(
                                    "Shard chunk at height {} timestamp {} is more than {} \
                                     days past the binary's known schedule horizon ({}). \
                                     Does your node need an upgrade?",
                                    block_number,
                                    timestamp.to_unix_seconds(),
                                    SHARD_STALENESS_GRACE_SECS / 86400,
                                    horizon,
                                );
                                error!(%self.last_height, error_message);
                                self.system_tx
                                    .try_send(SystemMessage::ExitWithError(error_message))
                                    .unwrap_or_else(|e| {
                                        error!(
                                            %self.last_height,
                                            "Failed to send system message: {}", e
                                        );
                                    });
                                return false;
                            }
                        }
                    }
                }
            }
            _ => {
                // Unknown (None) variants are dropped earlier in process_decided_value.
            }
        }
        true
    }

    pub async fn process_decided_value(&mut self, value: DecidedValue) -> u64 {
        let Some(height) = Self::decided_value_height(&value) else {
            warn!(last_height = %self.last_height, "Dropping decided value with missing header or height");
            return 0;
        };
        if height.shard_index != self.shard_id || !self.matches_engine(&value) {
            warn!(%height, last_height = %self.last_height, "Dropping decided value for a different shard");
            return 0;
        }
        let verified = self.verify_signatures(&value);
        if !verified {
            error!(%height, last_height = %self.last_height, "Dropping decided block because its signatures are invalid");
            return 0;
        }

        // F012 fix: the quorum signed `commits.value = ShardHash{hash}`,
        // but `hash` is a proposer-set proto field. Pre-fix nothing
        // rederived `blake3(header)` on the read path, so a relayer
        // with a valid `Commits` for height H could wrap it around a
        // Block/ShardChunk whose `hash` equals the signed value but
        // whose `header`+body were attacker-chosen. Bind hash → header
        // here so the signed value transitively covers the body via
        // `state_root`/`events_hash`/`shard_witnesses_hash`.
        if !self.validate_block_hash_matches_header(&value) {
            error!(
                %height,
                last_height = %self.last_height,
                "F012: decided block hash does not match blake3(header); dropping"
            );
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
                // The value at last_height + 1 may be one that the pivot
                // guard held back; shard 0 may have witnessed it since.
                if self.pivot_guard.is_some() {
                    self.process_buffered_blocks().await
                } else {
                    0
                }
            } else {
                warn!(%height, last_height = %self.last_height, "Dropping decided block because buffered block space is full");
                0
            }
        } else if height == self.last_height.increment() {
            if self.pivot_guard_allows(height) {
                self.commit_decided_value(&value, height).await;
                self.after_commit(height);
                let num_buffered_blocks_processed = self.process_buffered_blocks().await;
                num_buffered_blocks_processed + 1
            } else {
                // Not witnessed by shard 0 yet. Keep it; a later decided
                // value retries the buffer.
                self.buffered_blocks.insert(height, value);
                0
            }
        } else {
            debug!(%height, last_height = %self.last_height, "Dropping decided block because height is too low");
            // Retry values that the pivot guard held back: shard 0 may have
            // witnessed them since.
            if self.pivot_guard.is_some() {
                self.process_buffered_blocks().await
            } else {
                0
            }
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
