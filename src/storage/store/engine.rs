use super::account::{IntoU8, OnchainEventStorageError, UserDataStore, UsernameProofStore};
use crate::connectors::onchain_events;
use crate::consensus::proposer::ProposalSource;
use crate::core::{
    error::HubError, message::HubEventExt, types::Height, util::FarcasterTime, validations,
    validations::verification,
};
use crate::mempool::mempool::MempoolMessagesRequest;
use crate::proto::message_data::Body;
use crate::proto::shard_trie_entry_with_message::TrieMessage;
use crate::proto::BlockEvent;
use crate::proto::{
    self, hub_event, FarcasterNetwork, HubEvent, HubEventType, MessageType, OnChainEvent,
    OnChainEventType, Protocol, ShardChunk, ShardTrieEntryWithMessage, Transaction, UserDataType,
    UserNameProof,
};
use crate::storage::db::{PageOptions, RocksDB, RocksDbTransactionBatch};
use crate::storage::store::account::{
    BlockEventStorageError, CastStore, MergeContext, MessagesPage, StorageLendStore, StoreOptions,
    VerificationStore,
};
use crate::storage::store::engine_metrics::Metrics;
use crate::storage::store::mempool_poller::{MempoolMessage, MempoolPoller, MempoolPollerError};
use crate::storage::store::migrations::{MigrationContext, MigrationRunner};
use crate::storage::store::node_local_state;
use crate::storage::store::state_context::StateContext;
use crate::storage::store::stores::{StoreLimits, Stores};
use crate::storage::trie::{self, merkle_trie};
use crate::utils::statsd_wrapper::StatsdClientWrapper;
use crate::version::version::{EngineVersion, ProtocolFeature};
use alloy_primitives::hex::FromHex;
use alloy_primitives::Address;
use informalsystems_malachitebft_core_types::Round;
use itertools::Itertools;
use merkle_trie::TrieKey;
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::str;
use std::string::ToString;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::sync::{broadcast, mpsc, oneshot};
use tracing::{debug, error, info, warn};

#[derive(Error, Debug)]
pub enum EngineError {
    #[error(transparent)]
    TrieError(#[from] trie::errors::TrieError),

    #[error(transparent)]
    StoreError(#[from] HubError),

    #[error("unsupported message type")]
    UnsupportedMessageType(MessageType),

    #[error("merkle trie root hash mismatch")]
    HashMismatch,

    #[error("Unable to get usage count")]
    UsageCountError,

    #[error(transparent)]
    MergeOnchainEventError(#[from] OnchainEventStorageError),

    #[error(transparent)]
    EngineMessageValidationError(#[from] MessageValidationError),

    #[error(transparent)]
    MempoolPollerError(#[from] MempoolPollerError),

    #[error(transparent)]
    BlockEventStoreError(#[from] BlockEventStorageError),

    #[error("Replicator merge error: {0}")]
    ReplicatorError(String),

    #[error("rejected by the Hypersnap rules: {0}")]
    HypersnapRejected(String),

    #[error("content replay: {0}")]
    ContentReplay(String),
}

#[derive(Error, Debug, Clone)]
pub enum MessageValidationError {
    #[error("message has no data")]
    NoMessageData,

    #[error("unknown fid")]
    MissingFid,

    #[error("invalid signer")]
    MissingSigner,

    #[error("message type {msg_type} is not in the scope of the gasless signer")]
    GaslessKeyOutOfScope { msg_type: i32 },

    #[error(transparent)]
    MessageValidationError(#[from] validations::error::ValidationError),

    #[error("invalid message type")]
    InvalidMessageType(i32),

    #[error(transparent)]
    StoreError(#[from] HubError),

    #[error("fname is not registered for fid")]
    MissingFname,

    #[error("invalid ethereum address")]
    InvalidEthereumAddress,

    #[error("invalid solana address")]
    InvalidSolanaAddress,

    #[error("address is not part of any verification")]
    AddressNotPartOfVerification,

    #[error("invalid seqnum for block event")]
    InvalidSeqnumForBlockEvent,

    #[error("block event missing body")]
    BlockEventMissingBody,
}

pub struct MergedReplicatorMessage {
    pub fid: u64,
    pub trie_keys: Vec<Vec<u8>>,
    pub hub_event: HubEvent,
}

// Shard state root and the transactions
#[derive(Clone)]
pub struct ShardStateChange {
    pub shard_id: u32,
    pub timestamp: FarcasterTime,
    pub new_state_root: Vec<u8>,
    pub transactions: Vec<Transaction>,
    pub events: Vec<HubEvent>,
    pub version: EngineVersion,
    pub max_block_event_seqnum: u64,
}

#[derive(Clone)]
pub struct Senders {
    pub events_tx: broadcast::Sender<HubEvent>,
}

impl Senders {
    pub fn new() -> Senders {
        let (events_tx, _events_rx) = broadcast::channel::<HubEvent>(10_000); // About 10s of events with full blocks
        Senders { events_tx }
    }
}

#[derive(Debug)]
pub struct PostCommitMessage {
    pub shard_id: u32,
    pub header: proto::ShardHeader,
    pub channel: oneshot::Sender<bool>,
}

#[derive(Clone)]
struct CachedTransaction {
    shard_root: Vec<u8>,
    events: Vec<HubEvent>,
    max_block_event_seqnum: u64,
    block_events_hash: Vec<u8>,
    txn: RocksDbTransactionBatch,
    /// Hypersnap mode: the replica entries that the execution applied. Two
    /// proposals with the same transactions can reference different shard-0
    /// heights, so the cache must match them too.
    replica_key: Vec<u8>,
}

pub struct ShardEngine {
    shard_id: u32,
    pub network: FarcasterNetwork,
    pub db: Arc<RocksDB>,
    senders: Senders,
    stores: Stores,
    /// Shadow stores using Hyper key prefixes. When present, every merge
    /// is dual-written here (same RocksDB, different key space). Pruning
    /// is skipped so the hyper stores retain all historical data.
    hyper_stores: Option<Stores>,
    metrics: Metrics,
    pending_txn: Option<CachedTransaction>,
    /// Whether a stale `ShardHalt` record from a previous run has been cleared
    /// yet. Checked once, on the first successful commit after start, so a
    /// resolved halt stops being reported without costing a read per block.
    halt_record_checked: bool,
    fname_signer_address: Option<alloy_primitives::Address>,
    post_commit_tx: Option<mpsc::Sender<PostCommitMessage>>,
    pub mempool_poller: MempoolPoller,
    /// Shadow Keccak state trie (plan R0). `None` unless enabled.
    shadow_trie: Option<crate::storage::trie::shadow_trie::ShadowTrie>,
    /// Set while a backfill thread owns the shadow trie records.
    shadow_backfill_running: Arc<std::sync::atomic::AtomicBool>,
    /// After the epoch-1 pivot: the Keccak trie is the state commitment and
    /// the blake3 shard root is an internal value, not checked against the
    /// chunk header (FIP §16.13, §17.7).
    hypersnap_mode: bool,
    /// The content replay (FIP §17.4): snapchain chunks with no pruning.
    /// The state differs from snapchain's, so the snapchain roots are not
    /// checked.
    content_replay: bool,
    /// Hypersnap mode: the height of the block being built or checked, and
    /// the shard-0 outbox entries that it applies first (FIP §17.7).
    hypersnap_height: u64,
    hypersnap_replica: Vec<proto::OutboxEntry>,
    hypersnap_replica_key: Vec<u8>,
}

/// Result of replaying a Hypersnap block body on shard 1 or 2.
#[derive(Clone, Debug)]
pub struct HypersnapReplay {
    /// Keccak state root after the block (the header `state_root`).
    pub state_root: [u8; 32],
    /// Internal blake3 root after the block.
    pub blake3_root: Vec<u8>,
}

impl ShardEngine {
    pub async fn new(
        db: Arc<RocksDB>,
        network: proto::FarcasterNetwork,
        trie: merkle_trie::MerkleTrie,
        shard_id: u32,
        store_limits: StoreLimits,
        statsd_client: StatsdClientWrapper,
        max_messages_per_block: u32,
        messages_request_tx: Option<mpsc::Sender<MempoolMessagesRequest>>,
        fname_signer_address: Option<alloy_primitives::Address>,
        post_commit_tx: Option<mpsc::Sender<PostCommitMessage>>,
    ) -> Result<ShardEngine, HubError> {
        Self::new_with_opts(
            db,
            network,
            trie,
            shard_id,
            store_limits,
            statsd_client,
            max_messages_per_block,
            messages_request_tx,
            fname_signer_address,
            post_commit_tx,
            StoreOptions::default(),
        )
        .await
    }

    pub async fn new_with_opts(
        db: Arc<RocksDB>,
        network: proto::FarcasterNetwork,
        trie: merkle_trie::MerkleTrie,
        shard_id: u32,
        store_limits: StoreLimits,
        statsd_client: StatsdClientWrapper,
        max_messages_per_block: u32,
        messages_request_tx: Option<mpsc::Sender<MempoolMessagesRequest>>,
        fname_signer_address: Option<alloy_primitives::Address>,
        post_commit_tx: Option<mpsc::Sender<PostCommitMessage>>,
        store_opts: StoreOptions,
    ) -> Result<ShardEngine, HubError> {
        let stores = Stores::new_with_opts(
            db.clone(),
            shard_id,
            trie,
            store_limits,
            network,
            statsd_client.clone(),
            store_opts,
        );

        // No migrations on devnet (during tests)
        if network != proto::FarcasterNetwork::Devnet {
            let migration_context = MigrationContext {
                db: db.clone(),
                stores: stores.clone(),
            };
            let runner = MigrationRunner::new(migration_context);
            let migration_handle = runner.run_pending_migrations().await?;

            // If there are background migrations, we can optionally store the handle
            // for later checking or cancellation if needed
            if let Some(_background_handle) = migration_handle {
                // Background migrations are running, but we don't block startup
                info!(shard_id, "Background migrations started");
            }
        }

        let hyper_stores = Some(stores.with_state_context(StateContext::Hyper));

        Ok(ShardEngine {
            shard_id,
            network,
            hyper_stores,
            stores,
            mempool_poller: MempoolPoller {
                shard_id,
                max_messages_per_block,
                messages_request_tx,
                network,
                statsd_client: statsd_client.clone(),
            },
            senders: Senders::new(),
            db,
            metrics: Metrics {
                statsd_client,
                shard_id,
            },
            pending_txn: None,
            halt_record_checked: false,
            fname_signer_address,
            post_commit_tx,
            shadow_trie: None,
            shadow_backfill_running: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            hypersnap_mode: false,
            content_replay: false,
            hypersnap_height: 0,
            hypersnap_replica: vec![],
            hypersnap_replica_key: vec![],
        })
    }

    /// Hypersnap mode: no on-chain event goes into a block of shard 1 or 2
    /// (FIP §17.6). IdRegistry and KeyRegistry events come from the shard-0
    /// outbox; Hypersnap does not take `StorageRegistry` events.
    fn hypersnap_onchain_check(&self, event: &proto::OnChainEvent) -> Result<(), String> {
        Err(format!(
            "on-chain event of type {:?} in a block of shard {}",
            event.r#type(),
            self.shard_id
        ))
    }

    /// Switch to Hypersnap execution (after the pivot). The Keccak trie must
    /// be complete and live; on a fresh chain it is empty and goes live at
    /// `genesis_height`.
    pub fn enter_hypersnap_mode(&mut self, genesis_height: Option<u64>) -> Result<(), HubError> {
        use crate::storage::trie::shadow_trie::{ShadowStatus, ShadowTrie};
        if self.shadow_trie.is_none() {
            let shadow = ShadowTrie::open(self.db.clone())
                .map_err(|e| HubError::invalid_internal_state(&e.to_string()))?;
            self.shadow_trie = Some(shadow);
        }
        let shadow = self.shadow_trie.as_mut().unwrap();
        match (shadow.status(), genesis_height) {
            (ShadowStatus::Live { .. }, _) => {}
            (ShadowStatus::Absent, Some(height)) => {
                let mut txn = RocksDbTransactionBatch::new();
                shadow.mark_live(height, &mut txn);
                self.db.commit(txn)?;
            }
            (status, _) => {
                return Err(HubError::invalid_internal_state(&format!(
                    "Hypersnap mode needs a live state trie, found {:?}",
                    status
                )))
            }
        }
        self.hypersnap_mode = true;
        self.stores.hypersnap_unbounded = true;
        // The stores themselves keep every message now (§17.6).
        self.hyper_stores = None;
        Ok(())
    }

    /// Run snapchain chunks with no pruning (FIP §17.4): the content replay
    /// that gives the genesis state of a shard. The validation rules are
    /// the snapchain rules of each chunk's version; revocations apply. The
    /// Keccak trie is live from the first chunk.
    pub fn enter_content_replay(&mut self) -> Result<(), HubError> {
        use crate::storage::trie::shadow_trie::{ShadowStatus, ShadowTrie};
        let mut shadow = ShadowTrie::open(self.db.clone())
            .map_err(|e| HubError::invalid_internal_state(&e.to_string()))?;
        match shadow.status() {
            ShadowStatus::Live { .. } => {}
            ShadowStatus::Absent if self.get_last_shard_chunk().is_none() => {
                let mut txn = RocksDbTransactionBatch::new();
                shadow.mark_live(0, &mut txn);
                self.db.commit(txn)?;
            }
            status => {
                return Err(HubError::invalid_internal_state(&format!(
                    "the content replay needs a live state trie, found {:?}",
                    status
                )))
            }
        }
        self.shadow_trie = Some(shadow);
        self.content_replay = true;
        self.hyper_stores = None;
        Ok(())
    }

    /// Content replay: apply a snapchain chunk and commit it. The caller
    /// gives the chunks in order.
    pub async fn commit_replayed_chunk(&mut self, chunk: &ShardChunk) -> Result<(), EngineError> {
        use crate::storage::trie::shadow_trie::ShadowStatus;
        let missing = || EngineError::ContentReplay("a chunk has no header or height".into());
        let header = chunk.header.as_ref().ok_or_else(missing)?;
        let height = header.height.ok_or_else(missing)?.block_number;
        self.stores.event_handler.set_current_height(height);
        let timestamp = FarcasterTime::new(header.timestamp);
        let version = self.version_for(&timestamp);
        let mut txn = RocksDbTransactionBatch::new();
        let (events, max_block_event_seqnum) = self.replay_proposal(
            &merkle_trie::Context::new(),
            &mut txn,
            &chunk.transactions,
            &[],
            ProposalSource::Commit,
            version,
            &timestamp,
        )?;
        self.commit_and_emit_events(chunk, events, max_block_event_seqnum, txn)
            .await;
        // The genesis root comes from this trie: a failed update is an error
        // here, not a diagnostic.
        match self.shadow_trie.as_ref().map(|t| t.status()) {
            Some(ShadowStatus::Live { height: h }) if h == height => Ok(()),
            status => Err(EngineError::ContentReplay(format!(
                "the state trie is {:?} after chunk {}",
                status, height
            ))),
        }
    }

    pub fn is_content_replay(&self) -> bool {
        self.content_replay
    }

    pub fn is_hypersnap_mode(&self) -> bool {
        self.hypersnap_mode
    }

    /// Keccak state root (committed).
    pub fn state_root(&self) -> Option<[u8; 32]> {
        self.shadow_trie.as_ref().map(|t| t.report().root)
    }

    /// Set the height of the next Hypersnap block and the outbox entries of
    /// shard 0 that it applies before its transactions.
    pub fn set_hypersnap_block(
        &mut self,
        height: u64,
        replica: Vec<proto::OutboxEntry>,
        replica_key: Vec<u8>,
    ) {
        self.hypersnap_height = height;
        self.hypersnap_replica = replica;
        self.hypersnap_replica_key = replica_key;
    }

    /// The writes of `txn` that are in the shard state trie without a hub
    /// event (FIP §16.13): the gasless-key nonces and last-use times, from
    /// the content replay on, and after the pivot the replica records, fee
    /// charges and content fingerprints.
    fn hypersnap_raw_ops(&self, txn: &RocksDbTransactionBatch) -> Vec<(Vec<u8>, Option<Vec<u8>>)> {
        if !self.hypersnap_mode && !self.content_replay {
            return vec![];
        }
        use crate::storage::constants::RootPrefix as P;
        // The replica records, and the records of shard 1 or 2 itself.
        let own = [
            P::HyperUnsettledCharge as u8,
            P::HyperContentFingerprint as u8,
            P::HyperChainMeta as u8,
            P::HyperFalconSignerLastUse as u8,
        ];
        let raw = |p: &u8| crate::chain::shard0::REPLICATED.contains(p) || own.contains(p);
        let mut ops: Vec<(Vec<u8>, Option<Vec<u8>>)> = txn
            .batch
            .iter()
            .filter(|(k, _)| {
                crate::storage::trie::shadow_entries::is_gasless_state_key(k)
                    || (self.hypersnap_mode && k.first().is_some_and(raw))
            })
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        ops.sort_by(|a, b| a.0.cmp(&b.0));
        ops
    }

    /// Apply the shard-0 outbox entries of this block (FIP §17.7): replica
    /// writes, replayed snapchain messages and on-chain events.
    fn apply_hypersnap_replica(
        &mut self,
        trie_ctx: &merkle_trie::Context,
        txn_batch: &mut RocksDbTransactionBatch,
    ) -> Result<Vec<HubEvent>, EngineError> {
        if !self.hypersnap_mode || self.hypersnap_replica.is_empty() {
            return Ok(vec![]);
        }
        let entries = self.hypersnap_replica.clone();
        let settled_key = crate::chain::shard0::keys::settled_height(self.shard_id);
        let mut events = vec![];
        for entry in &entries {
            for w in &entry.writes {
                if w.key == settled_key {
                    let old = crate::storage::store::account::get_from_db_or_txn(
                        &self.db,
                        txn_batch,
                        &settled_key,
                    )?
                    .map(|v| crate::chain::shard0::keys::decode_u64(&v))
                    .unwrap_or(0);
                    let new = crate::chain::shard0::keys::decode_u64(&w.value);
                    crate::chain::replica::prune_settled(&self.db, txn_batch, old, new)
                        .map_err(|e| EngineError::ReplicatorError(e.to_string()))?;
                }
                if w.delete {
                    // A removed Falcon-512 signer has no last use.
                    if let Some(k) = crate::chain::replica::last_use_key_of_signer(&w.key) {
                        txn_batch.delete(k);
                    }
                    txn_batch.delete(w.key.clone());
                } else {
                    txn_batch.put(w.key.clone(), w.value.clone());
                }
            }
            if let Some(message) = &entry.replay_message {
                match self.merge_message(message, txn_batch) {
                    Ok(hub_events) => {
                        for event in &hub_events {
                            self.update_trie(trie_ctx, event, txn_batch)?;
                        }
                        events.extend(hub_events);
                    }
                    Err(e) => warn!(fid = entry.fid, "Replica message not merged: {}", e),
                }
            }
            if let Some(event) = &entry.replay_event {
                match self
                    .stores
                    .onchain_event_store
                    .merge_onchain_event(event.clone(), txn_batch)
                {
                    Ok(hub_event) => {
                        self.update_trie(trie_ctx, &hub_event, txn_batch)?;
                        events.push(hub_event);
                    }
                    Err(e) => warn!(fid = entry.fid, "Replica event not merged: {}", e),
                }
            }
            if !entry.remove_gasless_key.is_empty() {
                let record = crate::storage::store::account::get_gasless_key_record(
                    &self.db,
                    txn_batch,
                    entry.fid,
                    &entry.remove_gasless_key,
                )?;
                if let Some(record) = record {
                    crate::chain::shard0::registry::remove_gasless_key(
                        &self.db,
                        txn_batch,
                        entry.fid,
                        &entry.remove_gasless_key,
                    )
                    .map_err(|e| EngineError::ReplicatorError(e.to_string()))?;
                    let revoke = HubEvent::new_event(
                        HubEventType::RevokeMessage,
                        proto::hub_event::Body::RevokeMessageBody(proto::RevokeMessageBody {
                            message: record.message,
                        }),
                    );
                    self.update_trie(trie_ctx, &revoke, txn_batch)?;
                    events.push(revoke);
                }
            }
        }
        Ok(events)
    }

    fn keccak_root_with(
        &mut self,
        events: &[HubEvent],
        raw: &[(Vec<u8>, Option<Vec<u8>>)],
    ) -> Result<[u8; 32], EngineError> {
        let shadow = self
            .shadow_trie
            .as_mut()
            .ok_or_else(|| EngineError::HashMismatch)?;
        shadow.root_with_ops(events, raw).map_err(|e| {
            error!(shard_id = self.shard_id, "Keccak root: {}", e);
            EngineError::HashMismatch
        })
    }

    /// Hypersnap proposer: execute `messages` and return the per-FID
    /// transactions with the Keccak root after them. The pending batch is
    /// cached for the commit, as in `propose_state_change`.
    pub fn hypersnap_propose(
        &mut self,
        messages: Vec<MempoolMessage>,
        timestamp: FarcasterTime,
    ) -> Result<(ShardStateChange, [u8; 32]), EngineError> {
        let messages = messages
            .into_iter()
            .filter(|m| match m {
                MempoolMessage::OnchainEvent(e) => self.hypersnap_onchain_check(e).is_ok(),
                _ => true,
            })
            .collect();
        let change = self.propose_state_change(self.shard_id, messages, Some(timestamp));
        let raw = self
            .pending_txn
            .as_ref()
            .map(|c| self.hypersnap_raw_ops(&c.txn))
            .unwrap_or_default();
        let root = self.keccak_root_with(&change.events, &raw)?;
        Ok((change, root))
    }

    /// Hypersnap validator: replay a block body and return its roots. The
    /// caller compares `state_root` with the header. The pending batch is
    /// cached for the commit.
    pub fn hypersnap_validate(
        &mut self,
        transactions: &[Transaction],
        height: Height,
        timestamp: &FarcasterTime,
    ) -> Result<HypersnapReplay, EngineError> {
        let mut txn = RocksDbTransactionBatch::new();
        self.stores
            .event_handler
            .set_current_height(height.block_number);
        let version = self.version_for(timestamp);
        let replay = self.replay_proposal(
            &merkle_trie::Context::new(),
            &mut txn,
            transactions,
            &[],
            ProposalSource::Validate,
            version,
            timestamp,
        );
        let result = match replay {
            Ok((events, max_block_event_seqnum)) => {
                let blake3_root = self.stores.trie.root_hash()?;
                let raw = self.hypersnap_raw_ops(&txn);
                match self.keccak_root_with(&events, &raw) {
                    Ok(state_root) => {
                        self.pending_txn = Some(CachedTransaction {
                            shard_root: blake3_root.clone(),
                            txn,
                            events,
                            max_block_event_seqnum,
                            block_events_hash: Self::compute_block_events_hash(transactions),
                            replica_key: self.hypersnap_replica_key.clone(),
                        });
                        Ok(HypersnapReplay {
                            state_root,
                            blake3_root,
                        })
                    }
                    Err(e) => Err(e),
                }
            }
            Err(e) => Err(e),
        };
        self.stores.trie.reload(&self.db).unwrap();
        result
    }

    /// Commit a decided Hypersnap block of shard 1 or 2. Returns the Keccak
    /// root after it, which equals the header `state_root` for a valid block.
    pub async fn hypersnap_commit(
        &mut self,
        block: &crate::proto::HypersnapBlock,
    ) -> Result<[u8; 32], EngineError> {
        let header = block.header.as_ref().ok_or(EngineError::HashMismatch)?;
        let blake3_root = match &self.pending_txn {
            Some(cached)
                if cached.block_events_hash
                    == Self::compute_block_events_hash(&block.transactions) =>
            {
                cached.shard_root.clone()
            }
            _ => vec![],
        };
        let chunk = ShardChunk {
            header: Some(proto::ShardHeader {
                height: Some(Height::new(self.shard_id, header.height)),
                timestamp: header.timestamp,
                parent_hash: header.parent_hash.clone(),
                shard_root: blake3_root,
            }),
            hash: block.hash.clone(),
            transactions: block.transactions.clone(),
            commits: None,
        };
        self.commit_shard_chunk(&chunk).await;
        self.state_root().ok_or(EngineError::HashMismatch)
    }

    /// Turn on the shadow Keccak trie (plan R0). If the shard has no complete
    /// trie yet, this takes a read-only snapshot at the confirmed height and
    /// starts a backfill thread; commits keep running and the engine takes the
    /// trie over when the backfill has caught up.
    pub fn enable_shadow_trie(&mut self) -> Result<(), HubError> {
        use crate::storage::trie::{shadow_backfill, shadow_trie};
        use std::sync::atomic::Ordering;

        let internal =
            |e: shadow_trie::ShadowTrieError| HubError::invalid_internal_state(&e.to_string());
        let shadow = shadow_trie::ShadowTrie::open(self.db.clone()).map_err(internal)?;
        let status = shadow.status();
        self.shadow_trie = Some(shadow);

        let resume_from = match status {
            shadow_trie::ShadowStatus::Live { height } => {
                info!(shard_id = self.shard_id, height, "Shadow trie is live");
                return Ok(());
            }
            shadow_trie::ShadowStatus::Built { height } => Some(height),
            shadow_trie::ShadowStatus::Absent | shadow_trie::ShadowStatus::Building { .. } => None,
        };

        let snapshot = match resume_from {
            Some(_) => None,
            None => {
                let removed = shadow_backfill::clear_trie_records(&self.db).map_err(internal)?;
                let snapshot_height = self.get_confirmed_height().block_number;
                let read_only = self.db.open_read_only().map_err(|e| {
                    HubError::invalid_internal_state(&format!("read-only snapshot: {}", e))
                })?;
                let mut txn = RocksDbTransactionBatch::new();
                shadow_trie::ShadowStatus::Building { snapshot_height }.stage(&mut txn);
                self.db.commit(txn)?;
                info!(
                    shard_id = self.shard_id,
                    snapshot_height,
                    removed_partial_records = removed,
                    "Shadow trie backfill starting"
                );
                Some((Arc::new(read_only), snapshot_height))
            }
        };

        let running = self.shadow_backfill_running.clone();
        running.store(true, Ordering::SeqCst);
        let db = self.db.clone();
        let shard_id = self.shard_id;
        let network = self.network;
        let statsd = self.metrics.statsd_client.clone();
        std::thread::Builder::new()
            .name(format!("shadow-backfill-{}", shard_id))
            .spawn(move || {
                let result = (|| -> Result<u64, shadow_trie::ShadowTrieError> {
                    let from = match (resume_from, snapshot) {
                        (Some(height), _) => height,
                        (None, Some((read_only, snapshot_height))) => {
                            let stores = Stores::new(
                                read_only,
                                shard_id,
                                merkle_trie::MerkleTrie::new().unwrap(),
                                StoreLimits::default(),
                                network,
                                statsd,
                            );
                            let outcome = shadow_backfill::build_from_snapshot(
                                &stores,
                                db.clone(),
                                snapshot_height,
                            )?;
                            info!(
                                shard_id,
                                snapshot_height,
                                leaf_count = outcome.leaf_count,
                                unresolved_keys = outcome.unresolved_keys,
                                root = hex::encode(outcome.root),
                                "Shadow trie built from snapshot"
                            );
                            let mut txn = RocksDbTransactionBatch::new();
                            shadow_trie::ShadowStatus::Built {
                                height: snapshot_height,
                            }
                            .stage(&mut txn);
                            db.commit(txn)
                                .map_err(|e| shadow_trie::ShadowTrieError::Trie(e.to_string()))?;
                            snapshot_height
                        }
                        (None, None) => unreachable!(),
                    };
                    let shard_store =
                        crate::storage::store::shard::ShardStore::new(db.clone(), shard_id);
                    shadow_backfill::catch_up(db.clone(), from, || {
                        shard_store.max_block_number().unwrap_or(0)
                    })
                })();
                match result {
                    Ok(height) => info!(shard_id, height, "Shadow trie caught up; handing off"),
                    Err(e) => error!(shard_id, "Shadow trie backfill failed: {}", e),
                }
                running.store(false, Ordering::SeqCst);
            })
            .map_err(|e| HubError::invalid_internal_state(&format!("spawn backfill: {}", e)))?;
        Ok(())
    }

    /// Root, size and status of the shadow trie, if it is enabled.
    pub fn shadow_trie_report(
        &self,
    ) -> Option<crate::storage::trie::shadow_trie::ShadowRootReport> {
        self.shadow_trie.as_ref().map(|t| t.report())
    }

    /// True while a backfill thread owns the shadow trie records.
    pub fn shadow_backfill_running(&self) -> bool {
        self.shadow_backfill_running
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Commit hook of the shadow trie: stage this chunk's trie writes into
    /// the chunk batch, or take the trie over from a finished backfill.
    fn stage_shadow_trie(
        &mut self,
        events: &[HubEvent],
        height: u64,
        txn: &mut RocksDbTransactionBatch,
    ) {
        use crate::storage::trie::{shadow_backfill, shadow_trie::ShadowStatus};
        use std::sync::atomic::Ordering;

        let raw = self.hypersnap_raw_ops(txn);
        let Some(shadow) = self.shadow_trie.as_mut() else {
            return;
        };
        let staged = match shadow.status() {
            ShadowStatus::Live { .. } => shadow.stage_chunk_with_ops(events, &raw, height, txn),
            _ if self.shadow_backfill_running.load(Ordering::SeqCst) => return,
            _ => {
                if let Err(e) = shadow.reload(&self.db) {
                    error!(shard_id = self.shard_id, "Shadow trie reload failed: {}", e);
                    self.shadow_trie = None;
                    return;
                }
                match shadow.status() {
                    ShadowStatus::Built { height: built } if built < height => {
                        shadow_backfill::events_for_heights(&self.db, built + 1, height - 1)
                            .and_then(|replay| shadow.go_live(&replay, events, height, txn))
                    }
                    _ => return,
                }
            }
        };
        match staged {
            Ok(Some(root)) => {
                self.metrics.gauge("shadow_trie.height", height);
                self.metrics
                    .gauge("shadow_trie.leaf_count", shadow.report().leaf_count);
                debug!(
                    shard_id = self.shard_id,
                    height,
                    root = hex::encode(root),
                    "Shadow trie updated"
                );
            }
            Ok(None) => {}
            Err(e) => {
                // Diagnostic structure: never stop the shard for it. Drop it
                // for this run; the next start rebuilds it.
                error!(
                    shard_id = self.shard_id,
                    "Shadow trie update failed, disabling: {}", e
                );
                self.shadow_trie = None;
            }
        }
    }

    pub fn shard_id(&self) -> u32 {
        self.shard_id
    }

    pub fn get_stores(&self) -> Stores {
        self.stores.clone()
    }

    pub fn stores_with_state_context(&self, ctx: StateContext) -> Stores {
        self.stores.with_state_context(ctx)
    }

    /// Get the hyper shadow stores, if enabled.
    pub fn get_hyper_stores(&self) -> Option<Stores> {
        self.hyper_stores.clone()
    }

    pub fn get_senders(&self) -> Senders {
        self.senders.clone()
    }

    pub(crate) fn trie_root_hash(&self) -> Vec<u8> {
        self.stores.trie.root_hash().unwrap()
    }

    pub fn is_read_only(&self) -> bool {
        // For a read-only node, we will never pull from the mempool, so Engines are constructed without a
        // messages_request_tx for read-only nodes
        self.mempool_poller.for_read_node()
    }

    fn prepare_proposal(
        &mut self,
        trie_ctx: &merkle_trie::Context,
        txn_batch: &mut RocksDbTransactionBatch,
        shard_id: u32,
        messages: Vec<MempoolMessage>,
        timestamp: &FarcasterTime,
    ) -> Result<ShardStateChange, EngineError> {
        self.metrics.count(
            "prepare_proposal.recv_messages",
            messages.len() as u64,
            vec![],
        );

        let version = self.version_for(timestamp);
        let mut snapchain_txns = MempoolPoller::create_transactions_from_mempool(messages)?
            .into_iter()
            .filter_map(|mut transaction| {
                // TODO(aditi): In the future, this seems like it should just be a part of the validation logic in replay_snapchain_txn.
                let pending_onchain_events: Vec<OnChainEvent> = transaction
                    .system_messages
                    .iter()
                    .filter_map(|vm| vm.on_chain_event.clone())
                    .collect();

                let maybe_onchainevents =
                    if version.is_enabled(ProtocolFeature::DependentMessagesInBulkSubmit) {
                        pending_onchain_events.as_slice()
                    } else {
                        &[]
                    };

                let storage_slot = self
                    .stores
                    .get_storage_slot_for_fid(transaction.fid, version, true, maybe_onchainevents)
                    .ok()?;

                // Drop events if storage slot is inactive
                if !storage_slot.is_active() {
                    transaction.user_messages = vec![];
                }

                if transaction.system_messages.is_empty() && transaction.user_messages.is_empty() {
                    return None;
                } else {
                    return Some(transaction);
                }
            })
            .collect_vec();

        let mut events = self.apply_hypersnap_replica(trie_ctx, txn_batch)?;
        let mut validation_error_count = 0;
        let mut max_block_event_seqnum = self.stores.block_event_store.max_seqnum()?;
        for snapchain_txn in &mut snapchain_txns {
            let (account_root, txn_events, validation_errors, last_block_event_seqnum) = self
                .replay_snapchain_txn(
                    trie_ctx,
                    &snapchain_txn,
                    txn_batch,
                    ProposalSource::Propose,
                    version,
                    timestamp,
                    max_block_event_seqnum,
                )?;
            snapchain_txn.account_root = account_root;
            events.extend(txn_events);
            validation_error_count += validation_errors.len();
            max_block_event_seqnum = last_block_event_seqnum;
        }

        self.metrics
            .publish_transaction_counts(&snapchain_txns, ProposalSource::Propose);

        self.metrics.count(
            "validation_errors",
            validation_error_count as u64,
            Metrics::proposal_source_tags(ProposalSource::Propose),
        );

        let new_root_hash = self.stores.trie.root_hash()?;
        let result = ShardStateChange {
            shard_id,
            timestamp: timestamp.clone(),
            version,
            new_state_root: new_root_hash.clone(),
            transactions: snapchain_txns,
            events,
            max_block_event_seqnum,
        };

        Ok(result)
    }

    pub fn version_for(&self, timestamp: &FarcasterTime) -> EngineVersion {
        EngineVersion::version_for(timestamp, self.network)
    }

    pub fn start_round(&mut self, height: Height, _round: Round) {
        self.pending_txn = None;
        self.stores
            .event_handler
            .set_current_height(height.block_number);
    }

    pub fn propose_state_change(
        &mut self,
        shard: u32,
        messages: Vec<MempoolMessage>,
        timestamp: Option<FarcasterTime>,
    ) -> ShardStateChange {
        let now = std::time::Instant::now();
        let mut txn = RocksDbTransactionBatch::new();

        let count_fn = self.metrics.make_count_fn();
        let count_callback = move |read_count: (u64, u64)| {
            count_fn("trie.db_get_count.total", read_count.0, vec![]);
            count_fn("trie.db_get_count.for_propose", read_count.0, vec![]);
            count_fn("trie.mem_get_count.total", read_count.1, vec![]);
            count_fn("trie.mem_get_count.for_propose", read_count.1, vec![]);
        };
        let timestamp = timestamp.unwrap_or_else(FarcasterTime::current);
        let result = self
            .prepare_proposal(
                &merkle_trie::Context::with_callback(count_callback),
                &mut txn,
                shard,
                messages,
                &timestamp,
            )
            .unwrap(); //TODO: don't unwrap()

        // TODO: this should probably operate automatically via drop trait
        self.stores.trie.reload(&self.db).unwrap();

        let block_events_hash = Self::compute_block_events_hash(&result.transactions);

        self.pending_txn = Some(CachedTransaction {
            shard_root: result.new_state_root.clone(),
            events: result.events.clone(),
            txn,
            max_block_event_seqnum: result.max_block_event_seqnum,
            block_events_hash,
            replica_key: self.hypersnap_replica_key.clone(),
        });

        let proposal_duration = now.elapsed();
        self.metrics
            .time_with_shard("propose_time", proposal_duration.as_millis() as u64);

        self.metrics.count("propose.invoked", 1, vec![]);
        result
    }

    fn txn_summary(txn: &Transaction) -> String {
        let mut summary = String::new();
        let fid = format!("fid: {}\n", txn.fid);
        summary += fid.as_str();
        for message in &txn.user_messages {
            let msg_type = message.msg_type().as_str_name();
            let message_summary = format!(
                "message_type: {}, msg_hash: {}\n",
                hex::encode(&message.hash),
                msg_type
            );
            summary += message_summary.as_str()
        }

        for message in &txn.system_messages {
            let onchain_event_summary = match &message.on_chain_event {
                Some(onchain_event) => {
                    format!(
                        "message_type: onchain_event, type: {}, tx_hash: {}, log_index: {}\n",
                        onchain_event.r#type().as_str_name(),
                        hex::encode(&onchain_event.transaction_hash),
                        onchain_event.log_index
                    )
                }
                None => "".to_string(),
            };
            summary += onchain_event_summary.as_str();

            let fname_transfer_summary =
                match &message.fname_transfer {
                    Some(fname_transfer) => {
                        format!(
                        "message_type: fname_transfer, from_fid: {}, to_fid: {}, username: {:#?}",
                        fname_transfer.from_fid,
                        fname_transfer.id,
                        fname_transfer.proof.as_ref().map(|proof| proof.name.clone())
                    )
                    }
                    None => "".to_string(),
                };
            summary += fname_transfer_summary.as_str()
        }
        summary
    }

    fn txns_summary(transactions: &[Transaction]) -> String {
        let mut summary = String::new();
        for snapchain_txn in transactions {
            summary += Self::txn_summary(snapchain_txn).as_str()
        }
        summary
    }

    fn replay_proposal(
        &mut self,
        trie_ctx: &merkle_trie::Context,
        txn_batch: &mut RocksDbTransactionBatch,
        transactions: &[Transaction],
        shard_root: &[u8],
        source: ProposalSource,
        version: EngineVersion,
        timestamp: &FarcasterTime,
    ) -> Result<(Vec<HubEvent>, u64), EngineError> {
        let now = std::time::Instant::now();
        let mut events = vec![];
        let mut max_block_event_seqnum = self.stores.block_event_store.max_seqnum()?;
        // Validate that the trie is in a good place to start with
        match self.get_last_shard_chunk() {
            None => { // There are places where it's hard to provide a parent hash-- e.g. tests so make this an option and skip validation if not present
            }
            Some(_) if self.content_replay => {}
            Some(shard_chunk) => match self.stores.trie.root_hash() {
                Err(err) => {
                    warn!(
                        source = source.to_string(),
                        "Unable to compute trie root hash {:#?}", err
                    )
                }
                Ok(root_hash) => {
                    let parent_shard_root = shard_chunk.header.unwrap().shard_root;
                    if root_hash != parent_shard_root {
                        warn!(
                            shard_id = self.shard_id,
                            our_shard_root = hex::encode(&root_hash),
                            parent_shard_root = hex::encode(parent_shard_root),
                            source = source.to_string(),
                            "Parent shard root mismatch"
                        );
                    }
                }
            },
        }

        events.extend(self.apply_hypersnap_replica(trie_ctx, txn_batch)?);
        for snapchain_txn in transactions {
            let (account_root, txn_events, _, last_block_event_seqnum) = self
                .replay_snapchain_txn(
                    trie_ctx,
                    snapchain_txn,
                    txn_batch,
                    source.clone(),
                    version,
                    timestamp,
                    max_block_event_seqnum,
                )?;
            // Reject early if account roots fail to match (shard roots will definitely fail)
            if !self.content_replay && &account_root != &snapchain_txn.account_root {
                warn!(
                    fid = snapchain_txn.fid,
                    new_account_root = hex::encode(&account_root),
                    tx_account_root = hex::encode(&snapchain_txn.account_root),
                    source = source.to_string(),
                    summary = Self::txn_summary(snapchain_txn),
                    num_system_messages = snapchain_txn.system_messages.len(),
                    num_user_messages = snapchain_txn.user_messages.len(),
                    "Account root mismatch"
                );
                return Err(EngineError::HashMismatch);
            }
            events.extend(txn_events);
            max_block_event_seqnum = last_block_event_seqnum;
        }

        let root1 = self.stores.trie.root_hash()?;
        // Hypersnap mode: the blake3 root is internal; the caller checks the
        // Keccak root against the block header instead.
        let skip_root_check = (self.hypersnap_mode && shard_root.is_empty()) || self.content_replay;
        if !skip_root_check && &root1 != shard_root {
            warn!(
                shard_id = self.shard_id,
                new_shard_root = hex::encode(&root1),
                tx_shard_root = hex::encode(shard_root),
                source = source.to_string(),
                summary = Self::txns_summary(transactions),
                num_txns = transactions.len(),
                "Shard root mismatch"
            );
            return Err(EngineError::HashMismatch);
        }

        let elapsed = now.elapsed();
        self.metrics
            .time_with_shard("replay_proposal_time", elapsed.as_millis() as u64);
        Ok((events, max_block_event_seqnum))
    }

    pub(crate) fn replay_replicator_message(
        &self,
        txn_batch: &mut RocksDbTransactionBatch,
        trie_message: &ShardTrieEntryWithMessage,
    ) -> Result<MergedReplicatorMessage, EngineError> {
        let (hub_event, fid) = match &trie_message.trie_message {
            Some(TrieMessage::UserMessage(m)) => {
                let events = self.merge_message(m, txn_batch)?;
                self.merge_message_hyper(m, txn_batch);
                // This is only expected for deleted
                if events.len() != 1 {
                    return Err(EngineError::ReplicatorError(format!(
                        "Message generated incorrect number of hub events. Message:{:?}\nHubEvents {:?}",
                        trie_message, events
                    )));
                }
                (events[0].clone(), m.fid())
            }
            Some(TrieMessage::OnChainEvent(oe)) => {
                let event = self
                    .stores
                    .onchain_event_store
                    .merge_onchain_event(oe.clone(), txn_batch)?;

                (event, oe.fid)
            }
            Some(TrieMessage::FnameTransfer(f)) => match &f.proof {
                None => {
                    return Err(EngineError::ReplicatorError(format!(
                        "FnameTransfer proof is missing for fname message {:?}",
                        f
                    )));
                }
                Some(p) => {
                    let event = UserDataStore::merge_username_proof(
                        &self.stores.user_data_store,
                        p,
                        txn_batch,
                    )?;
                    (event, p.fid)
                }
            },
            _ => {
                return Err(EngineError::ReplicatorError(format!(
                    "Unknown trie_message type {:?}",
                    trie_message
                )))
            }
        };

        let (inserts, deletes) = TrieKey::for_hub_event(&hub_event);

        if !deletes.is_empty() {
            warn!(
                "Message generated deletes, ignoring them. Message {:?}\nHubEvent {:?}",
                trie_message, hub_event
            );
        }

        Ok(MergedReplicatorMessage {
            fid,
            trie_keys: inserts,
            hub_event,
        })
    }

    // Reset the event id generator to 0. This is used when doing replication, when we're merging in events from another node
    // and not from blocks (so no blockheight to use)
    pub(crate) fn reset_event_id(&self) {
        self.stores.event_handler.set_current_height(0);
    }

    fn handle_block_event(
        &mut self,
        trie_ctx: &merkle_trie::Context,
        block_event: &proto::BlockEvent,
        txn_batch: &mut RocksDbTransactionBatch,
    ) -> Result<Vec<HubEvent>, EngineError> {
        let body = block_event
            .data
            .as_ref()
            .ok_or(MessageValidationError::NoMessageData)?
            .body
            .as_ref()
            .ok_or(MessageValidationError::BlockEventMissingBody)?;
        match body {
            proto::block_event_data::Body::MergeMessageEventBody(merge_message_event) => {
                let message = &merge_message_event
                    .message
                    .as_ref()
                    .ok_or(MessageValidationError::BlockEventMissingBody)?;
                let msg_type = message.msg_type();
                // Per-msg-type feature gating for shard-0-hosted user messages. Any future
                // shard-0 feature whose merges propagate via a `MergeMessage` BlockEvent
                // should add its gate here, not at the call site — the call site
                // unconditionally invokes `handle_block_event` so this match is the single
                // place that knows which feature owns which message type. Returning
                // `InvalidMessageType` mirrors `validate_user_message`'s response to the
                // analogous live-admission case, so a pre-feature replay surfaces a `warn!`
                // through the caller's error arm and a downgraded validator never silently
                // merges into a store the rest of the code can't reason about.
                let feature_gate = match msg_type {
                    MessageType::LendStorage => Some(ProtocolFeature::StorageLending),
                    MessageType::KeyAdd | MessageType::KeyRemove => {
                        Some(ProtocolFeature::GaslessSigners)
                    }
                    _ => None,
                };
                if let Some(feature) = feature_gate {
                    let block_ts = block_event.block_timestamp();
                    let version =
                        EngineVersion::version_for(&FarcasterTime::new(block_ts), self.network);
                    if !version.is_enabled(feature) {
                        warn!(
                            msg_type = msg_type.into_u8(),
                            seqnum = block_event.seqnum(),
                            block_timestamp = block_ts,
                            "Skipping BlockEvent replay: feature not yet active for block timestamp"
                        );
                        return Err(
                            MessageValidationError::InvalidMessageType(msg_type as i32).into()
                        );
                    }
                }
                let hub_events = self.merge_message(&message, txn_batch)?;
                self.merge_message_hyper(&message, txn_batch);
                for event in &hub_events {
                    self.update_trie(trie_ctx, event, txn_batch)?;
                }
                Ok(hub_events)
            }
            proto::block_event_data::Body::HeartbeatEventBody(_) => Ok(vec![]),
        }
    }

    pub(crate) fn replay_snapchain_txn(
        &mut self,
        trie_ctx: &merkle_trie::Context,
        snapchain_txn: &Transaction,
        txn_batch: &mut RocksDbTransactionBatch,
        source: ProposalSource,
        version: EngineVersion,
        timestamp: &FarcasterTime,
        mut last_block_event_seqnum: u64,
    ) -> Result<(Vec<u8>, Vec<HubEvent>, Vec<MessageValidationError>, u64), EngineError> {
        let now = std::time::Instant::now();
        let total_user_messages = snapchain_txn.user_messages.len();
        let total_system_messages = snapchain_txn.system_messages.len();
        let mut user_messages_count = 0;
        let mut system_messages_count = 0;
        let mut onchain_events_count = 0;
        let mut merged_fnames_count = 0;
        let mut merged_messages_count = 0;
        let mut pruned_messages_count = 0;
        let mut revoked_messages_count = 0;
        let mut events = vec![];
        let mut message_types_to_prune = HashSet::new();
        let mut revoked_signers = HashSet::new();

        let mut validation_errors = vec![];

        // System messages first, then user messages and finally prunes

        // Sort system_messages to process OnChainEvents first in their canonical order,
        // followed by FnameTransfers sorted by timestamp.
        let mut sorted_system_messages = snapchain_txn.system_messages.clone();
        sorted_system_messages.sort_by(|a, b| {
            match (&a.on_chain_event, &b.on_chain_event) {
                (Some(event_a), Some(event_b)) => {
                    // Both are OnChainEvents, sort by block_number then log_index.
                    (event_a.block_number, event_a.log_index)
                        .cmp(&(event_b.block_number, event_b.log_index))
                }
                (Some(_), None) => Ordering::Less, // OnChainEvents come before FnameTransfers.
                (None, Some(_)) => Ordering::Greater, // FnameTransfers come after OnChainEvents.
                (None, None) => Ordering::Equal,   // Both are FnameTransfers, sort equal
            }
        });
        for msg in sorted_system_messages {
            if let Some(onchain_event) = &msg.on_chain_event {
                if self.hypersnap_mode {
                    if let Err(reason) = self.hypersnap_onchain_check(onchain_event) {
                        if source == ProposalSource::Validate {
                            return Err(EngineError::HypersnapRejected(reason));
                        }
                        warn!(shard_id = self.shard_id, "Skipped: {}", reason);
                        continue;
                    }
                }
                if onchain_event.r#type() == OnChainEventType::EventTypeTierPurchase
                    && !version.is_enabled(ProtocolFeature::FarcasterPro)
                {
                    warn!("Saw tier purchase while feature isn't active");
                    continue;
                }

                let event = self
                    .stores
                    .onchain_event_store
                    .merge_onchain_event(onchain_event.clone(), txn_batch);

                match event {
                    Ok(hub_event) => {
                        onchain_events_count += 1;
                        self.update_trie(trie_ctx, &hub_event, txn_batch)?;
                        events.push(hub_event.clone());
                        system_messages_count += 1;
                        match &onchain_event.body {
                            Some(proto::on_chain_event::Body::SignerEventBody(signer_event)) => {
                                if Self::should_revoke_signer(&signer_event, version) {
                                    revoked_signers.insert(signer_event.key.clone());
                                }
                            }
                            _ => {}
                        }
                    }
                    Err(err) => {
                        if source != ProposalSource::Simulate {
                            warn!("Error merging onchain event: {:?}", err);
                        }
                    }
                }
            }
            if let Some(fname_transfer) = &msg.fname_transfer {
                match &fname_transfer.proof {
                    None => {
                        if source != ProposalSource::Simulate {
                            warn!(
                                fid = snapchain_txn.fid,
                                id = fname_transfer.id,
                                "Fname transfer has no proof"
                            );
                        }
                    }
                    Some(proof) => {
                        match verification::validate_fname_transfer(
                            fname_transfer,
                            self.network,
                            self.fname_signer_address,
                        ) {
                            Ok(_) => {
                                let event = UserDataStore::merge_username_proof(
                                    &self.stores.user_data_store,
                                    proof,
                                    txn_batch,
                                );
                                match event {
                                    Ok(hub_event) => {
                                        merged_fnames_count += 1;
                                        self.update_trie(
                                            &merkle_trie::Context::new(),
                                            &hub_event,
                                            txn_batch,
                                        )?;
                                        events.push(hub_event.clone());
                                        system_messages_count += 1;
                                    }
                                    Err(err) => {
                                        if source != ProposalSource::Simulate {
                                            warn!("Error merging fname transfer: {:?}", err);
                                        }
                                    }
                                }
                                // If the name was transfered from an existing fid, we need to make sure to revoke any existing username UserDataAdd
                                if fname_transfer.from_fid > 0 {
                                    let existing_username = self.get_user_data_by_fid_and_type(
                                        fname_transfer.from_fid,
                                        proto::UserDataType::Username,
                                    );
                                    if existing_username.is_ok() {
                                        let existing_username = existing_username.unwrap();
                                        let event = self
                                            .stores
                                            .user_data_store
                                            .revoke(&existing_username, txn_batch);
                                        match event {
                                            Ok(hub_event) => {
                                                revoked_messages_count += 1;
                                                self.update_trie(
                                                    &merkle_trie::Context::new(),
                                                    &hub_event,
                                                    txn_batch,
                                                )?;
                                                events.push(hub_event.clone());
                                            }
                                            Err(err) => {
                                                if source != ProposalSource::Simulate {
                                                    warn!(
                                                        "Error revoking existing username: {:?}",
                                                        err
                                                    );
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            Err(err) => {
                                if source != ProposalSource::Simulate {
                                    warn!("Error validating fname transfer: {:?}", err);
                                }
                            }
                        }
                    }
                }
            }

            if let Some(block_event) = &msg.block_event {
                // TODO(aditi): Validate hash and insert into any other relevant stores and trie if the message is relevant
                if version.is_enabled(ProtocolFeature::ReadDataFromShardZero) {
                    if block_event.seqnum() == last_block_event_seqnum + 1 {
                        if let Err(err) = self
                            .stores
                            .block_event_store
                            .put_block_event(block_event, txn_batch)
                        {
                            error!(
                                seqnum = block_event.seqnum().to_string(),
                                "Error merging block event: {}",
                                err.to_string()
                            );
                        } else {
                            last_block_event_seqnum += 1;
                        }

                        // Per-feature gating lives inside `handle_block_event` (one match arm
                        // per shard-0-hosted user-message type). The call site stays
                        // feature-agnostic — adding a new shard-0 feature only edits the
                        // dispatch function, not this site.
                        match self.handle_block_event(trie_ctx, block_event, txn_batch) {
                            Ok(hub_events) => {
                                info!(
                                    num_hub_events = hub_events.len(),
                                    seqnum = block_event.seqnum(),
                                    fid = snapchain_txn.fid,
                                    "Merged block event"
                                );
                                events.extend(hub_events)
                            }
                            Err(err) => {
                                warn!(
                                    fid = snapchain_txn.fid,
                                    "Error merging block event {}",
                                    err.to_string()
                                );
                            }
                        }
                    } else {
                        warn!(
                            seqnum = block_event.seqnum(),
                            last_block_event_seqnum,
                            fid = snapchain_txn.fid,
                            "Error merging block event because it's not next"
                        )
                    }
                }
            }
        }

        for key in revoked_signers {
            // Revoke from hyper stores too — signer revocation is semantic,
            // not a storage limit, so revoked messages should be gone from both.
            if let Some(ref hyper) = self.hyper_stores {
                let _ = hyper.revoke_messages(snapchain_txn.fid, &key, txn_batch);
            }

            let result = self
                .stores
                .revoke_messages(snapchain_txn.fid, &key, txn_batch);
            match result {
                Ok(revoke_events) => {
                    for event in revoke_events {
                        revoked_messages_count += 1;
                        self.update_trie(trie_ctx, &event, txn_batch)?;
                        events.push(event.clone());
                    }
                }
                Err(err) => {
                    if source != ProposalSource::Simulate {
                        warn!(
                            fid = snapchain_txn.fid,
                            key = hex::encode(key),
                            "Error revoking signer: {:?}",
                            err
                        );
                    }
                }
            }
        }

        // Sort the user messages so that all dependent messages are processed in order
        let mut sorted_user_messages = snapchain_txn.user_messages.clone();
        sorted_user_messages.sort_by(|a, b| {
            fn get_message_priority(msg: &proto::Message) -> u8 {
                let msg_type = msg.msg_type();
                match msg_type {
                    MessageType::VerificationAddEthAddress => 1,
                    MessageType::UsernameProof => 2,
                    MessageType::UserDataAdd => {
                        if let Some(Body::UserDataBody(body)) = &msg.data.as_ref().unwrap().body {
                            let user_data_type = body.r#type();
                            if user_data_type == UserDataType::Username
                                || user_data_type == UserDataType::UserDataPrimaryAddressEthereum
                                || user_data_type == UserDataType::UserDataPrimaryAddressSolana
                            {
                                return 3; // Dependent UserData types
                            }
                        }
                        4 // Other UserDataAdd types
                    }
                    _ => 5, // All other message types
                }
            }

            let priority_a = get_message_priority(a);
            let priority_b = get_message_priority(b);

            // Message priority first, then timestamp
            priority_a.cmp(&priority_b).then_with(|| {
                a.data
                    .as_ref()
                    .unwrap()
                    .timestamp
                    .cmp(&b.data.as_ref().unwrap().timestamp)
            })
        });

        for msg in &sorted_user_messages {
            // Errors are validated based on the shard root
            match self.validate_user_message(msg, timestamp, version, txn_batch) {
                Ok(()) => {
                    let result = self.merge_message(msg, txn_batch);
                    match result {
                        Ok(merge_events) => {
                            // Dual-write to hyper shadow stores (same txn, different key space)
                            self.merge_message_hyper(msg, txn_batch);

                            for event in &merge_events {
                                merged_messages_count += 1;
                                self.update_trie(trie_ctx, &event, txn_batch)?;
                                user_messages_count += 1;
                            }
                            events.extend(merge_events.clone());
                            // After the pivot and in the content replay, no
                            // message is pruned (§17.4, §17.6).
                            if !self.hypersnap_mode && !self.content_replay {
                                message_types_to_prune.insert(msg.msg_type());
                            }
                        }
                        Err(err) => {
                            if source != ProposalSource::Simulate {
                                warn!(
                                    fid = msg.fid(),
                                    hash = msg.hex_hash(),
                                    "Error merging message: {:?}",
                                    err
                                );
                            }
                            validation_errors.push(err.clone());
                            let mut merge_failure = HubEvent::from_validation_error(err, msg);
                            let _ = self
                                .stores
                                .event_handler
                                .commit_transaction(txn_batch, &mut merge_failure);
                            events.push(merge_failure);
                        }
                    }
                }
                Err(err) => {
                    if source != ProposalSource::Simulate {
                        warn!(
                            fid = msg.fid(),
                            hash = msg.hex_hash(),
                            "Error validating user message: {:?}",
                            err
                        );
                    }
                    validation_errors.push(err.clone());
                    let mut merge_failure = HubEvent::from_validation_error(err, msg);
                    let _ = self
                        .stores
                        .event_handler
                        .commit_transaction(txn_batch, &mut merge_failure);
                    events.push(merge_failure);
                }
            }
        }

        for msg_type in message_types_to_prune {
            let fid = snapchain_txn.fid;
            let result = self.prune_messages(fid, msg_type, txn_batch, &version);
            match result {
                Ok(pruned_events) => {
                    for event in pruned_events {
                        pruned_messages_count += 1;
                        self.update_trie(trie_ctx, &event, txn_batch)?;
                        events.push(event.clone());
                    }
                }
                Err(err) => {
                    if source != ProposalSource::Simulate {
                        warn!(
                            fid = fid,
                            msg_type = msg_type.into_u8(),
                            "Error pruning messages: {:?}",
                            err
                        );
                    }
                }
            }
        }

        let result = self.handle_delete_side_effects(&version, &events, txn_batch);
        match result {
            Ok(revoke_events) => {
                for event in revoke_events {
                    revoked_messages_count += 1;
                    self.update_trie(trie_ctx, &event, txn_batch)?;
                    events.push(event);
                }
            }
            Err(err) => {
                if source != ProposalSource::Simulate {
                    warn!("Error handling delete side effects: {:?}", err);
                }
            }
        }

        let account_root =
            self.stores
                .trie
                .get_hash(&self.db, txn_batch, &TrieKey::for_fid(snapchain_txn.fid))?;

        debug!(
            shard_id = self.shard_id,
            fid = snapchain_txn.fid,
            num_user_messages = total_user_messages,
            num_system_messages = total_system_messages,
            user_messages_merged = user_messages_count,
            system_messages_merged = system_messages_count,
            onchain_events_merged = onchain_events_count,
            fnames_merged = merged_fnames_count,
            messages_merged = merged_messages_count,
            messages_pruned = pruned_messages_count,
            messages_revoked = revoked_messages_count,
            validation_errors = validation_errors.len(),
            new_account_root = hex::encode(&account_root),
            tx_account_root = hex::encode(&snapchain_txn.account_root),
            source = source.to_string(),
            last_block_event_seqnum,
            "Replayed transaction"
        );
        let elapsed = now.elapsed();
        self.metrics
            .time_with_shard("replay_txn_time_us", elapsed.as_micros() as u64);

        // Return the new account root hash
        Ok((
            account_root,
            events,
            validation_errors,
            last_block_event_seqnum,
        ))
    }

    /// Checks if a removed verification was set as the user's primary address and revokes it if necessary.
    ///
    /// When a verification is removed from a user's account, this function ensures that if the
    /// removed address was also set as their primary address (for either Ethereum or Solana),
    /// the primary address setting is also revoked to maintain consistency.
    ///
    fn check_and_revoke_primary_address(
        &mut self,
        fid: u64,
        deleted_verification: &proto::VerificationAddAddressBody,
        txn_batch: &mut RocksDbTransactionBatch,
    ) -> Result<Vec<HubEvent>, MessageValidationError> {
        // Determine protocol, parse address, and get user data type in one match
        let (parsed_address, user_data_type) = match deleted_verification.protocol {
            x if x == proto::Protocol::Ethereum as i32 => (
                Address::from_slice(&deleted_verification.address).to_checksum(None),
                UserDataType::UserDataPrimaryAddressEthereum,
            ),
            x if x == proto::Protocol::Solana as i32 => (
                bs58::encode(&deleted_verification.address).into_string(),
                UserDataType::UserDataPrimaryAddressSolana,
            ),
            _ => return Err(MessageValidationError::AddressNotPartOfVerification),
        };

        // Check if this address is set as the primary address
        let user_data_result = UserDataStore::get_user_data_by_fid_and_type(
            &self.stores.user_data_store,
            fid,
            user_data_type,
        );

        if let Ok(user_data) = user_data_result {
            if let Some(data_ref) = &user_data.data {
                if let Some(Body::UserDataBody(body)) = &data_ref.body {
                    if body.value == parsed_address {
                        let revoke_hub_event =
                            self.stores.user_data_store.revoke(&user_data, txn_batch)?;
                        return Ok(vec![revoke_hub_event]);
                    }
                }
            }
        }
        Ok(vec![])
    }

    /// Takes a list of merge events of type VerificationAddAddress and revokes the user's primary address
    /// if it was deleted as part of a verification remove message.
    fn handle_delete_side_effects(
        &mut self,
        version: &EngineVersion,
        events: &[HubEvent],
        txn_batch: &mut RocksDbTransactionBatch,
    ) -> Result<Vec<HubEvent>, EngineError> {
        if !version.is_enabled(ProtocolFeature::PrimaryAddresses) {
            return Ok(vec![]);
        }

        // Process verification removal hooks
        // Look for any events with deleted verification messages. We use this as a trigger to revoke
        // the user's primary address if it was deleted as part of a verification remove message.
        let mut revoke_events = Vec::new();
        for event in events {
            if let Some(hub_event::Body::MergeMessageBody(merge_body)) = &event.body {
                for deleted_message in &merge_body.deleted_messages {
                    let data = deleted_message
                        .data
                        .as_ref()
                        .ok_or(MessageValidationError::NoMessageData)?;
                    match &data.body {
                        Some(Body::VerificationAddAddressBody(body)) => {
                            let new_revoke_events = self.check_and_revoke_primary_address(
                                deleted_message.fid(),
                                body,
                                txn_batch,
                            )?;
                            revoke_events.extend(new_revoke_events);
                        }
                        _ => continue,
                    }
                }
            }
        }
        Ok(revoke_events)
    }

    fn merge_message(
        &self,
        msg: &proto::Message,
        txn_batch: &mut RocksDbTransactionBatch,
    ) -> Result<Vec<proto::HubEvent>, MessageValidationError> {
        let now = std::time::Instant::now();
        let data = msg
            .data
            .as_ref()
            .ok_or(MessageValidationError::NoMessageData)?;
        let mt = MessageType::try_from(data.r#type)
            .or(Err(MessageValidationError::InvalidMessageType(data.r#type)))?;

        let version =
            EngineVersion::version_for(&FarcasterTime::new(data.timestamp as u64), self.network);
        let gasless_enabled = version.is_enabled(ProtocolFeature::GaslessSigners);
        // Version-gated merge decisions (e.g. type-scoped link compaction under
        // ProtocolFeature::BlockLinks) are made inside each store's StoreDef from this context.
        let ctx = MergeContext { version };

        let event = match mt {
            MessageType::CastAdd | MessageType::CastRemove => vec![self
                .stores
                .cast_store
                .merge(msg, txn_batch, &ctx)
                .map_err(|e| MessageValidationError::StoreError(e))?],
            MessageType::LinkAdd | MessageType::LinkRemove | MessageType::LinkCompactState => {
                vec![self
                    .stores
                    .link_store
                    .merge(msg, txn_batch, &ctx)
                    .map_err(|e| MessageValidationError::StoreError(e))?]
            }
            MessageType::ReactionAdd | MessageType::ReactionRemove => vec![self
                .stores
                .reaction_store
                .merge(msg, txn_batch, &ctx)
                .map_err(|e| MessageValidationError::StoreError(e))?],
            MessageType::UserDataAdd => vec![self
                .stores
                .user_data_store
                .merge(msg, txn_batch, &ctx)
                .map_err(|e| MessageValidationError::StoreError(e))?],
            MessageType::VerificationAddEthAddress | MessageType::VerificationRemove => vec![self
                .stores
                .verification_store
                .merge(msg, txn_batch, &ctx)
                .map_err(|e| MessageValidationError::StoreError(e))?],
            MessageType::UsernameProof => {
                let store = &self.stores.username_proof_store;
                vec![store
                    .merge(msg, txn_batch, &ctx)
                    .map_err(|e| MessageValidationError::StoreError(e))?]
            }
            MessageType::LendStorage => {
                let store = &self.stores.storage_lend_store;
                StorageLendStore::merge(store, msg, txn_batch, &ctx)
                    .map_err(|e| MessageValidationError::StoreError(e))?
            }
            MessageType::KeyAdd if gasless_enabled => {
                // ShardEngine reaches `merge_message` for KEY_ADD only via
                // `handle_block_event` (BlockEvent replay) — KEY_ADD always routes to
                // shard 0, so a non-shard-0 ShardEngine never admits one as a user
                // message. Pass `is_replay = true` so `merge_key_add` skips the
                // request_fid IdRegister lookup that's redundant here (shard 0 already
                // validated it) and impossible to honour when request_fid lives on a
                // different user shard than this one.
                vec![crate::storage::store::account::merge_key_add(
                    &self.db,
                    &self.stores.onchain_event_store,
                    msg,
                    txn_batch,
                    true,
                )?]
            }
            MessageType::KeyRemove if gasless_enabled => {
                vec![crate::storage::store::account::merge_key_remove(
                    &self.db,
                    &self.stores.onchain_event_store,
                    msg,
                    txn_batch,
                )?]
            }
            unhandled_type => {
                return Err(MessageValidationError::InvalidMessageType(
                    unhandled_type as i32,
                ));
            }
        };
        // FIP §12 fee gate, after the pivot only (before it, the shards
        // follow snapchain and charge nothing). It runs after the merge, so a
        // duplicate or invalid message gives its own error; the charge and
        // the cast fingerprint go on the same batch as the merge.
        if self.hypersnap_mode {
            let fee =
                crate::chain::replica::charge_fee(&self.db, txn_batch, msg, self.hypersnap_height)
                    .map_err(|e| {
                        MessageValidationError::StoreError(
                            crate::core::error::HubError::validation_failure(&e.to_string()),
                        )
                    })?;
            let _ = fee;
            crate::chain::fingerprint_store::record_cast(&self.db, msg, txn_batch);
        }
        let elapsed = now.elapsed();
        self.metrics
            .time_with_shard("merge_message_time_us", elapsed.as_micros() as u64);
        Ok(event)
    }

    /// Dual-write a message to the hyper shadow stores.
    ///
    /// Writes to the same RocksDB transaction batch but using Hyper-prefixed
    /// keys. Errors are logged but do not fail the block — hyper is best-effort.
    fn merge_message_hyper(&self, msg: &proto::Message, txn_batch: &mut RocksDbTransactionBatch) {
        if let Some(ref hyper) = self.hyper_stores {
            let data = match msg.data.as_ref() {
                Some(d) => d,
                None => return,
            };
            let mt = match MessageType::try_from(data.r#type) {
                Ok(mt) => mt,
                Err(_) => return,
            };
            // Same version derivation as merge_message so the hyper shadow stores make the
            // same version-gated merge decisions as the canonical stores.
            let version = EngineVersion::version_for(
                &FarcasterTime::new(data.timestamp as u64),
                self.network,
            );
            let ctx = MergeContext { version };
            let result = match mt {
                MessageType::CastAdd | MessageType::CastRemove => {
                    hyper.cast_store.merge(msg, txn_batch, &ctx).map(|_| ())
                }
                MessageType::LinkAdd | MessageType::LinkRemove | MessageType::LinkCompactState => {
                    hyper.link_store.merge(msg, txn_batch, &ctx).map(|_| ())
                }
                MessageType::ReactionAdd | MessageType::ReactionRemove => {
                    hyper.reaction_store.merge(msg, txn_batch, &ctx).map(|_| ())
                }
                MessageType::UserDataAdd => hyper
                    .user_data_store
                    .merge(msg, txn_batch, &ctx)
                    .map(|_| ()),
                MessageType::VerificationAddEthAddress | MessageType::VerificationRemove => hyper
                    .verification_store
                    .merge(msg, txn_batch, &ctx)
                    .map(|_| ()),
                MessageType::UsernameProof => hyper
                    .username_proof_store
                    .merge(msg, txn_batch, &ctx)
                    .map(|_| ()),
                MessageType::LendStorage => {
                    StorageLendStore::merge(&hyper.storage_lend_store, msg, txn_batch, &ctx)
                        .map(|_| ())
                }
                _ => Ok(()),
            };
            if let Err(e) = result {
                warn!(shard_id = self.shard_id, error = %e, "hyper merge failed");
            }
        }
    }

    fn prune_messages(
        &mut self,
        fid: u64,
        msg_type: MessageType,
        txn_batch: &mut RocksDbTransactionBatch,
        version: &EngineVersion,
    ) -> Result<Vec<HubEvent>, EngineError> {
        let (current_count, max_count) = self
            .stores
            .get_usage(fid, msg_type, txn_batch)
            .map_err(|_| EngineError::UsageCountError)?;

        let events = match msg_type {
            MessageType::CastAdd | MessageType::CastRemove => self
                .stores
                .cast_store
                .prune_messages(fid, current_count, max_count, txn_batch)
                .map_err(|e| EngineError::StoreError(e)),
            MessageType::LinkAdd | MessageType::LinkRemove | MessageType::LinkCompactState => self
                .stores
                .link_store
                .prune_messages(fid, current_count, max_count, txn_batch)
                .map_err(|e| EngineError::StoreError(e)),
            MessageType::ReactionAdd | MessageType::ReactionRemove => self
                .stores
                .reaction_store
                .prune_messages(fid, current_count, max_count, txn_batch)
                .map_err(|e| EngineError::StoreError(e)),
            MessageType::UserDataAdd => self
                .stores
                .user_data_store
                .prune_messages(fid, current_count, max_count, txn_batch)
                .map_err(|e| EngineError::StoreError(e)),
            MessageType::VerificationAddEthAddress | MessageType::VerificationRemove => self
                .stores
                .verification_store
                .prune_messages(fid, current_count, max_count, txn_batch)
                .map_err(|e| EngineError::StoreError(e)),
            MessageType::UsernameProof => {
                // Usernameproof pruning was missing before this version
                if version.is_enabled(ProtocolFeature::EnsValidation) {
                    let store = &self.stores.username_proof_store;
                    store
                        .prune_messages(fid, current_count, max_count, txn_batch)
                        .map_err(|e| EngineError::StoreError(e))
                } else {
                    Ok(vec![])
                }
            }
            MessageType::LendStorage => {
                // Pruning not supported for storage lend messages
                Ok(vec![])
            }
            unhandled_type => {
                return Err(EngineError::UnsupportedMessageType(unhandled_type));
            }
        }?;

        if !events.is_empty() {
            info!(
                fid = fid,
                msg_type = msg_type.into_u8(),
                count = events.len(),
                "Pruned messages"
            );
        }
        Ok(events)
    }

    fn update_trie(
        &mut self,
        ctx: &merkle_trie::Context,
        event: &proto::HubEvent,
        txn_batch: &mut RocksDbTransactionBatch,
    ) -> Result<(), EngineError> {
        let now = std::time::Instant::now();

        self.stores
            .trie
            .update_for_event(ctx, &self.db, event, txn_batch)?;
        // The KEY_REMOVE leaves of the state trie have no other store.
        if self.content_replay || self.hypersnap_mode {
            crate::storage::store::account::stage_key_remove_messages(txn_batch, event);
        }

        let elapsed = now.elapsed();
        self.metrics
            .time_with_shard("update_trie_time_us", elapsed.as_micros() as u64);
        Ok(())
    }

    pub(crate) fn validate_user_message(
        &self,
        message: &proto::Message,
        timestamp: &FarcasterTime,
        version: EngineVersion,
        txn_batch: &mut RocksDbTransactionBatch,
    ) -> Result<(), MessageValidationError> {
        let now = std::time::Instant::now();

        // Reads use `read_txn` (in-flight writes when DependentMessagesInBulkSubmit is on,
        // empty otherwise); writes — specifically the gasless-key `last_used_at` bump
        // below — always land on the real `txn_batch`.
        let empty_txn = RocksDbTransactionBatch::new();
        let read_txn: &RocksDbTransactionBatch =
            if version.is_enabled(ProtocolFeature::DependentMessagesInBulkSubmit) {
                &*txn_batch
            } else {
                &empty_txn
            };

        // Ensure message data is present
        let message_data = message
            .data
            .as_ref()
            .ok_or(MessageValidationError::NoMessageData)?;

        // After the pivot every FID behaves as Pro (FIP §17.6), and a
        // migrated FID signs with Falcon-512 against the replica (FIP §16.8).
        let replica_signer = if self.hypersnap_mode {
            crate::chain::replica::check_signer(
                &self.db,
                txn_batch,
                message,
                self.network,
                timestamp.to_u64(),
            )
            .map_err(|e| {
                MessageValidationError::StoreError(HubError::validation_failure(&e.to_string()))
            })?
        } else {
            crate::chain::replica::SignerCheck::Snapchain
        };
        let is_pro_user = self.hypersnap_mode
            || self
                .stores
                .is_pro_user(message.fid(), timestamp)
                .map_err(|err| HubError::internal_db_error(&err.to_string()))?;
        validations::message::validate_message_with(
            message,
            self.network,
            is_pro_user,
            timestamp,
            version,
            replica_signer == crate::chain::replica::SignerCheck::Snapchain,
        )?;

        // 1. Check that the user has a custody address: an IdRegistry event,
        // or, after the pivot, the replica of the native FID registry.
        let native = self.hypersnap_mode && message_data.fid >> 63 == 1;
        if native {
            crate::storage::store::account::get_from_db_or_txn(
                &self.db,
                read_txn,
                &crate::chain::shard0::onboarding::native_fid_key(message_data.fid),
            )?
            .ok_or(MessageValidationError::MissingFid)?;
        } else {
            self.stores
                .onchain_event_store
                .get_id_register_event_by_fid(message_data.fid, Some(read_txn))
                .map_err(|_| MessageValidationError::MissingFid)?
                .ok_or(MessageValidationError::MissingFid)?;
        }

        // 2. Check that the user has a valid signer.
        //
        // KEY_ADD / KEY_REMOVE authenticate via custody EIP-712 (or, for self-revocation
        // KEY_REMOVE, via the Ed25519 key being revoked). `message.signer` on these is the
        // Ed25519 key being added or removed — not yet (KEY_ADD) or about to leave (KEY_REMOVE)
        // the signer set. Real auth lives in the merge path.
        let msg_type = MessageType::try_from(message_data.r#type).unwrap_or(MessageType::None);
        let mut gasless_ttl_for_bump: Option<u32> = None;
        let is_key_message = msg_type == MessageType::KeyAdd || msg_type == MessageType::KeyRemove;
        if is_key_message && !version.is_enabled(ProtocolFeature::GaslessSigners) {
            return Err(MessageValidationError::InvalidMessageType(
                message_data.r#type,
            ));
        }
        if !is_key_message && replica_signer == crate::chain::replica::SignerCheck::Snapchain {
            let active_key = crate::storage::store::account::get_active_key(
                &self.stores.onchain_event_store,
                &self.db,
                read_txn,
                message_data.fid,
                &message.signer,
            )
            .map_err(|_| MessageValidationError::MissingSigner)?
            .ok_or(MessageValidationError::MissingSigner)?;

            // On-chain signers are scope-free; gasless signers must declare msg_type in scope.
            if !active_key.admits(msg_type) {
                return Err(MessageValidationError::GaslessKeyOutOfScope {
                    msg_type: message_data.r#type,
                });
            }

            if let crate::storage::store::account::ActiveKey::Gasless { ttl_seconds, .. } =
                active_key
            {
                if ttl_seconds > 0 {
                    gasless_ttl_for_bump = Some(ttl_seconds);
                }
            }
        }

        // Don't allow storage lends to be merged directly without going through shard 0
        if message_data.r#type() == MessageType::LendStorage {
            return Err(MessageValidationError::InvalidMessageType(
                message_data.r#type,
            ));
        }

        // State-dependent verifications:
        match &message_data.body {
            Some(proto::message_data::Body::UserDataBody(user_data)) => {
                if user_data.r#type == proto::UserDataType::Username as i32 {
                    self.validate_username(message_data.fid, &user_data.value, read_txn)?;
                }
                if user_data.r#type == proto::UserDataType::UserDataPrimaryAddressEthereum as i32 {
                    self.validate_ethereum_address_ownership(
                        message_data.fid,
                        &user_data.value,
                        read_txn,
                    )?;
                }
                if user_data.r#type == proto::UserDataType::UserDataPrimaryAddressSolana as i32 {
                    self.validate_solana_address_ownership(
                        message_data.fid,
                        &user_data.value,
                        read_txn,
                    )?;
                }
            }
            _ => {}
        }

        // 3. Sliding-TTL enforcement for gasless keys. Bump `last_used_at` to the message's
        // own timestamp; reject if the key has expired since its last use.
        // The Falcon-512 signers of a migrated FID have the same sliding TTL.
        if let crate::chain::replica::SignerCheck::Verified(Some(used)) = &replica_signer {
            if !is_key_message {
                crate::chain::replica::record_use(txn_batch, used, message_data.timestamp as u64);
            }
        }
        if let Some(ttl) = gasless_ttl_for_bump {
            let current_block_timestamp = timestamp.to_u64();
            crate::storage::store::account::check_and_bump_last_used_at(
                &self.db,
                txn_batch,
                message_data.fid,
                &message.signer,
                ttl,
                message_data.timestamp,
                current_block_timestamp,
            )?;
        }

        let elapsed = now.elapsed();
        self.metrics
            .time_with_shard("validate_user_message_time_us", elapsed.as_micros() as u64);
        Ok(())
    }

    fn get_username_proof(
        &self,
        name: String,
        txn: &RocksDbTransactionBatch,
    ) -> Result<Option<UserNameProof>, MessageValidationError> {
        // TODO(aditi): The fnames proofs should live in the username proof store.
        if name.ends_with(".eth") {
            let version = EngineVersion::current(self.network);
            let batch_txn = if version.is_enabled(ProtocolFeature::DependentMessagesInBulkSubmit) {
                txn
            } else {
                &RocksDbTransactionBatch::new()
            };
            let proof_message = UsernameProofStore::get_username_proof(
                &self.stores.username_proof_store,
                &name.as_bytes().to_vec(),
                batch_txn,
            )
            .map_err(|e| MessageValidationError::StoreError(e))?;
            match proof_message {
                Some(message) => match message.data {
                    None => Ok(None),
                    Some(message_data) => match message_data.body {
                        Some(body) => match body {
                            proto::message_data::Body::UsernameProofBody(user_name_proof) => {
                                Ok(Some(user_name_proof))
                            }
                            _ => Ok(None),
                        },
                        None => Ok(None),
                    },
                },
                None => Ok(None),
            }
        } else {
            UserDataStore::get_username_proof(&self.stores.user_data_store, txn, name.as_bytes())
                .map_err(|e| MessageValidationError::StoreError(e))
        }
    }

    fn validate_ethereum_address_ownership(
        &self,
        fid: u64,
        address: &str,
        txn_batch: &RocksDbTransactionBatch,
    ) -> Result<(), MessageValidationError> {
        if address.is_empty() {
            return Ok(());
        }
        // Decode Ethereum address into bytes
        let address_instance: Address = Address::from_hex(address)
            .map_err(|_| MessageValidationError::InvalidEthereumAddress)?;
        self.verify_fid_owns_address(
            fid,
            Protocol::Ethereum,
            address_instance.as_ref(),
            txn_batch,
        )?;
        Ok(())
    }

    fn validate_solana_address_ownership(
        &self,
        fid: u64,
        address: &str,
        txn_batch: &RocksDbTransactionBatch,
    ) -> Result<(), MessageValidationError> {
        if address.is_empty() {
            return Ok(());
        }
        // Decode Solana address from base58 to bytes
        let address_bytes = bs58::decode(address)
            .into_vec()
            .map_err(|_| MessageValidationError::InvalidSolanaAddress)?;
        if address_bytes.len() != 32 {
            return Err(MessageValidationError::InvalidSolanaAddress);
        }
        self.verify_fid_owns_address(fid, Protocol::Solana, &address_bytes, txn_batch)?;
        Ok(())
    }

    fn validate_username(
        &self,
        fid: u64,
        name: &str,
        txn: &RocksDbTransactionBatch,
    ) -> Result<(), MessageValidationError> {
        if name.is_empty() {
            // Setting an empty username is allowed, no need to validate the proof
            return Ok(());
        }
        let name = name.to_string();
        // TODO: validate fname string

        let proof = self.get_username_proof(name.clone(), txn)?;
        match proof {
            Some(proof) => {
                if proof.fid != fid {
                    return Err(MessageValidationError::MissingFname);
                }

                if name.ends_with(".eth") {
                    // TODO: Validate ens names
                } else {
                }
            }
            None => {
                return Err(MessageValidationError::MissingFname);
            }
        }
        Ok(())
    }

    pub fn validate_state_change(
        &mut self,
        shard_state_change: &ShardStateChange,
        height: Height,
    ) -> bool {
        let mut txn = RocksDbTransactionBatch::new();

        let now = std::time::Instant::now();
        let transactions = &shard_state_change.transactions;
        let shard_root = &shard_state_change.new_state_root;
        // We ignore the events here, we don't know what they are yet. If state roots match, the events should match

        let mut result = true;

        let count_fn = self.metrics.make_count_fn();
        let count_callback = move |read_count: (u64, u64)| {
            count_fn("trie.db_get_count.total", read_count.0, vec![]);
            count_fn("trie.db_get_count.for_validate", read_count.0, vec![]);
            count_fn("trie.mem_get_count.total", read_count.1, vec![]);
            count_fn("trie.mem_get_count.for_validate", read_count.1, vec![]);
        };

        self.stores
            .event_handler
            .set_current_height(height.block_number);

        let proposal_result = self.replay_proposal(
            &merkle_trie::Context::with_callback(count_callback),
            &mut txn,
            transactions,
            shard_root,
            ProposalSource::Validate,
            shard_state_change.version,
            &shard_state_change.timestamp,
        );

        match proposal_result {
            Err(err) => {
                error!("State change validation failed: {}", err);
                result = false;
            }
            Ok((events, max_block_event_seqnum)) => {
                let block_events_hash =
                    Self::compute_block_events_hash(&shard_state_change.transactions);

                self.pending_txn = Some(CachedTransaction {
                    shard_root: shard_root.clone(),
                    txn,
                    events,
                    max_block_event_seqnum,
                    block_events_hash,
                    replica_key: self.hypersnap_replica_key.clone(),
                });
            }
        }

        self.stores.trie.reload(&self.db).unwrap();
        let elapsed = now.elapsed();
        self.metrics
            .time_with_shard("validate_time", elapsed.as_millis() as u64);

        if result {
            self.metrics.count("validate.true", 1, vec![]);
            self.metrics.count("validate.false", 0, vec![]);
        } else {
            self.metrics.count("validate.false", 1, vec![]);
            self.metrics.count("validate.true", 0, vec![]);
        }

        result
    }

    fn compute_event_counts_by_type(events: &Vec<HubEvent>) -> HashMap<i32, u64> {
        let mut counts_by_type = HashMap::new();
        for event in events {
            let count = counts_by_type.get(&event.r#type).unwrap_or(&0);
            counts_by_type.insert(event.r#type, count + 1);
        }
        counts_by_type
    }
    pub async fn commit_and_emit_events(
        &mut self,
        shard_chunk: &ShardChunk,
        mut events: Vec<HubEvent>,
        max_block_event_seqnum: u64,
        mut txn: RocksDbTransactionBatch,
    ) {
        let header = shard_chunk.header.as_ref().unwrap();
        let height = header.height.as_ref().unwrap();
        let mut event_counts_by_type = Self::compute_event_counts_by_type(&events);
        event_counts_by_type.insert(HubEventType::BlockConfirmed as i32, 1);
        let mut block_confirmed = HubEvent::new_event(
            proto::HubEventType::BlockConfirmed,
            proto::hub_event::Body::BlockConfirmedBody(proto::BlockConfirmedBody {
                block_number: height.block_number,
                shard_index: height.shard_index,
                timestamp: header.timestamp,
                block_hash: shard_chunk.hash.clone(),
                total_events: (events.len() + 1) as u64, // +1 for BLOCK_CONFIRMED itself
                event_counts_by_type,
                max_block_event_seqnum,
            }),
        );
        let _block_confirmed_id = self
            .stores
            .event_handler
            .commit_transaction(&mut txn, &mut block_confirmed)
            .unwrap();
        events.insert(0, block_confirmed);

        self.metrics
            .gauge("block_event_seqnum", max_block_event_seqnum);

        _ = self.emit_commit_metrics(&shard_chunk, &events);

        let now = std::time::Instant::now();
        // F033: stage the shard-chunk write on the same RocksDB batch
        // as the state mutations so trie/messages + chunk + header
        // all commit atomically. A crash between separate commits
        // could leave the trie at height H with the header still at
        // H-1, producing on-restart consensus divergence and
        // polluting bootstrap snapshots downstream.
        if let Err(e) = self
            .stores
            .shard_store
            .stage_shard_chunk(&mut txn, shard_chunk)
        {
            error!("Unable to stage shard chunk write: {}", e);
        }
        self.stage_shadow_trie(&events, height.block_number, &mut txn);
        self.db.commit(txn).unwrap();
        for mut event in events {
            event.timestamp = header.timestamp;
            let _ = self.senders.events_tx.send(event);
        }
        self.stores.trie.reload(&self.db).unwrap();
        let elapsed = now.elapsed();
        self.metrics
            .time_with_shard("commit_time", elapsed.as_millis() as u64);
        self.post_commit(shard_chunk.header.as_ref().unwrap().clone())
            .await;
    }

    fn emit_commit_metrics(
        &mut self,
        shard_chunk: &&ShardChunk,
        events: &Vec<HubEvent>,
    ) -> Result<(), EngineError> {
        self.metrics.count("commit.invoked", 1, vec![]);

        let block_number = &shard_chunk
            .header
            .as_ref()
            .unwrap()
            .height
            .unwrap()
            .block_number;

        self.metrics.gauge("block_height", *block_number);
        let block_timestamp = shard_chunk.header.as_ref().unwrap().timestamp;
        self.metrics.gauge(
            "block_delay_seconds",
            FarcasterTime::current()
                .to_u64()
                .saturating_sub(block_timestamp),
        );

        let trie_size = self.stores.trie.items()?;
        self.metrics.gauge("trie.num_items", trie_size as u64);

        self.metrics
            .publish_transaction_counts(&shard_chunk.transactions, ProposalSource::Commit);

        for event in events {
            self.metrics.count(
                "commit.emitted_event",
                1,
                vec![("event_type", &event.r#type.to_string())],
            );
            if event.r#type() == HubEventType::MergeMessage {
                match &event.body {
                    Some(hub_event::Body::MergeMessageBody(body)) => {
                        if let Some(message) = &body.message {
                            let mut tags =
                                vec![("message_type", (message.msg_type() as i32).to_string())];

                            // Try to get the request_fid from the signer metadata
                            if let Ok(Some(signer_event)) = self
                                .stores
                                .onchain_event_store
                                .get_active_signer(message.fid(), message.signer.clone(), None)
                            {
                                if let Some(proto::on_chain_event::Body::SignerEventBody(
                                    signer_body,
                                )) = &signer_event.body
                                {
                                    if let Some(request_fid) =
                                        onchain_events::get_request_fid_from_signer_event(
                                            &signer_body,
                                        )
                                    {
                                        let signer_name =
                                            onchain_events::map_signer_fid_to_name(request_fid);
                                        tags.push(("signer_app", signer_name.to_string()));
                                    }
                                }
                            }

                            self.metrics.count(
                                "commit.merged_message",
                                1,
                                tags.iter().map(|(k, v)| (*k, v.as_str())).collect(),
                            )
                        }
                    }
                    _ => {}
                }
            }
        }

        Ok(())
    }

    async fn post_commit(&mut self, header: proto::ShardHeader) {
        match &mut self.post_commit_tx {
            None => return,
            Some(tx) => {
                let now = std::time::Instant::now();

                // Attempt to send the post commit message and wait for a response,
                // but don't block indefinitely in case the receiver is not ready, unavailable,
                // or too slow.

                let (oneshot_tx, oneshot_rx) = oneshot::channel();
                let send_future = tx.send(PostCommitMessage {
                    shard_id: self.shard_id,
                    header: header,
                    channel: oneshot_tx,
                });

                if let Err(err) =
                    tokio::time::timeout(Duration::from_millis(200), send_future).await
                {
                    error!("Post commit hook send failed: {}", err);
                    return;
                }

                // Attempt to wait for the receiver to process the message, but don't block
                // indefinitely in case the receiver is not ready or available.
                match tokio::time::timeout(Duration::from_millis(200), oneshot_rx).await {
                    Ok(Ok(_)) => {} // success
                    Ok(Err(err)) => error!("Post commit hook failed: {}", err),
                    Err(err) => error!("Post commit hook receive failed: {}", err),
                }

                let elapsed = now.elapsed();
                self.metrics
                    .time_with_shard("post_commit_time", elapsed.as_millis() as u64);
            }
        }
    }

    fn compute_block_events_hash(transactions: &[Transaction]) -> Vec<u8> {
        let block_events: Vec<_> = transactions
            .iter()
            .flat_map(|txn| &txn.system_messages)
            .filter_map(|msg| msg.block_event.as_ref())
            .collect();

        if block_events.is_empty() {
            vec![]
        } else {
            let mut events_hasher = blake3::Hasher::new();
            for event in block_events.iter() {
                events_hasher.update(&event.hash);
            }
            events_hasher.finalize().as_bytes().to_vec()
        }
    }

    fn is_cached_txn_valid(
        &self,
        cached_txn: &CachedTransaction,
        shard_root: &[u8],
        transactions: &[Transaction],
    ) -> bool {
        // Check if shard roots match
        if &cached_txn.shard_root != shard_root {
            error!(
                shard_id = self.shard_id,
                cached_shard_root = hex::encode(&cached_txn.shard_root),
                commit_shard_root = hex::encode(shard_root),
                "Cached shard root mismatch"
            );
            self.metrics.count(
                "commit.cache_miss",
                1,
                vec![("reason", "shard_root_mismatch")],
            );
            return false;
        }

        // TODO(aditi): Ideally we would handle this by putting max block event seqnum in the block header but this requires a protocol upgrade.
        // Compute block events hash from transactions and compare with cached hash
        if cached_txn.replica_key != self.hypersnap_replica_key {
            self.metrics
                .count("commit.cache_miss", 1, vec![("reason", "replica_mismatch")]);
            return false;
        }
        let computed_hash = Self::compute_block_events_hash(transactions);
        if computed_hash != cached_txn.block_events_hash {
            error!(
                shard_id = self.shard_id,
                cached_block_events_hash = hex::encode(&cached_txn.block_events_hash),
                computed_block_events_hash = hex::encode(&computed_hash),
                "Cached block events hash mismatch"
            );
            self.metrics.count(
                "commit.cache_miss",
                1,
                vec![("reason", "block_events_hash_mismatch")],
            );
            return false;
        }

        true
    }

    pub async fn commit_shard_chunk(&mut self, shard_chunk: &ShardChunk) {
        let mut txn = RocksDbTransactionBatch::new();

        let shard_root = &shard_chunk.header.as_ref().unwrap().shard_root;
        let transactions = &shard_chunk.transactions;

        let mut applied_cached_txn = false;
        if let Some(cached_txn) = self.pending_txn.clone() {
            if self.is_cached_txn_valid(&cached_txn, shard_root, transactions) {
                applied_cached_txn = true;
                self.metrics.count("commit.cache_hit", 1, vec![]);
                self.commit_and_emit_events(
                    shard_chunk,
                    cached_txn.events,
                    cached_txn.max_block_event_seqnum,
                    cached_txn.txn,
                )
                .await;
            }
        } else {
            // is_cached_txn_valid emits its own miss metric when pending_txn
            // exists but doesn't match. This branch covers the other case:
            // there was never a prevalidated proposal for this value on this
            // node (e.g. this node wasn't the proposer and didn't see the
            // propose round that decided).
            self.metrics
                .count("commit.cache_miss", 1, vec![("reason", "no_pending_txn")]);
        }

        if !applied_cached_txn {
            if !self.is_read_only() {
                warn!(
                    shard_id = self.shard_id,
                    shard_root = hex::encode(shard_root),
                    "No valid cached transaction to apply. Replaying proposal"
                );
            }
            let header = &shard_chunk.header.as_ref().unwrap();
            let block_number = header.height.unwrap().block_number;
            self.stores.event_handler.set_current_height(block_number);
            let version = self.version_for(&FarcasterTime::new(header.timestamp));

            let count_fn = self.metrics.make_count_fn();
            let count_callback = move |read_count: (u64, u64)| {
                count_fn("trie.db_get_count.total", read_count.0, vec![]);
                count_fn("trie.db_get_count.for_commit", read_count.0, vec![]);
                count_fn("trie.mem_get_count.total", read_count.1, vec![]);
                count_fn("trie.mem_get_count.for_commit", read_count.1, vec![]);
            };
            let trie_ctx = &merkle_trie::Context::with_callback(count_callback);

            match self.replay_proposal(
                trie_ctx,
                &mut txn,
                transactions,
                shard_root,
                ProposalSource::Commit,
                version,
                &FarcasterTime::new(header.timestamp),
            ) {
                Err(err) => {
                    // Persist before panicking. The panic below is caught by
                    // ractor, which stops the ReadHost actor but leaves the
                    // process up and unsupervised — so this `error!` is the only
                    // statement of the cause, and it scrolls out of the log while
                    // the shard stays dead and `read_sync` emits SendErr forever.
                    // The record is what an operator can still read afterwards.
                    node_local_state::LocalStateStore::record_shard_halt(
                        &self.db,
                        self.shard_id,
                        block_number,
                        &err.to_string(),
                    );
                    error!("State change commit failed: {}", err);
                    panic!("State change commit failed: {}", err);
                }
                Ok((events, max_block_event_seqnum)) => {
                    self.commit_and_emit_events(shard_chunk, events, max_block_event_seqnum, txn)
                        .await;
                }
            }
        }

        // A commit got through, so any halt on record belongs to a previous run
        // and has been resolved. Clearing it keeps the status endpoint from
        // reporting a shard as dead after it recovered. Once per process.
        if !self.halt_record_checked {
            self.halt_record_checked = true;
            if node_local_state::LocalStateStore::read_shard_halt(&self.db, self.shard_id).is_some()
            {
                warn!(
                    shard_id = self.shard_id,
                    "Clearing a halt recorded by a previous run; this shard is committing again"
                );
                node_local_state::LocalStateStore::clear_shard_halt(&self.db, self.shard_id);
            }
        }
    }

    pub fn simulate_message(
        &mut self,
        message: &proto::Message,
    ) -> Result<(), MessageValidationError> {
        let mut txn = RocksDbTransactionBatch::new();
        let snapchain_txn = Transaction {
            fid: message.fid() as u64,
            account_root: vec![],
            system_messages: vec![],
            user_messages: vec![message.clone()],
        };
        let version = self.version_for(&FarcasterTime::current());
        let max_block_event_seqnum = self.stores.block_event_store.max_seqnum().unwrap_or(0);
        let result = self.replay_snapchain_txn(
            &merkle_trie::Context::new(),
            &snapchain_txn,
            &mut txn,
            ProposalSource::Simulate,
            version,
            &FarcasterTime::current(),
            max_block_event_seqnum,
        );

        match result {
            Ok((_, _, errors, _)) => {
                self.stores.trie.reload(&self.db).map_err(|e| {
                    MessageValidationError::StoreError(HubError::invalid_internal_state(
                        &*e.to_string(),
                    ))
                })?;
                if !errors.is_empty() {
                    return Err(errors[0].clone());
                } else {
                    Ok(())
                }
            }
            Err(err) => {
                error!("Error simulating message: {:?}", err);
                Err(MessageValidationError::StoreError(
                    HubError::invalid_internal_state(&*err.to_string()),
                ))
            }
        }
    }

    pub fn simulate_bulk_messages(
        &mut self,
        messages: &[proto::Message],
    ) -> Vec<Result<(), MessageValidationError>> {
        use std::collections::HashMap;

        let mut txn_batch = RocksDbTransactionBatch::new();
        let trie_ctx = merkle_trie::Context::new();
        let version = self.version_for(&FarcasterTime::current());
        let timestamp = FarcasterTime::current();

        // Group messages by FID and track their original positions
        let mut messages_by_fid: HashMap<u64, Vec<(usize, &proto::Message)>> = HashMap::new();
        for (index, message) in messages.iter().enumerate() {
            let fid = message.fid() as u64;
            messages_by_fid
                .entry(fid)
                .or_insert_with(Vec::new)
                .push((index, message));
        }

        // Initialize results vector with placeholder values
        let mut results: Vec<Result<(), MessageValidationError>> = vec![Ok(()); messages.len()];
        let mut max_block_event_seqnum = self.stores.block_event_store.max_seqnum().unwrap_or(0);

        // Process each FID group
        for (fid, fid_messages) in messages_by_fid {
            // Create a single transaction for all messages from this FID
            let user_messages: Vec<proto::Message> =
                fid_messages.iter().map(|(_, msg)| (*msg).clone()).collect();
            let snapchain_txn = Transaction {
                fid,
                account_root: vec![], // Not used for simulation
                system_messages: vec![],
                user_messages,
            };

            // Process the transaction for this FID
            match self.replay_snapchain_txn(
                &trie_ctx,
                &snapchain_txn,
                &mut txn_batch,
                ProposalSource::Simulate,
                version,
                &timestamp,
                max_block_event_seqnum,
            ) {
                Ok((_, _, validation_errors, latest_block_event_seqnum)) => {
                    // If there are any validation errors, assign them to the results
                    if !validation_errors.is_empty() {
                        let error = validation_errors[0].clone();
                        for (original_index, _) in fid_messages {
                            results[original_index] = Err(error.clone());
                        }
                    }
                    max_block_event_seqnum = latest_block_event_seqnum;
                }
                Err(err) => {
                    // If replay_snapchain_txn fails, all messages for this FID fail
                    let error = MessageValidationError::StoreError(
                        HubError::invalid_internal_state(&*err.to_string()),
                    );
                    for (original_index, _) in fid_messages {
                        results[original_index] = Err(error.clone());
                    }
                }
            }
        }

        // The simulation was successful. We must now discard all in-memory changes
        // to the trie and the transaction batch, as we are not committing state here.
        match self.stores.trie.reload(&self.db) {
            Ok(()) => results,
            Err(e) => {
                let trie_error = MessageValidationError::StoreError(
                    HubError::invalid_internal_state(&*e.to_string()),
                );
                // If trie reload fails, return the trie error for all messages
                vec![Err(trie_error); messages.len()]
            }
        }
    }

    pub fn trie_key_exists(&mut self, ctx: &merkle_trie::Context, sync_id: &Vec<u8>) -> bool {
        self.stores
            .trie
            .exists(ctx, &self.db, sync_id.as_ref())
            .unwrap_or_else(|err| {
                error!("Error checking if sync id exists: {:?}", err);
                false
            })
    }

    pub fn get_block_event(
        &self,
        seqnum: u64,
    ) -> Result<Option<BlockEvent>, BlockEventStorageError> {
        self.stores
            .block_event_store
            .get_block_event_by_seqnum(seqnum)
    }

    pub fn get_min_height(&self) -> Height {
        match self.stores.shard_store.min_block_number() {
            Ok(block_num) => Height::new(self.shard_id, block_num),
            // In case of no blocks, return height 1
            Err(_) => Height::new(self.shard_id, 1),
        }
    }

    pub fn get_confirmed_height(&self) -> Height {
        match self.stores.shard_store.max_block_number() {
            Ok(block_num) => Height::new(self.shard_id, block_num),
            Err(_) => Height::new(self.shard_id, 0),
        }
    }

    pub fn get_last_shard_chunk(&self) -> Option<ShardChunk> {
        match self.stores.shard_store.get_last_shard_chunk() {
            Ok(shard_chunk) => shard_chunk,
            Err(err) => {
                error!("Unable to obtain last shard chunk {:#?}", err);
                None
            }
        }
    }

    pub fn get_shard_chunk_by_height(&self, height: Height) -> Option<ShardChunk> {
        if self.shard_id != height.shard_index {
            error!(
                shard_id = self.shard_id,
                requested_shard_id = height.shard_index,
                "Requested shard chunk from incorrect shard"
            );
            return None;
        }
        self.stores
            .shard_store
            .get_chunk_by_height(height.block_number)
            .unwrap_or_else(|err| {
                error!("No shard chunk at height {:#?}", err);
                None
            })
    }

    pub fn get_casts_by_fid(&self, fid: u64) -> Result<MessagesPage, HubError> {
        CastStore::get_cast_adds_by_fid(&self.stores.cast_store, fid, &PageOptions::default())
    }

    pub fn get_links_by_fid(&self, fid: u64) -> Result<MessagesPage, HubError> {
        self.stores
            .link_store
            .get_adds_by_fid::<fn(&proto::Message) -> bool>(fid, &PageOptions::default(), None)
    }

    pub fn get_link_compact_state_messages_by_fid(
        &self,
        fid: u64,
    ) -> Result<MessagesPage, HubError> {
        self.stores
            .link_store
            .get_compact_state_messages_by_fid(fid, &PageOptions::default())
    }

    pub fn get_reactions_by_fid(&self, fid: u64) -> Result<MessagesPage, HubError> {
        self.stores
            .reaction_store
            .get_adds_by_fid::<fn(&proto::Message) -> bool>(fid, &PageOptions::default(), None)
    }

    pub fn get_user_data_by_fid(&self, fid: u64) -> Result<MessagesPage, HubError> {
        self.stores
            .user_data_store
            .get_adds_by_fid::<fn(&proto::Message) -> bool>(fid, &PageOptions::default(), None)
    }

    pub fn get_user_data_by_fid_and_type(
        &self,
        fid: u64,
        user_data_type: proto::UserDataType,
    ) -> Result<proto::Message, HubError> {
        UserDataStore::get_user_data_by_fid_and_type(
            &self.stores.user_data_store,
            fid,
            user_data_type,
        )
    }

    /// Verifies that a FID has an active verification for a specific address and protocol.
    ///
    /// This function checks if a user has previously verified ownership of an address by looking for
    /// existing VerificationAddAddress messages in their verification store. It's used to ensure that
    /// users can only set addresses as primary addresses if they have already proven ownership through
    /// the verification process.
    ///
    /// # Note
    /// Only checks for add messages since CRDT rules ensure that verification remove messages
    /// automatically drop the corresponding add messages from the active state.
    pub fn verify_fid_owns_address(
        &self,
        fid: u64,
        protocol: Protocol,
        address: &[u8],
        txn_batch: &RocksDbTransactionBatch,
    ) -> Result<(), MessageValidationError> {
        let page_result = VerificationStore::get_verification_add(
            &self.stores.verification_store,
            fid,
            address,
            Some(txn_batch),
        )
        .map_err(|_| {
            MessageValidationError::StoreError(HubError::invalid_internal_state(
                "Unable to get verifications by fid",
            ))
        })?;
        match page_result {
            Some(message) => {
                let verification = match &message.data.as_ref().unwrap().body.as_ref().unwrap() {
                    Body::VerificationAddAddressBody(body) => body,
                    _ => unreachable!(),
                };

                if verification.protocol == protocol as i32 {
                    Ok(())
                } else {
                    Err(MessageValidationError::AddressNotPartOfVerification)
                }
            }
            None => {
                return Err(MessageValidationError::AddressNotPartOfVerification);
            }
        }
    }

    pub fn get_verifications_by_fid(&self, fid: u64) -> Result<MessagesPage, HubError> {
        self.stores
            .verification_store
            .get_adds_by_fid::<fn(&proto::Message) -> bool>(fid, &PageOptions::default(), None)
    }

    pub fn get_username_proofs_by_fid(&self, fid: u64) -> Result<MessagesPage, HubError> {
        self.stores
            .username_proof_store
            .get_adds_by_fid::<fn(&proto::Message) -> bool>(fid, &PageOptions::default(), None)
    }

    pub fn get_fname_proof(&self, name: &String) -> Result<Option<UserNameProof>, HubError> {
        UserDataStore::get_username_proof(
            &self.stores.user_data_store,
            &mut RocksDbTransactionBatch::new(),
            name.as_bytes(),
        )
    }

    pub fn get_onchain_events(
        &self,
        event_type: OnChainEventType,
        fid: u64,
    ) -> Result<Vec<OnChainEvent>, OnchainEventStorageError> {
        self.stores
            .onchain_event_store
            .get_onchain_events(event_type, Some(fid))
    }

    pub fn trie_num_items(&mut self) -> usize {
        self.stores.trie.items().unwrap()
    }

    fn should_revoke_signer(signer_event: &proto::SignerEventBody, version: EngineVersion) -> bool {
        // When this bug was active, we did not revoke any signers, then we decided to intentionally stop revoking existing messages associated with revoked signers.
        if version.is_enabled(ProtocolFeature::SignerRevokeBug)
            || version.is_enabled(ProtocolFeature::StopRevokingExistingMessages)
        {
            return false;
        }
        signer_event.event_type == proto::SignerEventType::Remove as i32
    }
}
