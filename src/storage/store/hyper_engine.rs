use crate::core::error::HubError;
use crate::core::util::FarcasterTime;
use crate::core::validations;
use crate::core::validations::verification;
use crate::mempool::mempool::MempoolMessagesRequest;
use crate::proto::{self, FarcasterNetwork, HubEvent};
use crate::storage::constants::RootPrefix;
use crate::storage::db::{RocksDB, RocksDbTransactionBatch};
use crate::storage::store::engine::{EngineError, MessageValidationError};
use crate::storage::store::engine_metrics::Metrics;
use crate::storage::store::hyper_chunk_store::HyperChunkStore;
use crate::storage::store::mempool_poller::{MempoolMessage, MempoolPoller};
use crate::storage::store::stores::Stores;
use crate::storage::trie::merkle_trie;
use crate::utils::statsd_wrapper::StatsdClientWrapper;
use std::sync::Arc;
use tokio::sync::{mpsc, watch};
use tracing::{info, warn};

use crate::core::types::Height;

/// Anchor information from the latest snapchain block.
#[derive(Clone, Debug, Default)]
pub struct SnapchainAnchor {
    pub block_number: u64,
    pub state_root: Vec<u8>,
}

/// The result of proposing a hyper state change.
#[derive(Clone)]
pub struct HyperStateChange {
    pub timestamp: FarcasterTime,
    pub new_state_root: Vec<u8>,
    pub transactions: Vec<proto::HyperTransaction>,
    pub anchor: SnapchainAnchor,
}

/// Cached transaction from propose/validate for later commit.
#[derive(Clone)]
#[allow(dead_code)]
struct CachedHyperTransaction {
    state_root: Vec<u8>,
    txn: RocksDbTransactionBatch,
}

pub struct HyperEngine {
    shard_id: u32,
    pub network: FarcasterNetwork,
    pub db: Arc<RocksDB>,
    pub(crate) trie: merkle_trie::MerkleTrie,
    chunk_store: HyperChunkStore,
    /// Shared snapchain Stores (for FID/custody lookups). Read-only.
    stores: Stores,
    anchor_rx: watch::Receiver<SnapchainAnchor>,
    pub mempool_poller: MempoolPoller,
    pending_txn: Option<CachedHyperTransaction>,
    #[allow(dead_code)]
    metrics: Metrics,
}

impl HyperEngine {
    pub fn new(
        db: Arc<RocksDB>,
        network: FarcasterNetwork,
        shard_id: u32,
        stores: Stores,
        anchor_rx: watch::Receiver<SnapchainAnchor>,
        messages_request_tx: Option<mpsc::Sender<MempoolMessagesRequest>>,
        max_messages_per_block: u32,
        statsd_client: StatsdClientWrapper,
    ) -> Result<Self, HubError> {
        let mut trie =
            merkle_trie::MerkleTrie::new_with_prefix(RootPrefix::HyperMerkleTrieNode as u8)
                .map_err(|e| HubError::invalid_internal_state(&e.to_string()))?;
        trie.initialize(&db)
            .map_err(|e| HubError::invalid_internal_state(&e.to_string()))?;

        let chunk_store = HyperChunkStore::new(db.clone());

        Ok(HyperEngine {
            shard_id,
            network,
            stores,
            mempool_poller: MempoolPoller {
                shard_id,
                max_messages_per_block,
                messages_request_tx,
                network,
                statsd_client: statsd_client.clone(),
            },
            db,
            trie,
            chunk_store,
            anchor_rx,
            pending_txn: None,
            metrics: Metrics {
                statsd_client,
                shard_id,
            },
        })
    }

    pub fn shard_id(&self) -> u32 {
        self.shard_id
    }

    pub fn hyper_state_root(&self) -> Vec<u8> {
        self.trie.root_hash().unwrap_or_default()
    }

    /// Read the current snapchain anchor.
    fn current_anchor(&self) -> SnapchainAnchor {
        self.anchor_rx.borrow().clone()
    }

    // --- Propose / Validate / Commit lifecycle ---

    /// Process hyper messages and produce a state change for proposal.
    pub fn propose_state_change(
        &mut self,
        messages: Vec<MempoolMessage>,
        timestamp: Option<FarcasterTime>,
    ) -> HyperStateChange {
        let timestamp = timestamp.unwrap_or_else(FarcasterTime::current);
        let mut txn = RocksDbTransactionBatch::new();
        let mut transactions = Vec::new();

        // Group messages by FID
        let mut fid_messages: std::collections::BTreeMap<u64, Vec<&proto::HyperMessage>> =
            std::collections::BTreeMap::new();
        let hyper_messages: Vec<_> = messages
            .iter()
            .filter_map(|m| match m {
                MempoolMessage::HyperSignerMessage(msg) => Some(msg),
                _ => None,
            })
            .collect();

        for msg in &hyper_messages {
            fid_messages.entry(msg.fid()).or_default().push(msg);
        }

        for (fid, msgs) in &fid_messages {
            let mut hyper_msgs = Vec::new();
            for msg in msgs {
                match self.validate_hyper_signer_message(msg, &timestamp) {
                    Ok(()) => {
                        if let Err(e) = self.merge_hyper_signer_message(msg, &mut txn) {
                            warn!("Failed to merge hyper signer message: {:?}", e);
                        } else {
                            hyper_msgs.push((*msg).clone());
                        }
                    }
                    Err(e) => {
                        info!("Hyper signer message validation failed: {:?}", e);
                    }
                }
            }

            if !hyper_msgs.is_empty() {
                transactions.push(proto::HyperTransaction {
                    fid: *fid,
                    account_root: vec![], // Will be filled in after computing
                    hyper_messages: hyper_msgs,
                });
            }
        }

        // Commit the txn to DB immediately (hyper data is committed separately from snapchain)
        if txn.len() > 0 {
            self.db.commit(txn.clone()).unwrap();
            self.trie
                .reload(&self.db)
                .map_err(|e| HubError::invalid_internal_state(&e.to_string()))
                .unwrap();
        }

        let new_state_root = self.hyper_state_root();
        let anchor = self.current_anchor();

        self.pending_txn = Some(CachedHyperTransaction {
            state_root: new_state_root.clone(),
            txn,
        });

        HyperStateChange {
            timestamp,
            new_state_root,
            transactions,
            anchor,
        }
    }

    /// Validate a proposed state change from another validator.
    /// Replays the transactions and checks that the resulting state root matches.
    pub fn validate_state_change(
        &mut self,
        state_change: &HyperStateChange,
        _height: Height,
    ) -> bool {
        let mut txn = RocksDbTransactionBatch::new();

        for hyper_txn in &state_change.transactions {
            for msg in &hyper_txn.hyper_messages {
                match self.validate_hyper_signer_message(msg, &state_change.timestamp) {
                    Ok(()) => {
                        if let Err(e) = self.merge_hyper_signer_message(msg, &mut txn) {
                            warn!(
                                "Failed to merge hyper signer message during validation: {:?}",
                                e
                            );
                            return false;
                        }
                    }
                    Err(e) => {
                        warn!(
                            "Hyper signer message validation failed during validation: {:?}",
                            e
                        );
                        return false;
                    }
                }
            }
        }

        // Commit the txn to DB
        if txn.len() > 0 {
            self.db.commit(txn.clone()).unwrap();
            self.trie
                .reload(&self.db)
                .map_err(|e| HubError::invalid_internal_state(&e.to_string()))
                .unwrap();
        }

        let computed_root = self.hyper_state_root();
        if computed_root != state_change.new_state_root {
            warn!(
                shard_id = self.shard_id,
                computed_root = hex::encode(&computed_root),
                expected_root = hex::encode(&state_change.new_state_root),
                "Hyper state root mismatch"
            );
            return false;
        }

        self.pending_txn = Some(CachedHyperTransaction {
            state_root: computed_root,
            txn,
        });

        true
    }

    /// Commit a decided HyperChunk to storage.
    pub fn commit_hyper_chunk(&mut self, chunk: &proto::HyperChunk) {
        let mut txn = RocksDbTransactionBatch::new();

        // Store the chunk itself
        if let Err(e) = self.chunk_store.put_chunk(chunk, &mut txn) {
            panic!("Failed to store hyper chunk: {:?}", e);
        }

        self.db.commit(txn).unwrap();
        self.pending_txn = None;

        let height = chunk.header.as_ref().and_then(|h| h.height);
        info!(
            shard_id = self.shard_id,
            height = ?height,
            hash = hex::encode(&chunk.hash),
            "Committed hyper chunk"
        );
    }

    // --- Height / chunk accessors ---

    pub fn get_confirmed_height(&self) -> Height {
        match self.chunk_store.max_block_number() {
            Ok(block_num) => Height::new(self.shard_id, block_num),
            Err(_) => Height::new(self.shard_id, 0),
        }
    }

    pub fn get_last_hyper_chunk(&self) -> Option<proto::HyperChunk> {
        self.chunk_store.get_last_chunk().unwrap_or(None)
    }

    pub fn get_hyper_chunk_by_height(&self, height: Height) -> Option<proto::HyperChunk> {
        self.chunk_store
            .get_chunk_by_height(height.block_number)
            .unwrap_or(None)
    }

    // --- Hyper message validation and merging (moved from ShardEngine) ---

    /// Validate a HyperMessage for signer add/remove. Checks:
    /// 1. FID has a custody address (id register event)
    /// 2. hyper_message.signer matches the custody address
    /// 3. Deadline has not passed
    /// 4. Nonce > stored nonce
    /// 5. EIP-712 custody signature is valid
    pub fn validate_hyper_signer_message(
        &self,
        hyper_message: &proto::HyperMessage,
        timestamp: &FarcasterTime,
    ) -> Result<(), MessageValidationError> {
        // Structural validation
        validations::hyper_message::validate_hyper_message(hyper_message)?;

        let data = hyper_message
            .data
            .as_ref()
            .ok_or(MessageValidationError::NoMessageData)?;

        let fid = data.fid;

        // 1. Check FID is registered
        let id_register_event = self
            .stores
            .onchain_event_store
            .get_id_register_event_by_fid(fid, None)
            .map_err(|_| MessageValidationError::MissingFid)?
            .ok_or(MessageValidationError::MissingFid)?;

        // Extract custody address from id register event
        let custody_address = match &id_register_event.body {
            Some(proto::on_chain_event::Body::IdRegisterEventBody(body)) => body.to.clone(),
            _ => return Err(MessageValidationError::MissingFid),
        };

        // 2. Signer must match custody address
        if hyper_message.signer != custody_address {
            return Err(MessageValidationError::MissingSigner);
        }

        // 3. Deadline check
        let deadline = match &data.body {
            Some(proto::hyper_message_data::Body::SignerAddBody(b)) => b.deadline,
            Some(proto::hyper_message_data::Body::SignerRemoveBody(b)) => b.deadline,
            _ => return Err(MessageValidationError::NoMessageData),
        };
        if deadline < timestamp.to_u64() {
            return Err(MessageValidationError::StoreError(
                HubError::validation_failure("signer authorization deadline has passed"),
            ));
        }

        // 4. Nonce check
        let txn_batch = RocksDbTransactionBatch::new();
        let nonce = match &data.body {
            Some(proto::hyper_message_data::Body::SignerAddBody(b)) => b.nonce,
            Some(proto::hyper_message_data::Body::SignerRemoveBody(b)) => b.nonce,
            _ => return Err(MessageValidationError::NoMessageData),
        };
        let stored_nonce = self
            .stores
            .onchain_event_store
            .get_offchain_signer_nonce(fid, &txn_batch)
            .map_err(|e| {
                MessageValidationError::StoreError(HubError::internal_db_error(&e.to_string()))
            })?;
        if nonce <= stored_nonce {
            return Err(MessageValidationError::StoreError(
                HubError::validation_failure(&format!(
                    "nonce too low: got {}, expected > {}",
                    nonce, stored_nonce
                )),
            ));
        }

        // 5. EIP-712 signature validation (EOA)
        match &data.body {
            Some(proto::hyper_message_data::Body::SignerAddBody(body)) => {
                verification::validate_signer_add_custody_signature(
                    fid,
                    body,
                    &hyper_message.signature,
                    &custody_address,
                )?;
            }
            Some(proto::hyper_message_data::Body::SignerRemoveBody(body)) => {
                verification::validate_signer_remove_custody_signature(
                    fid,
                    body,
                    &hyper_message.signature,
                    &custody_address,
                )?;
            }
            _ => return Err(MessageValidationError::NoMessageData),
        }

        Ok(())
    }

    /// Merge a validated hyper signer message into storage.
    /// Creates a synthetic OnChainEvent and optionally tracks signer revocation.
    /// Updates hyper trie (NOT snapchain trie) to track hyper state.
    pub fn merge_hyper_signer_message(
        &mut self,
        hyper_message: &proto::HyperMessage,
        txn_batch: &mut RocksDbTransactionBatch,
    ) -> Result<HubEvent, EngineError> {
        let hub_event = self
            .stores
            .onchain_event_store
            .merge_offchain_signer_event(hyper_message, txn_batch)
            .map_err(EngineError::MergeOnchainEventError)?;

        // Update hyper trie (NOT self.stores.trie — keeps snapchain state root unchanged)
        let trie_ctx = merkle_trie::Context::new();
        let _ = self
            .trie
            .update_for_event(&trie_ctx, &self.db, &hub_event, txn_batch);

        // For signer removes, revoke messages signed by this key
        if hyper_message.hyper_msg_type() == proto::HyperMessageType::SignerRemove {
            if let Some(body) = hyper_message.signer_remove_body() {
                let fid = hyper_message.fid();
                let result = self.stores.revoke_messages(fid, &body.key, txn_batch);
                match result {
                    Ok(revoke_events) => {
                        for event in &revoke_events {
                            let _ = self
                                .trie
                                .update_for_event(&trie_ctx, &self.db, event, txn_batch);
                        }
                    }
                    Err(err) => {
                        warn!(
                            fid = fid,
                            key = hex::encode(&body.key),
                            "Error revoking messages for off-chain signer remove: {:?}",
                            err
                        );
                    }
                }
            }
        }

        Ok(hub_event)
    }
}
