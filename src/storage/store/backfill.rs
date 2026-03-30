use crate::proto;
use crate::proto::MessageType;
use crate::storage::constants::RootPrefix;
use crate::storage::db::{RocksDB, RocksDbTransactionBatch};
use crate::storage::store::account::{StorageLendStore, UserDataStore};
use crate::storage::store::stores::Stores;
use crate::storage::trie::merkle_trie::{self, MerkleTrie, TrieKey};
use std::sync::Arc;
use tracing::{info, warn};

/// Data-type byte for backfill progress (last processed height per shard).
/// Stored under RootPrefix::NodeLocalState.
const BACKFILL_PROGRESS_DATA_TYPE: u8 = 5;

/// Data-type byte for backfill completion marker per shard.
/// Stored under RootPrefix::NodeLocalState.
const BACKFILL_COMPLETE_DATA_TYPE: u8 = 6;

fn make_progress_key(shard_id: u32) -> Vec<u8> {
    let mut key = Vec::with_capacity(6);
    key.push(RootPrefix::NodeLocalState as u8);
    key.push(BACKFILL_PROGRESS_DATA_TYPE);
    key.extend_from_slice(&shard_id.to_be_bytes());
    key
}

fn make_complete_key(shard_id: u32) -> Vec<u8> {
    let mut key = Vec::with_capacity(6);
    key.push(RootPrefix::NodeLocalState as u8);
    key.push(BACKFILL_COMPLETE_DATA_TYPE);
    key.extend_from_slice(&shard_id.to_be_bytes());
    key
}

fn get_progress(hyper_db: &RocksDB, shard_id: u32) -> u64 {
    let key = make_progress_key(shard_id);
    match hyper_db.get(&key) {
        Ok(Some(bytes)) if bytes.len() == 8 => {
            u64::from_be_bytes(bytes.as_slice().try_into().unwrap())
        }
        _ => 0,
    }
}

fn set_progress(hyper_db: &RocksDB, shard_id: u32, height: u64) {
    let key = make_progress_key(shard_id);
    if let Err(e) = hyper_db.put(&key, &height.to_be_bytes()) {
        warn!(shard_id, height, "Failed to save backfill progress: {}", e);
    }
}

fn is_complete(hyper_db: &RocksDB, shard_id: u32) -> bool {
    let key = make_complete_key(shard_id);
    matches!(hyper_db.get(&key), Ok(Some(_)))
}

fn mark_complete(hyper_db: &RocksDB, shard_id: u32) {
    let key = make_complete_key(shard_id);
    if let Err(e) = hyper_db.put(&key, &[1u8]) {
        warn!(shard_id, "Failed to mark backfill complete: {}", e);
    }
}

/// Merge a single user message into the appropriate store.
/// Returns the resulting HubEvents on success.
fn merge_message_to_store(
    stores: &Stores,
    msg: &proto::Message,
    txn_batch: &mut RocksDbTransactionBatch,
) -> Result<Vec<proto::HubEvent>, String> {
    let data = msg.data.as_ref().ok_or("No message data")?;
    let mt = MessageType::try_from(data.r#type).map_err(|_| "Invalid message type")?;

    match mt {
        MessageType::CastAdd | MessageType::CastRemove => stores
            .cast_store
            .merge(msg, txn_batch)
            .map(|e| vec![e])
            .map_err(|e| e.to_string()),
        MessageType::LinkAdd | MessageType::LinkRemove | MessageType::LinkCompactState => stores
            .link_store
            .merge(msg, txn_batch)
            .map(|e| vec![e])
            .map_err(|e| e.to_string()),
        MessageType::ReactionAdd | MessageType::ReactionRemove => stores
            .reaction_store
            .merge(msg, txn_batch)
            .map(|e| vec![e])
            .map_err(|e| e.to_string()),
        MessageType::UserDataAdd => stores
            .user_data_store
            .merge(msg, txn_batch)
            .map(|e| vec![e])
            .map_err(|e| e.to_string()),
        MessageType::VerificationAddEthAddress | MessageType::VerificationRemove => stores
            .verification_store
            .merge(msg, txn_batch)
            .map(|e| vec![e])
            .map_err(|e| e.to_string()),
        MessageType::UsernameProof => stores
            .username_proof_store
            .merge(msg, txn_batch)
            .map(|e| vec![e])
            .map_err(|e| e.to_string()),
        MessageType::LendStorage => {
            StorageLendStore::merge(&stores.storage_lend_store, msg, txn_batch)
                .map_err(|e| e.to_string())
        }
        _ => Err(format!("Unhandled message type: {:?}", mt)),
    }
}

/// Run backfill for a single shard. Iterates through stored shard chunks,
/// merges all messages into the stores (idempotent), and inserts all message
/// keys into the hyper trie (prefix 23).
///
/// - `shard_stores`: The shard being backfilled (provides shard_store for chunks, stores for merging)
/// - `hyper_db`: Shard 1's DB where the hyper trie lives
pub fn run_backfill(shard_stores: &Stores, hyper_db: &Arc<RocksDB>) {
    let shard_id = shard_stores.shard_id;

    // Check if already complete
    if is_complete(hyper_db, shard_id) {
        info!(shard_id, "Backfill already complete, skipping");
        return;
    }

    // Determine range
    let max_height = shard_stores.shard_store.max_block_number().unwrap_or(0);
    if max_height == 0 {
        info!(shard_id, "No shard chunks found, nothing to backfill");
        mark_complete(hyper_db, shard_id);
        return;
    }

    let last_progress = get_progress(hyper_db, shard_id);
    let start_height = if last_progress > 0 {
        last_progress + 1
    } else {
        // Try to get min block number; if shard is empty, start from 1
        shard_stores.shard_store.min_block_number().unwrap_or(1)
    };

    if start_height > max_height {
        info!(
            shard_id,
            "Backfill progress ({}) >= max height ({}), marking complete",
            last_progress,
            max_height
        );
        mark_complete(hyper_db, shard_id);
        return;
    }

    info!(
        shard_id,
        start_height, max_height, "Starting backfill for shard"
    );

    // Create hyper trie for inserting keys
    let mut hyper_trie =
        MerkleTrie::new_with_prefix(RootPrefix::HyperMerkleTrieNode as u8).unwrap();
    hyper_trie
        .initialize(hyper_db)
        .expect("Failed to initialize hyper trie for backfill");

    let trie_ctx = merkle_trie::Context::new();
    let mut total_messages: u64 = 0;
    let mut total_trie_keys: u64 = 0;
    let mut chunks_processed: u64 = 0;

    for height in start_height..=max_height {
        let chunk = match shard_stores.shard_store.get_chunk_by_height(height) {
            Ok(Some(chunk)) => chunk,
            Ok(None) => {
                // Gap in chunk history — skip
                continue;
            }
            Err(e) => {
                warn!(shard_id, height, "Error reading shard chunk: {}", e);
                continue;
            }
        };

        let mut stores_txn = RocksDbTransactionBatch::new();
        let mut trie_txn = RocksDbTransactionBatch::new();
        let mut trie_insert_keys: Vec<Vec<u8>> = Vec::new();

        for txn in &chunk.transactions {
            // Process system messages
            for sys_msg in &txn.system_messages {
                // OnChainEvents
                if let Some(onchain_event) = &sys_msg.on_chain_event {
                    match shard_stores
                        .onchain_event_store
                        .merge_onchain_event(onchain_event.clone(), &mut stores_txn)
                    {
                        Ok(hub_event) => {
                            let (inserts, _deletes) = TrieKey::for_hub_event(&hub_event);
                            trie_insert_keys.extend(inserts);
                        }
                        Err(_) => {
                            // Duplicate or invalid — still try to derive trie key
                            let key = TrieKey::for_onchain_event(onchain_event);
                            trie_insert_keys.push(key);
                        }
                    }
                }

                // FnameTransfers
                if let Some(fname_transfer) = &sys_msg.fname_transfer {
                    if let Some(proof) = &fname_transfer.proof {
                        match UserDataStore::merge_username_proof(
                            &shard_stores.user_data_store,
                            proof,
                            &mut stores_txn,
                        ) {
                            Ok(hub_event) => {
                                let (inserts, _deletes) = TrieKey::for_hub_event(&hub_event);
                                trie_insert_keys.extend(inserts);
                            }
                            Err(_) => {
                                // Duplicate — derive trie key directly for fname
                                if proof.fid != 0 {
                                    let name =
                                        std::str::from_utf8(&proof.name).unwrap_or("").to_string();
                                    trie_insert_keys.push(TrieKey::for_fname(proof.fid, &name));
                                }
                            }
                        }
                    }
                }
            }

            // Process user messages
            for msg in &txn.user_messages {
                total_messages += 1;
                match merge_message_to_store(shard_stores, msg, &mut stores_txn) {
                    Ok(hub_events) => {
                        for event in &hub_events {
                            let (inserts, _deletes) = TrieKey::for_hub_event(event);
                            trie_insert_keys.extend(inserts);
                        }
                    }
                    Err(_) => {
                        // Duplicate or error — still insert trie keys for the message
                        trie_insert_keys.extend(TrieKey::for_message(msg));
                    }
                }
            }
        }

        // Insert all collected trie keys into hyper trie
        if !trie_insert_keys.is_empty() {
            let key_refs: Vec<&[u8]> = trie_insert_keys.iter().map(|k| k.as_slice()).collect();
            total_trie_keys += key_refs.len() as u64;
            if let Err(e) = hyper_trie.insert(&trie_ctx, hyper_db, &mut trie_txn, key_refs) {
                warn!(shard_id, height, "Error inserting trie keys: {}", e);
            }
        }

        // Commit stores txn to shard DB (message data)
        if let Err(e) = shard_stores.db.commit(stores_txn) {
            warn!(shard_id, height, "Error committing store txn: {}", e);
        }

        // Commit trie txn to hyper DB (hyper trie entries)
        if let Err(e) = hyper_db.commit(trie_txn) {
            warn!(shard_id, height, "Error committing trie txn: {}", e);
        }

        chunks_processed += 1;

        // Every 100 chunks: save progress, reload trie, log
        if chunks_processed % 100 == 0 {
            set_progress(hyper_db, shard_id, height);
            if let Err(e) = hyper_trie.reload(hyper_db) {
                warn!(
                    shard_id,
                    height, "Error reloading hyper trie during backfill: {}", e
                );
            }
            info!(
                shard_id,
                height,
                max_height,
                chunks_processed,
                total_messages,
                total_trie_keys,
                "Backfill progress"
            );
        }
    }

    // Final reload + save
    set_progress(hyper_db, shard_id, max_height);
    if let Err(e) = hyper_trie.reload(hyper_db) {
        warn!(shard_id, "Error reloading hyper trie after backfill: {}", e);
    }
    mark_complete(hyper_db, shard_id);

    info!(
        shard_id,
        chunks_processed, total_messages, total_trie_keys, "Backfill complete for shard"
    );
}
