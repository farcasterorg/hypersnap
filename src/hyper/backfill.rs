//! Hyper backfill: replays historical shard chunks to populate the
//! Hyper shadow stores with messages that were pruned from Legacy storage.
//!
//! On first run this iterates every shard chunk from genesis to the current
//! height, merging user messages into the Hyper-prefixed key space. Progress
//! is checkpointed per shard so the process can resume after a restart.

use crate::proto::{Message, MessageType};
use crate::storage::db::RocksDbTransactionBatch;
use crate::storage::store::account::StorageLendStore;
use crate::storage::store::stores::Stores;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tracing::{info, warn};

const CHECKPOINT_NAME: &str = "hyper_backfill";
const BATCH_SIZE: u64 = 100;
const COMMIT_INTERVAL: usize = 500; // messages per commit

/// Run the hyper backfill for all shards.
///
/// For each shard, iterates shard chunks from the last checkpoint to the
/// current height and merges every user message into the corresponding
/// hyper store. The Legacy stores and trie are not touched.
pub async fn run_hyper_backfill(
    api_db: &Arc<crate::storage::db::RocksDB>,
    shard_stores: &HashMap<u32, Stores>,
    hyper_shard_stores: &HashMap<u32, Stores>,
) {
    let mut sorted_shards: Vec<_> = shard_stores.keys().cloned().collect();
    sorted_shards.sort();

    for shard_id in sorted_shards {
        let stores = match shard_stores.get(&shard_id) {
            Some(s) => s,
            None => continue,
        };
        let hyper = match hyper_shard_stores.get(&shard_id) {
            Some(h) => h,
            None => continue,
        };

        let checkpoint =
            crate::api::backfill::load_shard_checkpoint(api_db, CHECKPOINT_NAME, shard_id);
        let max_height = match stores.shard_store.max_block_number() {
            Ok(h) => h,
            Err(e) => {
                warn!(shard_id, error = %e, "Failed to get max block number, skipping shard");
                continue;
            }
        };

        if checkpoint > max_height {
            info!(
                shard_id,
                checkpoint, max_height, "Hyper backfill already complete for shard"
            );
            continue;
        }

        info!(
            shard_id,
            from = checkpoint,
            to = max_height,
            "Starting hyper backfill"
        );

        let start = Instant::now();
        let mut messages_merged: u64 = 0;
        let mut chunks_processed: u64 = 0;
        let mut height = checkpoint;

        while height <= max_height {
            let end = (height + BATCH_SIZE).min(max_height);
            let chunks = match stores.shard_store.get_shard_chunks(height, Some(end)) {
                Ok(c) => c,
                Err(e) => {
                    warn!(shard_id, height, error = %e, "Failed to get shard chunks");
                    break;
                }
            };

            if chunks.is_empty() {
                height = end + 1;
                continue;
            }

            let mut txn_batch = RocksDbTransactionBatch::new();
            let mut batch_count = 0;

            for chunk in &chunks {
                for txn in &chunk.transactions {
                    for msg in &txn.user_messages {
                        if merge_message_to_hyper(hyper, msg, &mut txn_batch) {
                            messages_merged += 1;
                            batch_count += 1;
                        }

                        if batch_count >= COMMIT_INTERVAL {
                            if let Err(e) = hyper.db.commit(txn_batch) {
                                warn!(shard_id, error = %e, "Failed to commit hyper batch");
                            }
                            txn_batch = RocksDbTransactionBatch::new();
                            batch_count = 0;
                        }
                    }
                }
                chunks_processed += 1;
            }

            // Commit remaining writes
            if txn_batch.len() > 0 {
                if let Err(e) = hyper.db.commit(txn_batch) {
                    warn!(shard_id, error = %e, "Failed to commit hyper batch");
                }
            }

            height = end + 1;

            // Checkpoint periodically
            if chunks_processed % 1000 == 0 {
                let _ = crate::api::backfill::save_shard_checkpoint(
                    api_db,
                    CHECKPOINT_NAME,
                    shard_id,
                    height,
                );
                info!(
                    shard_id,
                    height,
                    messages_merged,
                    chunks_processed,
                    elapsed_secs = start.elapsed().as_secs(),
                    "Hyper backfill progress"
                );
            }

            // Yield to other tasks
            if chunks_processed % 100 == 0 {
                tokio::task::yield_now().await;
            }
        }

        // Final checkpoint
        let _ = crate::api::backfill::save_shard_checkpoint(
            api_db,
            CHECKPOINT_NAME,
            shard_id,
            max_height + 1,
        );

        let elapsed = start.elapsed();
        info!(
            shard_id,
            messages_merged,
            chunks_processed,
            elapsed_secs = elapsed.as_secs(),
            "Hyper backfill complete for shard"
        );
    }
}

/// Merge a single message into the hyper stores. Returns true if merged.
fn merge_message_to_hyper(
    hyper: &Stores,
    msg: &Message,
    txn_batch: &mut RocksDbTransactionBatch,
) -> bool {
    let data = match msg.data.as_ref() {
        Some(d) => d,
        None => return false,
    };
    let mt = match MessageType::try_from(data.r#type) {
        Ok(mt) => mt,
        Err(_) => return false,
    };

    let result = match mt {
        MessageType::CastAdd | MessageType::CastRemove => {
            hyper.cast_store.merge(msg, txn_batch).map(|_| ())
        }
        MessageType::LinkAdd | MessageType::LinkRemove | MessageType::LinkCompactState => {
            hyper.link_store.merge(msg, txn_batch).map(|_| ())
        }
        MessageType::ReactionAdd | MessageType::ReactionRemove => {
            hyper.reaction_store.merge(msg, txn_batch).map(|_| ())
        }
        MessageType::UserDataAdd => hyper.user_data_store.merge(msg, txn_batch).map(|_| ()),
        MessageType::VerificationAddEthAddress | MessageType::VerificationRemove => {
            hyper.verification_store.merge(msg, txn_batch).map(|_| ())
        }
        MessageType::UsernameProof => hyper.username_proof_store.merge(msg, txn_batch).map(|_| ()),
        MessageType::LendStorage => {
            StorageLendStore::merge(&hyper.storage_lend_store, msg, txn_batch).map(|_| ())
        }
        _ => return false,
    };

    match result {
        Ok(()) => true,
        Err(_) => false, // CRDT conflicts or duplicates are expected, silently skip
    }
}
