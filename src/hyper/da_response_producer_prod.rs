//! BlockEngine-backed `DaResponseProducer`. One engine-mutex
//! acquisition per epoch-boundary batch.

use crate::hyper::da_pow_driver::{produce_da_responses_via, DaResponseProducer};
use crate::proto;
use crate::storage::store::block_engine::BlockEngine;
use crate::storage::trie::merkle_trie;
use ed25519_dalek::SigningKey;
use std::sync::Arc;
use tokio::sync::Mutex;

pub struct BlockEngineDaResponseProducer {
    engine: Arc<Mutex<BlockEngine>>,
    signer_sk: SigningKey,
    validator_pubkey: Vec<u8>,
    fid: u64,
    chain_id: u64,
    /// F135: highest registered FID at the epoch boundary. Passed
    /// to `derive_challenge_prefix` so the derived FID falls within
    /// the live FID space. Set by the supervisor when constructing
    /// the producer.
    pub max_fid: u64,
}

impl BlockEngineDaResponseProducer {
    pub fn new(
        engine: Arc<Mutex<BlockEngine>>,
        signer_sk: SigningKey,
        validator_pubkey: Vec<u8>,
        fid: u64,
        chain_id: u64,
        max_fid: u64,
    ) -> Self {
        Self {
            engine,
            signer_sk,
            validator_pubkey,
            fid,
            chain_id,
            max_fid,
        }
    }
}

impl DaResponseProducer for BlockEngineDaResponseProducer {
    fn produce_for_epoch(
        &self,
        epoch: u64,
        epoch_boundary_seed: &[u8],
    ) -> Vec<proto::DaChallengeResponseBody> {
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                let mut engine = self.engine.lock().await;
                let ctx = merkle_trie::Context::new();
                produce_da_responses_via(
                    epoch,
                    epoch_boundary_seed,
                    &self.validator_pubkey,
                    self.fid,
                    self.chain_id,
                    self.max_fid,
                    &self.signer_sk,
                    |prefix| {
                        let matches = engine.trie_values_with_prefix(&ctx, prefix);
                        matches.into_iter().next()
                    },
                )
            })
        })
    }
}
