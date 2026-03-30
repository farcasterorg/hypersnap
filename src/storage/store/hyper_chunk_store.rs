use crate::core::error::HubError;
use crate::proto::HyperChunk;
use crate::storage::constants::RootPrefix;
use crate::storage::db::{RocksDB, RocksDbTransactionBatch};
use prost::Message;
use std::sync::Arc;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum HyperChunkStorageError {
    #[error(transparent)]
    RocksdbError(#[from] crate::storage::db::RocksdbError),

    #[error("Hyper chunk missing header")]
    MissingHeader,

    #[error("Hyper chunk missing height")]
    MissingHeight,

    #[error("Hub error")]
    HubError(#[from] HubError),

    #[error("Error decoding hyper chunk")]
    DecodeError(#[from] prost::DecodeError),
}

fn make_hyper_chunk_key(block_number: u64) -> Vec<u8> {
    let mut key = vec![RootPrefix::HyperChunk as u8];
    key.extend_from_slice(&block_number.to_be_bytes());
    key
}

pub struct HyperChunkStore {
    db: Arc<RocksDB>,
}

impl HyperChunkStore {
    pub fn new(db: Arc<RocksDB>) -> Self {
        HyperChunkStore { db }
    }

    pub fn put_chunk(
        &self,
        chunk: &HyperChunk,
        txn: &mut RocksDbTransactionBatch,
    ) -> Result<(), HyperChunkStorageError> {
        let header = chunk
            .header
            .as_ref()
            .ok_or(HyperChunkStorageError::MissingHeader)?;
        let height = header
            .height
            .as_ref()
            .ok_or(HyperChunkStorageError::MissingHeight)?;
        let key = make_hyper_chunk_key(height.block_number);
        txn.put(key, chunk.encode_to_vec());
        Ok(())
    }

    pub fn get_chunk_by_height(
        &self,
        block_number: u64,
    ) -> Result<Option<HyperChunk>, HyperChunkStorageError> {
        let key = make_hyper_chunk_key(block_number);
        match self.db.get(&key)? {
            None => Ok(None),
            Some(bytes) => {
                let chunk = HyperChunk::decode(bytes.as_slice())?;
                Ok(Some(chunk))
            }
        }
    }

    pub fn get_last_chunk(&self) -> Result<Option<HyperChunk>, HyperChunkStorageError> {
        let start_key = make_hyper_chunk_key(0);
        let stop_key = vec![RootPrefix::HyperChunk as u8 + 1];

        let mut result = None;
        self.db
            .for_each_iterator_by_prefix_paged(
                Some(start_key),
                Some(stop_key),
                &crate::storage::db::PageOptions {
                    reverse: true,
                    page_size: Some(1),
                    page_token: None,
                },
                |_key, value| {
                    result = Some(HyperChunk::decode(value).map_err(|e| HubError::from(e))?);
                    Ok(true) // Stop after first
                },
            )
            .map_err(HyperChunkStorageError::HubError)?;

        Ok(result)
    }

    pub fn max_block_number(&self) -> Result<u64, HyperChunkStorageError> {
        match self.get_last_chunk()? {
            None => Ok(0),
            Some(chunk) => {
                let header = chunk
                    .header
                    .as_ref()
                    .ok_or(HyperChunkStorageError::MissingHeader)?;
                let height = header
                    .height
                    .as_ref()
                    .ok_or(HyperChunkStorageError::MissingHeight)?;
                Ok(height.block_number)
            }
        }
    }
}
