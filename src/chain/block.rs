//! Hypersnap blocks (FIP §4.2, §4.3, §17.7): hashing, the messages root, and
//! the header checks that do not need state.

use super::epoch::{validate_epoch_ref_height, EpochParams};
use super::merkle;
use crate::proto::{self, HypersnapBlock, HypersnapBlockHeader};
use alloy_primitives::keccak256;
use prost::Message as _;

/// FIP §4.2.
pub const MAX_BLOCK_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_MESSAGE_BYTES: usize = 1024 * 1024;

/// Drop `data_bytes` when it is the encoding of `data` (and set `data` from
/// it if absent): the hash and the signatures cover the same bytes (FIP
/// §16.8), and a block carries the content once (FIP §4.2). Other messages do
/// not change.
pub fn compact_message(message: &mut proto::Message) {
    let Some(bytes) = message.data_bytes.as_ref().filter(|b| !b.is_empty()) else {
        return;
    };
    let Ok(decoded) = proto::MessageData::decode(bytes.as_slice()) else {
        return;
    };
    if decoded.encode_to_vec() != *bytes || message.data.as_ref().is_some_and(|d| *d != decoded) {
        return;
    }
    message.data = Some(decoded);
    message.data_bytes = None;
}

/// The encoded bytes of the messages that a proposer takes from its mempool
/// for one block: `MAX_BLOCK_BYTES` less 1 MiB for the header, the parent
/// certificate, the system messages and the encoding of the transactions.
pub const PULL_BYTES: usize = MAX_BLOCK_BYTES - 1024 * 1024;

/// The consensus timing (FIP §4.2). Release values: a devnet uses its
/// `[consensus]` values.
pub const BLOCK_TIME: std::time::Duration = std::time::Duration::from_millis(12_000);
pub const PROPOSE_TIME: std::time::Duration = std::time::Duration::from_millis(6_000);
pub const PREVOTE_TIME: std::time::Duration = std::time::Duration::from_millis(3_000);
pub const PRECOMMIT_TIME: std::time::Duration = std::time::Duration::from_millis(3_000);
pub const STEP_DELTA: std::time::Duration = std::time::Duration::from_millis(1_000);
/// Protocol version of the first Hypersnap release.
pub const BLOCK_VERSION: u32 = 1;
/// Shards whose links a shard-0 block carries.
pub const LINKED_SHARDS: [u32; 2] = [1, 2];

/// The block hash: `keccak256` of the canonical (protobuf) encoding of the
/// header.
pub fn block_hash(header: &HypersnapBlockHeader) -> [u8; 32] {
    keccak256(header.encode_to_vec()).0
}

/// Hash of a commit certificate, for `last_commit_hash`.
pub fn certificate_hash(certificate: &proto::CommitCertificate) -> [u8; 32] {
    keccak256(certificate.encode_to_vec()).0
}

const LEAF_SYSTEM: u8 = 0x00;
const LEAF_USER: u8 = 0x01;
const LEAF_TRANSACTION: u8 = 0x02;

fn leaf(kind: u8, item: &impl prost::Message) -> Vec<u8> {
    let mut leaf = Vec::with_capacity(1 + item.encoded_len());
    leaf.push(kind);
    item.encode(&mut leaf).expect("Vec has capacity");
    leaf
}

/// `messages_root`: ordered Keccak Merkle root (`chain::merkle`) over the
/// body in execution order: system messages (leaf kind `0x00`), then user
/// messages (`0x01`), then, on shards 1 and 2, the per-FID transactions
/// (`0x02`). Each leaf is the kind byte followed by the protobuf encoding.
pub fn messages_root(
    system_messages: &[proto::HypersnapSystemMessage],
    messages: &[proto::Message],
) -> [u8; 32] {
    body_root(system_messages, messages, &[])
}

pub fn body_root(
    system_messages: &[proto::HypersnapSystemMessage],
    messages: &[proto::Message],
    transactions: &[proto::Transaction],
) -> [u8; 32] {
    let mut leaves: Vec<Vec<u8>> =
        Vec::with_capacity(system_messages.len() + messages.len() + transactions.len());
    leaves.extend(system_messages.iter().map(|m| leaf(LEAF_SYSTEM, m)));
    leaves.extend(messages.iter().map(|m| leaf(LEAF_USER, m)));
    leaves.extend(transactions.iter().map(|t| leaf(LEAF_TRANSACTION, t)));
    merkle::root(&leaves)
}

fn block_body_root(block: &HypersnapBlock) -> [u8; 32] {
    body_root(&block.system_messages, &block.messages, &block.transactions)
}

/// Fill `messages_root` and `hash` from the body and the header.
pub fn seal(block: &mut HypersnapBlock) {
    let root = block_body_root(block);
    let header = block.header.get_or_insert_with(Default::default);
    header.messages_root = root.to_vec();
    block.hash = block_hash(header).to_vec();
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum BlockError {
    #[error("block has no header")]
    MissingHeader,
    #[error("block is {0} bytes, above MAX_BLOCK_BYTES")]
    TooLarge(usize),
    #[error("a message is {0} bytes, above MAX_MESSAGE_BYTES")]
    MessageTooLarge(usize),
    #[error("block hash does not match the header")]
    BadHash,
    #[error("messages_root does not match the body")]
    BadMessagesRoot,
    #[error("header field {field}: {reason}")]
    BadHeader { field: &'static str, reason: String },
}

fn bad(field: &'static str, reason: impl Into<String>) -> BlockError {
    BlockError::BadHeader {
        field,
        reason: reason.into(),
    }
}

/// What a header is checked against.
#[derive(Clone, Debug)]
pub struct ParentInfo {
    pub height: u64,
    pub hash: [u8; 32],
    pub timestamp: u64,
    /// `epoch_ref_height` of the parent (shards 1/2); `None` for the pivot
    /// block of the shard.
    pub epoch_ref_height: Option<u64>,
    /// Shard links of the parent (shard 0).
    pub shard_links: Vec<proto::ShardLink>,
}

#[derive(Clone, Debug)]
pub struct HeaderContext {
    pub shard_id: u32,
    pub epochs: EpochParams,
    pub version: u32,
    /// Highest certified shard-0 height this node knows (shards 1/2).
    pub highest_certified_shard0: u64,
    /// Latest acceptable timestamp (local clock plus drift).
    pub max_timestamp: u64,
}

/// Structural checks of a block: size, hash, messages root.
pub fn validate_body(block: &HypersnapBlock) -> Result<(), BlockError> {
    let size = block.encoded_len();
    if size > MAX_BLOCK_BYTES {
        return Err(BlockError::TooLarge(size));
    }
    for m in &block.messages {
        let n = m.encoded_len();
        if n > MAX_MESSAGE_BYTES {
            return Err(BlockError::MessageTooLarge(n));
        }
    }
    let header = block.header.as_ref().ok_or(BlockError::MissingHeader)?;
    if block_hash(header).as_slice() != block.hash.as_slice() {
        return Err(BlockError::BadHash);
    }
    if block_body_root(block).as_slice() != header.messages_root.as_slice() {
        return Err(BlockError::BadMessagesRoot);
    }
    if header.shard_id == 0 && !block.transactions.is_empty() {
        return Err(bad("transactions", "set on shard 0"));
    }
    if header.shard_id != 0 && (!block.messages.is_empty() || !block.system_messages.is_empty()) {
        return Err(bad("messages", "shards 1 and 2 carry per-FID transactions"));
    }
    Ok(())
}

/// Header checks against the parent (FIP §4.3, §17.7). Shard links are checked
/// for shape and monotonicity here; that they point to certified blocks is
/// checked by the caller, which has the shard stores.
pub fn validate_header(
    header: &HypersnapBlockHeader,
    parent: &ParentInfo,
    ctx: &HeaderContext,
) -> Result<(), BlockError> {
    if header.shard_id != ctx.shard_id {
        return Err(bad(
            "shard_id",
            format!("{} on shard {}", header.shard_id, ctx.shard_id),
        ));
    }
    if header.height != parent.height + 1 {
        return Err(bad(
            "height",
            format!("{} after parent {}", header.height, parent.height),
        ));
    }
    if header.parent_hash.as_slice() != parent.hash.as_slice() {
        return Err(bad("parent_hash", "does not match the parent"));
    }
    if header.timestamp < parent.timestamp {
        return Err(bad("timestamp", "before the parent"));
    }
    if header.timestamp > ctx.max_timestamp {
        return Err(bad("timestamp", "too far in the future"));
    }
    if header.version != ctx.version {
        return Err(bad(
            "version",
            format!("{} != {}", header.version, ctx.version),
        ));
    }
    if header.state_root.len() != 32 {
        return Err(bad("state_root", "not 32 bytes"));
    }

    if ctx.shard_id == 0 {
        let expected = ctx
            .epochs
            .epoch_of(header.height)
            .ok_or_else(|| bad("height", "below PIVOT_HEIGHT_0"))?;
        if header.epoch != expected {
            return Err(bad("epoch", format!("{} != {}", header.epoch, expected)));
        }
        if header.epoch_ref_height != 0 {
            return Err(bad("epoch_ref_height", "set on shard 0"));
        }
        if header.shard_links.len() != LINKED_SHARDS.len() {
            return Err(bad(
                "shard_links",
                "need one link for each of shards 1 and 2",
            ));
        }
        for (link, shard) in header.shard_links.iter().zip(LINKED_SHARDS) {
            if link.shard_id != shard {
                return Err(bad("shard_links", "not in shard order"));
            }
            if link.block_hash.len() != 32 || link.state_root.len() != 32 {
                return Err(bad("shard_links", "hash or root is not 32 bytes"));
            }
            if let Some(prev) = parent.shard_links.iter().find(|l| l.shard_id == shard) {
                if link.height < prev.height {
                    return Err(bad("shard_links", "a link decreased"));
                }
                if link.height == prev.height && link.block_hash != prev.block_hash {
                    return Err(bad("shard_links", "same height, different block"));
                }
            }
        }
    } else {
        let expected = ctx.epochs.shard_block_epoch(parent.epoch_ref_height);
        if header.epoch != expected {
            return Err(bad("epoch", format!("{} != {}", header.epoch, expected)));
        }
        // A shard references Hypersnap shard-0 blocks only, so its pivot
        // block follows the certified shard-0 pivot block (FIP §4.3, §17.5).
        if header.epoch_ref_height < ctx.epochs.pivot_height_0 {
            return Err(bad("epoch_ref_height", "below PIVOT_HEIGHT_0"));
        }
        validate_epoch_ref_height(
            parent.epoch_ref_height,
            header.epoch_ref_height,
            ctx.highest_certified_shard0,
        )
        .map_err(|e| bad("epoch_ref_height", e))?;
        if !header.shard_links.is_empty() {
            return Err(bad("shard_links", "set on a shard other than 0"));
        }
        if !header.bridge_lock_root.is_empty() {
            return Err(bad("bridge_lock_root", "set on a shard other than 0"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_message_carries_its_content_once() {
        let data = proto::MessageData {
            r#type: proto::MessageType::CastAdd as i32,
            fid: 7,
            timestamp: 100,
            network: proto::FarcasterNetwork::Devnet as i32,
            body: Some(proto::message_data::Body::CastAddBody(proto::CastAddBody {
                text: "once".into(),
                ..Default::default()
            })),
        };
        let bytes = data.encode_to_vec();
        let both = proto::Message {
            data: Some(data.clone()),
            data_bytes: Some(bytes.clone()),
            ..Default::default()
        };
        let mut m = both.clone();
        compact_message(&mut m);
        assert_eq!(
            (m.data.as_ref(), m.data_bytes.as_ref()),
            (Some(&data), None)
        );
        assert!(m.encoded_len() < both.encoded_len());

        // `data_bytes` alone: `data` comes from it.
        let mut m = proto::Message {
            data_bytes: Some(bytes.clone()),
            ..Default::default()
        };
        compact_message(&mut m);
        assert_eq!(
            (m.data.as_ref(), m.data_bytes.as_ref()),
            (Some(&data), None)
        );

        // Bytes that are not the canonical encoding, or that differ from
        // `data`, stay.
        let mut padded = bytes.clone();
        padded.extend_from_slice(&[0x98, 0x3e, 0x01]); // an unknown field (995)
        let mut m = proto::Message {
            data: Some(data.clone()),
            data_bytes: Some(padded.clone()),
            ..Default::default()
        };
        compact_message(&mut m);
        assert_eq!(m.data_bytes, Some(padded));
        let mut other = data.clone();
        other.fid = 8;
        let mut m = proto::Message {
            data: Some(other),
            data_bytes: Some(bytes.clone()),
            ..Default::default()
        };
        compact_message(&mut m);
        assert_eq!(m.data_bytes, Some(bytes));
    }

    fn shard1_block(parent: &ParentInfo, epoch_ref: u64) -> HypersnapBlock {
        let mut block = HypersnapBlock {
            header: Some(HypersnapBlockHeader {
                shard_id: 1,
                height: parent.height + 1,
                timestamp: parent.timestamp + 12,
                parent_hash: parent.hash.to_vec(),
                epoch: 1,
                state_root: vec![7u8; 32],
                version: BLOCK_VERSION,
                epoch_ref_height: epoch_ref,
                ..Default::default()
            }),
            transactions: vec![proto::Transaction {
                fid: 5,
                user_messages: vec![
                    crate::utils::factory::messages_factory::casts::create_cast_add(
                        5, "x", None, None,
                    ),
                ],
                ..Default::default()
            }],
            ..Default::default()
        };
        seal(&mut block);
        block
    }

    fn ctx(shard: u32) -> HeaderContext {
        HeaderContext {
            shard_id: shard,
            epochs: EpochParams::new(1_000),
            version: BLOCK_VERSION,
            highest_certified_shard0: 1_020,
            max_timestamp: u64::MAX,
        }
    }

    #[test]
    fn sealed_block_passes_and_tampering_fails() {
        let parent = ParentInfo {
            height: 500,
            hash: [1u8; 32],
            timestamp: 100,
            epoch_ref_height: Some(1_010),
            shard_links: vec![],
        };
        let block = shard1_block(&parent, 1_015);
        validate_body(&block).unwrap();
        validate_header(block.header.as_ref().unwrap(), &parent, &ctx(1)).unwrap();

        let mut tampered = block.clone();
        tampered.transactions.clear();
        assert_eq!(validate_body(&tampered), Err(BlockError::BadMessagesRoot));
        let mut tampered = block.clone();
        tampered.header.as_mut().unwrap().state_root = vec![8u8; 32];
        assert_eq!(validate_body(&tampered), Err(BlockError::BadHash));

        // The reference must not go back, and its epoch comes from the parent.
        let back = shard1_block(&parent, 1_005);
        assert!(validate_header(back.header.as_ref().unwrap(), &parent, &ctx(1)).is_err());
        // A shard pivot block cannot reference the snapchain fork block.
        let pivot_parent = ParentInfo {
            epoch_ref_height: None,
            ..parent.clone()
        };
        let early = shard1_block(&pivot_parent, 999);
        assert!(validate_header(early.header.as_ref().unwrap(), &pivot_parent, &ctx(1)).is_err());
        let first = shard1_block(&pivot_parent, 1_000);
        validate_header(first.header.as_ref().unwrap(), &pivot_parent, &ctx(1)).unwrap();
        let mut wrong_epoch = block.header.clone().unwrap();
        wrong_epoch.epoch = 2;
        assert!(validate_header(&wrong_epoch, &parent, &ctx(1)).is_err());
    }

    #[test]
    fn shard0_links_are_checked() {
        let link = |shard: u32, height: u64| proto::ShardLink {
            shard_id: shard,
            height,
            block_hash: vec![height as u8; 32],
            state_root: vec![0u8; 32],
        };
        let parent = ParentInfo {
            height: 1_001,
            hash: [2u8; 32],
            timestamp: 10,
            epoch_ref_height: None,
            shard_links: vec![link(1, 50), link(2, 60)],
        };
        let mut header = HypersnapBlockHeader {
            shard_id: 0,
            height: 1_002,
            timestamp: 22,
            parent_hash: vec![2u8; 32],
            epoch: 1,
            state_root: vec![0u8; 32],
            version: BLOCK_VERSION,
            shard_links: vec![link(1, 51), link(2, 60)],
            ..Default::default()
        };
        validate_header(&header, &parent, &ctx(0)).unwrap();
        header.shard_links[0].height = 49;
        assert!(validate_header(&header, &parent, &ctx(0)).is_err());
        header.shard_links = vec![link(2, 61), link(1, 51)];
        assert!(validate_header(&header, &parent, &ctx(0)).is_err());
    }

    #[test]
    fn messages_root_separates_system_and_user_leaves() {
        let cast =
            crate::utils::factory::messages_factory::casts::create_cast_add(5, "x", None, None);
        assert_ne!(
            messages_root(&[], &[cast.clone()]),
            merkle::root(&[cast.encode_to_vec()])
        );
        assert_eq!(messages_root(&[], &[]), merkle::EMPTY_ROOT);
    }
}
