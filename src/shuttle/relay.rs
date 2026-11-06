use super::{
    config::{Config, Side},
    publisher::{self, Publisher},
    state::{Cursor, State},
    Error,
};
use crate::proto::{
    self, hub_service_client::HubServiceClient, message_data::Body, Message, MessageData,
    Transaction,
};
use prost::Message as ProstMessage;
use std::{sync::Arc, time::Duration};
use tokio::{
    task::JoinSet,
    time::{sleep, timeout},
};
use tonic::transport::{Channel, Endpoint};
use tracing::{info, warn};

#[derive(Debug)]
struct CommittedBlock {
    shard: u32,
    height: u64,
    hash: Vec<u8>,
    parent: Vec<u8>,
    transactions: Vec<Transaction>,
}

pub async fn run(config: Config) -> Result<(), Error> {
    config.validate()?;
    let state = Arc::new(State::open(&config.state_dir, config.network)?);
    let (hyper, hyper_task) = publisher::create(
        Side::Hypersnap,
        &config.hypersnap,
        state.identity(Side::Hypersnap)?,
    )?;
    let (snap, snap_task) = publisher::create(
        Side::Snapchain,
        &config.snapchain,
        state.identity(Side::Snapchain)?,
    )?;
    let config = Arc::new(config);
    let mut tasks = JoinSet::new();
    tasks.spawn(hyper_task);
    tasks.spawn(snap_task);
    tasks.spawn(direction(
        config.clone(),
        state.clone(),
        Side::Hypersnap,
        snap,
    ));
    tasks.spawn(direction(config, state, Side::Snapchain, hyper));
    let result = tokio::select! {
        signal = tokio::signal::ctrl_c() => { signal?; info!("Shuttle shutting down; incomplete blocks resume on restart"); Ok(()) },
        result = tasks.join_next() => match result {
            Some(Ok(Err(error))) => Err(error),
            Some(Err(error)) => Err(error.into()),
            _ => Err("shuttle task stopped unexpectedly".into()),
        }
    };
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    result
}
async fn connect(url: &str, seconds: u64) -> Result<HubServiceClient<Channel>, Error> {
    let endpoint = Endpoint::new(url.to_owned())?
        .connect_timeout(Duration::from_secs(seconds))
        .timeout(Duration::from_secs(seconds));
    Ok(
        HubServiceClient::new(endpoint.connect().await?)
            .max_decoding_message_size(64 * 1024 * 1024),
    )
}
async fn direction(
    config: Arc<Config>,
    state: Arc<State>,
    side: Side,
    publisher: Publisher,
) -> Result<(), Error> {
    let mut schedule = config.topic_schedule()?;
    loop {
        let result = async {
            let mut source = connect(&config.side(side).rpc, config.rpc_timeout_secs).await?;
            let mut destination =
                connect(&config.side(side.other()).rpc, config.rpc_timeout_secs).await?;
            loop {
                let info = source
                    .get_info(proto::GetInfoRequest {})
                    .await?
                    .into_inner();
                if side.other() == Side::Hypersnap {
                    let heads = destination
                        .get_info(proto::GetInfoRequest {})
                        .await?
                        .into_inner();
                    for shard_id in 0..=config.num_shards {
                        let shard = heads
                            .shard_infos
                            .iter()
                            .find(|s| s.shard_id == shard_id)
                            .ok_or(
                                "Hypersnap destination did not report every topic-routing shard",
                            )?;
                        schedule.observe_next(proto::Height {
                            shard_index: shard.shard_id,
                            block_number: shard.max_height.saturating_add(1),
                        });
                    }
                }
                for &shard in &config.shards {
                    let tip = info
                        .shard_infos
                        .iter()
                        .find(|s| s.shard_id == shard)
                        .ok_or("source did not report configured shard")?
                        .max_height;
                    let cursor = match state.cursor(side, shard)? {
                        Some(cursor) => cursor,
                        None => {
                            let next = config
                                .side(side)
                                .start_blocks
                                .get(&shard.to_string())
                                .copied()
                                .unwrap_or(tip.checked_add(1).ok_or("source height overflow")?);
                            let cursor = Cursor { next, hash: vec![] };
                            state.save(side, shard, &cursor)?;
                            info!(
                                network = side.name(),
                                shard,
                                next_block = next,
                                "Shuttle initialized cursor"
                            );
                            cursor
                        }
                    };
                    if cursor.next > tip {
                        continue;
                    }
                    let end = cursor
                        .next
                        .checked_add(config.batch_blocks)
                        .ok_or("block range overflow")?
                        .min(tip.checked_add(1).ok_or("tip overflow")?);
                    let blocks = timeout(
                        Duration::from_secs(config.rpc_timeout_secs),
                        fetch(&mut source, shard, cursor.next, end),
                    )
                    .await??;
                    let mut cursor = cursor;
                    for block in blocks {
                        validate_block(&cursor, &block, shard)?;
                        let mut target = NetworkDestination {
                            publisher: &publisher,
                            client: &mut destination,
                            side: side.other(),
                            schedule: &schedule,
                            publish_timeout: Duration::from_secs(config.rpc_timeout_secs),
                        };
                        relay_block(&config, &state, side, &mut target, &block).await?;
                        cursor = Cursor {
                            next: block.height.checked_add(1).ok_or("block height overflow")?,
                            hash: block.hash,
                        };
                        state.save(side, shard, &cursor)?;
                        info!(
                            network = side.name(),
                            shard,
                            next_block = cursor.next,
                            tip,
                            "Shuttle block relayed"
                        );
                    }
                    if cursor.next != end {
                        return Err::<(), Error>(
                            "source returned missing or pruned blocks; cursor was not skipped"
                                .into(),
                        );
                    }
                }
                sleep(Duration::from_millis(config.poll_ms)).await;
            }
        }
        .await;
        warn!(network=side.name(),error=%result.unwrap_err(),"Shuttle direction retrying from durable cursor");
        sleep(Duration::from_secs(2)).await;
    }
}
async fn fetch(
    client: &mut HubServiceClient<Channel>,
    shard: u32,
    start: u64,
    end: u64,
) -> Result<Vec<CommittedBlock>, Error> {
    let mut result = vec![];
    if shard == 0 {
        let mut blocks = client
            .get_blocks(proto::BlocksRequest {
                start_block_number: start,
                stop_block_number: Some(end),
            })
            .await?
            .into_inner();
        while let Some(block) = blocks.message().await? {
            let header = block.header.ok_or("block missing header")?;
            let height = header.height.ok_or("block missing height")?;
            result.push(CommittedBlock {
                shard: height.shard_index,
                height: height.block_number,
                hash: block.hash,
                parent: header.parent_hash,
                transactions: block.transactions,
            });
        }
    } else {
        let chunks = client
            .get_shard_chunks(proto::ShardChunksRequest {
                shard_id: shard,
                start_block_number: start,
                stop_block_number: Some(end),
            })
            .await?
            .into_inner();
        for block in chunks.shard_chunks {
            let header = block.header.ok_or("chunk missing header")?;
            let height = header.height.ok_or("chunk missing height")?;
            result.push(CommittedBlock {
                shard: height.shard_index,
                height: height.block_number,
                hash: block.hash,
                parent: header.parent_hash,
                transactions: block.transactions,
            });
        }
    }
    Ok(result)
}
fn validate_block(cursor: &Cursor, block: &CommittedBlock, shard: u32) -> Result<(), Error> {
    if block.shard != shard || block.height != cursor.next || block.hash.is_empty() {
        return Err("non-contiguous or malformed source block".into());
    }
    if !cursor.hash.is_empty() && cursor.hash != block.parent {
        return Err(
            "source block parent changed; refusing to cross a fork or reset the cursor".into(),
        );
    }
    Ok(())
}
#[async_trait::async_trait]
trait Destination: Send {
    async fn validate(&mut self, message: Message) -> Result<bool, Error>;
    async fn publish(&mut self, bytes: Vec<u8>) -> Result<(), Error>;
}
struct NetworkDestination<'a> {
    publisher: &'a Publisher,
    client: &'a mut HubServiceClient<Channel>,
    side: Side,
    schedule: &'a crate::network::topic_schedule::Schedule,
    publish_timeout: Duration,
}
#[async_trait::async_trait]
impl Destination for NetworkDestination<'_> {
    async fn validate(&mut self, message: Message) -> Result<bool, Error> {
        Ok(self
            .client
            .validate_message(message)
            .await?
            .into_inner()
            .valid)
    }
    async fn publish(&mut self, bytes: Vec<u8>) -> Result<(), Error> {
        let topic = if self.side == Side::Hypersnap {
            self.schedule
                .publications(snapchain_proto::topics::MEMPOOL, &bytes)
                .into_iter()
                .next()
                .ok_or("message cannot be routed to Hypersnap")?
        } else {
            snapchain_proto::topics::SNAPCHAIN_MEMPOOL
        };
        timeout(self.publish_timeout, self.publisher.publish(bytes, topic))
            .await
            .map_err(|_| {
                "mempool publish timed out waiting for subscribers; refreshing destination heights"
            })?
    }
}
async fn relay_block(
    config: &Config,
    state: &State,
    side: Side,
    destination: &mut impl Destination,
    block: &CommittedBlock,
) -> Result<(), Error> {
    for transaction in &block.transactions {
        // On-chain events, Fname transfers, consensus and Hyper envelopes are not user mempool messages.
        for raw in &transaction.user_messages {
            let Some(message) = compatible(raw, config, side) else {
                continue;
            };
            state.mark(side, &message.hash)?;
            if state.seen(side.other(), &message.hash)? {
                continue;
            }
            if !destination.validate(message.clone()).await? {
                info!(source=side.name(),destination=side.other().name(),hash=%hex::encode(&message.hash),"Shuttle skipped destination-incompatible message");
                continue;
            }
            // Wait until the destination publisher has subscribers and publishes.
            // A failure leaves this block's durable cursor unchanged.
            destination.publish(envelope(message.clone())).await?;
            state.mark(side.other(), &message.hash)?;
        }
    }
    Ok(())
}
fn envelope(message: Message) -> Vec<u8> {
    proto::GossipMessage {
        gossip_message: Some(proto::gossip_message::GossipMessage::MempoolMessage(
            proto::MempoolMessage {
                mempool_message: Some(proto::mempool_message::MempoolMessage::UserMessage(message)),
            },
        )),
    }
    .encode_to_vec()
}
fn compatible(raw: &Message, config: &Config, side: Side) -> Option<Message> {
    let mut message = raw.clone();
    // Preserve signed bytes verbatim. `data` is populated only so destination
    // RPC routing can read the FID when a block carried data_bytes alone.
    let data = match message.data_bytes.as_ref() {
        Some(bytes) => MessageData::decode(bytes.as_slice()).ok()?,
        None => message.data.clone()?,
    };
    if data.network != config.network
        || data.fid == 0
        || !config.side(side).message_types.contains(&data.r#type)
        || !config
            .side(side.other())
            .message_types
            .contains(&data.r#type)
    {
        return None;
    }
    let valid_body = matches!(
        (data.r#type, data.body.as_ref()),
        (1, Some(Body::CastAddBody(_)))
            | (2, Some(Body::CastRemoveBody(_)))
            | (3 | 4, Some(Body::ReactionBody(_)))
            | (5 | 6, Some(Body::LinkBody(_)))
            | (7, Some(Body::VerificationAddAddressBody(_)))
            | (8, Some(Body::VerificationRemoveBody(_)))
            | (11, Some(Body::UserDataBody(_)))
            | (12, Some(Body::UsernameProofBody(_)))
            | (13, Some(Body::FrameActionBody(_)))
            | (14, Some(Body::LinkCompactStateBody(_)))
            | (15, Some(Body::LendStorageBody(_)))
            | (16, Some(Body::KeyAddBody(_)))
            | (17, Some(Body::KeyRemoveBody(_)))
            | (18, Some(Body::ChannelUpdateBody(_)))
            | (19, Some(Body::ChannelMemberBody(_)))
            | (20, Some(Body::ChannelPinBody(_)))
            | (21, Some(Body::ChannelModerateBody(_)))
    );
    if !valid_body {
        return None;
    }
    let bytes = message
        .data_bytes
        .clone()
        .unwrap_or_else(|| data.encode_to_vec());
    if message.hash_scheme != proto::HashScheme::Blake3 as i32
        || message.hash != blake3::hash(&bytes).as_bytes()[..20]
    {
        return None;
    }
    message.data = Some(data);
    Some(message)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn config() -> Config {
        toml::from_str(include_str!("../../shuttle.example.toml")).unwrap()
    }
    fn message() -> Message {
        let data = MessageData {
            fid: 42,
            network: 1,
            r#type: 1,
            body: Some(Body::CastAddBody(proto::CastAddBody {
                text: "relay me".into(),
                ..Default::default()
            })),
            ..Default::default()
        };
        let mut bytes = data.encode_to_vec();
        // Unknown future protobuf field must survive the relay byte-for-byte.
        bytes.extend_from_slice(&[0xa0, 0x06, 0x01]);
        Message {
            data: None,
            data_bytes: Some(bytes.clone()),
            hash: blake3::hash(&bytes).as_bytes()[..20].to_vec(),
            hash_scheme: proto::HashScheme::Blake3 as i32,
            signature: vec![7; 64],
            signer: vec![8; 32],
            ..Default::default()
        }
    }
    fn block(message: Message) -> CommittedBlock {
        CommittedBlock {
            shard: 1,
            height: 10,
            hash: vec![10],
            parent: vec![9],
            transactions: vec![Transaction {
                user_messages: vec![message],
                ..Default::default()
            }],
        }
    }
    #[test]
    fn compatibility_preserves_signed_bytes_and_filters_unsupported_messages() {
        let mut config = config();
        config.validate().unwrap();
        let original = message();
        let forwarded = compatible(&original, &config, Side::Hypersnap).unwrap();
        assert_eq!(forwarded.data_bytes, original.data_bytes);
        assert_eq!(forwarded.signature, original.signature);
        assert_eq!(forwarded.signer, original.signer);
        assert_eq!(forwarded.hash, original.hash);
        assert_eq!(forwarded.data.as_ref().unwrap().fid, 42);
        let decoded = proto::GossipMessage::decode(envelope(forwarded).as_slice()).unwrap();
        assert!(matches!(
            decoded.gossip_message,
            Some(proto::gossip_message::GossipMessage::MempoolMessage(_))
        ));
        let mut corrupted = original.clone();
        corrupted.hash[0] ^= 1;
        assert!(compatible(&corrupted, &config, Side::Hypersnap).is_none());
        config.network = 2;
        assert!(compatible(&original, &config, Side::Hypersnap).is_none());
        config.network = 1;
        config.snapchain.message_types.clear();
        assert!(compatible(&original, &config, Side::Hypersnap).is_none());
    }
    #[test]
    fn gaps_forks_and_wrong_shards_never_advance_cursor() {
        let cursor = Cursor {
            next: 10,
            hash: vec![9],
        };
        let mut block = block(message());
        validate_block(&cursor, &block, 1).unwrap();
        assert!(validate_block(&cursor, &block, 2).is_err());
        block.height += 1;
        assert!(validate_block(&cursor, &block, 1).is_err());
        block.height = 10;
        block.parent = vec![8];
        assert!(validate_block(&cursor, &block, 1).is_err());
    }
    #[derive(Default)]
    struct MockDestination {
        fail: bool,
        invalid: bool,
        sent: Vec<Vec<u8>>,
    }
    #[async_trait::async_trait]
    impl Destination for MockDestination {
        async fn validate(&mut self, _: Message) -> Result<bool, Error> {
            Ok(!self.invalid)
        }
        async fn publish(&mut self, bytes: Vec<u8>) -> Result<(), Error> {
            if self.fail {
                return Err("disconnected".into());
            }
            self.sent.push(bytes);
            Ok(())
        }
    }
    #[tokio::test]
    async fn retry_receipts_and_bidirectional_loop_suppression() {
        let dir = tempfile::tempdir().unwrap();
        let state = State::open(dir.path(), 1).unwrap();
        let block = block(message());
        let hash = &block.transactions[0].user_messages[0].hash;
        let config = config();
        let mut target = MockDestination {
            fail: true,
            ..Default::default()
        };
        assert!(
            relay_block(&config, &state, Side::Hypersnap, &mut target, &block)
                .await
                .is_err()
        );
        assert!(!state.seen(Side::Snapchain, hash).unwrap());
        target.fail = false;
        relay_block(&config, &state, Side::Hypersnap, &mut target, &block)
            .await
            .unwrap();
        assert!(state.seen(Side::Snapchain, hash).unwrap());
        assert_eq!(target.sent.len(), 1);
        // Retry before the block checkpoint, then observe the message committed on the opposite chain.
        relay_block(&config, &state, Side::Hypersnap, &mut target, &block)
            .await
            .unwrap();
        relay_block(&config, &state, Side::Snapchain, &mut target, &block)
            .await
            .unwrap();
        assert_eq!(target.sent.len(), 1);
    }
    #[tokio::test]
    async fn destination_validation_failure_is_skipped_without_publish() {
        let dir = tempfile::tempdir().unwrap();
        let state = State::open(dir.path(), 1).unwrap();
        let mut target = MockDestination {
            invalid: true,
            ..Default::default()
        };
        relay_block(
            &config(),
            &state,
            Side::Snapchain,
            &mut target,
            &block(message()),
        )
        .await
        .unwrap();
        assert!(target.sent.is_empty());
    }
}
