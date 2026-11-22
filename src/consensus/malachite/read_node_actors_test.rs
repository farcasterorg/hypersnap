#[cfg(test)]
mod tests {

    use std::collections::{HashMap, HashSet};
    use std::time::{Duration, Instant};

    use crate::consensus::consensus::{Config, SystemMessage, ValidatorSetConfig};
    use crate::consensus::malachite::network_connector::MalachiteNetworkEvent;
    use crate::consensus::malachite::read_sync::SYNC_WINDOW;
    use crate::consensus::malachite::snapchain_codec::SnapchainCodec;
    use crate::consensus::malachite::spawn_read_node::MalachiteReadNodeActors;
    use crate::consensus::read_validator::Engine;
    use crate::core::types::{Address, CommitsExt, SnapchainValidatorContext};
    use crate::network::gossip::GossipEvent;
    use crate::proto::{self, Height, ShardChunk, StatusMessage};
    use crate::storage::store::engine::ShardEngine;
    use crate::storage::store::test_helper::{
        self, commit_event, default_storage_event, new_engine_with_options, sign_chunk,
        EngineOptions, FID_FOR_TEST,
    };
    use bytes::Bytes;
    use informalsystems_malachitebft_codec::Codec;
    use informalsystems_malachitebft_metrics::SharedRegistry;
    use informalsystems_malachitebft_network::{Channel, PeerIdExt};
    use informalsystems_malachitebft_sync::{self as sync, PeerId, RawDecidedValue};
    use libp2p::identity::ed25519::Keypair;
    use prost::Message;
    use tokio::sync::mpsc;

    async fn setup(
        num_already_decided_blocks: u64,
    ) -> (
        ShardEngine,
        ShardEngine,
        mpsc::Receiver<GossipEvent<SnapchainValidatorContext>>,
        mpsc::Receiver<SystemMessage>,
        MalachiteReadNodeActors,
        Keypair,
    ) {
        let proposer_keypair = Keypair::generate();
        let (mut proposer_engine, _) = test_helper::new_engine().await;
        let (mut read_node_engine, _) = test_helper::new_engine().await;
        for _ in 0..num_already_decided_blocks {
            let shard_chunk = commit_shard_chunk(&mut proposer_engine, &proposer_keypair).await;
            read_node_engine.commit_shard_chunk(&shard_chunk).await;
        }
        let read_keypair = Keypair::generate();
        let (gossip_tx, gossip_rx) = mpsc::channel(100);
        let (system_tx, system_rx) = mpsc::channel(100);
        let shard_id = read_node_engine.shard_id();

        let proposer_address = Address(proposer_keypair.public().to_bytes());

        let validator_set_config = ValidatorSetConfig {
            effective_at: 0,
            validator_public_keys: vec![proposer_address.to_hex()],
            shard_ids: vec![read_node_engine.shard_id()],
        };

        let config = Config::default().with(vec![shard_id], vec![validator_set_config]);

        let (read_node_engine_clone, _) = new_engine_with_options(EngineOptions {
            db: Some(read_node_engine.db.clone()),
            ..Default::default()
        })
        .await;
        let read_node_actors = MalachiteReadNodeActors::create_and_start(
            SnapchainValidatorContext::new(read_keypair),
            Engine::ShardEngine(read_node_engine_clone),
            libp2p::PeerId::random(),
            gossip_tx,
            system_tx,
            SharedRegistry::global(),
            shard_id,
            test_helper::statsd_client(),
            config,
        )
        .await
        .unwrap();
        (
            proposer_engine,
            read_node_engine,
            gossip_rx,
            system_rx,
            read_node_actors,
            proposer_keypair,
        )
    }

    async fn assert_height_on_status(
        gossip_rx: &mut mpsc::Receiver<GossipEvent<SnapchainValidatorContext>>,
        expected_height: Height,
    ) {
        wait_for_status().await;
        let gossip_msg = gossip_rx.recv().await.unwrap();
        match gossip_msg {
            GossipEvent::BroadcastStatus(status) => {
                assert_eq!(status.height, expected_height);
            }
            _ => panic!("Unexpected gossip message"),
        }
    }

    async fn process_shard_chunk(actors: &MalachiteReadNodeActors, shard_chunk: &ShardChunk) {
        let decided_value = proto::DecidedValue {
            value: Some(proto::decided_value::Value::Shard(shard_chunk.clone())),
        };

        actors.cast_decided_value(decided_value).unwrap();
        wait_for_block().await;
    }

    async fn commit_shard_chunk(
        engine: &mut ShardEngine,
        proposer_keypair: &Keypair,
    ) -> ShardChunk {
        let shard_chunk = commit_event(engine, &default_storage_event(FID_FOR_TEST)).await;
        sign_chunk(proposer_keypair, shard_chunk).await
    }

    async fn wait_for_block() {
        tokio::time::sleep(Duration::from_millis(10)).await
    }

    async fn wait_for_status() {
        tokio::time::sleep(Duration::from_secs(6)).await
    }

    #[tokio::test]
    async fn test_process_decided_value() {
        let (
            mut proposer_engine,
            read_node_engine,
            mut gossip_rx,
            _system_rx,
            actors,
            proposed_keypair,
        ) = setup(0).await;

        let shard_chunk = commit_shard_chunk(&mut proposer_engine, &proposed_keypair).await;
        process_shard_chunk(&actors, &shard_chunk).await;
        assert_eq!(
            read_node_engine.get_confirmed_height(),
            shard_chunk.header.as_ref().unwrap().height.unwrap()
        );

        assert_height_on_status(
            &mut gossip_rx,
            shard_chunk.header.as_ref().unwrap().height.unwrap(),
        )
        .await;
    }

    #[tokio::test]
    async fn test_out_of_order_decided_values() {
        let (
            mut proposer_engine,
            read_node_engine,
            _gossip_rx,
            _system_rx,
            actors,
            proposer_keypair,
        ) = setup(0).await;

        let shard_chunk1 = commit_shard_chunk(&mut proposer_engine, &proposer_keypair).await;
        let shard_chunk2 = commit_shard_chunk(&mut proposer_engine, &proposer_keypair).await;
        let shard_chunk3 = commit_shard_chunk(&mut proposer_engine, &proposer_keypair).await;

        process_shard_chunk(&actors, &shard_chunk3).await;
        assert_eq!(
            read_node_engine.get_confirmed_height(),
            Height {
                shard_index: read_node_engine.shard_id(),
                block_number: 0
            }
        );

        process_shard_chunk(&actors, &shard_chunk2).await;
        assert_eq!(
            read_node_engine.get_confirmed_height(),
            Height {
                shard_index: read_node_engine.shard_id(),
                block_number: 0
            }
        );

        process_shard_chunk(&actors, &shard_chunk1).await;
        assert_eq!(
            read_node_engine.get_confirmed_height(),
            shard_chunk3.header.as_ref().unwrap().height.unwrap()
        );
    }

    #[tokio::test]
    async fn test_startup_with_already_decided_blocks() {
        let num_initial_blocks = 3;
        let (
            mut proposer_engine,
            read_node_engine,
            mut gossip_rx,
            _system_rx,
            actors,
            proposer_keypair,
        ) = setup(num_initial_blocks).await;

        let start_height = Height {
            shard_index: read_node_engine.shard_id(),
            block_number: num_initial_blocks,
        };

        assert_eq!(read_node_engine.get_confirmed_height(), start_height);
        assert_height_on_status(&mut gossip_rx, start_height).await;

        let shard_chunk4 = commit_shard_chunk(&mut proposer_engine, &proposer_keypair).await;
        process_shard_chunk(&actors, &shard_chunk4).await;
        assert_eq!(
            read_node_engine.get_confirmed_height(),
            start_height.increment()
        );
    }

    #[tokio::test]
    async fn test_block_with_height_too_low() {
        let (
            mut proposer_engine,
            read_node_engine,
            _gossip_rx,
            _system_rx,
            actors,
            proposer_keypair,
        ) = setup(0).await;

        let shard_chunk1 = commit_shard_chunk(&mut proposer_engine, &proposer_keypair).await;
        process_shard_chunk(&actors, &shard_chunk1).await;
        assert_eq!(
            read_node_engine.get_confirmed_height(),
            shard_chunk1.header.as_ref().unwrap().height.unwrap()
        );

        let shard_chunk2 = commit_shard_chunk(&mut proposer_engine, &proposer_keypair).await;
        process_shard_chunk(&actors, &shard_chunk2).await;
        assert_eq!(
            read_node_engine.get_confirmed_height(),
            shard_chunk2.header.as_ref().unwrap().height.unwrap()
        );

        // This shard chunk is just dropped
        process_shard_chunk(&actors, &shard_chunk1).await;
        assert_eq!(
            read_node_engine.get_confirmed_height(),
            shard_chunk2.header.as_ref().unwrap().height.unwrap()
        );

        let shard_chunk3 = commit_shard_chunk(&mut proposer_engine, &proposer_keypair).await;
        process_shard_chunk(&actors, &shard_chunk3).await;
        assert_eq!(
            read_node_engine.get_confirmed_height(),
            shard_chunk3.header.as_ref().unwrap().height.unwrap()
        );
    }

    /// Plays a peer that has `num_blocks` more blocks than the read node and answers each sync
    /// request after `latency`, the way a peer across the internet does. Returns how long the
    /// read node took to commit them all, the most requests it had out at once and how many it
    /// sent. With `drop_first`, the first request for each height is never answered.
    async fn catch_up(
        num_blocks: u64,
        latency: Duration,
        drop_first: bool,
    ) -> (Duration, usize, usize) {
        let (
            mut proposer_engine,
            read_node_engine,
            mut gossip_rx,
            _system_rx,
            actors,
            proposer_keypair,
        ) = setup(0).await;
        let mut chunks = HashMap::new();
        for _ in 0..num_blocks {
            let chunk = commit_shard_chunk(&mut proposer_engine, &proposer_keypair).await;
            chunks.insert(
                chunk.header.as_ref().unwrap().height.unwrap().block_number,
                chunk,
            );
        }
        let tip = proposer_engine.get_confirmed_height();

        let peer = PeerId::from_libp2p(&libp2p::PeerId::random());
        actors
            .cast_network_event(MalachiteNetworkEvent::PeerConnected(peer))
            .unwrap();
        let start = Instant::now();
        actors
            .cast_network_event(MalachiteNetworkEvent::Message(
                Channel::Sync,
                peer,
                Bytes::from(
                    StatusMessage {
                        peer_id: peer.to_libp2p().to_bytes(),
                        height: Some(tip),
                        min_height: Some(Height::new(tip.shard_index, 1)),
                    }
                    .encode_to_vec(),
                ),
            ))
            .unwrap();

        // Only used to mint request ids, which libp2p doesn't let anything else create.
        let mut rpc = sync::Behaviour::default();
        let (answer_tx, mut answer_rx) = mpsc::channel(1000);
        let (mut in_flight, mut max_in_flight, mut sent) = (0, 0, 0);
        let mut asked = HashSet::new();
        while read_node_engine.get_confirmed_height() < tip {
            assert!(start.elapsed() < Duration::from_secs(120), "sync stalled");
            tokio::select! {
                Some(event) = gossip_rx.recv() => {
                    let GossipEvent::SyncRequest(_, sync::Request::ValueRequest(request), reply) = event else {
                        continue;
                    };
                    let request_id = rpc.send_request(libp2p::PeerId::random(), Bytes::new());
                    reply.send(request_id).unwrap();
                    sent += 1;
                    if asked.insert(request.height.block_number) && drop_first {
                        continue;
                    }
                    in_flight += 1;
                    max_in_flight = max_in_flight.max(in_flight);
                    let answer_tx = answer_tx.clone();
                    tokio::spawn(async move {
                        tokio::time::sleep(latency).await;
                        let _ = answer_tx.send((request_id, request.height)).await;
                    });
                }
                Some((request_id, height)) = answer_rx.recv() => {
                    in_flight -= 1;
                    let chunk = &chunks[&height.block_number];
                    let value = RawDecidedValue {
                        certificate: chunk.commits.clone().unwrap().to_commit_certificate(),
                        value_bytes: Bytes::from(chunk.encode_to_vec()),
                    };
                    let response =
                        sync::Response::ValueResponse(sync::ValueResponse::new(height, Some(value)));
                    actors
                        .cast_network_event(MalachiteNetworkEvent::Sync(sync::RawMessage::Response {
                            request_id,
                            peer,
                            body: SnapchainCodec.encode(&response).unwrap(),
                        }))
                        .unwrap();
                }
                _ = tokio::time::sleep(Duration::from_millis(10)) => {}
            }
        }
        (start.elapsed(), max_in_flight, sent)
    }

    #[tokio::test]
    async fn test_catch_up_keeps_requests_in_flight() {
        // One request per round trip would take at least 100 x 50 ms = 5 s.
        let (elapsed, max_in_flight, _) = catch_up(100, Duration::from_millis(50), false).await;
        assert!(
            (16..=SYNC_WINDOW as usize).contains(&max_in_flight),
            "{max_in_flight} requests in flight"
        );
        assert!(elapsed < Duration::from_secs(4), "caught up in {elapsed:?}");
    }

    #[tokio::test]
    async fn test_catch_up_asks_again_after_a_timeout() {
        // Each height is asked for again once its request times out, and only then.
        let (_, _, sent) = catch_up(40, Duration::from_millis(10), true).await;
        assert_eq!(sent, 2 * 40);
    }

    #[tokio::test]
    async fn test_no_sync_request_to_a_peer_that_pruned_the_height() {
        let (_proposer_engine, read_node_engine, mut gossip_rx, _system_rx, actors, _) =
            setup(0).await;
        let peer = PeerId::from_libp2p(&libp2p::PeerId::random());
        actors
            .cast_network_event(MalachiteNetworkEvent::PeerConnected(peer))
            .unwrap();
        // The peer is at 10 but only keeps blocks from 5, and the read node needs block 1.
        actors
            .cast_network_event(MalachiteNetworkEvent::Message(
                Channel::Sync,
                peer,
                Bytes::from(
                    StatusMessage {
                        peer_id: peer.to_libp2p().to_bytes(),
                        height: Some(Height::new(read_node_engine.shard_id(), 10)),
                        min_height: Some(Height::new(read_node_engine.shard_id(), 5)),
                    }
                    .encode_to_vec(),
                ),
            ))
            .unwrap();

        let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
        while let Ok(Some(event)) = tokio::time::timeout_at(deadline, gossip_rx.recv()).await {
            assert!(
                !matches!(event, GossipEvent::SyncRequest(..)),
                "asked a peer for a block it pruned"
            );
        }
    }

    /// Prints blocks/s over a simulated round trip:
    /// `cargo test --lib catch_up_rate -- --ignored --nocapture`
    #[tokio::test]
    #[ignore]
    async fn catch_up_rate() {
        for latency in [0, 50, 100, 200] {
            let (elapsed, max_in_flight, _) =
                catch_up(300, Duration::from_millis(latency), false).await;
            println!(
                "{latency} ms round trip: {:.1} blocks/s, up to {max_in_flight} requests in flight",
                300.0 / elapsed.as_secs_f64()
            );
        }
    }

    #[tokio::test]
    async fn test_send_sync_request() {
        let (
            _proposer_engine,
            read_node_engine,
            mut gossip_rx,
            _system_rx,
            actors,
            _proposer_keypair,
        ) = setup(0).await;

        let peer = PeerId::from_libp2p(&libp2p::PeerId::random());

        actors
            .cast_network_event(MalachiteNetworkEvent::PeerConnected(peer))
            .unwrap();

        actors
            .cast_network_event(MalachiteNetworkEvent::Message(
                Channel::Sync,
                peer,
                Bytes::from(
                    (StatusMessage {
                        peer_id: peer.to_libp2p().to_bytes(),
                        height: Some(Height {
                            shard_index: read_node_engine.shard_id(),
                            block_number: 10,
                        }),
                        min_height: Some(Height {
                            shard_index: read_node_engine.shard_id(),
                            block_number: 1,
                        }),
                    })
                    .encode_to_vec(),
                ),
            ))
            .unwrap();

        tokio::time::sleep(Duration::from_secs(1)).await;

        // Show that we send a sync request when we're behind a peer
        match gossip_rx.recv().await.unwrap() {
            GossipEvent::SyncRequest(peer_id, request, _sender) => {
                assert_eq!(peer_id, peer);
                match request {
                    informalsystems_malachitebft_sync::Request::ValueRequest(value_request) => {
                        assert_eq!(
                            value_request.height,
                            read_node_engine.get_confirmed_height().increment()
                        );
                    }
                    _ => panic!("Expected value request"),
                }
            }
            _ => {
                panic!("Expected sync request")
            }
        };
    }
}
