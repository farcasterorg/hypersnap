use crate::consensus::consensus::SystemMessage;
use crate::core::types::SnapchainValidatorContext;
use crate::mempool::mempool::{MempoolRequest, MempoolSource};
use crate::network::gossip::{Config, GossipEvent, SnapchainGossip};
use crate::proto::{FarcasterNetwork, Message, MessageData};
use crate::storage::store::mempool_poller::MempoolMessage;
use crate::storage::store::test_helper::statsd_client;
use crate::utils::factory::messages_factory;
use libp2p::identity::ed25519::Keypair;
use prost::Message as _;
use serial_test::serial;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::{select, time};

const HOST_FOR_TEST: &str = "127.0.0.1";
const BASE_PORT_FOR_TEST: u32 = 9382;

/// Re-publishes `message` on `publisher_tx` every 200ms, polling `receiver` for
/// a matching `SystemMessage::Mempool(...)` delivery, and returns `true` as
/// soon as one arrives (or `false` once `deadline` elapses). Breaks the
/// publisher loop early if the gossip event channel closes — without that, a
/// dead gossip task would burn the full deadline before failing.
///
/// Repeat sends are safe: gossipsub message-id dedup ensures the receiver sees
/// each unique payload at most once. This is the right shape for tests where
/// the publisher hasn't yet formed a mesh with subscribed peers — the first
/// few `publish` calls can return `InsufficientPeers` and are only warn-logged
/// and dropped by `SnapchainGossip::publish`.
async fn publish_until_received(
    publisher_tx: mpsc::Sender<GossipEvent<SnapchainValidatorContext>>,
    receiver: &mut mpsc::Receiver<SystemMessage>,
    message: Message,
    deadline: Duration,
) -> bool {
    let expected_hash = message.hash.clone();

    let cast_for_publisher = message;
    let publisher = tokio::spawn(async move {
        loop {
            if publisher_tx
                .send(GossipEvent::BroadcastMempoolMessage(
                    MempoolMessage::UserMessage(cast_for_publisher.clone()),
                ))
                .await
                .is_err()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    });

    let end = tokio::time::Instant::now() + deadline;
    let received = loop {
        if tokio::time::Instant::now() >= end {
            break false;
        }
        match tokio::time::timeout(Duration::from_millis(200), receiver.recv()).await {
            Ok(Some(SystemMessage::Mempool(MempoolRequest::AddMessage(
                MempoolMessage::UserMessage(msg),
                MempoolSource::Gossip,
                _,
            )))) if msg.hash == expected_hash => break true,
            _ => {}
        }
    };

    publisher.abort();
    received
}

async fn wait_for_message(
    system_rx: &mut mpsc::Receiver<SystemMessage>,
    expected_message: Message,
) -> u32 {
    let deadline = time::Instant::now() + Duration::from_secs(2);
    let mut receive_counts = 0;
    loop {
        let timeout = time::sleep_until(deadline);
        select! {
            received = system_rx.recv()  => {
                match received {
                    Some(SystemMessage::Mempool(msg))  => {
                        match msg {
                            MempoolRequest::AddMessage(MempoolMessage::UserMessage(actual_message), source, _) => {
                                receive_counts += 1;
                                assert_eq!(actual_message.hash, expected_message.hash);
                                assert_eq!(actual_message.data.is_some(), true);
                                match &expected_message.data {
                                    Some(msg_data) => {
                                        assert_eq!(msg_data, &actual_message.data.unwrap());
                                    },
                                    None => {
                                        let msg_data = MessageData::decode(actual_message.data_bytes.as_ref().unwrap().as_slice()).unwrap();
                                        assert_eq!(msg_data, actual_message.data.unwrap());
                                    }
                                }
                                assert_eq!(source, MempoolSource::Gossip);
                            },
                            _ => {
                                panic!("Received unexpected message");
                            },
                        }
                    },
                    _ => {},
                }
            }
            _ = timeout => {
                break;
            }
        }
    }

    return receive_counts;
}

#[tokio::test]
#[serial]
async fn test_gossip_communication() {
    // Create two keypairs for our test nodes
    let keypair1 = Keypair::generate();
    let keypair2 = Keypair::generate();
    let keypair3 = Keypair::generate();

    // Create configs with different ports
    let node1_addr = format!("/ip4/{HOST_FOR_TEST}/udp/{BASE_PORT_FOR_TEST}/quic-v1");

    let node2_port = BASE_PORT_FOR_TEST + 1;
    let node2_addr = format!("/ip4/{HOST_FOR_TEST}/udp/{node2_port}/quic-v1");

    let node3_port = BASE_PORT_FOR_TEST + 2;
    let node3_addr = format!("/ip4/{HOST_FOR_TEST}/udp/{node3_port}/quic-v1");

    let config1 = Config::new(node1_addr.clone(), node2_addr.clone())
        .with_contact_info_interval(Duration::from_millis(100));
    let config2 = Config::new(node2_addr.clone(), node1_addr.clone())
        .with_contact_info_interval(Duration::from_millis(100));
    let config3 = Config::new(node3_addr.clone(), node2_addr.clone())
        .with_contact_info_interval(Duration::from_millis(100));

    // Create channels for system messages
    let (system_tx1, _) = mpsc::channel::<SystemMessage>(100);
    let (system_tx2, _) = mpsc::channel::<SystemMessage>(100);
    let (system_tx3, mut system_rx3) = mpsc::channel::<SystemMessage>(100);

    // Create gossip instances
    let mut gossip1 = SnapchainGossip::create(
        keypair1.clone(),
        &config1,
        Some(system_tx1),
        true,
        FarcasterNetwork::Devnet,
        statsd_client(),
        Vec::new(),
    )
    .await
    .unwrap();
    let mut gossip2 = SnapchainGossip::create(
        keypair2.clone(),
        &config2,
        Some(system_tx2),
        false,
        FarcasterNetwork::Devnet,
        statsd_client(),
        Vec::new(),
    )
    .await
    .unwrap();

    let mut gossip3 = SnapchainGossip::create(
        keypair3.clone(),
        &config3,
        Some(system_tx3),
        false,
        FarcasterNetwork::Devnet,
        statsd_client(),
        Vec::new(),
    )
    .await
    .unwrap();

    let gossip_tx1 = gossip1.tx.clone();

    // Spawn gossip tasks
    tokio::spawn(async move {
        gossip1.start().await;
    });
    tokio::spawn(async move {
        gossip2.start().await;
    });
    tokio::spawn(async move {
        gossip3.start().await;
    });

    // Wait for connection to establish
    tokio::time::sleep(Duration::from_secs(1)).await;

    // Create a test message
    let mut cast_add = messages_factory::casts::create_cast_add(123, "test", None, None);
    // Set data to None, so we can test that gossip populates data from data_bytes
    cast_add.data_bytes = Some(cast_add.data.unwrap().encode_to_vec());
    cast_add.data = None;

    let mempool_msg = MempoolMessage::UserMessage(cast_add.clone());
    // Send message from node1 to node2
    gossip_tx1
        .send(GossipEvent::BroadcastMempoolMessage(mempool_msg.clone()))
        .await
        .unwrap();

    // Sending the same message twice will cause the second message to be dropped
    gossip_tx1
        .send(GossipEvent::BroadcastMempoolMessage(mempool_msg))
        .await
        .unwrap();

    // Wait for message to be received with timeout. Node 1 is not connected directly to node 3 via bootstrap, but autodiscovery should cause it to find node 3.
    let receive_counts = wait_for_message(&mut system_rx3, cast_add).await;
    assert_eq!(receive_counts, 1);
}

/// A Hypersnap node (namespaced topics and gossipsub protocol) and a snapchain
/// node do not share messages, even when connected (FIP §4.7).
#[tokio::test]
#[serial]
async fn test_hypersnap_namespace_is_isolated() {
    let base = BASE_PORT_FOR_TEST + 40;
    let addr = |i: u32| format!("/ip4/{HOST_FOR_TEST}/udp/{}/quic-v1", base + i);
    let ns = Config::hypersnap_namespace(FarcasterNetwork::Devnet);
    let configs = [
        Config::new(addr(0), format!("{},{}", addr(1), addr(2))).with_namespace(ns.clone()),
        Config::new(addr(1), addr(0)).with_namespace(ns.clone()),
        Config::new(addr(2), addr(0)),
    ];
    let mut receivers = Vec::new();
    let mut senders = Vec::new();
    for config in &configs {
        let (system_tx, system_rx) = mpsc::channel::<SystemMessage>(100);
        let mut gossip = SnapchainGossip::create(
            Keypair::generate(),
            config,
            Some(system_tx),
            false,
            FarcasterNetwork::Devnet,
            statsd_client(),
            Vec::new(),
        )
        .await
        .unwrap();
        senders.push(gossip.tx.clone());
        receivers.push(system_rx);
        tokio::spawn(async move { gossip.start().await });
    }
    tokio::time::sleep(Duration::from_secs(2)).await;

    let cast = messages_factory::casts::create_cast_add(123, "namespaced", None, None);
    senders[0]
        .send(GossipEvent::BroadcastMempoolMessage(
            MempoolMessage::UserMessage(cast.clone()),
        ))
        .await
        .unwrap();
    let mut snapchain_rx = receivers.pop().unwrap();
    let mut hypersnap_rx = receivers.pop().unwrap();
    assert_eq!(wait_for_message(&mut hypersnap_rx, cast.clone()).await, 1);
    assert_eq!(wait_for_message(&mut snapchain_rx, cast).await, 0);
}

/// A Hypersnap node gossips its mempool messages in batches (by size and each
/// `MEMPOOL_BATCH_INTERVAL`): the peer gets each message once.
#[tokio::test]
#[serial]
async fn a_hypersnap_node_gossips_its_mempool_messages_in_batches() {
    let base = BASE_PORT_FOR_TEST + 44;
    let addr = |i: u32| format!("/ip4/{HOST_FOR_TEST}/udp/{}/quic-v1", base + i);
    let ns = Config::hypersnap_namespace(FarcasterNetwork::Devnet);
    let configs = [
        Config::new(addr(0), addr(1)).with_namespace(ns.clone()),
        Config::new(addr(1), addr(0)).with_namespace(ns.clone()),
    ];
    let mut receivers = Vec::new();
    let mut senders = Vec::new();
    for config in &configs {
        let (system_tx, system_rx) = mpsc::channel::<SystemMessage>(10_000);
        let mut gossip = SnapchainGossip::create(
            Keypair::generate(),
            config,
            Some(system_tx),
            false,
            FarcasterNetwork::Devnet,
            statsd_client(),
            Vec::new(),
        )
        .await
        .unwrap();
        senders.push(gossip.tx.clone());
        receivers.push(system_rx);
        tokio::spawn(async move { gossip.start().await });
    }
    tokio::time::sleep(Duration::from_secs(2)).await;

    // 500 casts of about 1 KB: one batch by size, then the rest by time.
    let mut sent = std::collections::BTreeSet::new();
    for i in 0..500 {
        let cast = messages_factory::casts::create_cast_add(
            123,
            &format!("{} {}", i, "x".repeat(300)),
            None,
            None,
        );
        sent.insert(cast.hash.clone());
        senders[0]
            .send(GossipEvent::BroadcastMempoolMessage(
                MempoolMessage::UserMessage(cast),
            ))
            .await
            .unwrap();
    }
    let rx = &mut receivers[1];
    let mut received = std::collections::BTreeSet::new();
    let deadline = time::Instant::now() + Duration::from_secs(10);
    while received.len() < sent.len() {
        select! {
            m = rx.recv() => {
                if let Some(SystemMessage::Mempool(MempoolRequest::AddMessage(
                    MempoolMessage::UserMessage(m),
                    MempoolSource::Gossip,
                    _,
                ))) = m
                {
                    assert!(received.insert(m.hash), "a message came twice");
                }
            }
            _ = time::sleep_until(deadline) => break,
        }
    }
    assert_eq!(received, sent);
}

/// The mesh-diagnostics responder serves only validator peers: a request from a
/// configured validator is answered, one from a non-validator is refused.
#[tokio::test]
#[serial]
async fn test_diagnostics_only_serves_validators() {
    let keypair1 = Keypair::generate();
    let keypair2 = Keypair::generate();
    let keypair3 = Keypair::generate();

    let peer_id = |kp: &Keypair| libp2p::identity::PublicKey::from(kp.public()).to_peer_id();
    let pid1 = peer_id(&keypair1); // responder
    let pid2 = peer_id(&keypair2); // validator requester

    let base = BASE_PORT_FOR_TEST + 20;
    let node1_addr = format!("/ip4/{HOST_FOR_TEST}/udp/{base}/quic-v1");
    let node2_addr = format!("/ip4/{HOST_FOR_TEST}/udp/{}/quic-v1", base + 1);
    let node3_addr = format!("/ip4/{HOST_FOR_TEST}/udp/{}/quic-v1", base + 2);

    // node2 and node3 both bootstrap to node1 so both connect to the responder.
    let config1 = Config::new(node1_addr.clone(), node2_addr.clone());
    let config2 = Config::new(node2_addr.clone(), node1_addr.clone());
    let config3 = Config::new(node3_addr.clone(), node1_addr.clone());

    let (system_tx1, _) = mpsc::channel::<SystemMessage>(100);
    let (system_tx2, _) = mpsc::channel::<SystemMessage>(100);
    let (system_tx3, _) = mpsc::channel::<SystemMessage>(100);

    let mut gossip1 = SnapchainGossip::create(
        keypair1.clone(),
        &config1,
        Some(system_tx1),
        false,
        FarcasterNetwork::Devnet,
        statsd_client(),
        Vec::new(),
    )
    .await
    .unwrap();
    let mut gossip2 = SnapchainGossip::create(
        keypair2.clone(),
        &config2,
        Some(system_tx2),
        false,
        FarcasterNetwork::Devnet,
        statsd_client(),
        Vec::new(),
    )
    .await
    .unwrap();
    let mut gossip3 = SnapchainGossip::create(
        keypair3.clone(),
        &config3,
        Some(system_tx3),
        false,
        FarcasterNetwork::Devnet,
        statsd_client(),
        Vec::new(),
    )
    .await
    .unwrap();

    // node1 serves diagnostics only to node2 (a "validator"), not node3.
    gossip1.set_validator_peers(std::collections::HashSet::from([pid2]));

    let gossip_tx2 = gossip2.tx.clone();
    let gossip_tx3 = gossip3.tx.clone();

    tokio::spawn(async move {
        gossip1.start().await;
    });
    tokio::spawn(async move {
        gossip2.start().await;
    });
    tokio::spawn(async move {
        gossip3.start().await;
    });

    // Let connections establish.
    tokio::time::sleep(Duration::from_secs(2)).await;

    // node2 is a validator → request is served.
    let (tx, rx) = tokio::sync::oneshot::channel();
    gossip_tx2
        .send(GossipEvent::SendMeshViewRequest(
            pid1,
            crate::proto::GetMeshViewRequest::default(),
            tx,
        ))
        .await
        .unwrap();
    let allowed = time::timeout(Duration::from_secs(4), rx)
        .await
        .expect("validator request timed out")
        .expect("oneshot dropped");
    assert!(
        allowed.is_ok(),
        "validator peer should be served, got {allowed:?}"
    );

    // node3 is not a validator → request is refused (OutboundFailure → Err).
    let (tx, rx) = tokio::sync::oneshot::channel();
    gossip_tx3
        .send(GossipEvent::SendMeshViewRequest(
            pid1,
            crate::proto::GetMeshViewRequest::default(),
            tx,
        ))
        .await
        .unwrap();
    let refused = time::timeout(Duration::from_secs(8), rx)
        .await
        .expect("non-validator request timed out")
        .expect("oneshot dropped");
    assert!(
        refused.is_err(),
        "non-validator peer should be refused, got {refused:?}"
    );
}

/// Mimic the RPC layer's validator classification so the renderer's
/// validator-only graph/counters exercise these peers.
fn classify_as_validators(mut view: crate::proto::MeshView) -> crate::proto::MeshView {
    if let Some(l) = view.local.as_mut() {
        l.is_validator = true;
    }
    for p in view.peers.iter_mut() {
        p.node_type = crate::proto::MeshNodeType::Validator as i32;
    }
    view
}

#[tokio::test]
#[serial]
async fn mesh_view_tags_direct_peers_as_direct_links() {
    // Two validators configured as each other's libp2p direct/explicit peers (the
    // mainnet/testnet topology). Gossipsub forwards published messages to explicit
    // peers but keeps them OUT of `mesh_peers()`, so the peer must report
    // `direct_peer=true` + consensus `in_mesh=false` and render as a `◆` direct
    // link — never a `○` sub-only or a partition. This is the testnet repro.
    let keypair1 = Keypair::generate();
    let keypair2 = Keypair::generate();
    let peer_id = |kp: &Keypair| libp2p::identity::PublicKey::from(kp.public()).to_peer_id();
    let pid2 = peer_id(&keypair2);

    let base = BASE_PORT_FOR_TEST + 30;
    let node1_addr = format!("/ip4/{HOST_FOR_TEST}/udp/{base}/quic-v1");
    let node2_addr = format!("/ip4/{HOST_FOR_TEST}/udp/{}/quic-v1", base + 1);

    // Each node lists the OTHER's PeerId as a direct peer — exactly what
    // setup_local_testnet now generates by default.
    let config1 = Config::new(node1_addr.clone(), node2_addr.clone())
        .with_direct_peers(peer_id(&keypair2).to_base58());
    let config2 = Config::new(node2_addr.clone(), node1_addr.clone())
        .with_direct_peers(peer_id(&keypair1).to_base58());

    let (system_tx1, _) = mpsc::channel::<SystemMessage>(100);
    let (system_tx2, _) = mpsc::channel::<SystemMessage>(100);

    let mut gossip1 = SnapchainGossip::create(
        keypair1.clone(),
        &config1,
        Some(system_tx1),
        false,
        FarcasterNetwork::Devnet,
        statsd_client(),
        Vec::new(),
    )
    .await
    .unwrap();
    let mut gossip2 = SnapchainGossip::create(
        keypair2.clone(),
        &config2,
        Some(system_tx2),
        false,
        FarcasterNetwork::Devnet,
        statsd_client(),
        Vec::new(),
    )
    .await
    .unwrap();

    let gossip_tx1 = gossip1.tx.clone();
    tokio::spawn(async move {
        gossip1.start().await;
    });
    tokio::spawn(async move {
        gossip2.start().await;
    });

    // Poll until node1 sees node2 as a connected direct peer with at least one
    // visible subscription. (Explicit peers can race their per-topic resub under
    // CPU contention from other tests' leaked gossip loops, so we don't pin to a
    // specific topic here — the consensus-specific `◆`/no-partition rendering is
    // covered deterministically by the render.rs unit tests.)
    let deadline = time::Instant::now() + Duration::from_secs(15);
    let mut found = None;
    while time::Instant::now() < deadline {
        let (tx, rx) = tokio::sync::oneshot::channel();
        gossip_tx1.send(GossipEvent::GetMeshView(tx)).await.unwrap();
        let view: crate::proto::MeshView = time::timeout(Duration::from_secs(2), rx)
            .await
            .expect("mesh view timed out")
            .expect("oneshot dropped");
        if let Some(p) = view.peers.iter().find(|p| p.peer_id == pid2.to_bytes()) {
            if p.direct_peer && p.topics.iter().any(|t| t.subscribed) {
                found = Some((view.clone(), p.clone()));
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(400)).await;
    }
    let (view, peer) = found.expect("node1 never saw node2 as a subscribed direct peer");

    // The gossip-layer invariant behind the testnet bug: an explicit/direct peer
    // is tagged `direct_peer` and is excluded from the gossipsub mesh on EVERY
    // topic it is subscribed to (so it would render `◆`, never `●`).
    assert!(peer.direct_peer, "node2 should be a direct peer");
    assert!(
        peer.topics.iter().any(|t| t.subscribed),
        "node2 should be subscribed to at least one topic"
    );
    assert!(
        peer.topics.iter().all(|t| !t.in_mesh),
        "explicit/direct peers must never appear in the gossipsub mesh: {:?}",
        peer.topics
    );

    // End-to-end render: a subscribed direct peer shows up as a `◆` direct link.
    let view = classify_as_validators(view);
    let topics = crate::network::mesh::render::parse_topics(Some("consensus,mempool,contact-info"));
    let rendered = crate::network::mesh::render::render_mesh_view(&view, &topics);
    assert!(
        rendered.contains("◆"),
        "expected a direct-link glyph for the direct peer:\n{rendered}"
    );
}

#[tokio::test]
#[serial]
async fn mesh_view_tags_meshed_peers_as_in_mesh() {
    // Without direct_peers the two validators form an emergent gossipsub mesh: the
    // peer reports consensus `in_mesh=true` (and `direct_peer=false`) and renders
    // `●`. Guards the original (non-explicit-peer) mesh-rendering path.
    let keypair1 = Keypair::generate();
    let keypair2 = Keypair::generate();
    let peer_id = |kp: &Keypair| libp2p::identity::PublicKey::from(kp.public()).to_peer_id();
    let pid2 = peer_id(&keypair2);

    let base = BASE_PORT_FOR_TEST + 32;
    let node1_addr = format!("/ip4/{HOST_FOR_TEST}/udp/{base}/quic-v1");
    let node2_addr = format!("/ip4/{HOST_FOR_TEST}/udp/{}/quic-v1", base + 1);

    let config1 = Config::new(node1_addr.clone(), node2_addr.clone());
    let config2 = Config::new(node2_addr.clone(), node1_addr.clone());

    let (system_tx1, _) = mpsc::channel::<SystemMessage>(100);
    let (system_tx2, _) = mpsc::channel::<SystemMessage>(100);

    let mut gossip1 = SnapchainGossip::create(
        keypair1.clone(),
        &config1,
        Some(system_tx1),
        false,
        FarcasterNetwork::Devnet,
        statsd_client(),
        Vec::new(),
    )
    .await
    .unwrap();
    let mut gossip2 = SnapchainGossip::create(
        keypair2.clone(),
        &config2,
        Some(system_tx2),
        false,
        FarcasterNetwork::Devnet,
        statsd_client(),
        Vec::new(),
    )
    .await
    .unwrap();

    let gossip_tx1 = gossip1.tx.clone();
    tokio::spawn(async move {
        gossip1.start().await;
    });
    tokio::spawn(async move {
        gossip2.start().await;
    });

    // Poll until node2 grafts into node1's consensus mesh (a few heartbeats).
    let deadline = time::Instant::now() + Duration::from_secs(20);
    let mut found = None;
    while time::Instant::now() < deadline {
        let (tx, rx) = tokio::sync::oneshot::channel();
        gossip_tx1.send(GossipEvent::GetMeshView(tx)).await.unwrap();
        let view: crate::proto::MeshView = time::timeout(Duration::from_secs(2), rx)
            .await
            .expect("mesh view timed out")
            .expect("oneshot dropped");
        if let Some(p) = view.peers.iter().find(|p| p.peer_id == pid2.to_bytes()) {
            if p.topics.iter().any(|t| t.topic == "consensus" && t.in_mesh) {
                found = Some((view.clone(), p.clone()));
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    let (view, peer) = found.expect("node2 never joined node1's consensus mesh");

    assert!(
        !peer.direct_peer,
        "node2 is not configured as a direct peer"
    );
    let consensus = peer
        .topics
        .iter()
        .find(|t| t.topic == "consensus")
        .expect("consensus membership");
    assert!(consensus.in_mesh, "a meshed peer should report in_mesh");

    let view = classify_as_validators(view);
    let topics = crate::network::mesh::render::parse_topics(None);
    let rendered = crate::network::mesh::render::render_mesh_view(&view, &topics);
    assert!(
        rendered.contains("●"),
        "expected an in-mesh glyph:\n{rendered}"
    );
}

#[tokio::test]
#[serial]
async fn test_bootstrap_peer_reconnection() {
    // Create two keypairs for our test nodes
    let keypair1 = Keypair::generate();
    let keypair2 = Keypair::generate();

    // Create configs with different ports
    let node1_port = BASE_PORT_FOR_TEST + 10; // Use different ports from other tests
    let node1_addr = format!("/ip4/{HOST_FOR_TEST}/udp/{node1_port}/quic-v1");

    let node2_port = BASE_PORT_FOR_TEST + 11;
    let node2_addr = format!("/ip4/{HOST_FOR_TEST}/udp/{node2_port}/quic-v1");

    // Node1 will try to connect to Node2
    let config1 = Config::new(node1_addr.clone(), node2_addr.clone())
        .with_bootstrap_reconnect_interval(Duration::from_secs(1))
        .with_announce_address(node1_addr.clone());

    let config2 = Config::new(node2_addr.clone(), node1_addr.clone())
        .with_announce_address(node2_addr.clone());

    // Create channels for system messages
    let (system_tx1, _) = mpsc::channel::<SystemMessage>(100);
    let (system_tx2, _) = mpsc::channel::<SystemMessage>(100);

    // Start node2 first
    let mut gossip2 = SnapchainGossip::create(
        keypair2.clone(),
        &config2,
        Some(system_tx2),
        false,
        FarcasterNetwork::Devnet,
        statsd_client(),
        Vec::new(),
    )
    .await
    .unwrap();

    let node2_handle = tokio::spawn(async move {
        gossip2.start().await;
    });

    // Create node1 instance
    let mut gossip1 = SnapchainGossip::create(
        keypair1.clone(),
        &config1,
        Some(system_tx1),
        false,
        FarcasterNetwork::Devnet,
        statsd_client(),
        Vec::new(),
    )
    .await
    .unwrap();

    let gossip_tx1 = gossip1.tx.clone();

    // Start node1
    tokio::spawn(async move {
        gossip1.start().await;
    });

    // Wait for initial connection
    tokio::time::sleep(Duration::from_secs(1)).await;

    // Now stop node2 (this will cause the connection to be lost)
    node2_handle.abort();
    tokio::time::sleep(Duration::from_secs(1)).await;

    // Create a new node2 and start it again (to test reconnection)
    let (system_tx2, mut system_rx2) = mpsc::channel::<SystemMessage>(100);
    let mut gossip2 = SnapchainGossip::create(
        keypair2.clone(),
        &Config::new(node2_addr.clone(), node1_addr.clone()),
        Some(system_tx2),
        false,
        FarcasterNetwork::Devnet,
        statsd_client(),
        Vec::new(),
    )
    .await
    .unwrap();

    tokio::spawn(async move {
        gossip2.start().await;
    });

    // Wait for reconnection attempts (timer is 30 seconds, but we only wait a bit)
    tokio::time::sleep(Duration::from_secs(2)).await;

    let cast_add = messages_factory::casts::create_cast_add(123, "test", None, None);
    let mempool_msg = MempoolMessage::UserMessage(cast_add.clone());
    // Send message from node1 to node2
    gossip_tx1
        .send(GossipEvent::BroadcastMempoolMessage(mempool_msg.clone()))
        .await
        .unwrap();

    let receive_counts = wait_for_message(&mut system_rx2, cast_add).await;
    assert_eq!(receive_counts, 1);
}

/// Regression test for #865: read nodes must subscribe to MEMPOOL_TOPIC so that
/// they receive mempool gossip from validator peers. Before the fix, a read
/// node never joined the mempool mesh and never delivered inbound mempool
/// messages to its system channel, regardless of how many validator peers
/// were publishing.
#[tokio::test]
#[serial]
async fn test_read_node_receives_mempool_gossip() {
    let validator_keypair = Keypair::generate();
    let read_node_keypair = Keypair::generate();

    let validator_port = BASE_PORT_FOR_TEST + 50;
    let validator_addr = format!("/ip4/{HOST_FOR_TEST}/udp/{validator_port}/quic-v1");

    let read_node_port = BASE_PORT_FOR_TEST + 51;
    let read_node_addr = format!("/ip4/{HOST_FOR_TEST}/udp/{read_node_port}/quic-v1");

    let validator_config = Config::new(validator_addr.clone(), read_node_addr.clone())
        .with_contact_info_interval(Duration::from_millis(100));
    let read_node_config = Config::new(read_node_addr.clone(), validator_addr.clone())
        .with_contact_info_interval(Duration::from_millis(100));

    let (validator_system_tx, _) = mpsc::channel::<SystemMessage>(100);
    let (read_node_system_tx, mut read_node_system_rx) = mpsc::channel::<SystemMessage>(100);

    let mut validator_gossip = SnapchainGossip::create(
        validator_keypair,
        &validator_config,
        Some(validator_system_tx),
        false,
        FarcasterNetwork::Devnet,
        statsd_client(),
        Vec::new(),
    )
    .await
    .unwrap();

    let mut read_node_gossip = SnapchainGossip::create(
        read_node_keypair,
        &read_node_config,
        Some(read_node_system_tx),
        true,
        FarcasterNetwork::Devnet,
        statsd_client(),
        Vec::new(),
    )
    .await
    .unwrap();

    let validator_tx = validator_gossip.tx.clone();

    tokio::spawn(async move { validator_gossip.start().await });
    tokio::spawn(async move { read_node_gossip.start().await });

    let cast_add = messages_factory::casts::create_cast_add(456, "regression", None, None);
    let received = publish_until_received(
        validator_tx,
        &mut read_node_system_rx,
        cast_add,
        Duration::from_secs(10),
    )
    .await;
    assert!(
        received,
        "read node did not receive mempool gossip from validator within deadline"
    );
}

/// Multi-hop variant of the regression test. Topology:
///
/// ```text
///   read_node_1  <-->  read_node_2  <-->  validator
/// ```
///
/// `read_node_1` and `validator` only bootstrap to `read_node_2`, never to
/// each other, and autodiscovery is left off (default). For a mempool message
/// published on `read_node_1` to reach `validator`, gossipsub must forward
/// it through `read_node_2`'s mempool-topic mesh. Crucially, this is
/// distinguishable from the fanout-fallback path that makes the simpler 2-node
/// regression pass even when read nodes don't subscribe: in the bug scenario
/// `read_node_2` isn't subscribed to MEMPOOL_TOPIC, `read_node_1`'s only
/// direct peer that knows the topic is no one, fanout has nothing to fall back
/// to, and the publish never leaves `read_node_1`.
#[tokio::test]
#[serial]
async fn test_read_node_relays_mempool_gossip() {
    let read_node_1_keypair = Keypair::generate();
    let read_node_2_keypair = Keypair::generate();
    let validator_keypair = Keypair::generate();

    let read_node_1_port = BASE_PORT_FOR_TEST + 60;
    let read_node_1_addr = format!("/ip4/{HOST_FOR_TEST}/udp/{read_node_1_port}/quic-v1");

    let read_node_2_port = BASE_PORT_FOR_TEST + 61;
    let read_node_2_addr = format!("/ip4/{HOST_FOR_TEST}/udp/{read_node_2_port}/quic-v1");

    let validator_port = BASE_PORT_FOR_TEST + 62;
    let validator_addr = format!("/ip4/{HOST_FOR_TEST}/udp/{validator_port}/quic-v1");

    // read_node_1 and validator only bootstrap to read_node_2, never to each
    // other. read_node_2 has no bootstrap (it'll be dialled by the others).
    let read_node_1_config = Config::new(read_node_1_addr.clone(), read_node_2_addr.clone())
        .with_contact_info_interval(Duration::from_millis(100));
    let read_node_2_config = Config::new(read_node_2_addr.clone(), "".to_string())
        .with_contact_info_interval(Duration::from_millis(100));
    let validator_config = Config::new(validator_addr.clone(), read_node_2_addr.clone())
        .with_contact_info_interval(Duration::from_millis(100));

    let (read_node_1_system_tx, _) = mpsc::channel::<SystemMessage>(100);
    let (read_node_2_system_tx, _) = mpsc::channel::<SystemMessage>(100);
    let (validator_system_tx, mut validator_system_rx) = mpsc::channel::<SystemMessage>(100);

    let mut read_node_1_gossip = SnapchainGossip::create(
        read_node_1_keypair,
        &read_node_1_config,
        Some(read_node_1_system_tx),
        true,
        FarcasterNetwork::Devnet,
        statsd_client(),
        Vec::new(),
    )
    .await
    .unwrap();

    let mut read_node_2_gossip = SnapchainGossip::create(
        read_node_2_keypair,
        &read_node_2_config,
        Some(read_node_2_system_tx),
        true,
        FarcasterNetwork::Devnet,
        statsd_client(),
        Vec::new(),
    )
    .await
    .unwrap();

    let mut validator_gossip = SnapchainGossip::create(
        validator_keypair,
        &validator_config,
        Some(validator_system_tx),
        false,
        FarcasterNetwork::Devnet,
        statsd_client(),
        Vec::new(),
    )
    .await
    .unwrap();

    let read_node_1_tx = read_node_1_gossip.tx.clone();

    tokio::spawn(async move { read_node_1_gossip.start().await });
    tokio::spawn(async move { read_node_2_gossip.start().await });
    tokio::spawn(async move { validator_gossip.start().await });

    let cast_add = messages_factory::casts::create_cast_add(789, "multi-hop", None, None);
    let received = publish_until_received(
        read_node_1_tx,
        &mut validator_system_rx,
        cast_add,
        Duration::from_secs(15),
    )
    .await;
    assert!(
        received,
        "validator did not receive mempool gossip relayed through read_node_2 within deadline"
    );
}

mod self_heal_bounce {
    use crate::network::gossip::{peers_to_bounce, BounceTimers};
    use libp2p::gossipsub::{IdentTopic, TopicHash};
    use libp2p::PeerId;
    use std::collections::HashMap;
    use std::time::{Duration, Instant};

    const SETTLE: Duration = Duration::from_secs(30);
    const COOLDOWN: Duration = Duration::from_secs(60);

    fn contact_info() -> TopicHash {
        IdentTopic::new("contact-info").hash()
    }

    fn bounce(
        peer: PeerId,
        topics: Vec<TopicHash>,
        connected_for: Duration,
        last_bounce_ago: Option<Duration>,
        streak: u32,
    ) -> bool {
        let now = Instant::now() + Duration::from_secs(10_000);
        let peer_topics = HashMap::from([(peer, topics)]);
        let connected_at = HashMap::from([(peer, now - connected_for)]);
        let last_bounce: HashMap<_, _> = last_bounce_ago
            .map(|ago| (peer, now - ago))
            .into_iter()
            .collect();
        let streaks = HashMap::from([(peer, streak)]);
        let timers = BounceTimers {
            connected_at: &connected_at,
            last_bounce: &last_bounce,
            streak: &streaks,
            settle: SETTLE,
            cooldown: COOLDOWN,
        };
        peers_to_bounce([peer], &peer_topics, &contact_info(), &timers, now) == vec![peer]
    }

    #[test]
    fn bounces_a_settled_peer_missing_its_subscriptions() {
        // The prod failure: a validator connected long ago that never sent SUBSCRIBE.
        assert!(bounce(PeerId::random(), vec![], SETTLE * 2, None, 0));
    }

    #[test]
    fn leaves_healthy_and_mid_handshake_peers_alone() {
        assert!(!bounce(
            PeerId::random(),
            vec![contact_info()],
            SETTLE * 2,
            None,
            0
        ));
        assert!(!bounce(PeerId::random(), vec![], SETTLE / 2, None, 0));
    }

    #[test]
    fn skips_peers_that_are_not_connected() {
        let peer = PeerId::random();
        let now = Instant::now();
        let none = HashMap::new();
        let streaks = HashMap::new();
        let timers = BounceTimers {
            connected_at: &none,
            last_bounce: &none,
            streak: &streaks,
            settle: SETTLE,
            cooldown: COOLDOWN,
        };
        assert!(peers_to_bounce([peer], &HashMap::new(), &contact_info(), &timers, now).is_empty());
    }

    #[test]
    fn cooldown_doubles_with_each_consecutive_bounce() {
        let peer = PeerId::random();
        // First bounce done (streak 1): eligible again after 60s.
        assert!(!bounce(peer, vec![], SETTLE * 2, Some(COOLDOWN), 1));
        assert!(bounce(
            peer,
            vec![],
            SETTLE * 2,
            Some(COOLDOWN + Duration::from_secs(1)),
            1
        ));
        // Third consecutive bounce (streak 3): 4 x 60s.
        assert!(!bounce(peer, vec![], SETTLE * 2, Some(COOLDOWN * 3), 3));
        assert!(bounce(
            peer,
            vec![],
            SETTLE * 2,
            Some(COOLDOWN * 4 + Duration::from_secs(1)),
            3
        ));
        // Capped at 32 x 60s however long the streak runs.
        assert!(bounce(
            peer,
            vec![],
            SETTLE * 2,
            Some(COOLDOWN * 32 + Duration::from_secs(1)),
            40
        ));
    }
}

async fn connected_peer_count(tx: &mpsc::Sender<GossipEvent<SnapchainValidatorContext>>) -> usize {
    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
    tx.send(GossipEvent::GetConnectedPeers(reply_tx))
        .await
        .unwrap();
    reply_rx.await.unwrap().len()
}

/// A node that shuts down must close its connections, not just stop. Otherwise each
/// peer keeps the dead connection until its 10s QUIC idle timeout, and a restart inside
/// that window leaves the peer treating us as already connected, so it never sends us
/// its gossipsub subscriptions.
#[tokio::test]
#[serial]
async fn test_shutdown_closes_peer_connections_promptly() {
    let validator_addr = format!(
        "/ip4/{HOST_FOR_TEST}/udp/{}/quic-v1",
        BASE_PORT_FOR_TEST + 80
    );
    let read_node_addr = format!(
        "/ip4/{HOST_FOR_TEST}/udp/{}/quic-v1",
        BASE_PORT_FOR_TEST + 81
    );

    let (validator_system_tx, _) = mpsc::channel::<SystemMessage>(100);
    let (read_node_system_tx, _) = mpsc::channel::<SystemMessage>(100);
    let mut validator = SnapchainGossip::create(
        Keypair::generate(),
        &Config::new(validator_addr.clone(), "".to_string()),
        Some(validator_system_tx),
        false,
        FarcasterNetwork::Devnet,
        statsd_client(),
        Vec::new(),
    )
    .await
    .unwrap();
    let mut read_node = SnapchainGossip::create(
        Keypair::generate(),
        &Config::new(read_node_addr, validator_addr),
        Some(read_node_system_tx),
        true,
        FarcasterNetwork::Devnet,
        statsd_client(),
        Vec::new(),
    )
    .await
    .unwrap();
    let validator_tx = validator.tx.clone();
    let read_node_tx = read_node.tx.clone();
    tokio::spawn(async move { validator.start().await });
    let read_node_task = tokio::spawn(async move { read_node.start().await });

    let deadline = time::Instant::now() + Duration::from_secs(10);
    while connected_peer_count(&validator_tx).await == 0 {
        assert!(time::Instant::now() < deadline, "read node never connected");
        time::sleep(Duration::from_millis(100)).await;
    }

    let (done_tx, done_rx) = tokio::sync::oneshot::channel();
    read_node_tx
        .send(GossipEvent::Shutdown(done_tx))
        .await
        .unwrap();
    time::timeout(Duration::from_secs(5), done_rx)
        .await
        .expect("shutdown did not finish")
        .unwrap();
    time::timeout(Duration::from_secs(1), read_node_task)
        .await
        .expect("gossip loop kept running after shutdown")
        .unwrap();

    // Well under the 10s QUIC idle timeout an abrupt exit would leave behind.
    let closed_by = time::Instant::now() + Duration::from_secs(3);
    while connected_peer_count(&validator_tx).await > 0 {
        assert!(
            time::Instant::now() < closed_by,
            "validator still holds the read node's connection after a clean shutdown"
        );
        time::sleep(Duration::from_millis(50)).await;
    }
}
