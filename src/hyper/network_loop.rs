//! Glue between the libp2p `SnapchainGossip` and the `HyperActor`.
//!
//! The actor produces a stream of `HyperActorOutbound` items; the gossip
//! task already owns a multi-producer `tx` channel for outbound publish
//! requests (`GossipEvent::BroadcastHyperWire`). This module bridges the
//! two: spawn it once at startup with the actor's outbound receiver and
//! a clone of `SnapchainGossip::tx`, and the pump runs until either side
//! closes.
//!
//! The inbound direction (gossip → actor) is wired by
//! `SnapchainGossip::attach_hyper_actor`.

use crate::core::types::SnapchainValidatorContext;
use crate::hyper::actor::{HyperActor, HyperActorEvent, HyperActorOutbound};
use crate::hyper::gossip_adapter::outbound_to_wire;
use crate::hyper::runtime::HyperRuntime;
use crate::network::gossip::{GossipEvent, SnapchainGossip};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::warn;

/// Run the actor-outbound → gossip-publish pump until both channels close.
///
/// `gossip_tx` is `SnapchainGossip::tx` — the existing publish channel.
/// `on_non_network` is invoked for outbounds that aren't network-bound
/// (`EventError`, `DkgFinalized`) so the operator can map them to
/// metrics or logs.
pub async fn run_outbound_pump<F>(
    mut outbound: mpsc::Receiver<HyperActorOutbound>,
    gossip_tx: mpsc::Sender<GossipEvent<SnapchainValidatorContext>>,
    mut on_non_network: F,
) where
    F: FnMut(HyperActorOutbound) + Send,
{
    while let Some(item) = outbound.recv().await {
        match &item {
            HyperActorOutbound::BroadcastBlock(_)
            | HyperActorOutbound::BroadcastDkls { .. }
            | HyperActorOutbound::BroadcastDklsSign { .. }
            | HyperActorOutbound::BroadcastMessage(_)
            | HyperActorOutbound::EvidenceConfirmed(_) => {
                if let Some((topic, wire)) = outbound_to_wire(item) {
                    if let Err(e) = gossip_tx
                        .send(GossipEvent::BroadcastHyperWire(topic, wire))
                        .await
                    {
                        warn!("hyper publish channel closed: {}", e);
                        break;
                    }
                }
            }
            HyperActorOutbound::DkgFinalized { .. }
            | HyperActorOutbound::DklsSignFinalized { .. }
            | HyperActorOutbound::EventError(_) => {
                on_non_network(item);
            }
        }
    }
}

/// Handle returned by `bootstrap`. Drop this to start a graceful shutdown
/// (close `inbound` so the actor exits its loop; the pump finishes when
/// the actor's outbound channel closes).
pub struct HyperBootstrap {
    /// Send `HyperActorEvent`s to the actor (e.g. `ProduceBlock` ticks
    /// from a scheduler, locally-originated messages, etc.).
    pub inbound: mpsc::Sender<HyperActorEvent>,
    /// The pump task handle. Awaited by the supervisor on shutdown.
    pub pump: JoinHandle<()>,
}

/// Wire a `HyperRuntime` into a running `SnapchainGossip` and start the
/// actor. The caller has already constructed both; this function:
///   1. Spawns the actor as a tokio task.
///   2. Calls `gossip.attach_hyper_actor(...)` to forward inbound wire
///      frames to the actor.
///   3. Spawns the outbound pump that converts actor outbounds back into
///      `GossipEvent::BroadcastHyperWire` requests on the existing
///      `gossip.tx` channel.
///
/// Returns a `HyperBootstrap` with the inbound sender (for local
/// submissions) and the pump's join handle (for shutdown).
pub fn bootstrap<F>(
    runtime: HyperRuntime,
    gossip: &mut SnapchainGossip,
    inbound_capacity: usize,
    is_validator: bool,
    on_non_network: F,
) -> HyperBootstrap
where
    F: FnMut(HyperActorOutbound) + Send + 'static,
{
    let handles = HyperActor::spawn(runtime, inbound_capacity);
    gossip.attach_hyper_actor(handles.inbound.clone(), is_validator);
    let gossip_tx = gossip.tx.clone();
    let pump = tokio::spawn(run_outbound_pump(
        handles.outbound,
        gossip_tx,
        on_non_network,
    ));
    HyperBootstrap {
        inbound: handles.inbound,
        pump,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hyper::topics::TOPIC_HYPER_BLOCKS;
    use crate::hyper::{HyperBlock, HyperBlockMetadata, HyperBlockSignature, HyperEnvelope};

    fn dummy_block() -> HyperBlock {
        HyperBlock {
            envelope: HyperEnvelope {
                metadata: HyperBlockMetadata {
                    canonical_block_id: 0,
                    parent_hash: vec![],
                    hyper_state_root: vec![0u8; 48],
                    extra_rules_version: 0,
                    retained_message_count: 0,
                    missed_proposals: vec![],
                    snapchain_anchor_block: 0,
                    snapchain_anchor_hash: vec![],

                    snapchain_range_start_block: 0,

                    snapchain_range_root: vec![],
                    snapchain_anchor_timestamp: 0,
                },
                payload: vec![],
            },
            signature: HyperBlockSignature {
                epoch: 0,
                signer_indices: vec![1],
                group_address: Vec::new(),
                ecdsa_signature: Vec::new(),
            },
        }
    }

    #[tokio::test]
    async fn pump_forwards_block_outbound_as_broadcast_hyper_wire() {
        let (out_tx, out_rx) = mpsc::channel::<HyperActorOutbound>(4);
        let (gossip_tx, mut gossip_rx) = mpsc::channel::<GossipEvent<SnapchainValidatorContext>>(4);

        out_tx
            .send(HyperActorOutbound::BroadcastBlock(dummy_block()))
            .await
            .unwrap();
        drop(out_tx);

        let pump = tokio::spawn(run_outbound_pump(out_rx, gossip_tx, |_| {}));

        let evt = gossip_rx.recv().await.expect("gossip event");
        match evt {
            GossipEvent::BroadcastHyperWire(topic, _) => {
                assert_eq!(topic, TOPIC_HYPER_BLOCKS);
            }
            _ => panic!("expected BroadcastHyperWire"),
        }
        pump.await.unwrap();
    }

    #[tokio::test]
    async fn pump_invokes_on_non_network_for_finalized() {
        let (out_tx, out_rx) = mpsc::channel::<HyperActorOutbound>(4);
        let (gossip_tx, _gossip_rx) = mpsc::channel::<GossipEvent<SnapchainValidatorContext>>(4);

        out_tx
            .send(HyperActorOutbound::DkgFinalized { target_epoch: 7 })
            .await
            .unwrap();
        drop(out_tx);

        let mut observed_epoch = None;
        run_outbound_pump(out_rx, gossip_tx, |item| {
            if let HyperActorOutbound::DkgFinalized { target_epoch } = item {
                observed_epoch = Some(target_epoch);
            }
        })
        .await;
        assert_eq!(observed_epoch, Some(7));
    }

    #[tokio::test]
    async fn pump_routes_dkls_outbound_to_dkg_topic() {
        use crate::hyper::topics::TOPIC_HYPER_DKG;
        use hypersnap_crypto::dkls23::protocols::Parameters;
        use hypersnap_crypto::dkls_ceremony::DklsCeremonyCoordinator;

        let (out_tx, out_rx) = mpsc::channel::<HyperActorOutbound>(4);
        let (gossip_tx, mut gossip_rx) = mpsc::channel::<GossipEvent<SnapchainValidatorContext>>(4);

        // Build a real DKLS round-1 fragment to ship through the
        // pump — pinning that the DKG-topic routing applies to
        // DKLS messages.
        let mut coord = DklsCeremonyCoordinator::new(
            5,
            Parameters {
                threshold: 2,
                share_count: 3,
            },
            1,
            b"network-loop-test".to_vec(),
        )
        .unwrap();
        coord.start().unwrap();
        let _ = coord.drain_outbound();
        out_tx
            .send(HyperActorOutbound::BroadcastDkls {
                target_epoch: 5,
                encoded: vec![0xab, 0xcd],
            })
            .await
            .unwrap();
        drop(out_tx);

        let pump = tokio::spawn(run_outbound_pump(out_rx, gossip_tx, |_| {}));
        let evt = gossip_rx.recv().await.expect("gossip event");
        match evt {
            GossipEvent::BroadcastHyperWire(topic, _) => {
                assert_eq!(topic, TOPIC_HYPER_DKG);
            }
            _ => panic!("expected BroadcastHyperWire"),
        }
        pump.await.unwrap();
    }
}
