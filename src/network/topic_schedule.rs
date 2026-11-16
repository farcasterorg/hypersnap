//! Height-based topic routing. Only local outbound state advances mempool and
//! discovery phases; a remote status cannot force an early namespace switch.
use crate::{
    proto::{self, gossip_message::GossipMessage as Payload},
    version::version::EngineVersion,
};
use prost::Message;
use std::collections::BTreeMap;

pub struct Schedule {
    cutovers: BTreeMap<u32, u64>,
    next: BTreeMap<u32, u64>,
    network: proto::FarcasterNetwork,
    num_shards: u32,
}
#[derive(Clone, Copy)]
enum Scope {
    Height(proto::Height),
    Shard(u32),
    Control,
}
impl Schedule {
    pub fn new(
        cutovers: &BTreeMap<String, u64>,
        network: proto::FarcasterNetwork,
    ) -> Result<Self, String> {
        let cutovers = cutovers
            .iter()
            .map(|(shard, height)| {
                Ok((
                    shard
                        .parse::<u32>()
                        .map_err(|_| "invalid topic-cutover shard ID")?,
                    *height,
                ))
            })
            .collect::<Result<_, String>>()?;
        Ok(Self {
            cutovers,
            next: BTreeMap::new(),
            network,
            num_shards: 2,
        })
    }
    pub fn set_num_shards(&mut self, n: u32) -> Result<(), String> {
        if n == 0 {
            return Err("topic routing requires at least one data shard".into());
        }
        if !self.cutovers.is_empty()
            && (self.cutovers.len() != n as usize + 1
                || (0..=n).any(|s| !self.cutovers.contains_key(&s)))
        {
            return Err("topic_cutovers must contain block shard 0 and every data shard".into());
        }
        self.num_shards = n;
        Ok(())
    }
    pub fn observe_next(&mut self, height: proto::Height) {
        let value = self.next.entry(height.shard_index).or_default();
        *value = (*value).max(height.block_number);
    }
    pub fn is_hypersnap(&self, shard: u32, height: u64) -> bool {
        self.cutovers
            .get(&shard)
            .map_or(self.network != proto::FarcasterNetwork::Mainnet, |cutoff| {
                height >= *cutoff
            })
    }
    pub fn phases(&self) -> Vec<bool> {
        if self.cutovers.is_empty() {
            return vec![self.network != proto::FarcasterNetwork::Mainnet];
        }
        let old = self
            .cutovers
            .keys()
            .any(|s| !self.is_hypersnap(*s, self.next.get(s).copied().unwrap_or(0)));
        let new = self
            .cutovers
            .keys()
            .any(|s| self.is_hypersnap(*s, self.next.get(s).copied().unwrap_or(0)));
        match (old, new) {
            (true, true) => vec![false, true],
            (true, false) => vec![false],
            _ => vec![true],
        }
    }
    pub fn subscriptions(&self, topic: &str) -> Vec<&'static str> {
        // Establish the new mesh in advance. Ignore messages from the wrong
        // domain before forwarding; retire legacy subscriptions after all cutoffs.
        let phases = if !self.cutovers.is_empty() && self.phases().contains(&false) {
            vec![false, true]
        } else {
            self.phases()
        };
        phases
            .into_iter()
            .filter_map(|p| snapchain_proto::topics::wire(topic, p))
            .collect()
    }
    fn scope(&self, payload: &Payload) -> Option<Scope> {
        use proto::{consensus_message, decided_value, mempool_message, read_node_message};
        Some(match payload {
            Payload::Consensus(c) => Scope::Height(match c.consensus_message.as_ref()? {
                consensus_message::ConsensusMessage::Vote(v) => v.height?,
                consensus_message::ConsensusMessage::Proposal(p) => p.height?,
            }),
            Payload::FullProposal(p) => Scope::Height(p.height?),
            Payload::Status(s) => {
                let mut h = s.height?;
                h.block_number = h.block_number.saturating_add(1);
                Scope::Height(h)
            }
            Payload::ReadNodeMessage(r) => {
                let read_node_message::ReadNodeMessage::DecidedValue(d) =
                    r.read_node_message.as_ref()?;
                let h = match d.value.as_ref()? {
                    decided_value::Value::Block(b) => b.header.as_ref()?.height?,
                    decided_value::Value::Shard(s) => s.header.as_ref()?.height?,
                };
                Scope::Height(h)
            }
            Payload::MempoolMessage(m) => {
                let mempool_message::MempoolMessage::UserMessage(raw) =
                    m.mempool_message.as_ref()?;
                let mut message = raw.clone();
                crate::storage::store::account::message_bytes_decode(&mut message);
                message.data.as_ref()?;
                let router: Box<dyn crate::mempool::routing::MessageRouter> =
                    Box::new(crate::mempool::routing::ShardRouter {});
                Scope::Shard(crate::mempool::routing::route_message(
                    &router,
                    &message,
                    self.num_shards,
                    EngineVersion::current(self.network),
                ))
            }
            Payload::ContactInfoMessage(_) | Payload::HyperEnvelope(_) => Scope::Control,
        })
    }
    fn payload_topics(payload: &Payload) -> &'static [&'static str] {
        use snapchain_proto::topics as t;
        match payload {
            Payload::Consensus(_) | Payload::FullProposal(_) => &[t::CONSENSUS],
            Payload::Status(_) => &[t::CONSENSUS, t::READ_NODE_PEERS],
            Payload::ReadNodeMessage(_) => &[t::DECIDED_VALUES],
            Payload::MempoolMessage(_) => &[t::MEMPOOL],
            Payload::ContactInfoMessage(_) => &[t::CONTACT_INFO],
            Payload::HyperEnvelope(_) => &[t::HYPER],
        }
    }
    pub fn observe_outbound(&mut self, bytes: &[u8]) {
        if let Ok(message) = proto::GossipMessage::decode(bytes) {
            if let Some(payload) = message.gossip_message {
                if let Some(Scope::Height(mut height)) = self.scope(&payload) {
                    if matches!(payload, Payload::ReadNodeMessage(_)) {
                        height.block_number = height.block_number.saturating_add(1);
                    }
                    self.observe_next(height);
                }
            }
        }
    }
    pub fn publications(&self, topic: &str, bytes: &[u8]) -> Vec<&'static str> {
        let Ok(message) = proto::GossipMessage::decode(bytes) else {
            return vec![];
        };
        let Some(payload) = message.gossip_message else {
            return vec![];
        };
        let Some(canonical) = snapchain_proto::topics::canonical(topic) else {
            return vec![];
        };
        if !Self::payload_topics(&payload).contains(&canonical) {
            return vec![];
        }
        let phases = match self.scope(&payload) {
            Some(Scope::Height(height)) => {
                if height.shard_index > self.num_shards {
                    return vec![];
                }
                vec![self.is_hypersnap(height.shard_index, height.block_number)]
            }
            Some(Scope::Shard(shard)) => {
                let hypersnap =
                    self.is_hypersnap(shard, self.next.get(&shard).copied().unwrap_or(0));
                if !hypersnap {
                    if let Payload::MempoolMessage(m) = &payload {
                        if let Some(proto::mempool_message::MempoolMessage::UserMessage(raw)) =
                            &m.mempool_message
                        {
                            let mut message = raw.clone();
                            crate::storage::store::account::message_bytes_decode(&mut message);
                            if message.msg_type() == proto::MessageType::NativeOnboard
                                || crate::native_registration::is_native_fid(message.fid())
                            {
                                return vec![];
                            }
                        }
                    }
                }
                vec![hypersnap]
            }
            Some(Scope::Control) => self.phases(),
            None => return vec![],
        };
        phases
            .into_iter()
            .filter_map(|p| snapchain_proto::topics::wire(canonical, p))
            .collect()
    }
    pub fn accepts(&self, topic: &str, bytes: &[u8]) -> bool {
        self.inbound(topic, bytes).is_some()
    }

    /// Validate an incoming wire message and bound legacy sync advertisements
    /// to the shared pre-fork history. An upstream Snapchain node keeps using
    /// legacy topics after our cutoff; dropping its newer status would strand
    /// a lagging node before it can fetch the final pre-fork blocks.
    pub fn inbound(&self, topic: &str, bytes: &[u8]) -> Option<Vec<u8>> {
        if self.publications(topic, bytes).contains(&topic) {
            return Some(bytes.to_vec());
        }
        if !matches!(topic, "consensus" | "read-node-peers") {
            return None;
        }
        let mut message = proto::GossipMessage::decode(bytes).ok()?;
        let Some(Payload::Status(status)) = &mut message.gossip_message else {
            return None;
        };
        let height = status.height.as_mut()?;
        let cutoff = *self.cutovers.get(&height.shard_index)?;
        let local_next = self.next.get(&height.shard_index).copied().unwrap_or(0);
        if local_next >= cutoff {
            return None;
        }
        let last_shared = cutoff.checked_sub(1)?;
        if status.min_height.is_some_and(|min| {
            min.shard_index != height.shard_index || min.block_number > last_shared
        }) {
            return None;
        }
        // Only the local sync consumer sees this bounded height. The signed
        // gossip payload itself is neither rewritten on the wire nor republished.
        height.block_number = height.block_number.min(last_shared);
        Some(message.encode_to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snapchain_proto::topics as t;
    fn schedule() -> Schedule {
        let mut s = Schedule::new(
            &[("0".into(), 100), ("1".into(), 200), ("2".into(), 300)].into(),
            proto::FarcasterNetwork::Mainnet,
        )
        .unwrap();
        s.set_num_shards(2).unwrap();
        s
    }
    fn status(shard: u32, committed: u64) -> Vec<u8> {
        proto::GossipMessage {
            gossip_message: Some(Payload::Status(proto::StatusMessage {
                height: Some(proto::Height {
                    shard_index: shard,
                    block_number: committed,
                }),
                ..Default::default()
            })),
        }
        .encode_to_vec()
    }
    #[test]
    fn exact_boundary_and_remote_status_cannot_advance_local_phase() {
        let s = schedule();
        assert_eq!(
            s.publications(t::CONSENSUS, &status(1, 198)),
            vec!["consensus"]
        );
        assert_eq!(
            s.publications(t::CONSENSUS, &status(1, 199)),
            vec![t::CONSENSUS]
        );
        assert!(s.accepts("consensus", &status(1, 198)));
        assert!(!s.accepts(t::CONSENSUS, &status(1, 198)));
        assert!(s.accepts("consensus", &status(1, 199)));
        assert!(s.accepts(t::CONSENSUS, &status(1, 999_999)));
        assert_eq!(s.phases(), vec![false]);
        assert!(s.publications(t::MEMPOOL, &status(1, 198)).is_empty());
    }
    #[test]
    fn legacy_status_above_cutoff_can_finish_pre_fork_sync_but_cannot_cross_it() {
        let mut s = schedule();
        s.observe_next(proto::Height {
            shard_index: 0,
            block_number: 97,
        });
        let advertised = status(0, 1000);
        for topic in ["consensus", "read-node-peers"] {
            let bytes = s
                .inbound(topic, &advertised)
                .expect("upstream still serves shared history");
            let message = proto::GossipMessage::decode(bytes.as_slice()).unwrap();
            let Some(Payload::Status(bounded)) = message.gossip_message else {
                panic!("expected status");
            };
            assert_eq!(bounded.height.unwrap().block_number, 99);
            assert_eq!(
                s.phases(),
                vec![false],
                "remote status must not advance our phase"
            );
            assert_eq!(s.publications(t::MEMPOOL, &advertised), Vec::<&str>::new());
        }
        assert!(s.inbound("mempool", &advertised).is_none());
        assert!(s.inbound("decided-values", &advertised).is_none());
        let mut pruned = proto::GossipMessage::decode(advertised.as_slice()).unwrap();
        let Some(Payload::Status(ref mut peer_status)) = pruned.gossip_message else {
            panic!("expected status");
        };
        peer_status.min_height = Some(proto::Height {
            shard_index: 0,
            block_number: 100,
        });
        assert!(s.inbound("consensus", &pruned.encode_to_vec()).is_none());
        s.observe_next(proto::Height {
            shard_index: 0,
            block_number: 100,
        });
        assert!(s.inbound("consensus", &advertised).is_none());
        assert!(s.inbound("read-node-peers", &advertised).is_none());
        // Other shards still need their shared history during the mixed window.
        assert!(s.inbound("consensus", &status(1, 1000)).is_some());
    }

    #[test]
    fn legacy_future_blocks_and_votes_remain_rejected_while_status_is_accepted() {
        let s = schedule();
        let proposal = proto::GossipMessage {
            gossip_message: Some(Payload::FullProposal(proto::FullProposal {
                height: Some(proto::Height {
                    shard_index: 0,
                    block_number: 100,
                }),
                ..Default::default()
            })),
        }
        .encode_to_vec();
        assert!(s.inbound("consensus", &proposal).is_none());
        let vote = proto::GossipMessage {
            gossip_message: Some(Payload::Consensus(proto::ConsensusMessage {
                consensus_message: Some(proto::consensus_message::ConsensusMessage::Vote(
                    proto::Vote {
                        height: Some(proto::Height {
                            shard_index: 0,
                            block_number: 100,
                        }),
                        ..Default::default()
                    },
                )),
                ..Default::default()
            })),
        }
        .encode_to_vec();
        assert!(s.inbound("consensus", &vote).is_none());
        let value = |height| {
            proto::GossipMessage {
                gossip_message: Some(Payload::ReadNodeMessage(proto::ReadNodeMessage {
                    read_node_message: Some(
                        proto::read_node_message::ReadNodeMessage::DecidedValue(
                            proto::DecidedValue {
                                value: Some(proto::decided_value::Value::Block(proto::Block {
                                    header: Some(proto::BlockHeader {
                                        height: Some(proto::Height {
                                            shard_index: 0,
                                            block_number: height,
                                        }),
                                        ..Default::default()
                                    }),
                                    ..Default::default()
                                })),
                                ..Default::default()
                            },
                        ),
                    ),
                })),
            }
            .encode_to_vec()
        };
        assert!(s.inbound("decided-values", &value(99)).is_some());
        assert!(s.inbound("decided-values", &value(100)).is_none());
        assert!(s.inbound(t::DECIDED_VALUES, &value(99)).is_none());
    }
    #[test]
    fn mixed_shards_and_restart_then_retire_all_legacy_topics() {
        let mut s = schedule();
        assert_eq!(s.subscriptions(t::MEMPOOL), vec!["mempool", t::MEMPOOL]);
        s.observe_outbound(&status(0, 99));
        assert_eq!(s.phases(), vec![false, true]);
        s.observe_outbound(&status(1, 199));
        s.observe_outbound(&status(2, 299));
        for topic in t::ALL {
            assert_eq!(s.subscriptions(topic), vec![topic]);
        }
        s.observe_outbound(&status(1, 1)); // old local status must not move phase backwards
        assert_eq!(s.phases(), vec![true]);
    }
    #[test]
    fn decided_value_uses_committed_height_but_advances_next_height() {
        let mut s = schedule();
        let bytes = proto::GossipMessage {
            gossip_message: Some(Payload::ReadNodeMessage(proto::ReadNodeMessage {
                read_node_message: Some(proto::read_node_message::ReadNodeMessage::DecidedValue(
                    proto::DecidedValue {
                        value: Some(proto::decided_value::Value::Block(proto::Block {
                            header: Some(proto::BlockHeader {
                                height: Some(proto::Height {
                                    shard_index: 0,
                                    block_number: 99,
                                }),
                                ..Default::default()
                            }),
                            ..Default::default()
                        })),
                        ..Default::default()
                    },
                )),
            })),
        }
        .encode_to_vec();
        s.observe_outbound(&bytes);
        assert_eq!(
            s.publications(t::DECIDED_VALUES, &bytes),
            vec!["decided-values"]
        );
        assert_eq!(s.phases(), vec![false, true]);
    }
    #[test]
    fn mempool_routes_by_its_own_shard_in_mixed_window() {
        let mut s = schedule();
        s.observe_next(proto::Height {
            shard_index: 0,
            block_number: 100,
        });
        let bytes = |kind| {
            proto::GossipMessage {
                gossip_message: Some(Payload::MempoolMessage(proto::MempoolMessage {
                    mempool_message: Some(proto::mempool_message::MempoolMessage::UserMessage(
                        proto::Message {
                            data: Some(proto::MessageData {
                                fid: 42,
                                r#type: kind,
                                ..Default::default()
                            }),
                            ..Default::default()
                        },
                    )),
                })),
            }
            .encode_to_vec()
        };
        assert_eq!(
            s.publications(t::MEMPOOL, &bytes(proto::MessageType::KeyAdd as i32)),
            vec![t::MEMPOOL]
        );
        assert_eq!(
            s.publications(t::MEMPOOL, &bytes(proto::MessageType::CastAdd as i32)),
            vec!["mempool"]
        );
    }
    #[test]
    fn incomplete_schedule_fails_closed() {
        let mut s = Schedule::new(
            &[("0".into(), 100)].into(),
            proto::FarcasterNetwork::Mainnet,
        )
        .unwrap();
        assert!(s.set_num_shards(2).is_err());
    }
    #[test]
    fn native_messages_never_enter_legacy_topics() {
        let mut s = schedule();
        let bytes = |fid, kind| {
            proto::GossipMessage {
                gossip_message: Some(Payload::MempoolMessage(proto::MempoolMessage {
                    mempool_message: Some(proto::mempool_message::MempoolMessage::UserMessage(
                        proto::Message {
                            data: Some(proto::MessageData {
                                fid,
                                r#type: kind,
                                ..Default::default()
                            }),
                            ..Default::default()
                        },
                    )),
                })),
            }
            .encode_to_vec()
        };
        let registration = bytes(0, proto::MessageType::NativeOnboard as i32);
        let cast = bytes(
            crate::native_registration::FIRST_NATIVE_FID,
            proto::MessageType::CastAdd as i32,
        );
        assert!(s.publications(t::MEMPOOL, &registration).is_empty());
        assert!(s.publications(t::MEMPOOL, &cast).is_empty());
        for (shard_index, block_number) in [(0, 100), (1, 200), (2, 300)] {
            s.observe_next(proto::Height {
                shard_index,
                block_number,
            });
        }
        assert_eq!(s.publications(t::MEMPOOL, &registration), vec![t::MEMPOOL]);
        assert_eq!(s.publications(t::MEMPOOL, &cast), vec![t::MEMPOOL]);
    }
}
