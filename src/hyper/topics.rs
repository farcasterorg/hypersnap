//! Gossip topic identifiers for the hyper protocol.
//!
//! Each topic is a constant string used as the libp2p gossipsub topic name.
//! Centralizing these here ensures publishers and subscribers don't drift on
//! topic names, and makes it easy to discover what gossip topics the
//! protocol uses.

/// Hyperblocks (proposed + finalized) — the primary chain advancement topic.
/// Subscribers run `import_hyper_block_with_index` on incoming blocks.
pub const TOPIC_HYPER_BLOCKS: &str = "hyper/blocks/v1";

/// Hyper-layer messages: locks, transfers, validator events.
/// Subscribers run `HyperRuntime::submit_message` on incoming messages.
pub const TOPIC_HYPER_MESSAGES: &str = "hyper/messages/v1";

/// DKG ceremony round messages — separate topic so they can be rate-limited
/// or peer-restricted independently from regular hyper messages.
pub const TOPIC_HYPER_DKG: &str = "hyper/dkg/v1";

/// Slashing evidence — when a validator is observed misbehaving (e.g.
/// producing two distinct blocks at the same height), evidence is gossiped
/// here for inclusion in subsequent blocks. Implementation TODO.
pub const TOPIC_HYPER_EVIDENCE: &str = "hyper/evidence/v1";

/// Convenience: all topics a full hyper validator subscribes to.
pub fn all_validator_topics() -> &'static [&'static str] {
    &[
        TOPIC_HYPER_BLOCKS,
        TOPIC_HYPER_MESSAGES,
        TOPIC_HYPER_DKG,
        TOPIC_HYPER_EVIDENCE,
    ]
}

/// Topics a non-validator full node (relay / explorer) subscribes to.
/// Excludes DKG (validators-only) and evidence (validators publish).
pub fn all_observer_topics() -> &'static [&'static str] {
    &[TOPIC_HYPER_BLOCKS, TOPIC_HYPER_MESSAGES]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn topic_names_are_unique() {
        let topics = [
            TOPIC_HYPER_BLOCKS,
            TOPIC_HYPER_MESSAGES,
            TOPIC_HYPER_DKG,
            TOPIC_HYPER_EVIDENCE,
        ];
        let unique: std::collections::HashSet<_> = topics.iter().collect();
        assert_eq!(unique.len(), topics.len());
    }

    #[test]
    fn topic_names_are_versioned() {
        for t in [
            TOPIC_HYPER_BLOCKS,
            TOPIC_HYPER_MESSAGES,
            TOPIC_HYPER_DKG,
            TOPIC_HYPER_EVIDENCE,
        ] {
            assert!(t.ends_with("/v1"), "topic {} should be versioned", t);
        }
    }

    #[test]
    fn validator_topics_superset_of_observer_topics() {
        let v: std::collections::HashSet<_> = all_validator_topics().iter().collect();
        let o: std::collections::HashSet<_> = all_observer_topics().iter().collect();
        for t in &o {
            assert!(v.contains(t), "validator topics should include {}", t);
        }
    }

    #[test]
    fn observer_excludes_dkg_and_evidence() {
        let o: std::collections::HashSet<_> = all_observer_topics().iter().collect();
        assert!(!o.contains(&TOPIC_HYPER_DKG));
        assert!(!o.contains(&TOPIC_HYPER_EVIDENCE));
    }
}
