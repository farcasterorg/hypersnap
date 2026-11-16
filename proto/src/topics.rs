//! Wire-level Hypersnap gossip isolation. Snapchain retains its original names.
pub const CONSENSUS: &str = "hypersnap/consensus";
pub const MEMPOOL: &str = "hypersnap/mempool";
pub const DECIDED_VALUES: &str = "hypersnap/decided-values";
pub const READ_NODE_PEERS: &str = "hypersnap/read-node-peers";
pub const CONTACT_INFO: &str = "hypersnap/contact-info";
pub const HYPER: &str = "hypersnap/hyper";
pub const SNAPCHAIN_MEMPOOL: &str = "mempool";
pub const ALL: [&str; 6] = [
    CONSENSUS,
    MEMPOOL,
    DECIDED_VALUES,
    READ_NODE_PEERS,
    CONTACT_INFO,
    HYPER,
];

pub fn canonical(name: &str) -> Option<&'static str> {
    ALL.into_iter()
        .find(|topic| *topic == name || topic.strip_prefix("hypersnap/") == Some(name))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn transition_content_ids_preserve_legacy_and_separate_domains() {
        use std::hash::{DefaultHasher, Hash, Hasher};
        let bytes = b"same signed message".to_vec();
        let mut upstream = DefaultHasher::new();
        bytes.hash(&mut upstream);
        assert_eq!(message_id("mempool", &bytes), upstream.finish().to_string());
        assert_ne!(message_id("mempool", &bytes), message_id(MEMPOOL, &bytes));
        assert_ne!(
            message_id(CONTACT_INFO, &bytes),
            message_id(MEMPOOL, &bytes)
        );
    }
    #[test]
    fn every_topic_is_isolated_from_snapchain() {
        for name in ALL {
            assert!(name.starts_with("hypersnap/"));
            assert_ne!(name, name.strip_prefix("hypersnap/").unwrap());
            assert_eq!(canonical(name), Some(name));
        }
        assert_eq!(canonical("mempool"), Some(MEMPOOL));
        assert_eq!(canonical("unknown"), None);
    }
}

pub const LEGACY: [&str; 6] = [
    "consensus",
    "mempool",
    "decided-values",
    "read-node-peers",
    "contact-info",
    "hyper",
];
pub const TRANSITION_TOPICS: [&str; 12] = [
    CONSENSUS,
    MEMPOOL,
    DECIDED_VALUES,
    READ_NODE_PEERS,
    CONTACT_INFO,
    HYPER,
    "consensus",
    "mempool",
    "decided-values",
    "read-node-peers",
    "contact-info",
    "hyper",
];
pub fn wire(canonical_topic: &str, hypersnap: bool) -> Option<&'static str> {
    let canonical = canonical(canonical_topic)?;
    let index = ALL.iter().position(|t| *t == canonical)?;
    Some(if hypersnap { ALL[index] } else { LEGACY[index] })
}
/// Preserve Snapchain's content IDs on legacy topics. Include the topic only
/// for Hypersnap so transition subscriptions cannot suppress each other's data.
pub fn message_id(topic: &str, data: &[u8]) -> String {
    use std::hash::{DefaultHasher, Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    if topic.starts_with("hypersnap/") {
        topic.hash(&mut hasher);
    }
    data.hash(&mut hasher);
    hasher.finish().to_string()
}
