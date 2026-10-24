//! Bounded cache of decoded nodes.
//!
//! Two-generation approximation of LRU: lookups hit `hot`, then `cold` (and
//! promote to `hot`). When `hot` reaches half the capacity it becomes `cold`
//! and the old `cold` is dropped. O(1) per operation, no per-entry metadata,
//! and the upper trie levels (touched by every block) stay resident.

use crate::node::{Node, NodeKey};
use foldhash::HashMap;

pub(crate) struct NodeCache {
    half: usize,
    hot: HashMap<NodeKey, Node>,
    cold: HashMap<NodeKey, Node>,
}

impl NodeCache {
    pub(crate) fn new(capacity: usize) -> Self {
        NodeCache {
            half: capacity / 2,
            hot: HashMap::default(),
            cold: HashMap::default(),
        }
    }

    pub(crate) fn get(&mut self, key: &NodeKey) -> Option<Node> {
        if let Some(n) = self.hot.get(key) {
            return Some(n.clone());
        }
        let n = self.cold.remove(key)?;
        self.insert(*key, n.clone());
        Some(n)
    }

    /// `hot` always holds the newest version of a key inserted since the last
    /// rotation and is consulted first, so a stale copy left in `cold` is never
    /// returned; it disappears at the next rotation.
    pub(crate) fn insert(&mut self, key: NodeKey, node: Node) {
        if self.half == 0 {
            return;
        }
        self.hot.insert(key, node);
        if self.hot.len() >= self.half {
            // Pre-size the new generation: no rehashing while it fills.
            let fresh = HashMap::with_capacity_and_hasher(self.half, Default::default());
            self.cold = std::mem::replace(&mut self.hot, fresh);
        }
    }

    pub(crate) fn remove(&mut self, key: &NodeKey) {
        self.hot.remove(key);
        self.cold.remove(key);
    }

    pub(crate) fn clear(&mut self) {
        self.hot.clear();
        self.cold.clear();
    }

    pub(crate) fn len(&self) -> usize {
        self.hot.len() + self.cold.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::LeafNode;

    fn leaf(i: u8) -> (NodeKey, Node) {
        (
            NodeKey::Leaf { path: [i; 32] },
            Node::Leaf(LeafNode {
                key: vec![i],
                value_hash: [i; 32],
            }),
        )
    }

    #[test]
    fn bounded_and_promotes() {
        let mut c = NodeCache::new(4);
        for i in 0..10 {
            let (k, n) = leaf(i);
            c.insert(k, n);
            assert!(c.len() <= 4);
        }
        // The most recent inserts are resident.
        assert!(c.get(&leaf(9).0).is_some());
        assert!(c.get(&leaf(0).0).is_none());
        let mut z = NodeCache::new(0);
        let (k, n) = leaf(1);
        z.insert(k, n);
        assert_eq!(z.len(), 0);
    }
}
