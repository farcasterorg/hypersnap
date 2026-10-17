//! The stored trie: batched updates, commit/rollback, reads, proofs, seeks.

use crate::cache::NodeCache;
use crate::hash::{
    bit, common_prefix_len, fold, inner_hash, leaf_hash, mask_prefix, path_of, path_successor,
    value_hash, Hash, Path, PATH_BITS, ZERO,
};
use crate::node::{decode_root, encode_root, BranchNode, ChildRef, LeafNode, Node, NodeKey, Slot};
use crate::proof::{Proof, Terminal};
use crate::store::{CommitBatch, NodeStore, StoreError};
use foldhash::HashMap;
use std::cmp::Ordering;
use std::fmt;
use std::sync::{Mutex, MutexGuard};

/// Default node-cache capacity, in decoded nodes.
pub const DEFAULT_CACHE_NODES: usize = 1 << 20;

/// A trie error.
#[derive(Debug)]
pub enum TrieError {
    /// The backend failed.
    Store(StoreError),
    /// A record the trie structure points to is absent.
    MissingNode(NodeKey),
    /// A record failed to decode or contradicts its key.
    Corrupt {
        /// The record's key.
        key: NodeKey,
        /// What was wrong.
        reason: &'static str,
    },
}

impl fmt::Display for TrieError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TrieError::Store(e) => write!(f, "{e}"),
            TrieError::MissingNode(k) => write!(f, "missing trie node {k:?}"),
            TrieError::Corrupt { key, reason } => write!(f, "corrupt trie node {key:?}: {reason}"),
        }
    }
}

impl std::error::Error for TrieError {}

impl From<StoreError> for TrieError {
    fn from(e: StoreError) -> Self {
        TrieError::Store(e)
    }
}

/// One update: put `key -> value_hash`, or delete `key` (`value_hash: None`).
///
/// `path` must be `keccak256(key)`; the constructors compute it. Callers that
/// already hold the hashes (or tests that need crafted paths) may build the
/// struct directly.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Op {
    /// `keccak256(key)`.
    pub path: Path,
    /// The original key, stored in the leaf.
    pub key: Vec<u8>,
    /// `Some(keccak256(value))` to put, `None` to delete.
    pub value_hash: Option<Hash>,
}

impl Op {
    /// Put `key -> value`.
    pub fn put(key: impl Into<Vec<u8>>, value: &[u8]) -> Self {
        Self::put_hashed(key, value_hash(value))
    }

    /// Put `key -> value` given `value_hash = keccak256(value)`.
    pub fn put_hashed(key: impl Into<Vec<u8>>, value_hash: Hash) -> Self {
        let key = key.into();
        Op {
            path: path_of(&key),
            key,
            value_hash: Some(value_hash),
        }
    }

    /// Delete `key`.
    pub fn delete(key: impl Into<Vec<u8>>) -> Self {
        let key = key.into();
        Op {
            path: path_of(&key),
            key,
            value_hash: None,
        }
    }
}

/// A leaf returned by [`KTrie::first_at_or_after`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LeafEntry {
    /// `keccak256(key)`.
    pub path: Path,
    /// The original key.
    pub key: Vec<u8>,
    /// `keccak256(value)`.
    pub value_hash: Hash,
}

/// Compare the first `bits` bits of `path` with `prefix` (masked to `bits`).
#[inline]
fn cmp_prefix(path: &Path, prefix: &Path, bits: usize) -> Ordering {
    let j = common_prefix_len(path, prefix);
    if j >= bits {
        Ordering::Equal
    } else if bit(path, j) == 0 {
        Ordering::Less
    } else {
        Ordering::Greater
    }
}

/// A subtree during an update: its slot plus the depth `at` its hash is
/// valid for. Leaf hashes are valid at every depth. A branch hash can be
/// lifted to any depth `<= at` with [`fold`], never pushed deeper.
#[derive(Clone, Copy, Debug)]
struct Item {
    slot: Slot,
    at: usize,
}

impl Item {
    fn leaf(path: Path, hash: Hash) -> Self {
        Item {
            slot: Slot {
                child: ChildRef::Leaf(path),
                hash,
                count: 1,
            },
            at: PATH_BITS,
        }
    }

    fn branch(node: &BranchNode, prefix: Path) -> Self {
        Item {
            slot: Slot {
                child: ChildRef::Branch {
                    depth: node.depth,
                    prefix,
                },
                hash: node.hash(),
                count: node.count(),
            },
            at: node.depth as usize,
        }
    }

    fn path(&self) -> &Path {
        self.slot.child.path()
    }

    /// The slot this subtree occupies when placed at depth `pos`.
    fn slot_at(&self, pos: usize) -> Slot {
        match &self.slot.child {
            ChildRef::Leaf(_) => self.slot,
            ChildRef::Branch { prefix, .. } => {
                assert!(pos <= self.at, "cannot push a branch hash deeper");
                Slot {
                    hash: fold(self.slot.hash, self.at, pos, prefix),
                    ..self.slot
                }
            }
        }
    }
}

/// The Keccak-256 sparse binary Merkle trie over a [`NodeStore`].
///
/// Reads go through three layers before the store: the *pending* overlay
/// (uncommitted updates), the *staged* layer (the last [`CommitBatch`], which
/// the caller may not have written yet), and a bounded cache of decoded,
/// store-confirmed nodes. See the crate docs ("Commit and rollback").
pub struct KTrie<S> {
    store: S,
    root: Option<Slot>,
    committed_root: Option<Slot>,
    pending: HashMap<NodeKey, Option<Node>>,
    staged: HashMap<NodeKey, Option<Node>>,
    cache: Mutex<NodeCache>,
}

impl<S: NodeStore> KTrie<S> {
    /// Open the trie in `store` (an empty store is an empty trie), with the
    /// default cache size.
    pub fn open(store: S) -> Result<Self, TrieError> {
        Self::open_with_cache(store, DEFAULT_CACHE_NODES)
    }

    /// Open with a cache of at most `cache_nodes` decoded nodes (0 disables it).
    pub fn open_with_cache(store: S, cache_nodes: usize) -> Result<Self, TrieError> {
        let mut t = KTrie {
            store,
            root: None,
            committed_root: None,
            pending: HashMap::default(),
            staged: HashMap::default(),
            cache: Mutex::new(NodeCache::new(cache_nodes)),
        };
        t.reload()?;
        Ok(t)
    }

    /// The backing store.
    pub fn store(&self) -> &S {
        &self.store
    }

    /// The backing store, mutably (to apply a [`CommitBatch`]).
    pub fn store_mut(&mut self) -> &mut S {
        &mut self.store
    }

    /// Consume the trie and return its store.
    pub fn into_store(self) -> S {
        self.store
    }

    /// The current state root, including uncommitted updates.
    pub fn root(&self) -> Hash {
        self.root.map_or(ZERO, |s| s.hash)
    }

    /// The root as of the last [`KTrie::commit`] / [`KTrie::reload`].
    pub fn committed_root(&self) -> Hash {
        self.committed_root.map_or(ZERO, |s| s.hash)
    }

    /// Number of keys, including uncommitted updates.
    pub fn len(&self) -> u64 {
        self.root.map_or(0, |s| s.count)
    }

    /// `true` if the trie has no keys.
    pub fn is_empty(&self) -> bool {
        self.root.is_none()
    }

    /// `true` if there are uncommitted updates.
    pub fn has_pending(&self) -> bool {
        !self.pending.is_empty() || self.root != self.committed_root
    }

    /// Number of decoded nodes in the cache.
    pub fn cached_nodes(&self) -> usize {
        self.cache().len()
    }

    // ---------------------------------------------------------------- updates

    /// Put `key -> value`.
    pub fn insert(&mut self, key: &[u8], value: &[u8]) -> Result<(), TrieError> {
        self.apply_ops(vec![Op::put(key, value)])
    }

    /// Delete `key` (no-op if absent).
    pub fn delete(&mut self, key: &[u8]) -> Result<(), TrieError> {
        self.apply_ops(vec![Op::delete(key)])
    }

    /// Apply `(key, Some(value))` puts and `(key, None)` deletes in one pass.
    /// Later operations on the same key override earlier ones.
    pub fn apply<K, V, I>(&mut self, ops: I) -> Result<(), TrieError>
    where
        K: AsRef<[u8]>,
        V: AsRef<[u8]>,
        I: IntoIterator<Item = (K, Option<V>)>,
    {
        let ops = ops
            .into_iter()
            .map(|(k, v)| match v {
                Some(v) => Op::put(k.as_ref(), v.as_ref()),
                None => Op::delete(k.as_ref()),
            })
            .collect();
        self.apply_ops(ops)
    }

    /// Apply prepared [`Op`]s in one pass: every touched node is read, rehashed
    /// and rewritten once. Later operations on the same path override earlier
    /// ones. The resulting root depends only on the final key/value set.
    pub fn apply_ops(&mut self, mut ops: Vec<Op>) -> Result<(), TrieError> {
        if ops.is_empty() {
            return Ok(());
        }
        // Stable sort, then keep the last op of each run of equal paths.
        ops.sort_by_key(|op| op.path);
        ops.dedup_by(|later, earlier| {
            if later.path == earlier.path {
                std::mem::swap(later, earlier);
                true
            } else {
                false
            }
        });
        self.pending.reserve(2 * ops.len());
        let cur = self.root.map(|slot| Item { slot, at: 0 });
        let new = self.apply_at(cur, 0, &mut ops)?;
        self.root = new.map(|item| item.slot_at(0));
        Ok(())
    }

    /// Update the subtree at depth `pos` whose current content is `cur`.
    /// Every op's path shares the subtree's first `pos` bits; `ops` is sorted
    /// with unique paths.
    fn apply_at(
        &mut self,
        cur: Option<Item>,
        pos: usize,
        ops: &mut [Op],
    ) -> Result<Option<Item>, TrieError> {
        if ops.is_empty() {
            return Ok(cur);
        }
        let Some(item) = cur else {
            let mut items = Vec::new();
            self.put_leaves(ops, &mut items);
            return Ok(self.build(pos, &items));
        };
        match item.slot.child {
            ChildRef::Leaf(q) => Ok(self.apply_leaf(item, q, pos, ops)),
            ChildRef::Branch { depth, prefix } => {
                self.apply_branch(item, depth as usize, prefix, pos, ops)
            }
        }
    }

    /// The subtree is the single leaf `q`. Leaves never move, so the old leaf
    /// record stays unless an op replaces or deletes it.
    fn apply_leaf(&mut self, item: Item, q: Path, pos: usize, ops: &mut [Op]) -> Option<Item> {
        let mut items = Vec::with_capacity(ops.len() + 1);
        let mut keep = true;
        for op in ops.iter_mut() {
            if op.path == q {
                match op.value_hash {
                    Some(vh) => {
                        let h = leaf_hash(&q, &vh);
                        if h != item.slot.hash {
                            keep = false;
                            items.push(self.put_leaf_hashed(op, vh, h));
                        } // else: same value, nothing to write
                    }
                    None => {
                        keep = false;
                        self.pending.insert(NodeKey::Leaf { path: q }, None);
                    }
                }
            } else if let Some(vh) = op.value_hash {
                items.push(self.put_leaf(op, vh));
            }
        }
        if keep {
            if items.is_empty() {
                return Some(item);
            }
            let at = items.partition_point(|it| it.path() < &q);
            items.insert(at, item);
        }
        self.build(pos, &items)
    }

    /// The subtree's top node is the branch at bit `b` under `prefix`, placed
    /// at depth `pos <= b`.
    fn apply_branch(
        &mut self,
        item: Item,
        b: usize,
        prefix: Path,
        pos: usize,
        ops: &mut [Op],
    ) -> Result<Option<Item>, TrieError> {
        // Sorted ops under `prefix` are contiguous; the ones before and after
        // diverge from it somewhere in [pos, b).
        let lo = ops.partition_point(|op| cmp_prefix(&op.path, &prefix, b) == Ordering::Less);
        let hi = lo
            + ops[lo..].partition_point(|op| cmp_prefix(&op.path, &prefix, b) == Ordering::Equal);
        let (before, rest) = ops.split_at_mut(lo);
        let (inside, after) = rest.split_at_mut(hi - lo);
        let outside_puts = before
            .iter()
            .chain(after.iter())
            .any(|op| op.value_hash.is_some());
        let key = NodeKey::Branch {
            depth: b as u8,
            prefix,
        };

        // `None` while the branch is untouched: `item` is still valid.
        let mut node: Option<BranchNode> = None;
        let mut changed = false;
        let mut inner = Some(item);
        if !inside.is_empty() {
            let old = self.read_branch(&key)?;
            node = Some(old);
            let split = inside.partition_point(|op| bit(&op.path, b) == 0);
            let (lops, rops) = inside.split_at_mut(split);
            let child = |i: usize| {
                Some(Item {
                    slot: old.children[i],
                    at: b + 1,
                })
            };
            let l = self.apply_at(child(0), b + 1, lops)?;
            let r = self.apply_at(child(1), b + 1, rops)?;
            match (l, r) {
                (Some(l), Some(r)) => {
                    let children = [l.slot_at(b + 1), r.slot_at(b + 1)];
                    if children != old.children {
                        let new = BranchNode {
                            depth: b as u8,
                            children,
                        };
                        self.pending.insert(key, Some(Node::Branch(new)));
                        node = Some(new);
                        inner = Some(Item::branch(&new, prefix));
                        changed = true;
                    }
                }
                // One side emptied: the branch disappears and the other side
                // takes its place (its hash is valid at b + 1 >= pos).
                (Some(x), None) | (None, Some(x)) => {
                    self.pending.insert(key, None);
                    inner = Some(x);
                    changed = true;
                }
                (None, None) => {
                    self.pending.insert(key, None);
                    inner = None;
                    changed = true;
                }
            }
        }
        if !outside_puts {
            return Ok(inner);
        }
        let mut items = Vec::with_capacity(before.len() + after.len() + 1);
        self.put_leaves(before, &mut items);
        if let Some(x) = inner {
            if changed {
                items.push(x);
            } else {
                // Unchanged: `item` only knows its hash at `pos`, but `build`
                // may place it deeper. Recompute it at the branch's own depth.
                let n = match node {
                    Some(n) => n,
                    None => self.read_branch(&key)?,
                };
                items.push(Item::branch(&n, prefix));
            }
        }
        self.put_leaves(after, &mut items);
        Ok(self.build(pos, &items))
    }

    fn put_leaf(&mut self, op: &mut Op, vh: Hash) -> Item {
        let h = leaf_hash(&op.path, &vh);
        self.put_leaf_hashed(op, vh, h)
    }

    /// Write the leaf of `op` given its leaf hash `h`.
    fn put_leaf_hashed(&mut self, op: &mut Op, vh: Hash, h: Hash) -> Item {
        let leaf = LeafNode {
            key: std::mem::take(&mut op.key),
            value_hash: vh,
        };
        self.pending
            .insert(NodeKey::Leaf { path: op.path }, Some(Node::Leaf(leaf)));
        Item::leaf(op.path, h)
    }

    fn put_leaves(&mut self, ops: &mut [Op], items: &mut Vec<Item>) {
        for op in ops.iter_mut() {
            if let Some(vh) = op.value_hash {
                items.push(self.put_leaf(op, vh));
            }
        }
    }

    /// Build the subtree at depth `pos` over `items` (sorted, disjoint paths),
    /// writing a branch wherever two items first diverge.
    fn build(&mut self, pos: usize, items: &[Item]) -> Option<Item> {
        match items {
            [] => None,
            [one] => Some(*one),
            [first, .., last] => {
                // For sorted paths the common prefix of all = that of the ends.
                let d = common_prefix_len(first.path(), last.path());
                debug_assert!(d >= pos && d < PATH_BITS);
                debug_assert!(items.iter().all(|it| it.slot.child.path_bits() > d));
                let split = items.partition_point(|it| bit(it.path(), d) == 0);
                let l = self.build(d + 1, &items[..split]).expect("left side");
                let r = self.build(d + 1, &items[split..]).expect("right side");
                let node = BranchNode {
                    depth: d as u8,
                    children: [l.slot_at(d + 1), r.slot_at(d + 1)],
                };
                let prefix = mask_prefix(first.path(), d);
                self.pending.insert(
                    NodeKey::Branch {
                        depth: d as u8,
                        prefix,
                    },
                    Some(Node::Branch(node)),
                );
                Some(Item::branch(&node, prefix))
            }
        }
    }

    // ------------------------------------------------------ commit / rollback

    /// Make the pending updates the committed state and return the writes that
    /// persist them, plus the new root.
    ///
    /// The batch stays readable inside the trie (the staged layer) until the
    /// next `commit`, so the caller can persist it whenever it persists the
    /// rest of the block, as long as that happens **before the next
    /// `commit`**. To abandon a batch that was never persisted, call
    /// [`KTrie::reload`].
    pub fn commit(&mut self) -> CommitBatch {
        let mut writes: Vec<(NodeKey, Option<Vec<u8>>)> = self
            .pending
            .iter()
            .map(|(k, v)| (*k, v.as_ref().map(Node::encode)))
            .collect();
        if self.root != self.committed_root {
            writes.push((NodeKey::Root, Some(encode_root(&self.root))));
        }
        writes.sort_unstable_by_key(|w| w.0);

        // The previous batch is persisted by now: move it into the cache.
        let persisted = std::mem::replace(&mut self.staged, std::mem::take(&mut self.pending));
        let cache = self.cache.get_mut().unwrap_or_else(|e| e.into_inner());
        for (k, v) in persisted {
            match v {
                Some(n) => cache.insert(k, n),
                None => cache.remove(&k),
            }
        }
        self.committed_root = self.root;
        CommitBatch {
            root: self.root(),
            len: self.len(),
            writes,
        }
    }

    /// [`KTrie::commit`] and apply the batch to the owned store.
    pub fn commit_to_store(&mut self) -> Result<CommitBatch, TrieError> {
        let batch = self.commit();
        self.store.apply(&batch)?;
        Ok(batch)
    }

    /// Discard the pending updates; the root returns to the committed root.
    pub fn rollback(&mut self) {
        self.pending.clear();
        self.root = self.committed_root;
    }

    /// Drop all in-memory state (pending, staged, cache) and re-read the root
    /// from the store, e.g. after a restart or to abandon an unpersisted
    /// [`CommitBatch`].
    pub fn reload(&mut self) -> Result<(), TrieError> {
        self.pending.clear();
        self.staged.clear();
        self.cache().clear();
        let root = match self.store.get(&NodeKey::Root)? {
            None => None,
            Some(bytes) => decode_root(&bytes).map_err(|reason| TrieError::Corrupt {
                key: NodeKey::Root,
                reason,
            })?,
        };
        self.root = root;
        self.committed_root = root;
        Ok(())
    }

    // ------------------------------------------------------------------ reads

    fn cache(&self) -> MutexGuard<'_, NodeCache> {
        self.cache.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn read_node(&self, key: &NodeKey) -> Result<Node, TrieError> {
        if let Some(entry) = self.pending.get(key).or_else(|| self.staged.get(key)) {
            return entry.clone().ok_or(TrieError::MissingNode(*key));
        }
        if let Some(n) = self.cache().get(key) {
            return Ok(n);
        }
        let bytes = self.store.get(key)?.ok_or(TrieError::MissingNode(*key))?;
        let node =
            Node::decode(key, &bytes).map_err(|reason| TrieError::Corrupt { key: *key, reason })?;
        self.cache().insert(*key, node.clone());
        Ok(node)
    }

    fn read_branch(&self, key: &NodeKey) -> Result<BranchNode, TrieError> {
        match self.read_node(key)? {
            Node::Branch(b) => Ok(b),
            Node::Leaf(_) => Err(TrieError::Corrupt {
                key: *key,
                reason: "expected a branch",
            }),
        }
    }

    fn read_leaf(&self, path: &Path) -> Result<LeafNode, TrieError> {
        let key = NodeKey::Leaf { path: *path };
        match self.read_node(&key)? {
            Node::Leaf(l) => Ok(l),
            Node::Branch(_) => Err(TrieError::Corrupt {
                key,
                reason: "expected a leaf",
            }),
        }
    }

    /// `keccak256(value)` for `key`, if present.
    pub fn get(&self, key: &[u8]) -> Result<Option<Hash>, TrieError> {
        Ok(self.get_leaf(&path_of(key))?.map(|l| l.value_hash))
    }

    /// `true` if `key` is present.
    pub fn contains(&self, key: &[u8]) -> Result<bool, TrieError> {
        Ok(self.get(key)?.is_some())
    }

    /// The leaf at `path`, if present.
    pub fn get_leaf(&self, path: &Path) -> Result<Option<LeafEntry>, TrieError> {
        let mut cur = self.root;
        while let Some(slot) = cur {
            match slot.child {
                ChildRef::Leaf(q) => {
                    if q != *path {
                        return Ok(None);
                    }
                    let leaf = self.read_leaf(&q)?;
                    return Ok(Some(LeafEntry {
                        path: q,
                        key: leaf.key,
                        value_hash: leaf.value_hash,
                    }));
                }
                ChildRef::Branch { depth, prefix } => {
                    let d = depth as usize;
                    if common_prefix_len(path, &prefix) < d {
                        return Ok(None);
                    }
                    let node = self.read_branch(&slot.child.node_key())?;
                    cur = Some(node.children[bit(path, d)]);
                }
            }
        }
        Ok(None)
    }

    // ----------------------------------------------------------------- proofs

    /// The canonical proof for `key`: inclusion if present, else
    /// non-inclusion. Verify with [`crate::verify_proof`].
    pub fn prove(&self, key: &[u8]) -> Result<Proof, TrieError> {
        self.prove_path(&path_of(key))
    }

    /// [`KTrie::prove`] for a path.
    pub fn prove_path(&self, path: &Path) -> Result<Proof, TrieError> {
        let mut siblings = Vec::new();
        let mut cur = self.root;
        let mut pos = 0;
        while let Some(slot) = cur {
            match slot.child {
                ChildRef::Leaf(q) => {
                    let terminal = if q == *path {
                        Terminal::Included
                    } else {
                        Terminal::OtherLeaf {
                            path: q,
                            value_hash: self.read_leaf(&q)?.value_hash,
                        }
                    };
                    return Ok(Proof { siblings, terminal });
                }
                ChildRef::Branch { depth, prefix } => {
                    let b = depth as usize;
                    let node = self.read_branch(&slot.child.node_key())?;
                    let j = common_prefix_len(path, &prefix);
                    if j < b {
                        // `path` leaves this subtree at bit j: the depth-(j+1)
                        // subtree on its side is empty, and the sibling there
                        // is this branch's subtree lifted to depth j + 1.
                        siblings.resize(j, ZERO);
                        siblings.push(fold(node.hash(), b, j + 1, &prefix));
                        return Ok(Proof {
                            siblings,
                            terminal: Terminal::Empty,
                        });
                    }
                    debug_assert!(siblings.len() == pos);
                    siblings.resize(b, ZERO);
                    let side = bit(path, b);
                    siblings.push(node.children[1 - side].hash);
                    cur = Some(node.children[side]);
                    pos = b + 1;
                }
            }
        }
        // Only reachable for the empty trie (branch children are never empty).
        Ok(Proof {
            siblings,
            terminal: Terminal::Empty,
        })
    }

    // ------------------------------------------------------------------ seeks

    /// The leaf with the smallest path `>= target`, in path (keccak) order.
    ///
    /// To find the first key under a bit prefix, pass the prefix padded with
    /// zero bits and check that the result still has the prefix.
    pub fn first_at_or_after(&self, target: &Path) -> Result<Option<LeafEntry>, TrieError> {
        let Some(path) = self.seek(self.root, target)? else {
            return Ok(None);
        };
        let leaf = self.read_leaf(&path)?;
        Ok(Some(LeafEntry {
            path,
            key: leaf.key,
            value_hash: leaf.value_hash,
        }))
    }

    /// The leaf with the smallest path `> target`.
    pub fn first_after(&self, target: &Path) -> Result<Option<LeafEntry>, TrieError> {
        match path_successor(target) {
            Some(next) => self.first_at_or_after(&next),
            None => Ok(None),
        }
    }

    fn seek(&self, cur: Option<Slot>, target: &Path) -> Result<Option<Path>, TrieError> {
        let Some(slot) = cur else { return Ok(None) };
        match slot.child {
            ChildRef::Leaf(q) => Ok((q >= *target).then_some(q)),
            ChildRef::Branch { depth, prefix } => {
                let b = depth as usize;
                let j = common_prefix_len(target, &prefix);
                if j < b {
                    // The whole subtree is above or below `target`.
                    return if bit(&prefix, j) == 1 {
                        self.min_leaf(slot).map(Some)
                    } else {
                        Ok(None)
                    };
                }
                let node = self.read_branch(&slot.child.node_key())?;
                if bit(target, b) == 1 {
                    return self.seek(Some(node.children[1]), target);
                }
                if let Some(p) = self.seek(Some(node.children[0]), target)? {
                    return Ok(Some(p));
                }
                self.min_leaf(node.children[1]).map(Some)
            }
        }
    }

    fn min_leaf(&self, mut slot: Slot) -> Result<Path, TrieError> {
        loop {
            match slot.child {
                ChildRef::Leaf(q) => return Ok(q),
                ChildRef::Branch { .. } => {
                    slot = self.read_branch(&slot.child.node_key())?.children[0];
                }
            }
        }
    }

    /// Recompute every hash below the root from the stored leaves and check
    /// the structure (counts, prefixes, compression). O(n); for tests and
    /// offline audits.
    pub fn check_integrity(&self) -> Result<(), TrieError> {
        let Some(root) = self.root else { return Ok(()) };
        let item = self.check_slot(&root)?;
        if item.slot_at(0) != root {
            return Err(TrieError::Corrupt {
                key: NodeKey::Root,
                reason: "root hash or count mismatch",
            });
        }
        Ok(())
    }

    /// Recompute the subtree of `slot` from its leaves; returns it at its own
    /// depth.
    fn check_slot(&self, slot: &Slot) -> Result<Item, TrieError> {
        let key = slot.child.node_key();
        match slot.child {
            ChildRef::Leaf(q) => {
                let leaf = self.read_leaf(&q)?;
                let h = leaf_hash(&q, &leaf.value_hash);
                if h != slot.hash || slot.count != 1 {
                    return Err(TrieError::Corrupt {
                        key,
                        reason: "leaf hash mismatch",
                    });
                }
                Ok(Item::leaf(q, h))
            }
            ChildRef::Branch { depth, prefix } => {
                let node = self.read_branch(&key)?;
                let d = depth as usize;
                let mut kids = [ZERO; 2];
                let mut count = 0;
                for (side, child) in node.children.iter().enumerate() {
                    let it = self.check_slot(child)?;
                    if it.slot_at(d + 1) != *child {
                        return Err(TrieError::Corrupt {
                            key,
                            reason: "child slot mismatch",
                        });
                    }
                    debug_assert_eq!(bit(child.child.path(), d), side);
                    kids[side] = child.hash;
                    count += child.count;
                }
                Ok(Item {
                    slot: Slot {
                        child: ChildRef::Branch { depth, prefix },
                        hash: inner_hash(&kids[0], &kids[1]),
                        count,
                    },
                    at: d,
                })
            }
        }
    }
}
