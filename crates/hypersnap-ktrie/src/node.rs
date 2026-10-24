//! Stored node types, node keys, and their byte encodings.
//!
//! See the crate docs ("Storage layout") for the design rationale.

use crate::hash::{bit, common_prefix_len, inner_hash, mask_prefix, Hash, Path, PATH_BITS};

/// The store key of a trie record.
///
/// Every key is a canonical function of the trie's key set; none depends on
/// node hashes or on history. See the crate docs ("Storage layout").
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum NodeKey {
    /// The root record: the root slot, or "empty trie".
    Root,
    /// The branch node at bit `depth` under `prefix` (first `depth` bits of
    /// the path; all later bits are zero). It exists iff the key set has keys
    /// with this prefix on both sides of bit `depth`.
    Branch {
        /// Index of the bit this node branches on (0..=255).
        depth: u8,
        /// The common path prefix, masked to `depth` bits.
        prefix: Path,
    },
    /// The leaf of the key whose path is `path`.
    Leaf {
        /// `keccak256(key)`.
        path: Path,
    },
}

impl NodeKey {
    /// Tag byte of the encoded root key.
    pub const ROOT_TAG: u8 = 0x00;
    /// Tag byte of an encoded branch key.
    pub const BRANCH_TAG: u8 = 0x01;
    /// Tag byte of an encoded leaf key.
    pub const LEAF_TAG: u8 = 0x02;

    /// The branch key at `depth` for any path under it (masks `path`).
    pub fn branch(depth: u8, path: &Path) -> Self {
        NodeKey::Branch {
            depth,
            prefix: mask_prefix(path, depth as usize),
        }
    }

    /// Append the canonical byte encoding to `out`:
    ///
    /// ```text
    /// Root            = 0x00
    /// Branch(d, P)    = 0x01 || d || P[0 .. ceil(d/8)]      (2..=34 bytes)
    /// Leaf(path)      = 0x02 || path                        (33 bytes)
    /// ```
    ///
    /// Byte order of encodings equals the derived `Ord` of `NodeKey`.
    pub fn encode_into(&self, out: &mut Vec<u8>) {
        match self {
            NodeKey::Root => out.push(Self::ROOT_TAG),
            NodeKey::Branch { depth, prefix } => {
                out.push(Self::BRANCH_TAG);
                out.push(*depth);
                out.extend_from_slice(&prefix[..prefix_bytes(*depth as usize)]);
            }
            NodeKey::Leaf { path } => {
                out.push(Self::LEAF_TAG);
                out.extend_from_slice(path);
            }
        }
    }

    /// The canonical byte encoding (see [`NodeKey::encode_into`]).
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(34);
        self.encode_into(&mut out);
        out
    }

    /// Strict inverse of [`NodeKey::encode`]; rejects non-canonical bytes.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        match bytes.split_first()? {
            (&Self::ROOT_TAG, []) => Some(NodeKey::Root),
            (&Self::BRANCH_TAG, rest) => {
                let (&depth, p) = rest.split_first()?;
                if p.len() != prefix_bytes(depth as usize) {
                    return None;
                }
                let mut prefix = [0u8; 32];
                prefix[..p.len()].copy_from_slice(p);
                (mask_prefix(&prefix, depth as usize) == prefix)
                    .then_some(NodeKey::Branch { depth, prefix })
            }
            (&Self::LEAF_TAG, rest) => Some(NodeKey::Leaf {
                path: rest.try_into().ok()?,
            }),
            _ => None,
        }
    }
}

#[inline]
fn prefix_bytes(bits: usize) -> usize {
    bits.div_ceil(8)
}

/// Reference from a parent to a child subtree's top stored node.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ChildRef {
    /// A single leaf (path-compressed: it hangs directly below the parent).
    Leaf(Path),
    /// A branch node deeper down; the levels in between are not stored.
    Branch { depth: u8, prefix: Path },
}

impl ChildRef {
    pub(crate) fn node_key(&self) -> NodeKey {
        match *self {
            ChildRef::Leaf(path) => NodeKey::Leaf { path },
            ChildRef::Branch { depth, prefix } => NodeKey::Branch { depth, prefix },
        }
    }

    /// The path bits this subtree is known to have: the full leaf path, or the
    /// branch prefix (zero beyond the branch depth).
    pub(crate) fn path(&self) -> &Path {
        match self {
            ChildRef::Leaf(p) => p,
            ChildRef::Branch { prefix, .. } => prefix,
        }
    }

    /// Number of meaningful bits in [`ChildRef::path`].
    pub(crate) fn path_bits(&self) -> usize {
        match self {
            ChildRef::Leaf(_) => PATH_BITS,
            ChildRef::Branch { depth, .. } => *depth as usize,
        }
    }
}

/// A child subtree as seen from its parent: its top node, its hash at the
/// parent's child depth, and its leaf count.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Slot {
    pub child: ChildRef,
    /// Subtree hash at the position this slot occupies (a branch child of a
    /// node at depth `d` occupies depth `d + 1`; the root slot depth 0).
    pub hash: Hash,
    pub count: u64,
}

/// A stored branch: both children are non-empty.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct BranchNode {
    pub depth: u8,
    /// `children[b]` holds the paths with bit `depth == b`; hashes are at
    /// depth `depth + 1`.
    pub children: [Slot; 2],
}

impl BranchNode {
    /// The subtree hash at the branch's own depth: `inner(left, right)`.
    pub(crate) fn hash(&self) -> Hash {
        inner_hash(&self.children[0].hash, &self.children[1].hash)
    }

    pub(crate) fn count(&self) -> u64 {
        self.children[0].count + self.children[1].count
    }
}

/// A stored leaf. The path is its [`NodeKey::Leaf`] key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LeafNode {
    /// The original key (so seeks can return keys; see crate docs).
    pub key: Vec<u8>,
    pub value_hash: Hash,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Node {
    Leaf(LeafNode),
    Branch(BranchNode),
}

const NODE_LEAF: u8 = 0x00;
const NODE_BRANCH: u8 = 0x01;
const NODE_ROOT: u8 = 0x02;
const SLOT_LEAF: u8 = 0x00;
const SLOT_BRANCH: u8 = 0x01;
const ROOT_EMPTY: u8 = 0x00;
const ROOT_SLOT: u8 = 0x01;

/// Why a stored record failed to decode.
pub(crate) type DecodeResult<T> = Result<T, &'static str>;

impl Node {
    /// Value encodings:
    ///
    /// ```text
    /// leaf   = 0x00 || value_hash(32) || key
    /// branch = 0x01 || slot(left) || slot(right)
    /// slot   = 0x00 || path(32) || hash(32)                                   (leaf child)
    ///        | 0x01 || depth || prefix[0 .. ceil(depth/8)] || hash(32) || count(u64 BE)
    /// ```
    pub(crate) fn encode(&self) -> Vec<u8> {
        match self {
            Node::Leaf(leaf) => {
                let mut out = Vec::with_capacity(33 + leaf.key.len());
                out.push(NODE_LEAF);
                out.extend_from_slice(&leaf.value_hash);
                out.extend_from_slice(&leaf.key);
                out
            }
            Node::Branch(b) => {
                let mut out = Vec::with_capacity(1 + 2 * 75);
                out.push(NODE_BRANCH);
                encode_slot(&b.children[0], &mut out);
                encode_slot(&b.children[1], &mut out);
                out
            }
        }
    }

    /// Decode the record stored under `key`, checking the structural
    /// invariants that tie it to its key.
    pub(crate) fn decode(key: &NodeKey, bytes: &[u8]) -> DecodeResult<Node> {
        match key {
            NodeKey::Leaf { .. } => {
                let (&tag, rest) = bytes.split_first().ok_or("empty leaf")?;
                if tag != NODE_LEAF || rest.len() < 32 {
                    return Err("bad leaf record");
                }
                Ok(Node::Leaf(LeafNode {
                    value_hash: rest[..32].try_into().unwrap(),
                    key: rest[32..].to_vec(),
                }))
            }
            NodeKey::Branch { depth, prefix } => {
                let (&tag, mut rest) = bytes.split_first().ok_or("empty branch")?;
                if tag != NODE_BRANCH {
                    return Err("bad branch tag");
                }
                let left = decode_slot(&mut rest)?;
                let right = decode_slot(&mut rest)?;
                if !rest.is_empty() {
                    return Err("trailing bytes in branch");
                }
                let d = *depth as usize;
                for (side, slot) in [(0, &left), (1, &right)] {
                    let p = slot.child.path();
                    if slot.child.path_bits() <= d
                        || common_prefix_len(p, prefix) < d
                        || bit(p, d) != side
                    {
                        return Err("branch child does not extend the branch prefix");
                    }
                }
                Ok(Node::Branch(BranchNode {
                    depth: *depth,
                    children: [left, right],
                }))
            }
            NodeKey::Root => Err("root record is not a node"),
        }
    }
}

fn encode_slot(slot: &Slot, out: &mut Vec<u8>) {
    match slot.child {
        ChildRef::Leaf(path) => {
            out.push(SLOT_LEAF);
            out.extend_from_slice(&path);
            out.extend_from_slice(&slot.hash);
        }
        ChildRef::Branch { depth, prefix } => {
            out.push(SLOT_BRANCH);
            out.push(depth);
            out.extend_from_slice(&prefix[..prefix_bytes(depth as usize)]);
            out.extend_from_slice(&slot.hash);
            out.extend_from_slice(&slot.count.to_be_bytes());
        }
    }
}

fn take<'a>(rest: &mut &'a [u8], n: usize) -> DecodeResult<&'a [u8]> {
    if rest.len() < n {
        return Err("truncated record");
    }
    let (head, tail) = rest.split_at(n);
    *rest = tail;
    Ok(head)
}

fn decode_slot(rest: &mut &[u8]) -> DecodeResult<Slot> {
    match take(rest, 1)?[0] {
        SLOT_LEAF => {
            let path: Path = take(rest, 32)?.try_into().unwrap();
            let hash: Hash = take(rest, 32)?.try_into().unwrap();
            Ok(Slot {
                child: ChildRef::Leaf(path),
                hash,
                count: 1,
            })
        }
        SLOT_BRANCH => {
            let depth = take(rest, 1)?[0];
            let p = take(rest, prefix_bytes(depth as usize))?;
            let mut prefix = [0u8; 32];
            prefix[..p.len()].copy_from_slice(p);
            if mask_prefix(&prefix, depth as usize) != prefix {
                return Err("unmasked branch prefix");
            }
            let hash: Hash = take(rest, 32)?.try_into().unwrap();
            let count = u64::from_be_bytes(take(rest, 8)?.try_into().unwrap());
            if count < 2 {
                return Err("branch child with fewer than two leaves");
            }
            Ok(Slot {
                child: ChildRef::Branch { depth, prefix },
                hash,
                count,
            })
        }
        _ => Err("bad slot tag"),
    }
}

/// Root record value: `0x02 || 0x00` (empty) or `0x02 || 0x01 || slot`.
pub(crate) fn encode_root(root: &Option<Slot>) -> Vec<u8> {
    let mut out = vec![NODE_ROOT];
    match root {
        None => out.push(ROOT_EMPTY),
        Some(slot) => {
            out.push(ROOT_SLOT);
            encode_slot(slot, &mut out);
        }
    }
    out
}

pub(crate) fn decode_root(bytes: &[u8]) -> DecodeResult<Option<Slot>> {
    match bytes {
        [NODE_ROOT, ROOT_EMPTY] => Ok(None),
        [NODE_ROOT, ROOT_SLOT, rest @ ..] => {
            let mut rest = rest;
            let slot = decode_slot(&mut rest)?;
            if !rest.is_empty() {
                return Err("trailing bytes in root record");
            }
            Ok(Some(slot))
        }
        _ => Err("bad root record"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::keccak256;

    #[test]
    fn node_key_roundtrip_and_order() {
        let p = keccak256(b"k");
        let keys = [
            NodeKey::Root,
            NodeKey::branch(0, &p),
            NodeKey::branch(5, &p),
            NodeKey::branch(17, &p),
            NodeKey::branch(255, &p),
            NodeKey::Leaf { path: p },
        ];
        for k in keys {
            assert_eq!(NodeKey::decode(&k.encode()), Some(k));
        }
        assert_eq!(NodeKey::branch(0, &p).encode(), vec![1, 0]);
        assert_eq!(NodeKey::branch(17, &p).encode().len(), 2 + 3);
        let mut sorted = keys.to_vec();
        sorted.sort();
        let mut by_bytes = keys.to_vec();
        by_bytes.sort_by_key(|k| k.encode());
        assert_eq!(sorted, by_bytes);
        // Non-canonical: prefix bits set beyond the depth.
        assert_eq!(NodeKey::decode(&[1, 1, 0xff]), None);
        assert_eq!(NodeKey::decode(&[1, 9, 0xff]), None);
        assert_eq!(NodeKey::decode(&[0, 0]), None);
    }

    #[test]
    fn branch_roundtrip() {
        let mut lp = [0u8; 32];
        lp[0] = 0b0010_0000;
        let mut rp = [0u8; 32];
        rp[0] = 0b0011_0000;
        let key = NodeKey::branch(3, &lp);
        let node = Node::Branch(BranchNode {
            depth: 3,
            children: [
                Slot {
                    child: ChildRef::Leaf(lp),
                    hash: keccak256(b"l"),
                    count: 1,
                },
                Slot {
                    child: ChildRef::Branch {
                        depth: 9,
                        prefix: mask_prefix(&rp, 9),
                    },
                    hash: keccak256(b"r"),
                    count: 7,
                },
            ],
        });
        let bytes = node.encode();
        assert_eq!(Node::decode(&key, &bytes).unwrap(), node);
        // The same record under a key it does not extend is rejected.
        assert!(Node::decode(&NodeKey::branch(2, &lp), &bytes).is_err());
        assert!(Node::decode(&NodeKey::branch(3, &[0xff; 32]), &bytes).is_err());
    }
}
