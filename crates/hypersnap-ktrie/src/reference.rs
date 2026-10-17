//! Executable specification: a direct transcription of the hashing rules,
//! with no stored nodes, no folding shortcuts and no caching.
//!
//! ```text
//! H(S, d) = 0                                  if |S| = 0
//!         = leaf(k, v)                         if S = {(k, v)}
//!         = inner(H(S0, d+1), H(S1, d+1))      if |S| >= 2,
//!           where Sb = { x in S : bit d of path(x) = b }
//! root(S) = H(S, 0)
//! ```
//!
//! It recomputes every hash on each call (O(n · depth)). Tests compare the
//! stored trie against it; it is not meant for production use.

use crate::hash::{bit, inner_hash, leaf_hash, path_of, value_hash, Hash, Path, ZERO};
use crate::proof::{Proof, Terminal};

/// Sort `(path, value_hash)` leaves by path; for duplicate paths keep the last.
pub fn normalize(mut leaves: Vec<(Path, Hash)>) -> Vec<(Path, Hash)> {
    leaves.reverse();
    leaves.sort_by_key(|l| l.0); // stable: the last occurrence comes first
    leaves.dedup_by(|later, first| later.0 == first.0);
    leaves
}

/// Hash raw `(key, value)` entries into normalized leaves.
pub fn leaves_of<K: AsRef<[u8]>, V: AsRef<[u8]>>(entries: &[(K, V)]) -> Vec<(Path, Hash)> {
    normalize(
        entries
            .iter()
            .map(|(k, v)| (path_of(k.as_ref()), value_hash(v.as_ref())))
            .collect(),
    )
}

/// `H(S, depth)` for leaves sorted by path with unique paths.
pub fn subtree_hash(leaves: &[(Path, Hash)], depth: usize) -> Hash {
    match leaves {
        [] => ZERO,
        [(p, vh)] => leaf_hash(p, vh),
        _ => {
            let split = leaves.partition_point(|(p, _)| bit(p, depth) == 0);
            inner_hash(
                &subtree_hash(&leaves[..split], depth + 1),
                &subtree_hash(&leaves[split..], depth + 1),
            )
        }
    }
}

/// The state root of a set of `(key, value)` entries.
pub fn root<K: AsRef<[u8]>, V: AsRef<[u8]>>(entries: &[(K, V)]) -> Hash {
    subtree_hash(&leaves_of(entries), 0)
}

/// The canonical proof for `path` over normalized `leaves`.
pub fn prove(leaves: &[(Path, Hash)], path: &Path) -> Proof {
    let mut siblings = Vec::new();
    let mut set = leaves;
    let mut depth = 0;
    loop {
        match set {
            [] => {
                return Proof {
                    siblings,
                    terminal: Terminal::Empty,
                }
            }
            [(q, vh)] => {
                let terminal = if q == path {
                    Terminal::Included
                } else {
                    Terminal::OtherLeaf {
                        path: *q,
                        value_hash: *vh,
                    }
                };
                return Proof { siblings, terminal };
            }
            _ => {
                let split = set.partition_point(|(p, _)| bit(p, depth) == 0);
                let (left, right) = set.split_at(split);
                let (mine, other) = if bit(path, depth) == 0 {
                    (left, right)
                } else {
                    (right, left)
                };
                siblings.push(subtree_hash(other, depth + 1));
                set = mine;
                depth += 1;
            }
        }
    }
}
