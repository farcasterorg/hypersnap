//! Inclusion and non-inclusion proofs, their compact encoding, and pure
//! (store-free) verification.
//!
//! # Proof semantics
//!
//! A proof for path `p` names a terminal subtree `T` at depth `D`: the subtree
//! whose path prefix is the first `D` bits of `p`. It carries the `D` sibling
//! hashes along the way: `siblings[i]` is the hash of the depth-`i + 1`
//! subtree whose prefix is `p[0..i] || !p[i]`. The terminal says what `T` is:
//!
//! * [`Terminal::Included`]: `T` is the single leaf of `p` itself
//!   (inclusion; the verifier supplies the value).
//! * [`Terminal::Empty`]: `T` is empty (non-inclusion).
//! * [`Terminal::OtherLeaf`]: `T` is a single leaf of a different path `q`
//!   with `q[0..D] == p[0..D]` (non-inclusion).
//!
//! Verification recomputes `h = hash(T)` (`leaf(p, vh)`, `0`, or
//! `leaf(q, vh_q)`) and folds upward: for `i = D-1 .. 0`,
//! `h = inner(h, siblings[i])` if bit `i` of `p` is 0, else
//! `h = inner(siblings[i], h)`. The proof is valid iff `h == root`.
//!
//! Canonical proofs are minimal: `D` is the shallowest depth at which the
//! subtree of `p` has at most one leaf, so when `D > 0` the deepest sibling
//! `siblings[D-1]` is never empty. The verifier rejects proofs that violate
//! this. (Soundness does not depend on that check — a longer or shorter proof
//! would need a Keccak collision between a leaf, an inner node and `0` — but it
//! makes the accepted encoding unique.)
//!
//! # Encoding
//!
//! ```text
//! proof    = kind(1) || D(u16 BE) || bitmap(ceil(D/8)) || siblings || terminal
//! kind     = 0x00 included | 0x01 empty | 0x02 other leaf
//! bitmap   = bit i (MSB-first: byte i/8, mask 0x80 >> (i%8)) is set iff
//!            siblings[i] != 0; padding bits after bit D-1 are zero
//! siblings = the non-zero siblings, 32 bytes each, in level order 0 .. D-1
//!            (root side first)
//! terminal = empty for kinds 0x00 and 0x01;
//!            path_q(32) || value_hash_q(32) for kind 0x02
//! ```
//!
//! Decoding is strict: unknown kind, `D > 256`, non-zero padding bits, an
//! explicitly encoded zero sibling, or a length mismatch are errors.

use crate::hash::{bit, common_prefix_len, inner_hash, leaf_hash, path_of, value_hash};
use crate::hash::{Hash, Path, PATH_BITS, ZERO};
use std::fmt;

/// What the subtree at the end of the proof path is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Terminal {
    /// The queried key's own leaf (inclusion).
    Included,
    /// An empty subtree (non-inclusion).
    Empty,
    /// A single leaf of a different key whose path shares the first `D` bits
    /// (non-inclusion).
    OtherLeaf {
        /// That leaf's path.
        path: Path,
        /// That leaf's value hash.
        value_hash: Hash,
    },
}

/// A Merkle proof for one path. See the [module docs](self).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proof {
    /// Sibling hashes from the root (level 0) down to level `D - 1`.
    pub siblings: Vec<Hash>,
    /// The terminal subtree at depth `D = siblings.len()`.
    pub terminal: Terminal,
}

/// Why proof bytes failed to decode.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProofError {
    /// Fewer bytes than the header and bitmap need, or extra bytes.
    Length,
    /// Unknown kind byte.
    Kind(u8),
    /// `D > 256`.
    Depth(u16),
    /// A bitmap padding bit is set.
    Padding,
    /// A sibling marked non-empty in the bitmap is zero.
    ZeroSibling(usize),
}

impl fmt::Display for ProofError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProofError::Length => write!(f, "proof length mismatch"),
            ProofError::Kind(k) => write!(f, "unknown proof kind {k:#04x}"),
            ProofError::Depth(d) => write!(f, "proof depth {d} exceeds 256"),
            ProofError::Padding => write!(f, "non-zero bitmap padding"),
            ProofError::ZeroSibling(i) => write!(f, "sibling {i} encoded but zero"),
        }
    }
}

impl std::error::Error for ProofError {}

const KIND_INCLUDED: u8 = 0x00;
const KIND_EMPTY: u8 = 0x01;
const KIND_OTHER_LEAF: u8 = 0x02;

impl Proof {
    /// `D`: the depth of the terminal subtree.
    pub fn depth(&self) -> usize {
        self.siblings.len()
    }

    /// `true` for an inclusion proof.
    pub fn is_inclusion(&self) -> bool {
        self.terminal == Terminal::Included
    }

    /// The compact encoding (see the [module docs](self)).
    pub fn encode(&self) -> Vec<u8> {
        let d = self.siblings.len();
        assert!(d <= PATH_BITS, "proof deeper than 256 levels");
        let nonzero = self.siblings.iter().filter(|s| **s != ZERO).count();
        let mut out = Vec::with_capacity(3 + d.div_ceil(8) + 32 * nonzero + 64);
        out.push(match self.terminal {
            Terminal::Included => KIND_INCLUDED,
            Terminal::Empty => KIND_EMPTY,
            Terminal::OtherLeaf { .. } => KIND_OTHER_LEAF,
        });
        out.extend_from_slice(&(d as u16).to_be_bytes());
        let mut bitmap = vec![0u8; d.div_ceil(8)];
        for (i, s) in self.siblings.iter().enumerate() {
            if *s != ZERO {
                bitmap[i / 8] |= 0x80 >> (i % 8);
            }
        }
        out.extend_from_slice(&bitmap);
        for s in self.siblings.iter().filter(|s| **s != ZERO) {
            out.extend_from_slice(s);
        }
        if let Terminal::OtherLeaf { path, value_hash } = &self.terminal {
            out.extend_from_slice(path);
            out.extend_from_slice(value_hash);
        }
        out
    }

    /// Strict inverse of [`Proof::encode`].
    pub fn decode(bytes: &[u8]) -> Result<Proof, ProofError> {
        if bytes.len() < 3 {
            return Err(ProofError::Length);
        }
        let kind = bytes[0];
        if kind > KIND_OTHER_LEAF {
            return Err(ProofError::Kind(kind));
        }
        let d16 = u16::from_be_bytes([bytes[1], bytes[2]]);
        if d16 as usize > PATH_BITS {
            return Err(ProofError::Depth(d16));
        }
        let d = d16 as usize;
        let bm_len = d.div_ceil(8);
        let bitmap = bytes.get(3..3 + bm_len).ok_or(ProofError::Length)?;
        if !d.is_multiple_of(8) && bitmap[bm_len - 1] & (0xffu8 >> (d % 8)) != 0 {
            return Err(ProofError::Padding);
        }
        let mut pos = 3 + bm_len;
        let mut siblings = Vec::with_capacity(d);
        for i in 0..d {
            if bitmap[i / 8] & (0x80 >> (i % 8)) != 0 {
                let s: Hash = bytes
                    .get(pos..pos + 32)
                    .ok_or(ProofError::Length)?
                    .try_into()
                    .unwrap();
                if s == ZERO {
                    return Err(ProofError::ZeroSibling(i));
                }
                siblings.push(s);
                pos += 32;
            } else {
                siblings.push(ZERO);
            }
        }
        let rest = &bytes[pos..];
        let terminal = match (kind, rest.len()) {
            (KIND_INCLUDED, 0) => Terminal::Included,
            (KIND_EMPTY, 0) => Terminal::Empty,
            (KIND_OTHER_LEAF, 64) => Terminal::OtherLeaf {
                path: rest[..32].try_into().unwrap(),
                value_hash: rest[32..].try_into().unwrap(),
            },
            _ => return Err(ProofError::Length),
        };
        Ok(Proof { siblings, terminal })
    }
}

/// Verify `proof` for `key` against `root`. `value = Some(v)` checks that the
/// trie maps `key` to `v`; `value = None` checks that `key` is absent.
pub fn verify_proof(root: &Hash, key: &[u8], value: Option<&[u8]>, proof: &Proof) -> bool {
    let vh = value.map(value_hash);
    verify_proof_hashed(root, &path_of(key), vh.as_ref(), proof)
}

/// [`verify_proof`] on pre-hashed inputs: `path = keccak256(key)`,
/// `value_hash = keccak256(v)`.
pub fn verify_proof_hashed(
    root: &Hash,
    path: &Path,
    value_hash: Option<&Hash>,
    proof: &Proof,
) -> bool {
    let d = proof.siblings.len();
    if d > PATH_BITS || (d > 0 && proof.siblings[d - 1] == ZERO) {
        return false;
    }
    let mut h = match (&proof.terminal, value_hash) {
        (Terminal::Included, Some(vh)) => leaf_hash(path, vh),
        (Terminal::Empty, None) => ZERO,
        (
            Terminal::OtherLeaf {
                path: q,
                value_hash: vq,
            },
            None,
        ) => {
            if q == path || common_prefix_len(q, path) < d {
                return false;
            }
            leaf_hash(q, vq)
        }
        _ => return false,
    };
    for i in (0..d).rev() {
        h = if bit(path, i) == 0 {
            inner_hash(&h, &proof.siblings[i])
        } else {
            inner_hash(&proof.siblings[i], &h)
        };
    }
    h == *root
}

/// Decode `proof` and [`verify_proof`] it; malformed bytes verify as `false`.
pub fn verify_proof_bytes(root: &Hash, key: &[u8], value: Option<&[u8]>, proof: &[u8]) -> bool {
    Proof::decode(proof).is_ok_and(|p| verify_proof(root, key, value, &p))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::keccak256;

    #[test]
    fn encoding_roundtrip_and_strictness() {
        let mut sibs = vec![ZERO; 11];
        sibs[2] = keccak256(b"a");
        sibs[10] = keccak256(b"b");
        let p = Proof {
            siblings: sibs,
            terminal: Terminal::OtherLeaf {
                path: keccak256(b"q"),
                value_hash: keccak256(b"v"),
            },
        };
        let bytes = p.encode();
        assert_eq!(bytes.len(), 3 + 2 + 64 + 64);
        assert_eq!(Proof::decode(&bytes).unwrap(), p);

        let mut bad = bytes.clone();
        bad.push(0);
        assert_eq!(Proof::decode(&bad), Err(ProofError::Length));
        let mut bad = bytes.clone();
        bad[4] |= 0x01; // padding bit (D = 11)
        assert_eq!(Proof::decode(&bad), Err(ProofError::Padding));
        let mut bad = bytes.clone();
        bad[0] = 7;
        assert_eq!(Proof::decode(&bad), Err(ProofError::Kind(7)));
        let mut bad = bytes.clone();
        bad[1..3].copy_from_slice(&257u16.to_be_bytes());
        assert_eq!(Proof::decode(&bad), Err(ProofError::Depth(257)));
        let mut bad = bytes.clone();
        bad[5..37].fill(0);
        assert_eq!(Proof::decode(&bad), Err(ProofError::ZeroSibling(2)));

        let empty = Proof {
            siblings: vec![],
            terminal: Terminal::Empty,
        };
        assert_eq!(empty.encode(), vec![1, 0, 0]);
        assert_eq!(Proof::decode(&[1, 0, 0]).unwrap(), empty);
    }

    #[test]
    fn single_leaf_and_empty_roots() {
        let empty = Proof {
            siblings: vec![],
            terminal: Terminal::Empty,
        };
        assert!(verify_proof(&ZERO, b"k", None, &empty));
        assert!(!verify_proof(&ZERO, b"k", Some(b"v"), &empty));

        let root = crate::hash::leaf_hash_kv(b"k", b"v");
        let incl = Proof {
            siblings: vec![],
            terminal: Terminal::Included,
        };
        assert!(verify_proof(&root, b"k", Some(b"v"), &incl));
        assert!(!verify_proof(&root, b"k", Some(b"w"), &incl));
        let other = Proof {
            siblings: vec![],
            terminal: Terminal::OtherLeaf {
                path: path_of(b"k"),
                value_hash: value_hash(b"v"),
            },
        };
        assert!(verify_proof(&root, b"j", None, &other));
        // A leaf cannot prove its own key absent.
        assert!(!verify_proof(&root, b"k", None, &other));
    }
}
