//! Hash primitives and bit-path helpers (FIP §16.13).
//!
//! All hashing is Ethereum Keccak-256 (the original Keccak padding `0x01`),
//! **not** FIPS-202 SHA3-256 (padding `0x06`). `keccak256("")` is
//! `c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470`.

use sha3::{Digest, Keccak256};

/// A 32-byte Keccak-256 digest.
pub type Hash = [u8; 32];

/// A 256-bit trie path: `keccak256(key)`. Bit 0 is the most significant bit
/// of byte 0.
pub type Path = [u8; 32];

/// Number of bits in a path, and the maximum depth of a subtree.
pub const PATH_BITS: usize = 256;

/// The hash of an empty subtree: 32 zero bytes.
pub const ZERO: Hash = [0u8; 32];

/// Domain-separation prefix of a leaf preimage.
pub const LEAF_PREFIX: u8 = 0x00;

/// Domain-separation prefix of an inner-node preimage.
pub const INNER_PREFIX: u8 = 0x01;

/// Ethereum Keccak-256 of `data`.
#[inline]
pub fn keccak256(data: &[u8]) -> Hash {
    Keccak256::digest(data).into()
}

/// `path(key) = keccak256(key)`.
#[inline]
pub fn path_of(key: &[u8]) -> Path {
    keccak256(key)
}

/// `keccak256(v)`: the trie commits to the hash of a value, never the value.
#[inline]
pub fn value_hash(value: &[u8]) -> Hash {
    keccak256(value)
}

/// `leaf = keccak256(0x00 || path || value_hash)`, where `path = keccak256(key)`
/// and `value_hash = keccak256(v)`.
#[inline]
pub fn leaf_hash(path: &Path, value_hash: &Hash) -> Hash {
    let mut buf = [0u8; 65];
    buf[0] = LEAF_PREFIX;
    buf[1..33].copy_from_slice(path);
    buf[33..].copy_from_slice(value_hash);
    keccak256(&buf)
}

/// `leaf(key, v)` computed from the raw key and value.
#[inline]
pub fn leaf_hash_kv(key: &[u8], value: &[u8]) -> Hash {
    leaf_hash(&path_of(key), &value_hash(value))
}

/// `inner(l, r) = keccak256(0x01 || l || r)`.
#[inline]
pub fn inner_hash(left: &Hash, right: &Hash) -> Hash {
    let mut buf = [0u8; 65];
    buf[0] = INNER_PREFIX;
    buf[1..33].copy_from_slice(left);
    buf[33..].copy_from_slice(right);
    keccak256(&buf)
}

/// Bit `i` of `path` (0 = most significant bit of byte 0). `0` selects the
/// left child and `1` the right child at depth `i`.
#[inline]
pub fn bit(path: &Path, i: usize) -> usize {
    debug_assert!(i < PATH_BITS);
    ((path[i >> 3] >> (7 - (i & 7))) & 1) as usize
}

/// Length in bits of the common prefix of `a` and `b` (256 if equal).
#[inline]
pub fn common_prefix_len(a: &Path, b: &Path) -> usize {
    for (i, (x, y)) in a.iter().zip(b.iter()).enumerate() {
        let d = x ^ y;
        if d != 0 {
            return i * 8 + d.leading_zeros() as usize;
        }
    }
    PATH_BITS
}

/// `path` with every bit at index `>= bits` cleared.
#[inline]
pub fn mask_prefix(path: &Path, bits: usize) -> Path {
    let mut out = [0u8; 32];
    let full = bits / 8;
    out[..full].copy_from_slice(&path[..full]);
    let rem = bits % 8;
    if rem != 0 {
        out[full] = path[full] & (0xffu8 << (8 - rem));
    }
    out
}

/// Lift the hash `h` of a subtree with at least two leaves from depth `from`
/// up to depth `to <= from`. Every level in `[to, from)` has an empty sibling,
/// because all leaves below share the bits of `prefix` there:
/// `h = inner(h, 0)` if the bit is 0, else `h = inner(0, h)`.
///
/// Never call this for a single leaf: a one-leaf subtree hashes as the leaf at
/// every depth (path compression).
#[inline]
pub(crate) fn fold(mut h: Hash, from: usize, to: usize, prefix: &Path) -> Hash {
    debug_assert!(to <= from && from <= PATH_BITS);
    for level in (to..from).rev() {
        h = if bit(prefix, level) == 0 {
            inner_hash(&h, &ZERO)
        } else {
            inner_hash(&ZERO, &h)
        };
    }
    h
}

/// The next path in path order (`path + 1` as a 256-bit big-endian integer),
/// or `None` for the all-ones path.
pub fn path_successor(path: &Path) -> Option<Path> {
    let mut out = *path;
    for byte in out.iter_mut().rev() {
        if *byte == 0xff {
            *byte = 0;
        } else {
            *byte += 1;
            return Some(out);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(h: &[u8]) -> String {
        h.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn keccak_is_ethereum_keccak_not_sha3() {
        assert_eq!(
            hex(&keccak256(b"")),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        );
        // SHA3-256("") would be a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a.
        assert_eq!(
            hex(&keccak256(b"abc")),
            "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"
        );
    }

    #[test]
    fn bits_are_msb_first() {
        let mut p = [0u8; 32];
        p[0] = 0b1000_0000;
        assert_eq!(bit(&p, 0), 1);
        assert_eq!(bit(&p, 1), 0);
        p[31] = 1;
        assert_eq!(bit(&p, 255), 1);
        assert_eq!(bit(&p, 254), 0);
    }

    #[test]
    fn prefix_helpers() {
        let a = [0xffu8; 32];
        let mut b = a;
        b[3] = 0b1110_1111;
        assert_eq!(common_prefix_len(&a, &b), 27);
        assert_eq!(common_prefix_len(&a, &a), 256);
        let m = mask_prefix(&a, 13);
        assert_eq!(m[0], 0xff);
        assert_eq!(m[1], 0b1111_1000);
        assert!(m[2..].iter().all(|&x| x == 0));
        assert_eq!(mask_prefix(&a, 0), [0u8; 32]);
        assert_eq!(mask_prefix(&a, 256), a);
    }

    #[test]
    fn successor() {
        let mut p = [0u8; 32];
        p[31] = 0xff;
        let s = path_successor(&p).unwrap();
        assert_eq!(s[30], 1);
        assert_eq!(s[31], 0);
        assert_eq!(path_successor(&[0xff; 32]), None);
    }

    #[test]
    fn fold_matches_explicit_chain() {
        let h = keccak256(b"x");
        let mut prefix = [0u8; 32];
        prefix[0] = 0b0100_0000; // bits: 0, 1, 0, ...
        let expected = inner_hash(&inner_hash(&ZERO, &inner_hash(&h, &ZERO)), &ZERO);
        assert_eq!(fold(h, 3, 0, &prefix), expected);
        assert_eq!(fold(h, 3, 3, &prefix), h);
    }
}
