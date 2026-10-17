//! Ordered Keccak-256 Merkle tree (RFC 6962 shape) for `messages_root`
//! (FIP §17.7) and `set_root` (FIP §16.6).
//!
//! ```text
//! MTH([])      = 32 zero bytes
//! MTH([d])     = keccak256(0x00 || d)
//! MTH(D[0..n]) = keccak256(0x01 || MTH(D[0..k]) || MTH(D[k..n]))
//!                where k is the largest power of two < n
//! ```
//!
//! The leaves keep their order; there is no sorting and no duplication of an
//! odd last node. A proof of leaf `i` is the list of sibling hashes from the
//! leaf up, as in RFC 6962 §2.1.1.

use alloy_primitives::keccak256;

pub const EMPTY_ROOT: [u8; 32] = [0u8; 32];

pub fn leaf_hash(data: &[u8]) -> [u8; 32] {
    let mut pre = Vec::with_capacity(1 + data.len());
    pre.push(0x00);
    pre.extend_from_slice(data);
    keccak256(&pre).0
}

pub fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut pre = [0u8; 65];
    pre[0] = 0x01;
    pre[1..33].copy_from_slice(left);
    pre[33..].copy_from_slice(right);
    keccak256(pre).0
}

fn split(n: usize) -> usize {
    debug_assert!(n > 1);
    let mut k = 1;
    while k << 1 < n {
        k <<= 1;
    }
    k
}

fn root_of_hashes(leaves: &[[u8; 32]]) -> [u8; 32] {
    match leaves.len() {
        0 => EMPTY_ROOT,
        1 => leaves[0],
        n => {
            let k = split(n);
            node_hash(&root_of_hashes(&leaves[..k]), &root_of_hashes(&leaves[k..]))
        }
    }
}

/// Root over the leaf data, in order.
pub fn root<D: AsRef<[u8]>>(items: &[D]) -> [u8; 32] {
    let leaves: Vec<[u8; 32]> = items.iter().map(|d| leaf_hash(d.as_ref())).collect();
    root_of_hashes(&leaves)
}

/// Audit path of leaf `index` (sibling hashes, leaf level first).
pub fn proof<D: AsRef<[u8]>>(items: &[D], index: usize) -> Option<Vec<[u8; 32]>> {
    if index >= items.len() {
        return None;
    }
    let leaves: Vec<[u8; 32]> = items.iter().map(|d| leaf_hash(d.as_ref())).collect();
    let mut path = Vec::new();
    path_of(&leaves, index, &mut path);
    Some(path)
}

fn path_of(leaves: &[[u8; 32]], index: usize, path: &mut Vec<[u8; 32]>) {
    let n = leaves.len();
    if n <= 1 {
        return;
    }
    let k = split(n);
    if index < k {
        path_of(&leaves[..k], index, path);
        path.push(root_of_hashes(&leaves[k..]));
    } else {
        path_of(&leaves[k..], index - k, path);
        path.push(root_of_hashes(&leaves[..k]));
    }
}

/// RFC 6962 §2.1.1.2 verification of an audit path.
pub fn verify(root: &[u8; 32], data: &[u8], index: usize, size: usize, path: &[[u8; 32]]) -> bool {
    if index >= size {
        return false;
    }
    let mut fn_ = index;
    let mut sn = size - 1;
    let mut r = leaf_hash(data);
    for p in path {
        if sn == 0 {
            return false;
        }
        if fn_ & 1 == 1 || fn_ == sn {
            r = node_hash(p, &r);
            while fn_ & 1 == 0 && fn_ != 0 {
                fn_ >>= 1;
                sn >>= 1;
            }
        } else {
            r = node_hash(&r, p);
        }
        fn_ >>= 1;
        sn >>= 1;
    }
    sn == 0 && &r == root
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shapes() {
        assert_eq!(root::<&[u8]>(&[]), EMPTY_ROOT);
        assert_eq!(root(&[b"a"]), leaf_hash(b"a"));
        let ab = node_hash(&leaf_hash(b"a"), &leaf_hash(b"b"));
        assert_eq!(root(&[b"a", b"b"]), ab);
        // n = 3: split at 2, no duplication of the odd node.
        assert_eq!(root(&[b"a", b"b", b"c"]), node_hash(&ab, &leaf_hash(b"c")));
        // Order matters.
        assert_ne!(root(&[b"b", b"a"]), ab);
    }

    #[test]
    fn proofs_verify_for_every_leaf_and_size() {
        for size in 1..40usize {
            let items: Vec<Vec<u8>> = (0..size)
                .map(|i| format!("item-{}", i).into_bytes())
                .collect();
            let r = root(&items);
            for i in 0..size {
                let p = proof(&items, i).unwrap();
                assert!(
                    verify(&r, &items[i], i, size, &p),
                    "size {} index {}",
                    size,
                    i
                );
                assert!(!verify(&r, b"other", i, size, &p));
                if size > 1 {
                    assert!(!verify(&r, &items[i], (i + 1) % size, size, &p));
                }
            }
        }
    }
}
