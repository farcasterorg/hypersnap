#![allow(dead_code)]

use hypersnap_ktrie::{reference, Hash, KTrie, MemStore, NodeKey, Op, Path};
use std::collections::BTreeMap;

/// splitmix64: small deterministic RNG for reproducible randomized tests.
pub struct Rng(pub u64);

impl Rng {
    pub fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    pub fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }

    pub fn bytes(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| self.next() as u8).collect()
    }

    /// Random bytes with a length in `lo..hi`.
    pub fn bytes_in(&mut self, lo: usize, hi: usize) -> Vec<u8> {
        let len = lo + self.below((hi - lo) as u64) as usize;
        self.bytes(len)
    }
}

pub type Model = BTreeMap<Vec<u8>, Vec<u8>>;

pub fn model_root(model: &Model) -> Hash {
    let entries: Vec<_> = model.iter().collect();
    reference::root(&entries)
}

pub fn model_leaves(model: &Model) -> Vec<(Path, Hash)> {
    let entries: Vec<_> = model.iter().collect();
    reference::leaves_of(&entries)
}

pub fn new_trie() -> KTrie<MemStore> {
    KTrie::open(MemStore::new()).unwrap()
}

/// A trie built from scratch with one batch holding the whole model.
pub fn fresh(model: &Model) -> KTrie<MemStore> {
    let mut t = new_trie();
    t.apply(model.iter().map(|(k, v)| (k, Some(v)))).unwrap();
    t.commit_to_store().unwrap();
    t
}

pub fn records(t: &KTrie<MemStore>) -> Vec<(NodeKey, Vec<u8>)> {
    t.store().records()
}

/// An op with a crafted path (the key is only a label).
pub fn path_op(path: Path, value: Option<&[u8]>) -> Op {
    Op {
        path,
        key: path[..4].to_vec(),
        value_hash: value.map(hypersnap_ktrie::value_hash),
    }
}

pub fn path_with_bits(bits: &[(usize, bool)]) -> Path {
    let mut p = [0u8; 32];
    for &(i, on) in bits {
        if on {
            p[i / 8] |= 0x80 >> (i % 8);
        }
    }
    p
}
