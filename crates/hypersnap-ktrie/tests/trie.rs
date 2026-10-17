mod common;

use common::*;
use hypersnap_ktrie::hash::{bit, PATH_BITS};
use hypersnap_ktrie::{
    inner_hash, leaf_hash, leaf_hash_kv, path_of, reference, value_hash, verify_proof_hashed, Hash,
    KTrie, MemStore, NodeKey, NodeStore, Op, Path, ZERO,
};
use std::collections::BTreeSet;

#[test]
fn empty_and_single_key_roots() {
    let mut t = new_trie();
    assert_eq!(t.root(), ZERO);
    assert_eq!(t.len(), 0);
    t.insert(b"k", b"v").unwrap();
    assert_eq!(t.root(), leaf_hash_kv(b"k", b"v"));
    assert_eq!(t.len(), 1);
    t.delete(b"k").unwrap();
    assert_eq!(t.root(), ZERO);
    assert!(t.is_empty());
    // Deleting an absent key, or from an empty trie, changes nothing.
    t.delete(b"nope").unwrap();
    assert_eq!(t.root(), ZERO);
}

#[test]
fn two_and_three_key_structure_matches_spec() {
    // Two paths that share exactly bits 0..3 = 1,0,1 and then split at bit 3.
    let a = path_with_bits(&[(0, true), (2, true)]); // 101 0...
    let b = path_with_bits(&[(0, true), (2, true), (3, true)]); // 101 1...
    let mut t = new_trie();
    t.apply_ops(vec![path_op(a, Some(b"va")), path_op(b, Some(b"vb"))])
        .unwrap();
    let la = leaf_hash(&a, &value_hash(b"va"));
    let lb = leaf_hash(&b, &value_hash(b"vb"));
    let expected = inner_hash(
        &ZERO,
        &inner_hash(&inner_hash(&ZERO, &inner_hash(&la, &lb)), &ZERO),
    );
    assert_eq!(t.root(), expected);

    // A third path diverging at bit 1 (11...) sits beside the a/b subtree.
    let c = path_with_bits(&[(0, true), (1, true)]);
    t.apply_ops(vec![path_op(c, Some(b"vc"))]).unwrap();
    let lc = leaf_hash(&c, &value_hash(b"vc"));
    let ab_at_2 = inner_hash(&ZERO, &inner_hash(&la, &lb)); // bit 2 = 1
    let expected3 = inner_hash(&ZERO, &inner_hash(&ab_at_2, &lc));
    assert_eq!(t.root(), expected3);

    // Deleting `a` collapses to the two-leaf form of {b, c}.
    t.apply_ops(vec![path_op(a, None)]).unwrap();
    assert_eq!(t.root(), inner_hash(&ZERO, &inner_hash(&lb, &lc)));
    // Deleting `c` leaves one leaf, whose hash is the root at depth 0.
    t.apply_ops(vec![path_op(c, None)]).unwrap();
    assert_eq!(t.root(), lb);
    t.check_integrity().unwrap();
}

#[test]
fn deepest_possible_split() {
    // Two paths that differ only in bit 255: a branch at depth 255, leaves at
    // depth 256, and 255 one-sided levels above it.
    let mut p0 = [0xa5u8; 32];
    p0[31] &= 0xfe;
    let mut p1 = p0;
    p1[31] |= 1;
    let mut t = new_trie();
    t.apply_ops(vec![path_op(p0, Some(b"x")), path_op(p1, Some(b"y"))])
        .unwrap();
    let leaves = reference::normalize(vec![(p0, value_hash(b"x")), (p1, value_hash(b"y"))]);
    assert_eq!(t.root(), reference::subtree_hash(&leaves, 0));
    for (p, v) in [(p0, b"x"), (p1, b"y")] {
        let proof = t.prove_path(&p).unwrap();
        assert_eq!(proof.depth(), PATH_BITS);
        assert_eq!(proof, reference::prove(&leaves, &p));
        assert!(verify_proof_hashed(
            &t.root(),
            &p,
            Some(&value_hash(v)),
            &proof
        ));
        assert_eq!(
            hypersnap_ktrie::Proof::decode(&proof.encode()).unwrap(),
            proof
        );
    }
    t.check_integrity().unwrap();
    t.commit_to_store().unwrap();
    let r = t.root();
    let t2 = KTrie::open(t.into_store()).unwrap();
    assert_eq!(t2.root(), r);
    t2.check_integrity().unwrap();
}

/// Paths drawn from a few clusters with long shared prefixes, so chains of
/// one-sided levels, collapses and re-splits happen often.
fn clustered_path(rng: &mut Rng) -> Path {
    let mut p = [0u8; 32];
    let cluster = rng.below(4) as u8;
    p[0] = cluster << 6;
    // Keep bits 2..(2+shared) zero, randomize the rest.
    let shared = [0usize, 9, 40, 200][rng.below(4) as usize];
    for i in (2 + shared)..PATH_BITS {
        if rng.below(2) == 1 {
            p[i / 8] |= 0x80 >> (i % 8);
        }
    }
    if rng.below(8) == 0 {
        p[31] ^= 1; // near-duplicates differing only at the end
    }
    p
}

/// Randomized insert / update / delete sequences, in batches of random size,
/// with commits, rollbacks and reloads interleaved, checked against a
/// from-scratch reference build of the remaining keys after every step.
#[test]
fn randomized_against_reference() {
    for seed in 0..24u64 {
        let mut rng = Rng(seed);
        let crafted = seed % 2 == 1;
        // Universe of keys (or crafted paths).
        let universe: Vec<Path> = (0..(40 + rng.below(160)))
            .map(|i| {
                if crafted {
                    clustered_path(&mut rng)
                } else {
                    path_of(format!("key-{seed}-{i}").as_bytes())
                }
            })
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let mut model: std::collections::BTreeMap<Path, Hash> = Default::default();
        let mut committed_model = model.clone();
        let mut t =
            KTrie::open_with_cache(MemStore::new(), [0, 8, 1 << 20][seed as usize % 3]).unwrap();
        for _step in 0..60 {
            let big = rng.below(4) == 0;
            let n = 1 + rng.below(if big { 120 } else { 6 });
            let mut ops = Vec::new();
            for _ in 0..n {
                let p = universe[rng.below(universe.len() as u64) as usize];
                if rng.below(3) == 0 {
                    ops.push(path_op(p, None));
                    model.remove(&p);
                } else {
                    let v = rng.bytes_in(0, 5);
                    ops.push(path_op(p, Some(&v)));
                    model.insert(p, value_hash(&v));
                }
            }
            t.apply_ops(ops).unwrap();
            let leaves: Vec<_> = model.iter().map(|(p, v)| (*p, *v)).collect();
            assert_eq!(t.root(), reference::subtree_hash(&leaves, 0), "seed {seed}");
            assert_eq!(t.len(), model.len() as u64);
            match rng.below(6) {
                0 => {
                    t.rollback();
                    model = committed_model.clone();
                    let leaves: Vec<_> = model.iter().map(|(p, v)| (*p, *v)).collect();
                    assert_eq!(t.root(), reference::subtree_hash(&leaves, 0));
                }
                1 | 2 => {
                    t.commit_to_store().unwrap();
                    committed_model = model.clone();
                }
                3 => {
                    t.commit_to_store().unwrap();
                    committed_model = model.clone();
                    t.reload().unwrap();
                }
                _ => {}
            }
            if rng.below(10) == 0 {
                t.check_integrity().unwrap();
            }
        }
        t.check_integrity().unwrap();
        t.commit_to_store().unwrap();

        // Canonical storage: the store equals that of a one-shot build of the
        // final key set.
        let mut f = new_trie();
        f.apply_ops(
            model
                .iter()
                .map(|(p, v)| Op {
                    path: *p,
                    key: p[..4].to_vec(),
                    value_hash: Some(*v),
                })
                .collect(),
        )
        .unwrap();
        f.commit_to_store().unwrap();
        assert_eq!(f.root(), t.root());
        assert_eq!(records(&f), records(&t), "seed {seed}");
    }
}

#[test]
fn delete_everything_returns_to_empty() {
    let mut rng = Rng(7);
    let keys: Vec<Vec<u8>> = (0..500).map(|_| rng.bytes(12)).collect();
    let mut t = new_trie();
    t.apply(keys.iter().map(|k| (k, Some(b"v")))).unwrap();
    t.commit_to_store().unwrap();
    assert!(t.store().len() > 500);
    // Delete in a few batches.
    for chunk in keys.chunks(170) {
        t.apply(chunk.iter().map(|k| (k, None::<&[u8]>))).unwrap();
        t.commit_to_store().unwrap();
    }
    assert_eq!(t.root(), ZERO);
    // Only the root record (marking "empty") remains.
    assert_eq!(t.store().records().len(), 1);
    let t = KTrie::open(t.into_store()).unwrap();
    assert_eq!(t.root(), ZERO);
}

#[test]
fn batch_semantics() {
    let mut t = new_trie();
    // Within one batch, the last op on a key wins.
    t.apply([
        (b"a".as_slice(), Some(b"1".as_slice())),
        (b"b", Some(b"2")),
        (b"a", None),
        (b"c", Some(b"3")),
        (b"c", Some(b"4")),
    ])
    .unwrap();
    let mut m = Model::new();
    m.insert(b"b".to_vec(), b"2".to_vec());
    m.insert(b"c".to_vec(), b"4".to_vec());
    assert_eq!(t.root(), model_root(&m));
    let b1 = t.commit_to_store().unwrap();
    assert!(!b1.is_empty());

    // No-op batches produce no writes: absent deletes, identical puts.
    t.apply([(b"zzz".as_slice(), None), (b"b", Some(b"2".as_slice()))])
        .unwrap();
    assert!(!t.has_pending());
    let b2 = t.commit();
    assert!(b2.is_empty());
    assert_eq!(b2.root, b1.root);

    // Insert then delete before commit: same root, no root-record write.
    t.insert(b"tmp", b"x").unwrap();
    t.delete(b"tmp").unwrap();
    assert_eq!(t.root(), b1.root);
    let b3 = t.commit_to_store().unwrap();
    assert!(b3.writes.iter().all(|(k, _)| *k != NodeKey::Root));
    t.check_integrity().unwrap();
    assert_eq!(records(&t), records(&fresh(&m)));
}

#[test]
fn block_sized_batch() {
    let mut rng = Rng(42);
    let mut model = Model::new();
    for i in 0..20_000u32 {
        model.insert(i.to_be_bytes().to_vec(), rng.bytes(8));
    }
    let mut t = fresh(&model);
    let mut ops = Vec::new();
    for i in 0..12_000u32 {
        let k = (rng.below(30_000) as u32).to_be_bytes().to_vec();
        if i % 5 == 0 {
            model.remove(&k);
            ops.push(Op::delete(k));
        } else {
            let v = rng.bytes(8);
            model.insert(k.clone(), v.clone());
            ops.push(Op::put(k, &v));
        }
    }
    t.apply_ops(ops).unwrap();
    assert_eq!(t.root(), model_root(&model));
    let batch = t.commit_to_store().unwrap();
    assert_eq!(batch.len, model.len() as u64);
    t.check_integrity().unwrap();
    assert_eq!(records(&t), records(&fresh(&model)));
}

#[test]
fn get_and_contains() {
    let mut rng = Rng(3);
    let mut model = Model::new();
    for _ in 0..300 {
        model.insert(rng.bytes_in(1, 41), rng.bytes(10));
    }
    let t = fresh(&model);
    for (k, v) in &model {
        assert_eq!(t.get(k).unwrap(), Some(value_hash(v)));
        let leaf = t.get_leaf(&path_of(k)).unwrap().unwrap();
        assert_eq!(&leaf.key, k);
    }
    for _ in 0..300 {
        let k = rng.bytes(41);
        assert!(!t.contains(&k).unwrap());
    }
}

/// Mirrors snapchain's commit/rollback contract (src/storage/trie/
/// commit_rollback_tests.rs and the engine's `trie.reload()` calls).
#[test]
fn commit_rollback_reload() {
    let mut t = KTrie::open_with_cache(MemStore::new(), 4).unwrap(); // tiny cache: force evictions
    t.apply([
        (b"k1".as_slice(), Some(b"v1".as_slice())),
        (b"k2", Some(b"v2")),
    ])
    .unwrap();
    let r12 = t.root();
    assert_eq!(t.committed_root(), ZERO);
    let b = t.commit();
    assert_eq!(b.root, r12);
    t.store_mut().apply(&b).unwrap();
    t.reload().unwrap();
    assert_eq!(t.root(), r12);

    // Uncommitted insert is visible, then reload (like snapchain) discards it.
    t.insert(b"k3", b"v3").unwrap();
    let r123 = t.root();
    assert_ne!(r123, r12);
    assert!(t.contains(b"k3").unwrap());
    t.reload().unwrap();
    assert_eq!(t.root(), r12);
    assert!(!t.contains(b"k3").unwrap());

    // rollback() does the same without touching the cache.
    t.insert(b"k3", b"v3").unwrap();
    t.rollback();
    assert_eq!(t.root(), r12);
    assert!(!t.has_pending());

    // Commit without persisting: the staged batch serves reads (even through
    // cache evictions), and further updates build on it.
    t.insert(b"k3", b"v3").unwrap();
    let staged = t.commit();
    assert_eq!(t.committed_root(), r123);
    for _ in 0..3 {
        for k in [b"k1", b"k2", b"k3"] {
            assert!(t.contains(k).unwrap());
            let p = t.prove(k).unwrap();
            assert!(p.is_inclusion());
        }
    }
    t.insert(b"k4", b"v4").unwrap();
    let r1234 = t.root();
    // Abandon both: reload returns to what the store holds.
    t.reload().unwrap();
    assert_eq!(t.root(), r12);

    // Persist the staged batch after the fact, then reload: we are at r123.
    t.store_mut().apply(&staged).unwrap();
    t.reload().unwrap();
    assert_eq!(t.root(), r123);
    t.insert(b"k4", b"v4").unwrap();
    assert_eq!(t.root(), r1234);

    // Deferred persistence across one commit: persist batch N before commit N+1.
    let bn = t.commit();
    t.insert(b"k5", b"v5").unwrap();
    t.store_mut().apply(&bn).unwrap();
    let bn1 = t.commit();
    t.store_mut().apply(&bn1).unwrap();
    t.check_integrity().unwrap();

    // Restart.
    let root = t.root();
    let store = t.into_store();
    let mut t = KTrie::open(store).unwrap();
    assert_eq!(t.root(), root);
    assert_eq!(t.len(), 5);
    t.check_integrity().unwrap();
    let mut m = Model::new();
    for i in 1..=5 {
        m.insert(format!("k{i}").into_bytes(), format!("v{i}").into_bytes());
    }
    assert_eq!(root, model_root(&m));
    t.delete(b"k5").unwrap();
    m.remove(b"k5".as_slice());
    assert_eq!(t.root(), model_root(&m));
}

#[test]
fn corrupt_and_missing_records_are_errors() {
    let mut m = Model::new();
    for i in 0..50u8 {
        m.insert(vec![i], vec![i]);
    }
    let t = fresh(&m);
    let mut store = t.into_store();
    let (key, _) = store
        .records()
        .into_iter()
        .find(|(k, _)| matches!(k, NodeKey::Branch { .. }))
        .unwrap();
    store.put(&key, &[1, 2, 3]).unwrap();
    let t = KTrie::open(store.clone()).unwrap();
    assert!(t.check_integrity().is_err());
    store.delete(&key).unwrap();
    let t = KTrie::open(store).unwrap();
    assert!(matches!(
        t.check_integrity(),
        Err(hypersnap_ktrie::TrieError::MissingNode(_))
    ));
    let mut bad = MemStore::new();
    bad.put(&NodeKey::Root, &[9]).unwrap();
    assert!(KTrie::open(bad).is_err());
}

#[test]
fn seek_in_path_order() {
    let mut rng = Rng(11);
    let mut model = Model::new();
    for _ in 0..400 {
        model.insert(rng.bytes(9), rng.bytes(3));
    }
    let t = fresh(&model);
    let mut sorted: Vec<(Path, Vec<u8>)> = model.keys().map(|k| (path_of(k), k.clone())).collect();
    sorted.sort();

    // Random targets, plus every exact path, plus each path + 1.
    let mut targets: Vec<Path> = (0..500)
        .map(|_| rng.bytes(32).try_into().unwrap())
        .collect();
    for (p, _) in &sorted {
        targets.push(*p);
        if let Some(n) = hypersnap_ktrie::hash::path_successor(p) {
            targets.push(n);
        }
    }
    targets.push([0u8; 32]);
    targets.push([0xff; 32]);
    for target in targets {
        let expected = sorted.iter().find(|(p, _)| *p >= target);
        let got = t.first_at_or_after(&target).unwrap();
        match (expected, got) {
            (None, None) => {}
            (Some((p, k)), Some(e)) => {
                assert_eq!(e.path, *p);
                assert_eq!(&e.key, k);
                assert_eq!(e.value_hash, value_hash(&model[k]));
            }
            (e, g) => panic!("seek mismatch: {e:?} vs {g:?}"),
        }
    }

    // Full iteration with first_after visits every key once, in path order.
    let mut walked = Vec::new();
    let mut cur = t.first_at_or_after(&[0u8; 32]).unwrap();
    while let Some(e) = cur {
        walked.push((e.path, e.key.clone()));
        cur = t.first_after(&e.path).unwrap();
    }
    assert_eq!(walked, sorted);

    // Prefix query: first key whose path starts with bits 1,0,1.
    let prefix = path_with_bits(&[(0, true), (2, true)]);
    let first = t.first_at_or_after(&prefix).unwrap().unwrap();
    let want = sorted
        .iter()
        .find(|(p, _)| bit(p, 0) == 1 && bit(p, 1) == 0 && bit(p, 2) == 1)
        .unwrap();
    assert_eq!(first.path, want.0);

    // Empty trie.
    assert_eq!(new_trie().first_at_or_after(&[0u8; 32]).unwrap(), None);
}

#[test]
fn order_independence_smoke() {
    let mut rng = Rng(5);
    let entries: Vec<(Vec<u8>, Vec<u8>)> = (0..200).map(|_| (rng.bytes(6), rng.bytes(4))).collect();
    let mut roots = BTreeSet::<Hash>::new();
    let mut stores = BTreeSet::new();
    for s in 0..6u64 {
        let mut order = entries.clone();
        let mut r = Rng(s);
        for i in (1..order.len()).rev() {
            order.swap(i, r.below(i as u64 + 1) as usize);
        }
        let mut t = new_trie();
        for chunk in order.chunks(1 + s as usize * 13) {
            t.apply(chunk.iter().map(|(k, v)| (k, Some(v)))).unwrap();
            if s % 2 == 0 {
                t.commit_to_store().unwrap();
            }
        }
        t.commit_to_store().unwrap();
        roots.insert(t.root());
        stores.insert(t.store().records());
    }
    assert_eq!(roots.len(), 1);
    assert_eq!(stores.len(), 1);
    let m: Model = entries.into_iter().collect();
    assert_eq!(*roots.iter().next().unwrap(), model_root(&m));
}
