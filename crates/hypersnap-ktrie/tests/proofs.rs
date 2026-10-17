mod common;

use common::*;
use hypersnap_ktrie::{
    path_of, reference, value_hash, verify_proof, verify_proof_bytes, verify_proof_hashed, Proof,
    Terminal, ZERO,
};

fn check_all_proofs(model: &Model, absent: &[Vec<u8>]) -> (usize, usize, usize) {
    let t = fresh(model);
    let root = t.root();
    let leaves = model_leaves(model);
    let (mut incl, mut empty, mut other) = (0, 0, 0);
    for (k, v) in model {
        let p = t.prove(k).unwrap();
        assert_eq!(p, reference::prove(&leaves, &path_of(k)));
        assert_eq!(p.terminal, Terminal::Included);
        assert!(verify_proof(&root, k, Some(v), &p));
        let mut wrong = v.clone();
        wrong.push(0);
        assert!(!verify_proof(&root, k, Some(&wrong), &p));
        assert!(!verify_proof(&root, k, None, &p));
        let bytes = p.encode();
        assert_eq!(Proof::decode(&bytes).unwrap(), p);
        assert!(verify_proof_bytes(&root, k, Some(v), &bytes));
        incl += 1;
    }
    for k in absent {
        if model.contains_key(k) {
            continue;
        }
        let p = t.prove(k).unwrap();
        assert_eq!(p, reference::prove(&leaves, &path_of(k)));
        match p.terminal {
            Terminal::Empty => empty += 1,
            Terminal::OtherLeaf { .. } => other += 1,
            Terminal::Included => panic!("absent key proved included"),
        }
        assert!(verify_proof(&root, k, None, &p));
        assert!(!verify_proof(&root, k, Some(b""), &p));
        assert!(verify_proof_bytes(&root, k, None, &p.encode()));
        // A non-inclusion proof does not transfer to another absent key with a
        // different path, nor does it verify against another root.
        let mut r2 = root;
        r2[0] ^= 1;
        assert!(!verify_proof(&r2, k, None, &p));
    }
    (incl, empty, other)
}

#[test]
fn proofs_match_reference_for_many_sizes() {
    let mut rng = Rng(99);
    let (mut e_total, mut o_total) = (0, 0);
    for n in [0usize, 1, 2, 3, 4, 5, 7, 10, 16, 33, 100, 257] {
        let mut model = Model::new();
        while model.len() < n {
            model.insert(rng.bytes_in(1, 21), rng.bytes_in(0, 8));
        }
        let absent: Vec<Vec<u8>> = (0..200).map(|_| rng.bytes(21)).collect();
        let (i, e, o) = check_all_proofs(&model, &absent);
        assert_eq!(i, n);
        e_total += e;
        o_total += o;
    }
    // Both non-inclusion shapes were exercised.
    assert!(
        e_total > 0 && o_total > 0,
        "empty={e_total} other={o_total}"
    );
}

#[test]
fn proofs_with_crafted_paths() {
    // Clusters with long shared prefixes: empty terminals deep inside chains.
    let mut rng = Rng(1);
    let mut ops = Vec::new();
    let mut leaves = Vec::new();
    for c in 0..3u8 {
        for _ in 0..5 {
            let mut p: [u8; 32] = rng.bytes(32).try_into().unwrap();
            p[..12].fill(c * 0x55);
            let v = rng.bytes(3);
            leaves.push((p, value_hash(&v)));
            ops.push(path_op(p, Some(&v)));
        }
    }
    let leaves = reference::normalize(leaves);
    let mut t = new_trie();
    t.apply_ops(ops).unwrap();
    let root = t.root();
    assert_eq!(root, reference::subtree_hash(&leaves, 0));
    for (p, vh) in &leaves {
        let proof = t.prove_path(p).unwrap();
        assert_eq!(proof, reference::prove(&leaves, p));
        assert!(verify_proof_hashed(&root, p, Some(vh), &proof));
    }
    let mut saw_deep_empty = false;
    for _ in 0..300 {
        let mut q: [u8; 32] = rng.bytes(32).try_into().unwrap();
        let c = rng.below(3) as u8;
        let keep = rng.below(12) as usize;
        q[..keep].fill(c * 0x55);
        let proof = t.prove_path(&q).unwrap();
        assert_eq!(proof, reference::prove(&leaves, &q));
        assert!(verify_proof_hashed(&root, &q, None, &proof));
        saw_deep_empty |= proof.terminal == Terminal::Empty && proof.depth() > 8;
    }
    assert!(saw_deep_empty);
}

#[test]
fn every_single_byte_tamper_fails() {
    let mut rng = Rng(5);
    let mut model = Model::new();
    while model.len() < 40 {
        model.insert(rng.bytes(5), rng.bytes(5));
    }
    let t = fresh(&model);
    let root = t.root();
    let mut checked = 0;
    let absent: Vec<Vec<u8>> = (0..40).map(|_| rng.bytes(6)).collect();
    let cases = model
        .iter()
        .map(|(k, v)| (k.clone(), Some(v.clone())))
        .chain(absent.into_iter().map(|k| (k, None)));
    for (k, v) in cases {
        let bytes = t.prove(&k).unwrap().encode();
        assert!(verify_proof_bytes(&root, &k, v.as_deref(), &bytes));
        for i in 0..bytes.len() {
            for mask in [0x01u8, 0x80] {
                let mut bad = bytes.clone();
                bad[i] ^= mask;
                assert!(
                    !verify_proof_bytes(&root, &k, v.as_deref(), &bad),
                    "tamper at byte {i} mask {mask:#x} accepted"
                );
                checked += 1;
            }
        }
        // Truncation and extension fail.
        assert!(!verify_proof_bytes(
            &root,
            &k,
            v.as_deref(),
            &bytes[..bytes.len() - 1]
        ));
        let mut ext = bytes.clone();
        ext.push(0);
        assert!(!verify_proof_bytes(&root, &k, v.as_deref(), &ext));
    }
    assert!(checked > 1000);
}

#[test]
fn non_canonical_depths_are_rejected() {
    let mut rng = Rng(8);
    let mut model = Model::new();
    while model.len() < 30 {
        model.insert(rng.bytes(4), rng.bytes(4));
    }
    let t = fresh(&model);
    let root = t.root();
    for (k, v) in &model {
        let p = t.prove(k).unwrap();
        // One level deeper with an empty sibling: the leaf would be hashed as
        // a one-sided inner node.
        let mut longer = p.clone();
        longer.siblings.push(ZERO);
        assert!(!verify_proof(&root, k, Some(v), &longer));
        // One level shallower.
        if p.depth() > 0 {
            let mut shorter = p.clone();
            shorter.siblings.pop();
            assert!(!verify_proof(&root, k, Some(v), &shorter));
        }
        // An inclusion proof cannot be relabelled as non-inclusion.
        let other = Proof {
            siblings: p.siblings.clone(),
            terminal: Terminal::OtherLeaf {
                path: path_of(k),
                value_hash: value_hash(v),
            },
        };
        assert!(!verify_proof(&root, k, None, &other));
    }
    // An empty proof only verifies against the empty root.
    let empty = Proof {
        siblings: vec![],
        terminal: Terminal::Empty,
    };
    assert!(!verify_proof(&root, b"x", None, &empty));
    assert!(verify_proof(&ZERO, b"x", None, &empty));
}

#[test]
fn proof_sizes_are_logarithmic() {
    let mut rng = Rng(77);
    let mut model = Model::new();
    while model.len() < 4096 {
        model.insert(rng.bytes(8), rng.bytes(8));
    }
    let t = fresh(&model);
    let mut total = 0;
    let mut max_d = 0;
    for k in model.keys().take(500) {
        let p = t.prove(k).unwrap();
        total += p.encode().len();
        max_d = max_d.max(p.depth());
    }
    let avg = total / 500;
    // ~12-13 levels for 4096 keys: ~3 + 2 + 13 * 32 bytes.
    assert!(avg < 3 + 4 + 16 * 32, "avg proof {avg} bytes");
    assert!(max_d < 40);
}
