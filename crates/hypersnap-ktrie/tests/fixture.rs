//! Test vectors: `testdata/vectors.json` and the generated vector block of
//! `contracts/test/KeccakTrieVerifier.t.sol` must match what this crate
//! computes. Regenerate both with
//!
//! ```text
//! KTRIE_REGEN=1 cargo test --test fixture
//! ```

mod common;

use common::*;
use hypersnap_ktrie::hash::bit;
use hypersnap_ktrie::{
    inner_hash, keccak256, leaf_hash, leaf_hash_kv, path_of, reference, value_hash,
    verify_proof_hashed, Hash, KTrie, MemStore, Path, Proof, Terminal, ZERO,
};
use serde_json::{json, Value};
use std::path::PathBuf;

fn hex(b: &[u8]) -> String {
    let mut s = String::from("0x");
    for x in b {
        s.push_str(&format!("{x:02x}"));
    }
    s
}

struct Vector {
    name: String,
    root: Hash,
    /// Raw key/value when the vector comes from a real key; `None` for
    /// crafted paths.
    raw: Option<(Vec<u8>, Option<Vec<u8>>)>,
    path: Path,
    value_hash: Option<Hash>,
    proof: Proof,
    valid: bool,
}

impl Vector {
    fn kind(&self) -> &'static str {
        match self.proof.terminal {
            Terminal::Included => "inclusion",
            Terminal::Empty => "non-inclusion-empty",
            Terminal::OtherLeaf { .. } => "non-inclusion-leaf",
        }
    }

    fn json(&self) -> Value {
        let (key, key_utf8, value) = match &self.raw {
            Some((k, v)) => (
                json!(hex(k)),
                json!(String::from_utf8_lossy(k)),
                json!(v.as_ref().map(|v| hex(v))),
            ),
            None => (Value::Null, Value::Null, Value::Null),
        };
        json!({
            "name": self.name,
            "key": key,
            "key_utf8": key_utf8,
            "value": value,
            "path": hex(&self.path),
            "value_hash": self.value_hash.map(|h| hex(&h)),
            "kind": self.kind(),
            "depth": self.proof.depth(),
            "proof": hex(&self.proof.encode()),
            "valid": self.valid,
        })
    }
}

fn kv(i: usize) -> (Vec<u8>, Vec<u8>) {
    (
        format!("key-{i}").into_bytes(),
        format!("value-{i}").into_bytes(),
    )
}

fn trie_case(n: usize, out: &mut Vec<Vector>) -> Value {
    let model: Model = (0..n).map(kv).collect();
    let t = fresh(&model);
    let root = t.root();
    assert_eq!(root, model_root(&model));
    let mut vecs = Vec::new();
    for (k, v) in &model {
        vecs.push(Vector {
            name: format!("{n} keys: {} included", String::from_utf8_lossy(k)),
            root,
            raw: Some((k.clone(), Some(v.clone()))),
            path: path_of(k),
            value_hash: Some(value_hash(v)),
            proof: t.prove(k).unwrap(),
            valid: true,
        });
    }
    // The first absent keys of each non-inclusion shape that exists.
    let (mut empty, mut other) = (false, false);
    for j in 0..20_000 {
        if empty && other {
            break;
        }
        let k = format!("absent-{j}").into_bytes();
        let proof = t.prove(&k).unwrap();
        let seen = match proof.terminal {
            Terminal::Empty => &mut empty,
            Terminal::OtherLeaf { .. } => &mut other,
            Terminal::Included => unreachable!(),
        };
        if !*seen {
            *seen = true;
            vecs.push(Vector {
                name: format!("{n} keys: {} absent", String::from_utf8_lossy(&k)),
                root,
                raw: Some((k.clone(), None)),
                path: path_of(&k),
                value_hash: None,
                proof,
                valid: true,
            });
        }
    }
    if n == 10 {
        // Invalid vectors: each must be rejected.
        let (k3, _) = kv(3);
        vecs.push(Vector {
            name: "10 keys: key-3 with the wrong value".into(),
            root,
            raw: Some((k3.clone(), Some(b"value-4".to_vec()))),
            path: path_of(&k3),
            value_hash: Some(value_hash(b"value-4")),
            proof: t.prove(&k3).unwrap(),
            valid: false,
        });
        let (k4, v4) = kv(4);
        let mut p = t.prove(&k4).unwrap();
        let i = p.siblings.iter().position(|s| *s != ZERO).unwrap();
        p.siblings[i][31] ^= 1;
        vecs.push(Vector {
            name: "10 keys: key-4 with a tampered sibling".into(),
            root,
            raw: Some((k4.clone(), Some(v4.clone()))),
            path: path_of(&k4),
            value_hash: Some(value_hash(&v4)),
            proof: p,
            valid: false,
        });
        let mut p = t.prove(&k4).unwrap();
        p.siblings.push(ZERO);
        vecs.push(Vector {
            name: "10 keys: key-4 with a non-canonical extra empty level".into(),
            root,
            raw: Some((k4.clone(), Some(v4.clone()))),
            path: path_of(&k4),
            value_hash: Some(value_hash(&v4)),
            proof: p,
            valid: false,
        });
        let (k5, _) = kv(5);
        let absent = vecs
            .iter()
            .find(|v| v.valid && !v.proof.is_inclusion())
            .unwrap();
        vecs.push(Vector {
            name: "10 keys: an absent key's proof reused for present key-5".into(),
            root,
            raw: Some((k5.clone(), None)),
            path: path_of(&k5),
            value_hash: None,
            proof: absent.proof.clone(),
            valid: false,
        });
    }
    for v in &vecs {
        assert_eq!(
            verify_proof_hashed(&v.root, &v.path, v.value_hash.as_ref(), &v.proof),
            v.valid,
            "{}",
            v.name
        );
    }
    let entries: Vec<Value> = model
        .iter()
        .map(|(k, v)| json!({ "key": hex(k), "key_utf8": String::from_utf8_lossy(k), "value": hex(v), "path": hex(&path_of(k)), "leaf": hex(&leaf_hash_kv(k, v)) }))
        .collect();
    let case = json!({
        "name": format!("{n} keys"),
        "entries": entries,
        "root": hex(&root),
        "vectors": vecs.iter().map(Vector::json).collect::<Vec<_>>(),
    });
    out.extend(vecs);
    case
}

/// Crafted paths (no preimages): the deepest split and a long proof.
fn synthetic(out: &mut Vec<Vector>) -> Value {
    let mut vecs = Vec::new();

    // Two paths differing only in bit 255.
    let mut p0 = keccak256(b"deep");
    p0[31] &= 0xfe;
    let mut p1 = p0;
    p1[31] |= 1;
    let mut t = KTrie::open(MemStore::new()).unwrap();
    t.apply_ops(vec![path_op(p0, Some(b"x")), path_op(p1, Some(b"y"))])
        .unwrap();
    let root = t.root();
    let leaves = reference::normalize(vec![(p0, value_hash(b"x")), (p1, value_hash(b"y"))]);
    assert_eq!(root, reference::subtree_hash(&leaves, 0));
    vecs.push(Vector {
        name: "split at bit 255: leaf at depth 256 included".into(),
        root,
        raw: None,
        path: p0,
        value_hash: Some(value_hash(b"x")),
        proof: t.prove_path(&p0).unwrap(),
        valid: true,
    });
    let mut q = p0;
    q[12] ^= 0x08; // diverges at bit 100
    assert_eq!(hypersnap_ktrie::hash::common_prefix_len(&q, &p0), 100);
    vecs.push(Vector {
        name: "split at bit 255: path diverging at bit 100 absent".into(),
        root,
        raw: None,
        path: q,
        value_hash: None,
        proof: t.prove_path(&q).unwrap(),
        valid: true,
    });

    // A 30-level inclusion proof (the size of a 2^30-key trie), with
    // arbitrary non-zero siblings; its root is computed by folding.
    let path = keccak256(b"synthetic-30");
    let vh = value_hash(b"v");
    let siblings: Vec<Hash> = (0..30u8).map(|i| keccak256(&[i])).collect();
    let mut h = leaf_hash(&path, &vh);
    for i in (0..30).rev() {
        h = if bit(&path, i) == 0 {
            inner_hash(&h, &siblings[i])
        } else {
            inner_hash(&siblings[i], &h)
        };
    }
    vecs.push(Vector {
        name: "synthetic 30-level inclusion".into(),
        root: h,
        raw: None,
        path,
        value_hash: Some(vh),
        proof: Proof {
            siblings,
            terminal: Terminal::Included,
        },
        valid: true,
    });
    for v in &vecs {
        assert_eq!(
            verify_proof_hashed(&v.root, &v.path, v.value_hash.as_ref(), &v.proof),
            v.valid,
            "{}",
            v.name
        );
    }
    let json = json!(vecs.iter().map(Vector::json).collect::<Vec<_>>());
    out.extend(vecs);
    json
}

fn hash_vectors() -> Value {
    let (k0, v0) = kv(0);
    let (k1, v1) = kv(1);
    let l0 = leaf_hash_kv(&k0, &v0);
    let l1 = leaf_hash_kv(&k1, &v1);
    // Lifting a two-leaf hash h over one-sided levels: bit 1 = 0, bit 0 = 1.
    let h = inner_hash(&l0, &l1);
    let lifted = inner_hash(&ZERO, &inner_hash(&h, &ZERO));
    json!([
        { "name": "keccak256(\"\")", "input": "0x", "output": hex(&keccak256(b"")) },
        { "name": "keccak256(\"key-0\") = path(key-0)", "input": hex(&k0), "output": hex(&path_of(&k0)) },
        { "name": "keccak256(\"value-0\")", "input": hex(&v0), "output": hex(&value_hash(&v0)) },
        { "name": "leaf(key-0, value-0) = keccak256(0x00 || path || value_hash)",
          "input": hex(&[&[0u8][..], &path_of(&k0), &value_hash(&v0)].concat()), "output": hex(&l0) },
        { "name": "inner(leaf(key-0), leaf(key-1)) = keccak256(0x01 || l || r)",
          "input": hex(&[&[1u8][..], &l0, &l1].concat()), "output": hex(&inner_hash(&l0, &l1)) },
        { "name": "inner(0, inner(h, 0)) for h = inner(leaf0, leaf1): lifting h from depth 2 to 0 under prefix bits 1,0",
          "input": hex(&h), "output": hex(&lifted) },
    ])
}

fn fixture() -> (String, Vec<Vector>) {
    let mut all = Vec::new();
    let tries: Vec<Value> = [0, 1, 2, 3, 10]
        .into_iter()
        .map(|n| trie_case(n, &mut all))
        .collect();
    let synth = synthetic(&mut all);
    let doc = json!({
        "description": "hypersnap-ktrie test vectors: Keccak-256 sparse binary Merkle trie (FIP-proof-of-work-tokenization §16.13). Generated by `KTRIE_REGEN=1 cargo test --test fixture`; all byte strings are 0x-hex.",
        "spec": {
            "keccak256": "Ethereum Keccak-256 (0x01 padding), not FIPS-202 SHA3-256",
            "path": "path(key) = keccak256(key); bit 0 = most significant bit of byte 0; bit d selects left (0) / right (1) at depth d",
            "leaf": "leaf(key, v) = keccak256(0x00 || keccak256(key) || keccak256(v))",
            "inner": "inner(l, r) = keccak256(0x01 || l || r)",
            "empty": "32 zero bytes",
            "subtree": "H(S,d) = 0 if |S|=0; leaf(k,v) if S={(k,v)} (at any depth); inner(H(S0,d+1), H(S1,d+1)) if |S|>=2",
            "root": "H(all, 0); empty trie = 0; one key = its leaf hash",
            "proof": "kind(1: 0x00 inclusion, 0x01 empty, 0x02 other leaf) || D(u16 BE) || bitmap(ceil(D/8), bit i MSB-first set iff sibling i != 0, padding zero) || non-zero siblings (32 B each, level 0 first) || [other_path(32) || other_value_hash(32) if kind 0x02]",
            "verify": "h = leaf(path, vh) | 0 | leaf(other_path, other_vh); for i = D-1..0: h = bit_i(path) ? inner(sib_i, h) : inner(h, sib_i); valid iff h == root, D <= 256, sibling D-1 != 0 when D > 0, and for kind 0x02 other_path != path and shares the first D bits"
        },
        "hash_vectors": hash_vectors(),
        "tries": tries,
        "synthetic": synth,
    });
    (serde_json::to_string_pretty(&doc).unwrap() + "\n", all)
}

fn sol_bytes(b: &[u8]) -> String {
    format!("hex\"{}\"", &hex(b)[2..])
}

fn sol_b32(h: &Hash) -> String {
    format!("bytes32({})", hex(h))
}

/// The generated body of `_vectors()` in the Solidity test.
fn solidity_block(vecs: &[Vector]) -> String {
    let mut s = String::new();
    s.push_str("    // BEGIN GENERATED VECTORS (KTRIE_REGEN=1 cargo test --test fixture, in crates/hypersnap-ktrie)\n");
    s.push_str("    function _vectors() internal pure returns (Vector[] memory v) {\n");
    s.push_str(&format!("        v = new Vector[]({});\n", vecs.len()));
    for (i, v) in vecs.iter().enumerate() {
        let (raw, key, value) = match &v.raw {
            Some((k, val)) => (true, k.clone(), val.clone().unwrap_or_default()),
            None => (false, vec![], vec![]),
        };
        s.push_str(&format!(
            "        v[{i}] = Vector({{\n            name: \"{}\",\n            root: {},\n            raw: {raw},\n            key: {},\n            value: {},\n            path: {},\n            hasValue: {},\n            valueHash: {},\n            proof: {},\n            valid: {}\n        }});\n",
            v.name,
            sol_b32(&v.root),
            sol_bytes(&key),
            sol_bytes(&value),
            sol_b32(&v.path),
            v.value_hash.is_some(),
            sol_b32(&v.value_hash.unwrap_or(ZERO)),
            sol_bytes(&v.proof.encode()),
            v.valid,
        ));
    }
    s.push_str("    }\n");
    s.push_str("    // END GENERATED VECTORS\n");
    s
}

fn regen() -> bool {
    std::env::var("KTRIE_REGEN").is_ok_and(|v| v == "1")
}

#[test]
fn json_fixture_is_current() {
    let (json, vecs) = fixture();
    assert!(vecs.len() > 20);
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata/vectors.json");
    if regen() {
        std::fs::write(&path, &json).unwrap();
    }
    let on_disk =
        std::fs::read_to_string(&path).expect("testdata/vectors.json (run with KTRIE_REGEN=1)");
    assert!(
        on_disk == json,
        "testdata/vectors.json is stale: run KTRIE_REGEN=1 cargo test --test fixture"
    );
}

#[test]
fn solidity_vectors_are_current() {
    let (_, vecs) = fixture();
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../contracts/test/KeccakTrieVerifier.t.sol");
    let Ok(src) = std::fs::read_to_string(&path) else {
        eprintln!("skipping: {} not found", path.display());
        return;
    };
    let begin = src
        .find("    // BEGIN GENERATED VECTORS")
        .expect("begin marker");
    let end_marker = "    // END GENERATED VECTORS\n";
    let end = src.find(end_marker).expect("end marker") + end_marker.len();
    let block = solidity_block(&vecs);
    if regen() {
        let updated = format!("{}{}{}", &src[..begin], block, &src[end..]);
        std::fs::write(&path, updated).unwrap();
        return;
    }
    assert!(
        src[begin..end] == block,
        "KeccakTrieVerifier.t.sol vectors are stale: run KTRIE_REGEN=1 cargo test --test fixture"
    );
}

#[test]
fn fixture_roots_match_reference() {
    // Independent of the stored trie: the JSON roots are the reference roots.
    let (json, _) = fixture();
    let doc: Value = serde_json::from_str(&json).unwrap();
    for case in doc["tries"].as_array().unwrap() {
        let entries: Vec<(Vec<u8>, Vec<u8>)> = case["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| {
                let k = e["key_utf8"].as_str().unwrap().as_bytes().to_vec();
                let n: usize = std::str::from_utf8(&k[4..]).unwrap().parse().unwrap();
                (k, kv(n).1)
            })
            .collect();
        assert_eq!(
            case["root"].as_str().unwrap(),
            hex(&reference::root(&entries))
        );
    }
    assert_eq!(doc["tries"][0]["root"].as_str().unwrap(), hex(&ZERO));
    assert_eq!(
        doc["tries"][1]["root"].as_str().unwrap(),
        hex(&leaf_hash_kv(b"key-0", b"value-0"))
    );
}
