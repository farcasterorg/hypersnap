//! Property tests: the root (and the stored records) depend only on the final
//! key/value set, never on insertion order, batching, commits or history.

mod common;

use common::*;
use hypersnap_ktrie::{path_of, reference, verify_proof, Op};
use proptest::prelude::*;

fn entries() -> impl Strategy<Value = Vec<(Vec<u8>, Vec<u8>)>> {
    prop::collection::vec(
        (
            prop::collection::vec(any::<u8>(), 0..6),
            prop::collection::vec(any::<u8>(), 0..4),
        ),
        0..80,
    )
}

/// Apply `ops` split at the given cut points, committing after some batches.
fn run(
    ops: &[Op],
    cuts: &[usize],
    commit_mask: u64,
) -> hypersnap_ktrie::KTrie<hypersnap_ktrie::MemStore> {
    let mut t = new_trie();
    let mut cuts: Vec<usize> = cuts.iter().map(|c| c % (ops.len() + 1)).collect();
    cuts.push(0);
    cuts.push(ops.len());
    cuts.sort_unstable();
    cuts.dedup();
    for (i, w) in cuts.windows(2).enumerate() {
        t.apply_ops(ops[w[0]..w[1]].to_vec()).unwrap();
        if commit_mask >> (i % 64) & 1 == 1 {
            t.commit_to_store().unwrap();
        }
    }
    t.commit_to_store().unwrap();
    t
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Same set, any permutation and any batching: same root, same records,
    /// equal to the reference build.
    #[test]
    fn root_is_order_independent(
        es in entries(),
        seed in any::<u64>(),
        cuts in prop::collection::vec(any::<usize>(), 0..6),
        mask in any::<u64>(),
    ) {
        let model: Model = es.iter().cloned().collect();
        let ops: Vec<Op> = model.iter().map(|(k, v)| Op::put(k.clone(), v)).collect();
        let mut shuffled = ops.clone();
        let mut rng = Rng(seed);
        for i in (1..shuffled.len().max(1)).rev() {
            shuffled.swap(i, rng.below(i as u64 + 1) as usize);
        }
        let a = run(&ops, &[], 0);
        let b = run(&shuffled, &cuts, mask);
        prop_assert_eq!(a.root(), model_root(&model));
        prop_assert_eq!(b.root(), a.root());
        prop_assert_eq!(records(&a), records(&b));
    }

    /// Random put/delete histories end at the root of the surviving set, and
    /// at the same records as a from-scratch build of it.
    #[test]
    fn history_independent(
        ops in prop::collection::vec(
            (0u8..24, prop::option::of(prop::collection::vec(any::<u8>(), 0..3))),
            0..120,
        ),
        cuts in prop::collection::vec(any::<usize>(), 0..8),
        mask in any::<u64>(),
    ) {
        let mut model = Model::new();
        let ops: Vec<Op> = ops
            .into_iter()
            .map(|(k, v)| {
                let key = vec![k];
                match v {
                    Some(v) => {
                        model.insert(key.clone(), v.clone());
                        Op::put(key, &v)
                    }
                    None => {
                        model.remove(&key);
                        Op::delete(key)
                    }
                }
            })
            .collect();
        let t = run(&ops, &cuts, mask);
        prop_assert_eq!(t.root(), model_root(&model));
        prop_assert_eq!(t.len(), model.len() as u64);
        t.check_integrity().unwrap();
        prop_assert_eq!(records(&t), records(&fresh(&model)));
    }

    /// Every present key proves included, every absent key proves absent, and
    /// proofs equal the reference construction.
    #[test]
    fn proofs_hold(es in entries(), probes in prop::collection::vec(prop::collection::vec(any::<u8>(), 0..6), 0..20)) {
        let model: Model = es.into_iter().collect();
        let t = fresh(&model);
        let root = t.root();
        let leaves = model_leaves(&model);
        for (k, v) in &model {
            let p = t.prove(k).unwrap();
            prop_assert!(verify_proof(&root, k, Some(v), &p));
            prop_assert_eq!(p, reference::prove(&leaves, &path_of(k)));
        }
        for k in probes {
            let p = t.prove(&k).unwrap();
            match model.get(&k) {
                Some(v) => prop_assert!(verify_proof(&root, &k, Some(v), &p)),
                None => prop_assert!(verify_proof(&root, &k, None, &p)),
            }
        }
    }
}
