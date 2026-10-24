//! Block-update and build benchmarks over the in-memory store.
//!
//! ```text
//! cargo bench --bench ktrie                               # 1M and 10M existing keys
//! KTRIE_BENCH_SIZES=1000000 KTRIE_BENCH_BLOCKS=5 cargo bench --bench ktrie
//! cargo bench --features asm --bench ktrie                # ARMv8 SHA-3 Keccak backend
//! ```
//!
//! The initial trie is built in `KTRIE_BENCH_CHUNK`-op batches (default
//! 2,500,000; a size up to the chunk is a one-shot build).
//!
//! Wall-clock times depend on machine load; the "thread CPU" line is the CPU
//! time of the benchmark thread itself.
//!
//! A block is 12,000 ops: 6,000 puts of new keys, 4,000 updates of existing
//! keys and 2,000 deletes of existing keys. Keys are 26 bytes, shaped like
//! snapchain trie keys; values are 64 bytes. Timings include hashing keys and
//! values (`Op::put`), the batched update, `commit()` (encoding the batch) and
//! applying the batch to the store.

use hypersnap_ktrie::{verify_proof, KTrie, MemStore, NodeStore, Op};
use std::time::{Duration, Instant};

/// CPU time consumed by the calling thread.
fn cpu_now() -> Duration {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `ts` is a valid, writable timespec.
    unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut ts) };
    Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32)
}

const BLOCK_OPS: usize = 12_000;

fn mix(mut z: u64) -> u64 {
    z = z.wrapping_add(0x9e37_79b9_7f4a_7c15);
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

/// shard(1) || fid(4) || message type(1) || message hash(20)
fn key(i: u64) -> Vec<u8> {
    let mut k = Vec::with_capacity(26);
    let mut x = mix(i);
    k.push((x >> 56) as u8);
    k.extend_from_slice(&((i / 64) as u32).to_be_bytes());
    k.push(1 << 3);
    for _ in 0..20 {
        x = mix(x);
        k.push(x as u8);
    }
    k
}

fn value(i: u64, version: u64) -> [u8; 64] {
    let mut v = [0u8; 64];
    let mut x = mix(i ^ (version << 40));
    for chunk in v.chunks_mut(8) {
        x = mix(x);
        chunk.copy_from_slice(&x.to_le_bytes());
    }
    v
}

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1e3
}

fn build(n: u64, chunk: u64) -> (KTrie<MemStore>, Duration, Duration) {
    let mut t = KTrie::open(MemStore::new()).unwrap();
    let cpu = cpu_now();
    let start = Instant::now();
    let mut i = 0;
    while i < n {
        let end = (i + chunk).min(n);
        let ops: Vec<Op> = (i..end).map(|j| Op::put(key(j), &value(j, 0))).collect();
        t.apply_ops(ops).unwrap();
        t.commit_to_store().unwrap();
        i = end;
    }
    (t, start.elapsed(), cpu_now() - cpu)
}

#[derive(Default)]
struct BlockTimes {
    prep: Vec<f64>,
    apply: Vec<f64>,
    commit: Vec<f64>,
    store: Vec<f64>,
    total: Vec<f64>,
    cpu: Vec<f64>,
    writes: Vec<usize>,
}

fn stats(v: &[f64]) -> String {
    let mut s = v.to_vec();
    s.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let mean = s.iter().sum::<f64>() / s.len() as f64;
    format!(
        "median {:7.1}  mean {:7.1}  min {:7.1}  max {:7.1}",
        s[s.len() / 2],
        mean,
        s[0],
        s[s.len() - 1]
    )
}

fn run_blocks(
    t: &mut KTrie<MemStore>,
    n: u64,
    next_new: &mut u64,
    blocks: usize,
    cold: bool,
    seed: u64,
) -> BlockTimes {
    let mut out = BlockTimes::default();
    for b in 0..blocks {
        if cold {
            t.reload().unwrap(); // empty node cache: every node decodes from the store
        }
        let mut rng = mix(seed ^ b as u64);
        let mut rand_existing = || {
            rng = mix(rng);
            rng % n
        };
        let c0 = cpu_now();
        let t0 = Instant::now();
        let mut ops = Vec::with_capacity(BLOCK_OPS);
        for _ in 0..6_000 {
            ops.push(Op::put(key(*next_new), &value(*next_new, 0)));
            *next_new += 1;
        }
        for _ in 0..4_000 {
            let i = rand_existing();
            ops.push(Op::put(key(i), &value(i, 1 + b as u64)));
        }
        for _ in 0..2_000 {
            ops.push(Op::delete(key(rand_existing())));
        }
        let t1 = Instant::now();
        t.apply_ops(ops).unwrap();
        let _root = t.root();
        let t2 = Instant::now();
        let batch = t.commit();
        let t3 = Instant::now();
        t.store_mut().apply(&batch).unwrap();
        let t4 = Instant::now();
        out.cpu.push(ms(cpu_now() - c0));
        out.prep.push(ms(t1 - t0));
        out.apply.push(ms(t2 - t1));
        out.commit.push(ms(t3 - t2));
        out.store.push(ms(t4 - t3));
        out.total.push(ms(t4 - t0));
        out.writes.push(batch.writes.len());
    }
    out
}

fn report(label: &str, bt: &BlockTimes) {
    println!("  {label}");
    println!("    hash keys+values (ms)   {}", stats(&bt.prep));
    println!("    apply + root (ms)       {}", stats(&bt.apply));
    println!("    commit/encode (ms)      {}", stats(&bt.commit));
    println!("    store.apply (ms)        {}", stats(&bt.store));
    println!("    TOTAL per block (ms)    {}", stats(&bt.total));
    println!("    thread CPU / block (ms) {}", stats(&bt.cpu));
    let w = bt.writes.iter().sum::<usize>() / bt.writes.len();
    println!("    store writes per block  {w}");
}

fn main() {
    // `cargo bench` passes `--bench`; ignore arguments.
    let sizes: Vec<u64> = std::env::var("KTRIE_BENCH_SIZES")
        .ok()
        .map(|s| s.split(',').map(|x| x.trim().parse().unwrap()).collect())
        .unwrap_or_else(|| vec![1_000_000, 10_000_000]);
    let blocks: usize = std::env::var("KTRIE_BENCH_BLOCKS")
        .ok()
        .map(|s| s.parse().unwrap())
        .unwrap_or(10);

    let chunk: u64 = std::env::var("KTRIE_BENCH_CHUNK")
        .ok()
        .map(|s| s.parse().unwrap())
        .unwrap_or(2_500_000);

    for &n in &sizes {
        println!("\n=== {n} existing keys ===");
        let (mut t, d, cpu) = build(n, chunk);
        println!(
            "build: {n} keys in {}-op batches: {:.2} s wall ({:.0} keys/s), {:.2} s thread CPU ({:.0} keys/s); root {}",
            chunk.min(n),
            d.as_secs_f64(),
            n as f64 / d.as_secs_f64(),
            cpu.as_secs_f64(),
            n as f64 / cpu.as_secs_f64(),
            hex(&t.root())
        );
        println!(
            "store: {} records, {:.1} MiB encoded ({:.0} B/key)",
            t.store().len(),
            t.store().byte_size() as f64 / (1 << 20) as f64,
            t.store().byte_size() as f64 / n as f64
        );
        let mut next_new = n;
        // Warm-up block, not reported.
        run_blocks(&mut t, n, &mut next_new, 1, false, 0xabc);
        let warm = run_blocks(&mut t, n, &mut next_new, blocks, false, 1);
        report(
            &format!(
                "{blocks} blocks x {BLOCK_OPS} ops, warm node cache (cap {} nodes, {} resident)",
                hypersnap_ktrie::DEFAULT_CACHE_NODES,
                t.cached_nodes()
            ),
            &warm,
        );
        let cold = run_blocks(&mut t, n, &mut next_new, blocks.min(5), true, 2);
        report(
            &format!(
                "{} blocks x {BLOCK_OPS} ops, cold cache (reload() before each block)",
                blocks.min(5)
            ),
            &cold,
        );

        // Proofs and seeks.
        let root = t.root();
        let probes = 10_000u64;
        let mut proofs = Vec::with_capacity(probes as usize);
        let t0 = Instant::now();
        for i in 0..probes {
            let k = key(mix(i) % n);
            proofs.push((k.clone(), t.prove(&k).unwrap()));
        }
        let gen = t0.elapsed();
        let mut bytes = 0;
        let mut depth = 0;
        let mut included = 0;
        for (k, p) in &proofs {
            let vh = t.get(k).unwrap();
            bytes += p.encode().len();
            depth += p.depth();
            let ok = match vh {
                Some(_) => p.is_inclusion(),
                None => verify_proof(&root, k, None, p),
            };
            assert!(ok);
            included += vh.is_some() as usize;
        }
        // Pure verification throughput on inclusion proofs (values re-derived).
        let incl: Vec<_> = proofs
            .iter()
            .filter(|(_, p)| p.is_inclusion())
            .map(|(k, p)| (k.clone(), p.clone(), t.get(k).unwrap().unwrap()))
            .collect();
        let t0 = Instant::now();
        for (k, p, vh) in &incl {
            assert!(hypersnap_ktrie::verify_proof_hashed(
                &root,
                &hypersnap_ktrie::path_of(k),
                Some(vh),
                p
            ));
        }
        let ver = t0.elapsed();
        println!(
            "proofs: {probes} generated in {:.1} ms ({:.1} us each); avg depth {:.1}, avg {} B encoded; {} inclusion verified in {:.1} ms ({:.1} us each)",
            ms(gen),
            gen.as_secs_f64() * 1e6 / probes as f64,
            depth as f64 / probes as f64,
            bytes / probes as usize,
            included,
            ms(ver),
            ver.as_secs_f64() * 1e6 / incl.len() as f64
        );
        let t0 = Instant::now();
        let mut found = 0;
        for i in 0..probes {
            let target = hypersnap_ktrie::keccak256(&i.to_be_bytes());
            found += t.first_at_or_after(&target).unwrap().is_some() as usize;
        }
        let seek = t0.elapsed();
        println!(
            "seeks: {probes} first_at_or_after in {:.1} ms ({:.1} us each, {found} found)",
            ms(seek),
            seek.as_secs_f64() * 1e6 / probes as f64
        );
    }
}

fn hex(h: &[u8]) -> String {
    h.iter().map(|b| format!("{b:02x}")).collect()
}
