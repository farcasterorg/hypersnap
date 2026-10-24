//! Timings for the provisional parameter set.
//!
//!     cargo run --release --example bench

use std::time::Instant;

use hypersnap_lattice::params::PROVISIONAL_V1;
use hypersnap_lattice::{expand_a, expand_a_uncached, Keypair, PublicKey, Signature};

fn main() {
    let p = &PROVISIONAL_V1;
    println!("{p}");
    println!(
        "q={} n={} m={} k={} kappa={} eta={} gamma1={} gamma2={} B={}",
        p.q,
        p.n,
        p.m,
        p.k,
        p.kappa,
        p.eta,
        p.gamma1,
        p.gamma2,
        p.z_bound()
    );
    println!(
        "pk {} B, sk {} B, sig {} B, expected attempts {:.3}",
        p.public_key_bytes(),
        p.secret_key_bytes(),
        p.signature_bytes(),
        p.expected_attempts()
    );

    let t = Instant::now();
    let _ = expand_a_uncached(p);
    println!(
        "expand_a (uncached)      {:>9.2} ms",
        t.elapsed().as_secs_f64() * 1e3
    );
    let _ = expand_a(p);

    let t = Instant::now();
    let kp = Keypair::from_seed(p, &[7u8; 32]);
    println!(
        "keygen                   {:>9.2} ms",
        t.elapsed().as_secs_f64() * 1e3
    );

    let pk_bytes = kp.public.to_bytes();
    let t = Instant::now();
    let pk = PublicKey::from_bytes(p, &pk_bytes).unwrap();
    println!(
        "pk decode (+tr, address) {:>9.2} ms",
        t.elapsed().as_secs_f64() * 1e3
    );

    const N: u32 = 200;
    let ctx = b"hypersnap-bench-v1";
    let mut sigs = Vec::new();
    let mut attempts = 0u32;
    let t = Instant::now();
    for i in 0..N {
        let (s, a) = kp
            .secret
            .sign_with_attempts(ctx, &i.to_le_bytes(), &[0u8; 32])
            .unwrap();
        attempts += a;
        sigs.push(s.to_bytes());
    }
    let sign = t.elapsed().as_secs_f64() / N as f64;
    println!(
        "sign                     {:>9.3} ms  ({:.3} attempts avg, {:.3} ms/attempt)",
        sign * 1e3,
        attempts as f64 / N as f64,
        sign * 1e3 * N as f64 / attempts as f64
    );

    let t = Instant::now();
    for (i, s) in sigs.iter().enumerate() {
        pk.verify_bytes(ctx, &(i as u32).to_le_bytes(), s).unwrap();
    }
    println!(
        "verify (incl. decode)    {:>9.3} ms",
        t.elapsed().as_secs_f64() * 1e3 / N as f64
    );

    let t = Instant::now();
    for s in &sigs {
        let _ = Signature::from_bytes(p, s).unwrap();
    }
    println!(
        "sig decode               {:>9.4} ms",
        t.elapsed().as_secs_f64() * 1e3 / N as f64
    );
}
