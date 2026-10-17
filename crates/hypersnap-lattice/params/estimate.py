#!/usr/bin/env sage -python
"""Lattice-estimator script for the LWE-FSA parameter sets.

Authoritative security estimate for `src/params.rs`. Requires SageMath and
https://github.com/malb/lattice-estimator.

    git clone https://github.com/malb/lattice-estimator /path/to/lattice-estimator
    sage -python estimate.py /path/to/lattice-estimator [--full]

Without --full the script runs the core-SVP estimate that the parameter
target is stated in (RC.ADPS16, classical 0.292*beta and quantum
0.265*beta) for the LWE key-recovery problem and for the SIS forgery problem.
With --full it also runs every LWE attack of the estimator under the
estimator's default (MATZOV) cost model, which takes several minutes.

Problems
--------

LWE key recovery. Each column t_j = A s_j + e_j of the public key is an LWE
instance with secret dimension m, n samples, modulus q, and secret and error
uniform on [-eta, eta]. The k columns share A; they are k independent
instances of the same problem.

SIS forgery. As for Dilithium, the forgery problems reduce to SIS for the
matrix [A | T | I_n] (n rows, m + k + n columns; T is pseudorandom by LWE) in
the infinity norm:

    weak unforgeability   (SelfTargetSIS)  zeta  = max(B,  2*gamma2 + 1)
    strong unforgeability (SIS)            zeta' = max(2B, 4*gamma2 + 2)

B = gamma1 - beta - 1 bounds z. The u-part bound 2*gamma2 + 1 is Dilithium's
(it covers a hint); without hints the honest u part is gamma2 + 1, so these
bounds are conservative.
"""

import sys
import time
from math import ceil, log2


def load_estimator(argv):
    paths = [a for a in argv[1:] if not a.startswith("--")]
    if paths:
        sys.path.insert(0, paths[0])
    import estimator  # noqa: F401

    return estimator


# Keep in sync with src/params.rs.
PROVISIONAL_V1 = dict(
    id=1,
    name="LWE-FSA provisional v1",
    q=4193633,  # 2^22 - 671, prime, q - 1 = 32 * 131051
    n=1280,
    m=1280,
    k=256,
    kappa=60,
    eta=1,
    gamma1=2**18,
    gamma2=131051,  # (q - 1) / 32
)


def derived(p):
    beta = p["kappa"] * p["eta"]
    B = p["gamma1"] - beta - 1
    q, n, m, k = p["q"], p["n"], p["m"], p["k"]
    pz = ((2 * B + 1) / (2 * p["gamma1"])) ** m
    pr = ((2 * (p["gamma2"] - beta) - 1) / (2 * p["gamma2"])) ** n
    gold_p = 2**64 - 2**32 + 1
    row = m * (q - 1) * B + p["kappa"] * (q - 1)
    return dict(
        beta=beta,
        B=B,
        zeta_weak=max(B, 2 * p["gamma2"] + 1),
        zeta_strong=max(2 * B, 4 * p["gamma2"] + 2),
        attempts=1 / (pz * pr),
        pk_bytes=4 + ceil(n * k * ceil(log2(q)) / 8),
        sig_bytes=32 + ceil(m * (2 * B).bit_length() / 8),
        row_bound=row,
        headroom=(gold_p - 1) // 2 // row,
    )


def main(argv):
    est = load_estimator(argv)
    from estimator import LWE, ND, RC, SIS
    from estimator.reduction import ADPS16
    from sage.all import oo

    full = "--full" in argv
    p = PROVISIONAL_V1
    d = derived(p)

    print("=== %s (LWE_PARAM_SET_ID %d) ===" % (p["name"], p["id"]))
    print("q=%d n=%d m=%d k=%d kappa=%d eta=%d gamma1=2^%d gamma2=%d"
          % (p["q"], p["n"], p["m"], p["k"], p["kappa"], p["eta"], log2(p["gamma1"]), p["gamma2"]))
    print("beta=%d B=%d zeta(weak)=%d zeta(strong)=%d" % (d["beta"], d["B"], d["zeta_weak"], d["zeta_strong"]))
    print("expected attempts %.3f, pk %d bytes, sig %d bytes" % (d["attempts"], d["pk_bytes"], d["sig_bytes"]))
    print("Goldilocks: max |row . (z, c)| = %d = 2^%.2f < (p-1)/2 = 2^%.2f, headroom x%d"
          % (d["row_bound"], log2(d["row_bound"]), log2((2**64 - 2**32) // 2), d["headroom"]))
    print()

    Xs = ND.Uniform(-p["eta"], p["eta"])
    lwe = LWE.Parameters(n=p["m"], q=p["q"], Xs=Xs, Xe=Xs, m=p["n"], tag="LWE-FSA-v1 key recovery")
    sis_w = SIS.Parameters(n=p["n"], q=p["q"], length_bound=d["zeta_weak"], m=p["m"] + p["k"] + p["n"],
                           norm=oo, tag="LWE-FSA-v1 SIS weak unforgeability")
    sis_s = SIS.Parameters(n=p["n"], q=p["q"], length_bound=d["zeta_strong"], m=p["m"] + p["k"] + p["n"],
                           norm=oo, tag="LWE-FSA-v1 SIS strong unforgeability")
    print(lwe)
    print(sis_w)
    print(sis_s)
    print()

    betas = {}

    def show(label, res):
        b = res["beta"]
        betas[label] = b
        print("%-34s beta=%4d  core-SVP classical 2^%.1f  quantum 2^%.1f   (rop 2^%.1f)"
              % (label, b, 0.292 * b, 0.265 * b, log2(res["rop"])))

    t0 = time.time()
    print("--- core-SVP, RC.ADPS16 ---")
    show("LWE primal uSVP", LWE.primal_usvp(lwe, red_cost_model=RC.ADPS16))
    show("LWE primal BDD", LWE.primal_bdd(lwe, red_cost_model=RC.ADPS16))
    show("LWE dual", LWE.dual(lwe, red_cost_model=RC.ADPS16))
    show("LWE dual hybrid", LWE.dual_hybrid(lwe, red_cost_model=RC.ADPS16))
    show("SIS weak unforgeability (inf)", SIS.lattice(sis_w, red_cost_model=RC.ADPS16))
    show("SIS strong unforgeability (inf)", SIS.lattice(sis_s, red_cost_model=RC.ADPS16))
    print("quantum mode check: ", end="")
    q_res = SIS.lattice(sis_s, red_cost_model=ADPS16(mode="quantum"))
    print("SIS strong, ADPS16(quantum): beta=%d rop=2^%.1f" % (q_res["beta"], log2(q_res["rop"])))
    bmin = min(betas.values())
    print()
    print("minimum beta %d -> core-SVP classical 2^%.1f, quantum 2^%.1f (target: quantum >= 2^128, beta >= 484)"
          % (bmin, 0.292 * bmin, 0.265 * bmin))
    print("[%.0f s]" % (time.time() - t0))

    if full:
        print()
        print("--- LWE.estimate, default cost model (MATZOV), all attacks ---")
        t0 = time.time()
        LWE.estimate(lwe, jobs=1)
        print("--- SIS.estimate, default cost model ---")
        SIS.estimate(sis_s, jobs=1)
        print("[%.0f s]" % (time.time() - t0))


if __name__ == "__main__":
    main(sys.argv)
