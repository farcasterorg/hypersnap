# LWE-FSA parameter set: provisional v1 (`LWE_PARAM_SET_ID = 1`)

> **PROVISIONAL. NOT FROZEN.** These numbers are a candidate for external
> review. A release freezes the parameter set only after that review, and
> after the LWE-MS2 analysis (FIP §16.5, §18 item 2) has confirmed that the
> same keys and modulus support aggregation. Any number here can still
> change; keys made under id 1 can become invalid.

The [`TEST`](../src/params.rs) set (`LWE_PARAM_SET_ID = 0xFFFFFF00`) is a toy
set for unit tests. It has no security.

## Parameters

| Symbol | Value | Meaning |
|---|---|---|
| `q` | 4 193 633 = 2^22 − 671 | prime modulus, `q − 1 = 32 · 131 051` |
| `n` | 1280 | rows of `A` (LWE samples, SIS rows) |
| `m` | 1280 | columns of `A` (LWE secret dimension, length of `z`) |
| `k` | 256 | columns of `S`, `E`, `T`; length of `c` |
| `κ` | 60 | weight of `c ∈ {−1,0,1}^k` |
| `η` | 1 | `S`, `E` uniform in `{−1, 0, 1}` |
| `β = κη` | 60 | worst-case `‖S·c‖∞`, `‖E·c‖∞` |
| `γ1` | 2^18 | `y` uniform in `[−γ1+1, γ1]^m` |
| `B = γ1 − β − 1` | 262 083 | verifier bound `‖z‖∞ ≤ B` |
| `γ2` | 131 051 = (q−1)/32 | `Decompose` range, `HighBits ∈ [0, 16)` |

### Rationale

* **Challenge, `k = 256`, `κ = 60`.** `|C| = C(256,60)·2^60 = 2^257.0`.
  A Grover search for a challenge then costs at least 2^128. A smaller `k`
  needs a larger `κ` for the same space (`k = 192` needs `κ = 75`), which
  raises `β` and with it `γ1`, `γ2` and the SIS bound. A larger `k` grows the
  public key linearly for little gain (`k = 384` still needs `κ = 49`). The
  signature stores the 32-byte seed `c̃` of `c`.
* **Secret distribution, `η = 1`.** `β = κη` is a worst-case bound, so no
  key or signing check on `‖S·c‖∞` is necessary. Against `η = 2` at
  `q ≈ 2^23`, `η = 1` at `q ≈ 2^22` gives about the same LWE hardness (the
  ratio `q/σ` is similar), halves `β` and therefore `γ1`, `γ2` and the SIS
  bound, and saves one bit per coefficient in the key and the signature.
* **Modulus.** `q` is the largest prime below 2^22 with `q ≡ 1 (mod 32)`, so
  `2γ2 = (q−1)/16` and `HighBits` has 16 values (4 bits). The scheme is
  unstructured, so no NTT condition applies. A prime avoids the subgroup
  structure of SIS over `Z_{2^ℓ}` (a solution mod 2 lifts to a solution of
  norm `q/2`).
* **Dimensions.** `m` sets the LWE hardness (secret dimension); `n` sets
  the SIS hardness (rows). `n = 1280` is the smallest multiple of 64 for
  which SIS (strong unforgeability) reaches the target (`n = 1216` gives
  β ≈ 468); it is the binding constraint (β = 500). `m = 1216` would still
  pass LWE (dual hybrid β = 497) and save 152 bytes per signature;
  `m = 1280` keeps a margin of 45 in β on the LWE side, where the hybrid
  and dual attacks are refined most often.
* **`γ1`, `γ2`.** They balance the two rejection conditions against the SIS
  bound `ζ' = max(2B, 4γ2 + 2) ≈ 2^19`.

### Abort probability

`z_j = y_j + (S·c)_j` with `y_j` uniform on `2γ1` values and `|(S·c)_j| ≤ β`,
so a coordinate passes `|z_j| ≤ B` with probability exactly `(2B+1)/(2γ1)`.
`w − E·c` is close to uniform mod `q`, so a coordinate passes
`|LowBits| < γ2 − β` with probability `(2(γ2−β)−1)/(2γ2)`. One attempt
succeeds with probability

```
P = ((2B+1)/(2γ1))^m · ((2(γ2−β)−1)/(2γ2))^n = e^−(0.2954 + 0.5911) = 0.412
```

Expected attempts `1/P = 2.427`. Measured: 2.413 over 20 000 signatures
(4 keys); the release test suite measures 1 000 more each run.

### CERT-STARK constraint (FIP §16.6)

All entries of `A` and `T` are in `[0, q)`. For `‖z‖∞ ≤ B` and weight-`κ`
`c ∈ {−1,0,1}^k`, every row of `A·z − T·c` over the integers satisfies

```
|⟨A_i, z⟩ − ⟨T_i, c⟩| ≤ m·(q−1)·B + κ·(q−1)
                      = 1 280 · 4 193 632 · 262 083 + 60 · 4 193 632
                      = 1 406 822 210 601 600 ≈ 2^50.32
                      < (p − 1)/2 = 9 223 372 034 707 292 160 ≈ 2^63
```

with `p = 2^64 − 2^32 + 1`. The integer value is thus unique in the signed
range of the field, and one range check per row reduces it mod `q`. The
headroom is ×6556: an aggregate (LWE-MS2) `z` can have an `‖·‖∞` bound up to
6556·B before the constraint breaks. For the actual matrix `A`,
`max_i Σ_j a_ij · B + κ(q−1) ≈ 2^49.40`; real signatures reach
`max |⟨A_i, z⟩| ≈ 2^45`. The signer's `A·y` has the same bound with `γ1`
(2^50.32). `ParamSet::check` asserts both bounds at compile time.

## Security estimate

Problems:

* **LWE key recovery.** Each column `t_j = A s_j + e_j`: secret dimension
  `m = 1280`, `n = 1280` samples, `q`, secret and error uniform ternary
  (`σ = 0.82`).
* **SIS forgery.** As for Dilithium, forgery reduces to SIS in the infinity
  norm for `[A | T | I_n]` (1280 rows, 2816 columns; `T` is pseudorandom
  under LWE):
  weak unforgeability `ζ = max(B, 2γ2+1) = 262 103`,
  strong unforgeability `ζ' = max(2B, 4γ2+2) = 524 206`.
  The `u` part bound `2γ2+1` is Dilithium's, which covers its hint; this
  scheme has no hint, so the bounds are conservative.

### Lattice estimator (authoritative)

`estimate.py`, lattice-estimator `53da598` (2026-08-19), SageMath 10.6.
Full output: [`estimate-output.txt`](estimate-output.txt).

Core-SVP (`RC.ADPS16`; classical `2^(0.292β)`, quantum `2^(0.265β)`):

| Attack | β | classical | quantum |
|---|---|---|---|
| LWE primal uSVP | 547 | 2^159.7 | 2^145.0 |
| LWE primal BDD | 547 | 2^159.7 | 2^145.0 |
| LWE dual | 559 | 2^163.2 | 2^148.1 |
| LWE dual hybrid | 529 | 2^154.5 | 2^140.2 |
| SIS weak unforgeability (ℓ∞) | 562 | 2^164.1 | 2^148.9 |
| **SIS strong unforgeability (ℓ∞)** | **500** | **2^146.0** | **2^132.5** |

Minimum: β = 500, i.e. **2^132.5 quantum core-SVP** (target: 2^128, β ≥ 484).

Default cost model (MATZOV, all LWE attacks): LWE ≥ 2^179.3 (dual hybrid,
β = 524), coded-BKW 2^283.5; SIS strong ≈ 2^176.1 (β = 512).

### Pure-Python cross-check (not authoritative)

`coresvp.py` reimplements the Kyber/Dilithium "2016 estimate" scripts
(primal uSVP, dual, and the Dilithium ℓ∞ SIS model) without Sage. It
reproduces the published Dilithium round-3 block sizes (LWE 423/623, SIS
423/638) and gives for this set: LWE primal β = 547, dual β = 545, SIS weak
β = 562, SIS strong β = 501. Output: [`coresvp-output.txt`](coresvp-output.txt).

## Running

```
git clone https://github.com/malb/lattice-estimator /path/to/lattice-estimator
sage -python estimate.py /path/to/lattice-estimator          # core-SVP, ~20 s
sage -python estimate.py /path/to/lattice-estimator --full   # + all attacks, ~3 min
python3 coresvp.py                                           # cross-check, ~10 s
```

`estimate.py` and `coresvp.py` repeat the numbers of `src/params.rs`; keep
the three in sync.

## Open items before freezing

1. External review of this estimate (in particular the SIS ℓ∞ model, which
   is the binding constraint).
2. LWE-MS2 (§16.5) uses the same `A`, `q` and keys. Its aggregate `z` must
   keep the SIS problem hard and fit the Goldilocks bound above. With
   uniform masks as in LWE-FSA, a per-signer abort probability of `1/|P|`
   needs `γ1 ≈ |P|·m·β` and a worst-case aggregate `‖z‖∞ ≈ |P|²·m·β`, which
   exceeds `q/2` already for `|P| ≥ 6`. LWE-MS2 therefore needs Gaussian masks with a
   low-abort rejection method and an ℓ2 SIS analysis, and that analysis can
   force a larger `q` (and then larger `n`, `m`) for this parameter set.
3. Message size limits: a public key is 901 124 bytes, so validator
   registrations and the genesis validator file need limits above that.
