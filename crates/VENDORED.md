# Vendored QCT3 crates

This file records the vendored copy of the QCT3 confidential-token crates
(FIP-proof-of-work-tokenization Section 16.12, plan item B11/WS11). It covers
only `quil-lattice-ct` and `quil-lattice-proof-sys`. The other vendored
crates (`dkls23`, `ed448-bulletproofs`) are described in the root
`Cargo.toml`.

## Source

| Item | Value |
|---|---|
| Repository | Quilibrium monorepo, `git@github.com:QuilibriumNetwork/monorepo.git` (local checkout `~/src/quilibrium/monorepo`, branch `v2.1.0.25`) |
| Revision | `75f7cff10f5f3b8fc31999d6f80bc5829a7a7774` (2026-10-16, "fix shard quorum sealing misbehavior") |
| Last commit that changed the two crates | `ba1631bf7fc64258e477c9d2576bfbbeb84ac2d8` (2026-10-06) |
| Upstream paths | `crates/quil-lattice-ct`, `crates/quil-lattice-proof-sys` |
| Working-tree state at the copy | Clean. `git status --short --ignored` showed no change, untracked file or ignored file under either crate. |
| Copy method | `git archive 75f7cff1 crates/quil-lattice-ct crates/quil-lattice-proof-sys`. The export was compared with the working tree and was identical. |
| Files | 634 tracked upstream files. 630 are vendored. |
| Not vendored | `quil-lattice-proof-sys/tools/__pycache__/*.pyc` (4 tracked Python bytecode caches, which are build artifacts) and the empty, untracked `quil-lattice-ct/docs/` directory. |
| Native sources in the crates | labrados `3f95485139ffaa65fe572da809b90772901372e5`, SIMDe `2b2a2b8182f66c899a90fedb27c8621d5e5c9354` (`quil-lattice-proof-sys/SOURCE.json`) |

The monorepo was not modified.

## Licenses

These were checked in the files themselves.

| Part | License | Evidence |
|---|---|---|
| `quil-lattice-ct` | Apache-2.0 | `Cargo.toml` `license = "Apache-2.0"`. `NOTICE` records Rust adaptations of labrados `gaussian.c` and `poly.c` (Copyright (C) 2026 IBM Corp., Apache-2.0) and the public-domain fdlibm `e_exp.c` origin of the exponential approximation. The crate has no license text file of its own. |
| `quil-lattice-proof-sys` | Apache-2.0 | `Cargo.toml` `license = "Apache-2.0"` and `LICENSE-APACHE` (Apache License 2.0 text). The README says that this license covers the integration glue. |
| `vendor/labrados` | Apache-2.0 | `UPSTREAM-LICENSE`: "Copyright (C) 2026, IBM Corp. Licensed under the Apache License, Version 2.0". `fips202.c` and `aesctr.c` state that they are based on public-domain code. |
| LaZer notice | MIT | `vendor/labrados/LAZER-LICENSE`: MIT, "Copyright (c) 2022-2024 IBM". |
| `vendor/simde` | MIT, with 6 files CC0-1.0 | `COPYING`: MIT, "Copyright (c) 2017 Evan Nemerson". 466 headers have `SPDX-License-Identifier: MIT`. These 6 have `SPDX-License-Identifier: CC0-1.0`: `simde/check.h`, `simde/debug-trap.h`, `simde/hedley.h`, `simde/simde-align.h`, `simde/simde-arch.h`, `simde/simde-detect-clang.h`. `simde/simde-math.h` contains two snippets marked "Public Domain". |

Notes:

- The monorepo root `LICENSE` is AGPL-3.0. The two crates declare Apache-2.0
  in their manifests. The owner of both repositories holds the copyright.
- The `NOTICE` of `quil-lattice-ct` names stale paths. The file
  `src/amount_candidate/relation/backend/portable/gaussian.rs` is now
  `src/confidential/relation/backend/portable/gaussian.rs`, and the
  challenge files are under the same directory. The vendored `NOTICE` is
  unchanged.

## Build isolation

The crates are not members of the Hypersnap workspace. The root
`Cargo.toml` and `Cargo.lock` are not changed.

- Each crate's `Cargo.toml` ends with an empty `[workspace]` table, marked
  `HYPERSNAP`. Without it, Cargo attaches the crate to the root workspace and
  stops with "current package believes it's in a workspace when it's not".
  `quil-lattice-ct/Cargo.toml:45-49`, `quil-lattice-proof-sys/Cargo.toml:16-19`.
- To make the crates workspace members, delete both `[workspace]` tables and
  add the two paths to `members` in the root `Cargo.toml`.
- No `Cargo.lock` is vendored (the same rule as for the other vendored
  crates). The tests below used the dependency versions of the monorepo lock
  file at the vendored revision. To get the same versions, copy the monorepo
  `Cargo.lock` at `75f7cff1` into the crate directory before the first build.
  Cargo then removes the packages that the crate does not use (49 remain).

Commands (the target directory is outside the repository):

```sh
export CARGO_TARGET_DIR=/path/outside/the/repo/target-qct
cd crates/quil-lattice-ct
cargo test --release --features native-proof          # all ct tests
cargo test --release --features confidential-tokens   # without native code
cargo build --release --features native-proof --example transfer_roundtrip
cd ../quil-lattice-proof-sys
cargo test --release --features native-backend        # native ABI tests
```

## Dependencies

No dependency was rewritten. Neither manifest uses `workspace = true`
inheritance, and no monorepo `[patch]` entry applies to these crates. The
only internal dependency is
`quil-lattice-proof-sys = { path = "../quil-lattice-proof-sys", features = ["native-backend"], optional = true }`
in `quil-lattice-ct`. The relative path is unchanged, and it now resolves to
the vendored sibling crate.

| Crate | Dependency | Requirement (unchanged) | Version used in the tests |
|---|---|---|---|
| quil-lattice-ct | `sha2` | `0.10` | 0.10.9 |
| quil-lattice-ct | `libc` (optional) | `0.2` | 0.2.186 |
| quil-lattice-ct | `sha3` (optional) | `0.10` | 0.10.8 |
| quil-lattice-ct | `zeroize` (optional) | `1.8` | 1.8.1 |
| quil-lattice-ct | `aes` (optional, `zeroize`) | `0.8.4` | 0.8.4 |
| quil-lattice-ct | `num-bigint` (optional) | `0.4.6` | 0.4.6 |
| quil-lattice-ct | `aes-gcm` (optional, `zeroize`) | `0.10.3` | 0.10.3 |
| quil-lattice-ct | `pqcrypto-ntruprime` (optional) | `0.1` | 0.1.6 (with `pqcrypto-internals` 0.2.11) |
| quil-lattice-ct | `pqcrypto-traits` (optional) | `0.3` | 0.3.5 |
| quil-lattice-ct | `rand` (optional) | `0.8` | 0.8.5 |
| quil-lattice-ct | `quil-lattice-proof-sys` (optional) | path `../quil-lattice-proof-sys` | vendored copy |
| quil-lattice-proof-sys | `cc` (build) | `1.2.67` | 1.2.67 |

Manifest changes other than dependencies: the `ablation-bench` feature
(`quil-lattice-ct`) and the `bench-knobs` feature
(`quil-lattice-proof-sys`) are removed (change 5), and the two `[workspace]`
tables are added.

## Hypersnap changes

All changes are encoding changes or removals. No change alters a proof
relation: the amount, membership and ownership equations, the commitment
key, the transcript and the native parameters are the same as upstream.
Each changed place has a `HYPERSNAP` comment. The line numbers are those of
the vendored tree.

### 1. Shield owner: keccak256 of the account key

- `src/confidential/shield.rs:24` adds `OWNER_KEY_HASH_BYTES = 32`.
- `src/confidential/shield.rs:45` replaces `owner_public_key: [u8; 57]`
  (Ed448) with `owner_key_hash: [u8; 32]` in `ShieldStatement`. The same
  change is at `:167` in `BatchShieldStatement`.
- The bound bytes contain the 32-byte hash in place of the 57-byte key:
  `shield.rs:81` (single) and `:210` (batch). The header sizes are at `:25`
  and `:31`. The layout is in the comment at `:61-63`.
- The proof binds only these bytes. `ShieldStatement::public_relation` and
  `private_relation` pass the complete `context_bytes()` to
  `with_transaction_context` (`shield.rs:104`, `:127`; batch `:234`, `:257`).
- The 114-byte Ed448 `signature` field is removed from `Shield` (`:52`) and
  `BatchShield` (`:175`), from both encoders and decoders, and from the size
  checks. `AnyShield::signature()` is removed. `AnyShield::owner_public_key()`
  becomes `owner_key_hash()` (`:354`). Hypersnap authenticates the account key
  with the Falcon signature of the enclosing message, and that message
  contains these bytes.
- The routing offset of the first batch source follows the new layout
  (`:146`).
- `src/confidential/hypersnap.rs:72` adds `account_key_hash(key)`, which is
  keccak256 (Ethereum Keccak, not SHA3-256).

### 2. Transfer: 32-byte binding field

- `src/confidential/transfer.rs:24` adds `BINDING_BYTES = 32`.
- `transfer.rs:69` adds `pub binding: [u8; 32]` to `TransferStatement`.
- `transfer.rs:159` writes it into `context_bytes()` after `fee` and before
  `root` (layout comment at `:132-134`). `transfer.rs:312` reads it in
  `decode`.
- The library gives the bytes no meaning. The node sets them as Section 16.12
  says (unshield, lock, or 32 zero bytes for a plain transfer).
- Struct literals in other modules get `binding: [0; 32]`:
  `settlement.rs:284`, `pending_create.rs:168`, `pending_create.rs:229`,
  `examples/transfer_roundtrip.rs:134`.

**The transfer proof binds the statement encoding, as the shield proof
does.** The path:

1. `TransferStatement::public_relation` and `private_relation` call
   `with_transaction_context(&self.context_bytes()?)` (`transfer.rs:204`,
   `:255`). The prover and the verifier use the same call.
2. `bind_transaction_context` (`src/confidential/relation.rs:189-208`)
   computes SHAKE256(`"quil/token/transaction-context/v2\0"` ‖ length as
   u64 LE ‖ context bytes) to 64 bytes. It adds two binary witness
   polynomials, one for each 256 bits, with the ring equations
   `1 · x = bits`. The digest bits are the public right-hand sides.
3. The verifier builds these rows from the public bytes and submits them
   with the other rows (`relation/backend/submission.rs`,
   `submit_public_statement`).
4. The native verifier absorbs every constraint's coefficients and
   right-hand side into the statement hash
   (`quil-lattice-proof-sys/vendor/labrados/labrados_python.c:203-241`,
   domain `quil/native-public-statement/v6` at `:105-115`). That hash
   starts the Fiat-Shamir transcript (`labrador_core.c:660`). The verifier
   also checks the rows against the proof, so a proof for other bytes fails
   the constraint check.

Thus all context bytes are bound, which includes prefix, version, network,
application, depth, counts, fee, binding, root, key images, output
commitments, output owners and memos. The proof length and the proof are
not bound.

Evidence from tests:

- `transfer::tests::proof_statement_binds_the_binding_field`
  (`transfer.rs:642`). The prover's public statement (from the witness)
  is equal to the verifier's statement (from public bytes) only when the
  binding bytes are equal. A flip of byte 0, 17 or 31, or all-zero bytes,
  gives a different statement. The binding goes through the wire codec.
- Native end-to-end: `examples/transfer_roundtrip.rs` `verify-binding` now
  also flips a binding byte (`:95-102`). A real proof at depth 1 and at depth
  32 verifies, and after a change to the memo, an output owner or the binding
  the verifier rejects it (results below).
- For the shield owner hash: `hypersnap::tests::shield_owner_is_the_bound_keccak256_of_the_account_key`
  (`hypersnap.rs:384`) does the same statement check for `owner_key_hash`.

### 3. Unshield and lock: public outflow in `fee`, `u64` limit

No new statement type. `QCT_UNSHIELD` and `QCT_LOCK` are transfers whose
public outflow is the `u128` field `TransferStatement::fee`.

- `hypersnap::public_outflow(statement) -> Result<u64, _>`
  (`hypersnap.rs:77`) gives `fee` as a `u64`, or `AmountRange` if
  `fee > u64::MAX`.
- `hypersnap::check_public_outflow(statement, amount)` (`hypersnap.rs:83`)
  also requires `fee == amount` (Section 16.12 statement encoding item 3).
- `hypersnap::shield_amounts(statement)` (`hypersnap.rs:91`) applies the
  same limit to a shield's `amount` and `fee`.
- `hypersnap::decode` (`hypersnap.rs:107`) applies these limits to every
  accepted transfer and shield, so the worker gives `invalid` for a public
  amount above `u64::MAX`.

### 4. Accepted proof types: transfer and shield only

- `src/confidential/hypersnap.rs` (new, 420 lines; registered at
  `src/confidential.rs:29-30`).
  - `accepted_kind` (`:58`) accepts two (prefix, version) pairs: transfer
    `0x0512` / `QCT3TXH\x02` and single shield `0x0516` / `QCT3SHH\x02`.
  - `decode` (`:107`) rejects every other type with `UnsupportedType`: mint
    and custom mint (`0x0513`), pending create (`0x0514`), pending claim
    (`0x0515`), mint claim (`0x0517`), settlement (`0x0518`), the batch
    shield (`0x0516` / `QCT3SHH\x03`), every upstream encoding and unknown
    prefixes.
- `src/confidential/relation/backend/worker_request.rs:69-86` replaces the
  upstream `verify_amount_proof`, which dispatched to all seven types, with
  `verify_hypersnap_amount_proof`. `run_worker` (the
  `quil-amount-proof-worker` binary) calls it (`:118`). A rejected type gives
  `Ok(false)`, which is exit code 81 (`invalid`).
- The modules for the rejected types stay in the crate, unchanged except
  for the struct literals of change 2, to keep upstream merges small. No
  Hypersnap entry point reaches them.

### 5. Benchmark features removed

- `quil-lattice-ct/Cargo.toml`: the `ablation-bench` feature is removed
  (upstream lines 25-26).
- `src/confidential/relation/membership.rs:681`: the `Ablation` enum, the
  `ablation()` function (`QUIL_ABLATION`) and both ablation branches are
  removed. The normal path is kept unchanged.
- `quil-lattice-proof-sys/Cargo.toml`: the `bench-knobs` feature is removed
  (upstream lines 12-13).
- `quil-lattice-proof-sys/build.rs:29-30`: the `QUIL_BENCH_KNOBS` define is
  removed.
- `vendor/labrados/pack.c:46-48` and `vendor/labrados/proofsystem.c:89`:
  the `#ifdef QUIL_BENCH_KNOBS` blocks (the `QUIL_BENCH_MAX_ROUNDS`,
  `QUIL_BENCH_MIN_ZK_ROUNDS` and `QUIL_BENCH_LOGDELTA` environment
  overrides) are removed, and the `#else` code is kept. A `-DQUIL_BENCH_KNOBS`
  in `CFLAGS` can therefore not turn them on again. After preprocessing with
  the build flags, `pack.c` is byte-identical to upstream, and
  `proofsystem.c` differs only in the `__LINE__` numbers of `assert`
  messages.
- `quil-lattice-proof-sys/SOURCE.json`: the sha256 entries of these two
  files are updated, and a `hypersnap_note` key records the upstream values.
  All 567 entries match the vendored files.

### Changes that follow from 1 to 4

- Version tags. The transfer and shield layouts changed, so their tags
  replace the NUL byte with `H`: `QCT3TX\0\x02` becomes `QCT3TXH\x02`
  (`transfer.rs:22`), `QCT3SH\0\x02` becomes `QCT3SHH\x02` (`shield.rs:21`),
  `QCT3SH\0\x03` becomes `QCT3SHH\x03` (`shield.rs:29`). An upstream
  encoding therefore never decodes as a Hypersnap encoding. The tags are in
  the bound bytes. The `PREFIX` and `VERSION` constants of `transfer.rs` and
  `shield.rs` are `pub(super)`, so that `hypersnap.rs` can use them.
- Worker readiness identifier.
  `relation/backend/worker_process.rs:22` changes
  `QUIL-AMOUNT-WORKER-READY-QCT3-V1` to
  `QUIL-AMOUNT-WORKER-READY-QCT3-HYPERSNAP-V1`, as the upstream comment
  requires when the supported operation suite changes. The request envelope
  (`QCTW1`) and the exit codes 80/81/82 are unchanged.
- Upstream tests with fixed sizes or offsets are adjusted:
  `transfer.rs:540` (+32 bytes), `:555-590` (root offset 97 becomes 129),
  `:613-625` (the binding is one of the mutated fields); `shield.rs:523`
  (180507 − 25 − 114 bytes), `:607` (batch truncation offsets).
- New tests: `hypersnap::tests` (3 tests, `hypersnap.rs:297`, `:361`,
  `:384`), `transfer::tests::proof_statement_binds_the_binding_field`, and
  `worker_request::tests::hypersnap_worker_rejects_types_outside_the_whitelist`
  (`worker_request.rs:134`, needs `native-proof`). The shared test sink
  `hypersnap::test_support::StatementDigest` (`hypersnap.rs:152`) hashes the
  complete public statement as a statement sink receives it.

## Test results

Machine: Apple M-series (aarch64-apple-darwin), 10 CPUs, 64 GB, rustc 1.95.0,
Apple clang 21.0.0. Release mode, monorepo dependency versions.

| Suite | Upstream copy (75f7cff1) | Vendored copy |
|---|---|---|
| `quil-lattice-ct` lib, `--features native-proof` | 151 passed, 7 ignored, 5.96 s | 156 passed, 7 ignored, TBD s |
| `quil-lattice-ct` `tests/canonical_range.rs` | 3 passed, 0.10 s | 3 passed, TBD s |
| `quil-lattice-proof-sys` lib, `--features native-backend` | 24 passed, 1 ignored, 1.96 s | TBD |

TBD

## QCT_DEPENDENCY_REV

TBD

## Library facts for FIP Section 16.12

TBD

## Update from upstream

TBD

# Vendored rust-rocksdb wrapper

`crates/rust-rocksdb` is the Rust wrapper crate `rocksdb` 0.24.0 of
`https://github.com/rust-rocksdb/rust-rocksdb.git` at revision
`a4f178d0ca668c4b48d993ab8aef6f4004780f23`, the revision that the root
`Cargo.toml` pins. The root `Cargo.toml` replaces the git dependency with
this path through `[patch."https://github.com/rust-rocksdb/rust-rocksdb.git"]`.

| Item | Value |
|---|---|
| Copied | `src/`, `Cargo.toml`, `LICENSE` (Apache-2.0), `README.md` |
| Not copied | `librocksdb-sys` (the C++ library and its bindings), `tests/`, CI files |
| `Cargo.toml` changes | No `[workspace]` table; `librocksdb-sys` is a git dependency at the same revision (it was a path dependency) |
| Source change | `TransactionDB::create_checkpoint` in `src/transactions/transaction_db.rs`, over the C API `rocksdb_transactiondb_checkpoint_object_create` and `rocksdb_checkpoint_create`. Nothing else changed. |
| Reason | The epoch boundary checkpoints (FIP §17.7, plan A4) of the shard DBs, which are `TransactionDB`s. The upstream wrapper exposes checkpoints only for `DB`. |

To update: copy the same files from the new revision, keep the two
`Cargo.toml` changes, and apply the `create_checkpoint` function again. Drop
the vendored copy when upstream exposes a `TransactionDB` checkpoint.
