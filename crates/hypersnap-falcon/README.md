# hypersnap-falcon

Falcon-512 (FN-DSA-512) user keys and validator consensus keys for Hypersnap,
and the registry of all protocol domain separators. Spec:
FIP-proof-of-work-tokenization §16.4, §16.5, §16.7–§16.11.

Falcon-512 is the scheme for app signers, custody and recovery keys, spend keys
and node keys. Clients sign their messages. Validators sign consensus votes and
proposals with a Falcon-512 consensus key (§16.4).

The crate is a standalone workspace for now (empty `[workspace]` table in
`Cargo.toml`). Delete that table and the local `Cargo.lock` when the crate goes
into the root workspace.

## API

```rust
use hypersnap_falcon::{domains, keygen, keygen_from_seed, sign, verify, key_id};

let sk = keygen_from_seed(seed);               // or keygen(&mut rng)
let pk = sk.public_key();
let sig = sign(&sk, domains::MSG, data_bytes, &mut rng)?;
verify(pk, domains::MSG, data_bytes, &sig)?;   // Ok(()) or Err(FalconError)
let signer_id: [u8; 32] = key_id(pk);          // keccak256(encoded public key)
```

| Item | Description |
|---|---|
| `FalconPublicKey` | 897 bytes. `from_bytes` is strict. `key_id()`. |
| `FalconSecretKey` | 1345 bytes, on the heap, zeroized on drop. No `Clone`; `Debug` shows only the key ID. |
| `FalconSignature` | Exactly 666 bytes. `from_bytes` is strict. |
| `keygen(rng)` / `keygen_from_seed([u8; 32])` | Key generation. The seed form is deterministic on all platforms. |
| `sign` / `sign_parts` | Sign `domain \|\| payload` (or `domain \|\| part0 \|\| part1 ...`). |
| `verify` / `verify_parts` | Verify. `Ok(())` only for a valid signature. |
| `verify_bytes` | Strict decode of wire bytes, then verify. |
| `key_id(&pk)` | `keccak256(pk)`, Ethereum Keccak-256 (not SHA3-256). |
| `keccak256` | Helper. |
| `domains::*` | Falcon-512 domain separators (`Domain`). |
| `domains::hash_domains::*` | Keccak-256 and SHAKE domain strings (`HashDomain`). |

The RNG traits are `rand_core` 0.6 (`hypersnap_falcon::{CryptoRng, RngCore}`),
because fn-dsa 0.4 uses that version.

## Strict decoding

A byte string is accepted only if fn-dsa would make it:

- Public key: length 897, header `0x09`, each 14-bit coefficient < 12289.
- Signature: length 666, header `0x39`, a 40-byte nonce, then a canonical
  compressed `s2`: no "-0", each |coefficient| ≤ 840, no truncation, and all
  padding bits zero. The norm bound needs the key, so only `verify` checks it.
- Secret key: length 1345, header `0x59`, accepted by fn-dsa, and the
  SHAKE256 public-key hash at its end agrees with the key. fn-dsa does not do
  the last check.

The FIP says that a signature is "666 bytes or less". fn-dsa 0.4 uses the
fixed-length FN-DSA format, so a signature is always exactly 666 bytes.

## Domain rules

Each Falcon-512 signature signs `domain || payload`. There is one domain for
each message type and each signed field (§16.7).

- The signature of a `Message` uses `MSG` over `data_bytes` (§16.8), for every
  key role. `data_bytes` contains the message type, so `MSG` also separates the
  types.
- A second Falcon-512 signature in a body (a proof of possession, a custody
  approval, an escrow authorization) or a signature outside a `Message`
  (consensus vote or proposal, genesis entry, gossip attestation) has its own
  domain.

Rules:

1. The domain is a `Domain` constant from `domains.rs`. Code outside the module
   cannot make a `Domain`.
2. All domain strings, Falcon and hash, are unique and prefix-free. The payload
   has no length prefix, so a domain that is a prefix of another makes two
   different (domain, payload) pairs give the same signed bytes.
3. Falcon domains have the form `hypersnap-<message-type>[-<field>]-v<N>`.
   `-pop` marks a proof of possession by the key that the message registers.
   A string that the FIP gives literally is used as given.
4. A new payload layout gets a new version, not an edit of a string.

The unit tests in `domains.rs` enforce rules 2 and 3. The doc comment of each
constant gives the FIP section, the signer, the field and the payload.

## Mapping to FN-DSA

`sign`/`verify` are plain FN-DSA-512 with an empty context string and no
pre-hash, over the message `domain || payload`:

```text
vk.verify(sig, &DOMAIN_NONE, &HASH_ID_RAW, domain || payload)
```

The domain is not the FN-DSA context string. Another implementation (a wallet
in another language) must use an empty context and put the domain bytes at the
start of the message. The crate streams the message into the FN-DSA message
representative, so it does not copy the payload; `interop_with_plain_fn_dsa`
checks that the result is identical.

## Determinism of verification

- fn-dsa key generation and verification use integer arithmetic only. On x86
  fn-dsa selects an AVX2 path at run time; it is specified to give the same
  results as the portable path. This crate adds only Keccak-256, SHAKE256 and
  byte comparisons. Thus all nodes get the same result for the same input.
- The KATs were generated on aarch64 (Apple). Run them in x86_64 CI too, so
  that both fn-dsa code paths are checked against the same values.
- Signing uses floating-point arithmetic (native IEEE-754 on x86_64 and
  aarch64, emulated on other targets). Clients and validators sign. Consensus
  depends only on verification, never on the bytes that a signer makes.
- fn-dsa is pre-1.0, and its README says that encodings can change before 1.0.
  fn-dsa 0.4.0 implements a "best guess" (2026-07-22) at the FN-DSA draft.
  The versions of `fn-dsa` and `fn-dsa-comm` are pinned with `=0.4.0`. A
  change of the pin can change which keys and signatures are valid, so it is a
  hard fork. The known-answer tests in `tests/kat.rs` fail if a change of the
  pin changes key generation, signing or verification.

## Deterministic signing

fn-dsa has no separate deterministic mode, but its signing is hedged: it
replaces the 40 RNG bytes with `SHAKE256(hash(sk) || mu || rng_bytes)`. Thus:

- A weak RNG does not leak the key.
- A fixed RNG output (for example a seeded ChaCha20) gives a deterministic
  signature. The KATs use this.

Use a real RNG in production. If a deterministic signer gives two different
signatures for the same nonce, the difference leaks key information. fn-dsa
requires strict IEEE-754 behavior to prevent this, but a fixed RNG output on a
non-conformant platform removes the protection that fresh randomness gives.

## Tests

```sh
CARGO_TARGET_DIR=<dir> cargo test
CARGO_TARGET_DIR=<dir> cargo clippy --all-targets -- -D warnings
```

- `src/domains.rs`: registry uniqueness, prefix-freeness (in each group and
  across both), naming rule, FIP literal strings.
- `tests/sign_verify.rs`: round trips, tampered payload, signature (all 5,328
  bit flips) and key, wrong key, wrong domain (all pairs), parts versus
  concatenation, interop with plain fn-dsa.
- `tests/strict_decoding.rs`: all truncations, length + 1, all header bytes,
  coefficient range, padding, "-0", the 840 bound, random bytes.
- `tests/kat.rs`: three fixed seeds with hard-coded key IDs, secret-key hashes
  and full signatures.

## Zeroization

The secret key bytes, the key-generation seed, and the fn-dsa signing and
key-generation contexts are zeroized on drop. Rust can leave copies on the
stack when it moves a value, so this is best effort.
