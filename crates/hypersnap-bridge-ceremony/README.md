# hypersnap-bridge-ceremony

CLI tooling for the genesis bootstrap and ongoing relay workflow against
`HypersnapBridge.sol`.

## Genesis ceremony — full sequence

```bash
BIN="cargo run -q -p hypersnap-bridge-ceremony --release --"

# 1) Build the pre-genesis merkle tree from a snapshot of locks.
$BIN build-tree --input pregenesis-locks.json --output tree.json
# Prints R_initial. tree.json contains per-leaf merkle proofs for distribution.

# 2) Get the digest the deployer EOA must sign for the initial root update.
ROOT=$(jq -r .root tree.json)
$BIN digest root-update --root $ROOT --block 1
# → 0x<digest_root_init>

# 3) Sign that digest externally with the deployer's hardware wallet.
#    Foundry: `cast wallet sign --no-hash --ledger 0x<digest_root_init>`
#    For dev/testing, use the convenience `sign` subcommand:
export HYPERSNAP_DEPLOYER_KEY=0x<32-byte-hex>
SIG_ROOT=$($BIN sign --digest 0x<digest_root_init>)
# → 65-byte signature in (r || s || v) form, v ∈ {27, 28}

# 4) Verify the signature recovers to the deployer EOA before broadcasting.
$BIN recover --digest 0x<digest_root_init> \
    --signature $SIG_ROOT \
    --expected 0x<deployer_eoa>

# 5) Distribute tree.json + R_initial + sig_root_init to claimants. Each
#    claimant relays a `claim()` tx using their entry's per-leaf proof. The
#    first such tx per chain advances the root on-chain; subsequent claims
#    at that block ride free.
$BIN bundle claim \
    --tree tree.json \
    --lock-id 0x<lock_id> \
    --signature $SIG_ROOT \
    --block 1
# → ABI-encoded calldata for `claim()`. Send via `cast send <bridge_addr>
#   --raw-input 0x<calldata>`.

# --- After validators complete DKG and produce O₁ ---

# 6) Get the rotation-authorization digest, signed by the OUTGOING deployer.
$BIN digest rotate-auth --new-owner 0x<O1> --block 2
# → 0x<digest_rotate_auth>
SIG_AUTH=$($BIN sign --digest 0x<digest_rotate_auth>)

# 7) Get the acceptance digest, signed by the INCOMING threshold key via
#    DKLS23 MPC (separate tooling — validators run their MPC ceremony
#    against this exact digest).
$BIN digest owner-acceptance --new-owner 0x<O1>
# → 0x<digest_owner_accept>

# 8) Bundle and relay the rotation. Same calldata works on every chain
#    (universal sig).
$BIN bundle rotate \
    --new-owner 0x<O1> \
    --block 2 \
    --authorization-sig $SIG_AUTH \
    --acceptance-sig 0x<sig_accept_from_dkls23>
# → ABI-encoded `rotateOwner()` calldata.

# 9) Wipe the deployer key. Its signing authority is now zero.
unset HYPERSNAP_DEPLOYER_KEY
```

## Subcommand reference

| Command | What it does |
|---|---|
| `build-tree --input <locks.json> --output <tree.json>` | Hash each lock entry into an EVM-family lock leaf, sort canonically, build sorted-pair merkle tree, write root + per-leaf proofs. |
| `digest root-update --root <hex> --block <u64>` | Digest the deployer (or threshold key, post-handoff) signs to advance `latestRoot`. |
| `digest rotate-auth --new-owner <addr> --block <u64>` | Digest signed by the OUTGOING owner authorizing rotation. |
| `digest owner-acceptance --new-owner <addr>` | Digest signed by the INCOMING owner proving key possession. |
| `digest upgrade-propose --new-implementation <addr> --block <u64>` | Digest authorizing a UUPS upgrade proposal. |
| `digest upgrade-cancel --pending-implementation <addr> --block <u64>` | Digest authorizing cancellation of a pending upgrade. |
| `digest pause --block <u64>` | Digest authorizing a 48h emergency pause. |
| `sign --digest <hex>` | Convenience: sign with `HYPERSNAP_DEPLOYER_KEY` env var. **Testing only.** |
| `recover --digest <hex> --signature <hex> [--expected <addr>]` | Recover signer address from `(digest, sig)`; optionally assert match. |
| `bundle claim --tree <tree.json> --lock-id <hex> --signature <hex> --block <u64>` | ABI-encoded `claim()` calldata. |
| `bundle rotate --new-owner <addr> --block <u64> --authorization-sig <hex> --acceptance-sig <hex>` | ABI-encoded `rotateOwner()` calldata. |

## Input formats

### `pregenesis-locks.json`

```json
{
  "locks": [
    {
      "lock_id": "0x<32-byte hex>",
      "destination_chain_id": 1,
      "recipient": "0x<20-byte hex>",
      "amount": "1000000"
    },
    {
      "lock_id": "0x<32-byte hex>",
      "destination_chain_id": 8453,
      "recipient": "0x<20-byte hex>",
      "amount": "999999999999999999999"
    }
  ]
}
```

`amount` is a decimal string holding any uint256. `(lock_id,
destination_chain_id)` pairs must be unique across the snapshot — duplicates
are rejected.

### `tree.json` (output of `build-tree`)

```json
{
  "root": "0x<32-byte hex>",
  "leaves": [
    {
      "lock_id": "...",
      "destination_chain_id": 1,
      "recipient": "...",
      "amount": "...",
      "leaf_hash": "0x...",
      "merkle_proof": ["0x...", "0x..."]
    },
    ...
  ]
}
```

Leaves are sorted by `leaf_hash` ascending (canonical order). Per-leaf
proofs are sibling-only, claim-order, exactly as `MerkleProof.verifyCalldata`
consumes them.

## Production signing notes

Reading the deployer's private key from an environment variable is a
**testing convenience**. For genesis ceremony and any production-grade
signing, sign externally with hardware-walleted keys and feed the resulting
signature back into `recover` (to verify) and `bundle` (to package
calldata).

**Foundry / Ledger:**
```bash
cast wallet sign --no-hash --ledger 0x<digest>
```
Returns a 65-byte signature with `v ∈ {27, 28}` — exactly what the bridge
expects.

**Anvil / dev key:**
```bash
cast wallet sign --no-hash --private-key 0x<key> 0x<digest>
```

The `--no-hash` flag is critical — without it, `cast` applies the EIP-191
`personal_sign` prefix, which would produce a digest the bridge does not
recognize.

## Cross-side determinism

The merkle root, per-leaf hashes, and ceremony digests produced here must
match byte-for-byte what `HypersnapBridge.sol` computes. Any change to:

- domain tags in `hypersnap_crypto::bridge_payload`,
- field widths or order in `lock_leaf_evm`,
- merkle pair-sorting logic,

requires a coordinated update on both sides and a fresh test-vector pin.
The Solidity contract has no automated cross-check yet — see `F-03` in the
audit notes (need Foundry tests asserting digest hex against the same
vectors pinned in Rust).
