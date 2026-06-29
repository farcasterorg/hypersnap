# Hypersnap L1 Bridge Contracts

Solidity contracts that anchor Hypersnap-locked tokens on EVM chains. The
hyper-layer validator set runs threshold ECDSA (DKLS23 over secp256k1) and
produces standard `(r, s, v)` signatures verifiable here via `ecrecover`.

## Files

| File | Purpose |
|---|---|
| `HypersnapBridge.sol` | Hypersnap ERC20 (with EIP-2612 permit) + permissionless-relay bridge (UUPS upgradeable). One contract houses the token and the bridge. |

## Design

### Signed payload domains

| Domain tag | Used by | Scope | Signed payload |
|---|---|---|---|
| `HYPERSNAP_MERKLE_ROOT_UPDATE_V1` | `claim` | universal | `tag ‖ u64_be(blockNumber) ‖ bytes32(merkleRoot)` |
| `HYPERSNAP_OWNER_UPDATE_V1`       | `rotateOwner` (auth) | universal | `tag ‖ u64_be(blockNumber) ‖ bytes20(newOwner)` |
| `HYPERSNAP_OWNER_ACCEPTANCE_V1`   | `rotateOwner` (proof of key possession by incoming owner) | universal | `tag ‖ bytes20(newOwner)` |
| `HYPERSNAP_UPGRADE_V1`            | `proposeUpgrade` | universal | `tag ‖ u64_be(blockNumber) ‖ bytes20(newImplementation)` |
| `HYPERSNAP_UPGRADE_CANCEL_V1`     | `cancelUpgrade` | universal | `tag ‖ u64_be(blockNumber) ‖ bytes20(pendingImplementation)` |
| `HYPERSNAP_PAUSE_V1`              | `pause` (72h emergency halt) | universal | `tag ‖ u64_be(blockNumber)` |
| `HYPERSNAP_RECOVER_ERC20_V1`      | `recoverERC20` | **chain-specific** | `tag ‖ bytes32(chainId) ‖ u64_be(blockNumber) ‖ bytes20(token) ‖ bytes20(to) ‖ bytes32(amount)` |

All universal sigs share a strictly-monotonic 64-bit Hypersnap block-number
watermark. Any stale signature of any kind is invalidated by any later applied
signature of any kind.

The `recoverERC20` sig binds to `block.chainid` because the same `token`
address could refer to a totally different contract on another chain;
universal scope would be unsafe here.

### Lock leaf format (multi-network)

The leaf carries a 1-byte network-family discriminator so a single merkle
tree can serve every destination. The EVM bridge contract verifies only
`FAMILY_EVM (0)` leaves; Solana / Quilibrium / future bridges live in
separate codebases and verify their own family.

```
keccak256(
    "HYPERSNAP_LOCK_LEAF_V1"             ‖
    bytes32(lockId)                      ‖
    u8(networkFamily)                    ‖
    family_specific_target               ‖
    u256_be(amount)
)
```

| Family | Code | Family-specific target |
|---|---|---|
| EVM        | 0 | `u32_be(chainId) ‖ bytes20(recipient)` |
| Solana     | 1 | `bytes32(recipient_pubkey)` |
| Quilibrium | 2 | TBD |

All families use keccak256 (Solana has a syscall for it). One hash function
across families means one merkle tree, one signed root per epoch.

### Claim / lock direction (Hypersnap → EVM)

`claim` enforces:
- bridge not paused
- `destinationChainId == uint32(block.chainid)`
- `lockId` not already claimed (replay protection)
- if `blockNumber > latestBlock`: signature valid; advance `latestRoot`
- otherwise `(blockNumber, merkleRoot)` must match stored values
- `MerkleProof.verifyCalldata(proof, latestRoot, leaf)`

The first claim at each new block pays gas for the root advancement; later
claims at the same block ride free.

### Burn / unlock direction (EVM → Hypersnap)

```solidity
function burn(uint256 amount, bytes32 hypersnapRecipient) external returns (uint256 burnId);
```

Burns wrapped tokens, increments per-contract monotonic `burnNonce`, and
emits `Burned(burnId, sender, hypersnapRecipient, amount, sourceChainId)`.

`(chainId, contractAddress, burnId)` is the canonical identifier consumed by
the validator-set observer. There is no on-chain proof of the burn going
back to Hypersnap; the trust assumption is that ≥threshold of the active
validator set independently observed the event at L1 finality before it
appears in a threshold-signed hyperblock. Same trust model as Cosmos
peg-zones, Wormhole guardians, Axelar.

### Owner rotation

`rotateOwner(blockNumber, newOwner, authorizationSig, acceptanceSig)`
requires both:

1. **Authorization** by the outgoing owner (current `ownerAddress`).
2. **Acceptance** by the incoming owner — a signature over a magic string
   bound to its address, proving key possession. Defends against accidental
   rotation to an unspendable address (precompile addrs, `0xdead`, addresses
   derived from zero-vector pubkeys, etc.).

Rotation is **immediate** — no timelock — so a key compromise can be
mitigated as fast as the validator set can run a fresh DKG and submit the
rotation.

### Upgrade (timelocked)

Three-step flow with a 48h delay protecting against single-block exploitation
of a compromised threshold key:

1. `proposeUpgrade(blockNumber, newImplementation, sig)` — owner-signed.
   Records `pendingImplementation` and starts the 48h timer. Reverts if
   another upgrade is already pending; one must be executed or cancelled
   before another can be proposed.

2. `cancelUpgrade(blockNumber, pendingImpl, sig)` — owner-signed and
   **bound to the pending implementation address**. After a legitimate
   `rotateOwner` post-compromise, the new owner uses this to disavow any
   in-flight malicious upgrade.

3. `executeUpgrade()` — permissionless. Once `block.timestamp >=
   pendingUpgradeEffectiveAt`, anyone can run this; no fresh signature
   needed (auth happened at propose time).

The inherited `upgradeToAndCall` reverts and `_authorizeUpgrade` reverts;
the only path to the implementation slot is `executeUpgrade`, which calls
`ERC1967Utils.upgradeToAndCall` directly.

**Compromise-recovery sequence**: validators run a fresh DKG → relay
`rotateOwner(... newOwner ...)` (immediate) → new owner signs and relays
`cancelUpgrade(... pendingImpl ...)` (immediate). The malicious 48h timer
never fires.

**Tail risk**: if the compromised key both proposes a malicious upgrade and
rotates to itself within one block, no rotation can dislodge it. This is
the inherent limit of single-key control and not addressable by timelock
alone — defense lives at the threshold-DKG layer.

### Emergency pause

`pause(blockNumber, sig)` — owner-signed, halts `claim`, `burn`, and
`executeUpgrade` for **72h**. **No unpause path**: the pause auto-expires
after `PAUSE_DURATION` and the bridge resumes. To re-pause after expiry,
owner signs another `pause` with a fresh block number. Universal — same sig
pauses every deployment.

`PAUSE_DURATION (72h)` is intentionally longer than `UPGRADE_DELAY (48h)`.
This guarantees that a defensive pause submitted in the *same* block as a
malicious `proposeUpgrade` still strictly outlasts the upgrade-ready
instant — leaving validators a 24h "guaranteed" lockout window to land
`cancelUpgrade` even in the worst-case adversarial scheduling. Without the
asymmetry, both 48h timers would expire simultaneously and `executeUpgrade`
could fire the same instant pause expires.

### ERC20 recovery

`recoverERC20(blockNumber, token, to, amount, sig)` — owner-signed transfer
of stuck non-SNAP tokens accidentally sent to the bridge. Cannot recover
the bridge's own token (`token == address(this)` reverts). Sig is
chain-specific.

## Cross-references

Canonical encoders live in `crates/hypersnap-crypto/src/bridge_payload.rs`.
Any change to a domain tag or payload format must update both sides in
lockstep and re-pin the test vectors.

ECDSA `v` byte: DKLS23 outputs `recovery_id ∈ {0, 1}`; the EVM `ecrecover`
expects `v ∈ {27, 28}`. The signature serializer must add 27 to
`recovery_id` when packing the on-chain 65-byte form. OZ `ECDSA.recover`
also rejects high-`s` signatures (EIP-2 anti-malleability) — DKLS23 should
produce normalized signatures already, but verify in the wiring layer.

## Gas envelope

| Operation | Approximate cost |
|---|---|
| `claim` (advances new root) | ~60k — ecrecover (3k) + merkle path (~2k for depth 32) + mint (25k) + nullifier SSTORE (22k) |
| `claim` (rides existing root) | ~35k — merkle path + mint + nullifier |
| `rotateOwner` | ~50k — two ecrecovers + two SSTOREs |
| `proposeUpgrade` | ~50k — ecrecover + 2 SSTOREs (impl + effectiveAt packed) |
| `cancelUpgrade` | ~30k — ecrecover + clear |
| `executeUpgrade` | ~30k + impl-pointer SSTORE |
| `pause` | ~40k |
| `burn` | ~25k + ERC20 burn |
| `recoverERC20` | ~30k + ERC20 transfer |

20× cheaper than the previous BLS+verkle design and EVM-portable (no
EIP-2537 dependency).

## Tests

Foundry-based. Setup:

```bash
cd contracts
forge build
forge test
```

`test/CrossSideDigests.t.sol` pins the byte-exact digest output for every
signed-payload domain and the lock-leaf encoding. The same hex values are
asserted on the Rust side in
`crates/hypersnap-crypto/src/bridge_payload.rs::cross_side_pinned_vectors`.
Any drift between the contract's `keccak256(abi.encodePacked(...))` and the
Rust encoder fails one (likely both) test suite.

To regenerate the test vectors after a deliberate domain-tag or layout
change, run:

```bash
cargo run -q -p hypersnap-bridge-ceremony -- digest <subcommand> <args...>
```

and update the pinned hex on both sides in lockstep.

## Audit surface

Built on OZ upgradeable primitives:
- `ERC20PermitUpgradeable` (extends `ERC20Upgradeable` with EIP-2612)
- `UUPSUpgradeable`
- `ECDSA.recover`
- `MerkleProof.verifyCalldata`
- `ERC1967Utils.upgradeToAndCall`
- `SafeERC20.safeTransfer`
- `IERC1822Proxiable` (UUPS compatibility check on `proposeUpgrade`)

The contract-specific logic is ~170 lines. A focused audit on the glue
layer is the only custom-code audit needed.

## Deployment

The deploy script `script/Deploy.s.sol` produces **the same proxy and
implementation addresses on every chain**. No nonce alignment, no
bytecode-reproducibility headaches. Atomic deploy + initialize in one
broadcast.

### How the deterministic addresses work

The script deploys via [CreateX](https://createx.rocks) — a singleton
factory deployed at `0xba5Ed099633D3B313e4D5F7bdc1305d3c28ba5Ed` on every
major EVM chain. CreateX provides CREATE3, where the resulting contract
address depends only on `(CreateX, salt)` — *not* on the contract bytecode.
That means:

- Compiler version, optimizer settings, metadata hash differences across
  machines: **don't matter**.
- Deploy nonce on the deployer account: **doesn't matter**.
- Constructor arguments: **don't affect the address** (only the runtime
  state of the resulting contract).

What does matter, and must be the same on every chain you deploy to:
- CreateX is deployed at the canonical address (true for ~50 major chains
  today; the script reverts with a clear message if not).
- The same deployer EOA broadcasts the script.
- The same `HYPERSNAP_SALT_TAG` is used (default `"hypersnap.v1"`).

The salt is `bytes20(deployer) || 0x00 || bytes11(keccak(salt_tag))`. Bytes
0..19 give CreateX frontrun protection (only your deployer can deploy at
that address); byte 20 = 0x00 disables CreateX's chain-id mixing (so the
address is the same on every chain).

### Prerequisites

### Prerequisites

- `foundry` installed (`forge`, `cast`, `anvil`).
- OZ + forge-std cloned into `contracts/lib/` (see top of README).
- A **fresh hardware-walleted EOA** for the deployer key. Use a dedicated
  key for this ceremony, not your usual dev/treasury key. After handoff to
  the threshold address, the deployer key is retired.
- The same deployer EOA on every target chain (this is what makes the
  cross-chain addresses match — change the deployer and the addresses
  change too).
- RPC URL for the target chain.
- Etherscan API key for source verification (optional but recommended).

### Required environment variables

| Variable | Notes |
|---|---|
| `HYPERSNAP_GENESIS_OWNER` | Optional. If unset, defaults to the broadcasting EOA. **Affects runtime state, not the proxy address.** |
| `HYPERSNAP_TOKEN_NAME` | Optional. Default `"Hypersnap"`. **Affects runtime state, not the proxy address.** |
| `HYPERSNAP_TOKEN_SYMBOL` | Optional. Default `"SNAP"`. **Affects runtime state, not the proxy address.** |
| `HYPERSNAP_SALT_TAG` | Optional. Default `"hypersnap.v1"`. **Affects the proxy address.** Bump if you ever need a fresh address space (e.g., `v2` for a complete redeploy at new addresses). |

### Deploy commands

**With a Ledger** (recommended for production):

```bash
cd contracts
forge script script/Deploy.s.sol \
    --rpc-url $RPC_URL \
    --broadcast \
    --verify --etherscan-api-key $ETHERSCAN_KEY \
    --ledger --sender $DEPLOYER_ADDR
```

**With a private key** (dev / testnet only):

```bash
cd contracts
forge script script/Deploy.s.sol \
    --rpc-url $RPC_URL \
    --broadcast \
    --verify --etherscan-api-key $ETHERSCAN_KEY \
    --private-key $DEPLOYER_KEY
```

**Dry-run against a real chain to predict addresses:**

```bash
forge script script/Deploy.s.sol --rpc-url $RPC_URL
```

This computes and logs the addresses without broadcasting. Run against
any chain with CreateX deployed (Ethereum mainnet, Base, etc.) to
preview what proxy/impl addresses your deployer EOA will land on. The
addresses will match across every chain.

**Local-only dry-run** (without an RPC URL) reverts with
`Deploy: CreateX not deployed on this chain at 0xba5Ed099...` because
Anvil doesn't have CreateX in-memory; that's expected — the script is
intentionally strict about CreateX presence so a non-deterministic
fallback can never silently happen.

The script prints the proxy and implementation addresses, plus the
chosen genesis owner / name / symbol. The proxy address is the canonical
bridge contract — pin it for indexers, frontends, and the
Hypersnap-side `BridgeRegistry`.

**Idempotence:** if the script is rerun on a chain where the
`(deployer, salt_tag)` already produced contracts, it logs the existing
addresses and exits without broadcasting. Useful when re-running the
same script across many chains and some of them already have it.

### Per-chain process

Repeat the deploy command above for every chain you want to bridge to.
**Use the same deployer EOA on every chain** — that's what makes the
proxy and impl addresses identical across chains, and it also collapses
the rotation handoff (later) into a single ceremony.

| Chain | Status |
|---|---|
| Ethereum mainnet | post-Cancun ✓ |
| Base | post-Cancun ✓ |
| Arbitrum One | post-Cancun ✓ |
| Optimism | post-Cancun ✓ |
| Polygon PoS | post-Bhilai ✓ |

Verify your target chain has shipped EIP-6780 (Cancun's selfdestruct
nerf) before deploying — pre-Cancun chains expose a residual bricking
path even with the 48h timelock.

### Post-deploy checklist

The script's internal sanity reads catch most issues, but also confirm
externally:

```bash
# Owner is the deployer EOA (NOT zero, NOT a different key).
cast call $PROXY 'ownerAddress()(address)' --rpc-url $RPC_URL

# Token metadata.
cast call $PROXY 'name()(string)' --rpc-url $RPC_URL
cast call $PROXY 'symbol()(string)' --rpc-url $RPC_URL
cast call $PROXY 'decimals()(uint8)' --rpc-url $RPC_URL

# Initial state.
cast call $PROXY 'totalSupply()(uint256)' --rpc-url $RPC_URL
cast call $PROXY 'latestBlock()(uint64)' --rpc-url $RPC_URL
cast call $PROXY 'pendingImplementation()(address)' --rpc-url $RPC_URL
```

All values should match the deploy log: zero supply, zero latestBlock,
zero pending impl, owner == deployer EOA.

### Pinning what you deploy

Save these per chain, version-controlled:

```
chain_id, proxy_address, implementation_address, deploy_tx_hash, deployer_eoa
```

The proxy address is what users and indexers interact with. The impl
address is only needed for Etherscan source verification and for future
upgrade audits (storage-layout compatibility against this baseline).

### Storage-layout linting

For every future V2 upgrade PR, run `@openzeppelin/upgrades-core` linting
in CI to verify storage compatibility against this V1 baseline. The
slot table in [Storage layout (V1)](#storage-layout-v1) below is the
reference.

## Storage layout (V1)

| Slot | Field | Width |
|---|---|---|
| 0 | `ownerAddress` + `latestBlock` (packed) | 20 + 8 bytes |
| 1 | `latestRoot` | 32 bytes |
| 2 | `burnNonce` | 32 bytes |
| 3 | `pauseExpiry` + `pendingImplementation` (packed) | 8 + 20 bytes |
| 4 | `pendingUpgradeEffectiveAt` | 8 bytes (24 free) |
| 5 | `claimed` mapping base | 32 bytes |
| 6..49 | `__gap[44]` | reserved for V2 |

V2 implementations must preserve this layout; use
`@openzeppelin/upgrades-core` linting on every upgrade.
