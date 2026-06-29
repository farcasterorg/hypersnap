# Hypersnap

A fork of [Snapchain](https://github.com/farcasterxyz/protocol/discussions/207)
extended with the **hyper layer**: a deterministic, threshold-signed
overlay that adds in-protocol Proof-of-Quality scoring, validator
selection, reward issuance, and trust gating on top of the base
Farcaster data network.

The base data layer (cast/like/follow/reaction storage) remains
wire-compatible with snapchain so a hypersnap node can ingest and
serve standard Farcaster traffic. The hyper-layer messages travel on
their own gossip topic and are processed by the `HyperRuntime` actor —
they never enter snapchain blocks or the legacy merkle trie.

## What it adds on top of snapchain

- **Proof-of-Quality scoring** (`crates/proof-of-quality`): per-FID
  EigenTrust + sustained-mutual-engagement + ring-symmetry penalties,
  ported from the offline retro tool to a deterministic in-protocol
  computation that every validator runs at every epoch boundary.
- **Hyperblocks**: BLS12-381 threshold-signed blocks anchored to
  snapchain blocks via `snapchain_anchor_block` + `snapchain_anchor_hash`
  + a Merkle root over the snapchain block range covered.
- **Validator FID binding** (FIP-hyper-validator-selection): every
  validator slot is cross-signed by an Ed25519 identity key + the FID's
  custody key (EIP-712), capped at 3 per FID, gated on a trust score.
- **Three work markets** (FIP-proof-of-work-tokenization §C-2): Data
  Availability, Growth, and App Usage rewards each with their own
  per-epoch budget. Per-FID per-market replay protection.
- **Pedersen DKG ceremony** at every epoch boundary, threshold-signed
  trust snapshot rotation, scheduler-driven block production with
  proposer gating.

## Status

Hypersnap is being built towards mainnet cutover. The cutover from the
static-PoA snapchain validator set to the epoch-based hyper-validator
set is block-pinned (FIP §4.3 — every node runs the same transition at
a configured snapchain block).

## Running a node

A hypersnap node ingests and serves the standard snapchain network plus
the hyper-layer gossip topic. You'll need:

- 16 GB of RAM
- 4 CPU cores or vCPUs
- 1.5 TB of free storage
- A public IP address
- Ports 3381 – 3383 exposed on TCP and UDP

(More detailed runbook is in `HYPER_OPERATOR_RUNBOOK.md`.)

## Compatibility note

Some identifiers in this codebase intentionally retain the
"snapchain" name — they are part of the wire-compatible network layer
shared with upstream snapchain:

- `proto/definitions/blocks.proto`, `gossip.proto`, `message.proto`,
  `onchain_event.proto` (the snapchain wire format)
- gossip topic name prefixes for the snapchain-compatible streams
- `RootPrefix` enum values in `src/storage/constants.rs` that name the
  legacy snapchain stores

Hyper-layer additions live under the `Hyper*` proto messages,
`hypersnap-*` gossip topics (in `src/hyper/topics.rs`), and the
`Hyper*` `RootPrefix` values. Documentation, runbooks, and module-level
descriptions throughout this repository refer to the project as
**hypersnap**.

## Installation

### Prerequisites

- Rust (latest stable)
- Cargo
- Protocol Buffers compiler (`brew install protobuf`)
- cmake (`brew install cmake`)

### Build

```sh
# Sibling-checkout deps used by the hyper layer.
git clone git@github.com:CassOnMars/eth-signature-verifier.git
cd eth-signature-verifier && git checkout 8deb4a091982c345949dc66bf8684489d9f11889 && cd ..

git clone git@github.com:informalsystems/malachite.git
cd malachite && git checkout 13bca14cd209d985c3adf101a02924acde8723a5 && cd ..

# This repo.
cd hypersnap
cargo build
```

### Tests

```sh
cargo test
```

The hyper-layer tests (840+ across the snapchain crate, the
`proof-of-quality` crate, and the integration tests) live under
`src/hyper/` and `crates/proof-of-quality/`. The base snapchain tests
under `src/storage/`, `src/network/`, etc. continue to validate the
wire-compatible layer.

### Local devnet

```sh
make dev
```

## Contributing

PRs are welcome. Please tag an issue with "help wanted" or sync with
the team before opening a large change. PRs that look LLM-generated
without engineering judgment will be closed.
