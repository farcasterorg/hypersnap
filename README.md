# Hypersnap

A fork of [Snapchain](https://github.com/farcasterxyz/protocol/discussions/207)
that becomes its own chain at the epoch-1 pivot
(`FIP-proof-of-work-tokenization.md`).

Before the pivot, a Hypersnap node is a snapchain read node: it ingests and
serves the standard Farcaster network, and it keeps every message (also the
messages that the snapchain storage limits prune). At the pivot, the
bootstrap validators build a genesis state from the snapchain history, and
the network continues as three Hypersnap shards with Falcon-512 validators.

## What it adds to snapchain

- **Shard 0**: the FID registry and signers (with Falcon-512 custody and
  signers), the token ledger and the bridge, the validator set and the work
  markets (`src/chain/shard0`).
- **Shards 1 and 2**: the Farcaster messages, with no content pruning and a
  fee gate, over a Keccak state trie (`src/chain`, `src/storage/trie`).
- **Proof of Quality** (`crates/proof-of-quality`): the deterministic
  scoring of the Growth, App Usage and Data Availability markets.
- **The relay worker** (`crates/hypersnap-relay`): forwards messages between
  Hypersnap and snapchain.

## Running a node

You'll need:

- 16 GB of RAM
- 4 CPU cores or vCPUs
- 1.5 TB of free storage
- A public IP address
- Ports 3381 – 3383 exposed on TCP and UDP

The pivot procedures for operators are in `HYPERSNAP_PIVOT_RUNBOOK.md`.

## Compatibility note

Some identifiers in this codebase intentionally retain the
"snapchain" name — they are part of the wire-compatible network layer
shared with upstream snapchain:

- `proto/definitions/blocks.proto`, `gossip.proto`, `message.proto`,
  `onchain_event.proto` (the snapchain wire format)
- gossip topic name prefixes for the snapchain-compatible streams
- `RootPrefix` enum values in `src/storage/constants.rs` that name the
  legacy snapchain stores

Hypersnap additions use the `Hypersnap*` and `Hyper*` proto messages, the
`hypersnap/<network>` gossip namespace after the pivot, and the `Hyper*`
`RootPrefix` values.

## Installation

### Prerequisites

- Rust (latest stable)
- Cargo
- Protocol Buffers compiler (`brew install protobuf`)
- cmake (`brew install cmake`)

### Build

```sh
# Sibling-checkout dependencies.
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

The chain tests are under `src/chain/` (shard 0, the replica, the pivot,
checkpoints), and the scoring tests under `crates/proof-of-quality/`. The
base snapchain tests under `src/storage/`, `src/network/`, etc. continue to
validate the wire-compatible layer.

### Local devnet

```sh
make dev
```

## Contributing

PRs are welcome. Please tag an issue with "help wanted" or sync with
the team before opening a large change. PRs that look LLM-generated
without engineering judgment will be closed.
