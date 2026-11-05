# Snapchain

The open-source, canonical implementation of Farcaster's [Snapchain](https://github.com/farcasterxyz/protocol/discussions/207) network. 

![snapchain](https://github.com/user-attachments/assets/e5a041db-e3ae-4250-ad6b-7043ad648d34)


<!-- TODO:  links to installation, user docs, contributor docs -->

## What is Snapchain?

Snapchain is a data storage layer for the Farcaster social protocol. It is a blockchain-like decentralized p2p network that stores data created by Farcaster users. Learn more about Snapchain's design from the [whitepaper](https://github.com/farcasterxyz/protocol/discussions/207).

The main goals of this implementation are:

1. **High Throughput**: Written in Rust and will process at least 10,000 transactions per second. 

2. **Data Availability**: Can be run for < $1,000/month and provide real-time access to user data. 

3. **Canonical Implementation**: Is the most accurate reference for how Snapchain and Farcaster should work. 

## Status 

Snapchain is in the migration phase. Please check the [release docs](https://www.notion.so/warpcast/Snapchain-Mainnet-Public-1b96a6c0c101809493cfda3998a65c7a) for more details on timelines. 

## Running a Node

A snapchain node lets you read and write messages to the network. You will need a machine with the following system requirements to get started: 

- 16 GB of RAM
- 4 CPU cores or vCPUs
- 1.5TB of free storage
- A public IP address
- Ports 3381 - 3383 exposed on both TCP and UDP. 

You can start a new node or upgrade an existing node with the following command: 

```bash
curl -sSL https://raw.githubusercontent.com/farcasterxyz/snapchain/refs/heads/main/scripts/snapchain-bootstrap.sh | bash
```
You can manage your node using the snapchain.sh script. It uses docker compose to run the node in a container. The script provides commands to start, stop, and check the logs of your node.
A brand new node will download historical snapshots to catchup to the latest state before it begins sync. This can take up to 2 hours. Check the node's status by running `curl http://localhost:3381/v1/info`. You should see `maxHeight` increasing and `blockDelay` decreasing until it approaches zero. 

## Upgrade

To upgrade your Snapchain node to the latest version, follow these steps:

```bash
cd snapchain
./snapchain.sh upgrade
```

This ensures your node is always running the latest available version.

### Persistent search index

When search is enabled, its Tantivy index defaults to `search_index` inside
`rocksdb_dir`. The supplied mainnet and nightly Compose files explicitly use
`.rocks/search_index`, on the same persistent mount as the node databases.
If you set `[api.search].index_path` yourself, keep that directory on persistent
storage too.

Older versions used `./data/search_index`, outside the supplied Docker mounts.
On the first upgrade, search rebuilds once at the new location when
`backfill_on_startup = true`; later restarts reuse the index and saved cursors.
To retain an existing index, stop the old node and copy the entire old index
directory to `<rocksdb_dir>/search_index` before starting the updated node.
The backfill status endpoint is `GET /v2/farcaster/_status/backfill`.

Cast search matches `#hashtag` exactly and takes Neynar's `sort_type`
(`desc_chronological`, `chron`, `algorithmic`) and `cursor`. An index built
before hashtags is moved to `<index_path>.legacy` on startup and keeps
answering searches, and receiving new casts, while a new index is backfilled
next to it. The backfill runs alongside live indexing, so the node keeps
serving and indexing throughout. When it completes, the legacy directory is
deleted. Plan for disk space for both indexes during the rebuild. With
`backfill_on_startup = false`, the legacy index keeps serving until a backfill runs.

### Social graph rebuilds

Social graph schema upgrades rebuild follower/following indexes in a dedicated
background worker. The node, HTTP server, and other API indexers start as
usual, and the rebuild has no API downtime: the index stays in two
generations, and readers keep the one they have, which the worker keeps current
with every new block, while it rebuilds the other generation a batch at a time
in between. Once the rebuilt generation reaches the tip, readers switch to it
in one write and the old generation is deleted, also a batch at a time.
`social_graph.backfill_complete` in the backfill status response's `indexers`
array is false until the switch.

A node with no social graph index yet (or with `backfill_on_startup = false`)
builds in place instead, so its follower lists, counts and the feeds that
depend on them fill in as the replay runs.

Shard blocks are the durable queue during a rebuild, and per-generation,
per-shard cursors resume replay after a restart, so keep block retention long
enough to cover the rebuild. Logs report replay progress every five seconds,
and storage failures are logged and retried without skipping the failed batch.

## Contributing 

We welcome contributions from developers of all skill levels. Please look for issues labeled with "help wanted" to find good tickets to work on. If you are working on something that is not explicitly a ticket, we may or may not accept it. We encourage checking with someone on the team before spending a lot of time on something. 

We will ban and report accounts that appear to engage in reputating farming by using LLMs or automated tools to generate PRs. 

## Installation

### Prerequisites

Before you begin, ensure you have the following installed:
- Rust (latest stable version)
- Cargo (comes with Rust)
- Protocol Buffers compiler (`brew install protobuf`)
- cmake (`brew install cmake`) 

### Installation

Clone the snapchain and dependent repos and build snapchain:
```
git clone git@github.com:CassOnMars/eth-signature-verifier.git
cd eth-signature-verifier
git checkout 8deb4a091982c345949dc66bf8684489d9f11889
cd ..
git clone git@github.com:informalsystems/malachite.git
cd malachite
git checkout 13bca14cd209d985c3adf101a02924acde8723a5
cd ..
git clone git@github.com:farcasterxyz/snapchain.git
cd snapchain
cargo build
```

### Testing

After setting up your Rust toolchain above, you can run tests with:

```
cargo test
```

### Running the Application

For development, you can run multiple nodes by running:
```
make dev
```

These will be configured to communicate with each other.

To query a node, you can run `grpcurl` from within the container:

```
docker compose exec node1 grpcurl -import-path proto -proto proto/rpc.proto list
```

If you need fresh keypairs for your node, you can generate them with:

```
cargo run --bin generate_keys
```

### Clean up

You can remove any cached items by running:

```
make clean
```

## Publishing

1. Update `package.version` in `Cargo.toml`
2. Run `cargo build`, to make sure everything is working and update cargo.lock
3. Update the changelog by running `SNAPCHAIN_VERSION=0.x.y make changelog`
4. Commit the change and create and merge the PR
5. Ensure you have the release commit `git checkout main && git pull`
6. Tag the commit using `git tag v0.x.y`, and push it with `git push origin HEAD --tags` to trigger the docker build
7. Also tag with @latest using `git tag -f @latest`, and push it (with --force) so install scripts will use the latest version
8. Once automated build is complete, confirm the Docker image was [published](https://hub.docker.com/r/farcasterxyz/snapchain)
