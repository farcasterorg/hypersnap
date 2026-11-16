# Hypersnap

The open-source, canonical implementation of Farcaster's Hypersnap network. Not to be confused with Snapchain, the former protocol, which is now being developed by the Network State team, who conducted a hostile takeover of the Farcaster app and domains and mass purge of users. Farcaster as a brand is CC0, [as per Merkle cofounder Dan Romero](https://forkcaster.xyz/dwr/0x5c0fe52314b0e6bbf6eeb935a50b47ede43bed17). Hypersnap team includes one of the original developers of Snapchain. No original team members of Snapchain are working on the Network State-owned protocol. In terms of crypto parlance, it is similar to Ethereum (Hypersnap) and Ethereum Classic (Snapchain). 

## What is Hypersnap?

Hypersnap is a data storage layer for the Farcaster social protocol. It is a blockchain-like decentralized p2p network that stores data created by Farcaster users. Learn more about Hypersnap's design from the [whitepaper](https://github.com/farcasterxyz/protocol/discussions/207) and ongoing [protocol discussions](https://github.com/orgs/farcasterorg/discussions).

The main goals of this implementation are:

1. **High Throughput**: Written in Rust and will process at least 10,000 transactions per second. 

2. **Data Availability**: Can be run for < $1,000/month and provide real-time access to user data. 

3. **Canonical Implementation**: Is the most accurate reference for how Hypersnap and Farcaster should work. 


## Running a Node

A hypersnap node lets you read and write messages to the network. You will need a machine with the following system requirements to get started: 

- 16 GB of RAM
- 4 CPU cores or vCPUs
- 1.5TB of free storage
- A public IP address
- Ports 3381 - 3383 exposed on both TCP and UDP. 

You can start a new node or upgrade an existing node with the following command: 

```bash
curl -sSL https://raw.githubusercontent.com/farcasterorg/hypersnap/refs/heads/main/scripts/hypersnap-bootstrap.sh | bash
```
You can manage your node using the hypersnap.sh script. It uses docker compose to run the node in a container. The script provides commands to start, stop, and check the logs of your node.
A brand new node will download historical snapshots to catchup to the latest state before it begins sync. This can take up to 2 hours. Check the node's status by running `curl http://localhost:3381/v1/info`. You should see `maxHeight` increasing and `blockDelay` decreasing until it approaches zero. 

## Upgrade

To upgrade your Hypersnap node to the latest version, follow these steps:

```bash
cd hypersnap
./hypersnap.sh upgrade
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

The cast-hash index automatically fills missing historical mappings from both
legacy and Hyper cast stores in the background, without clearing existing data
or blocking API startup. It checkpoints each batch and resumes after restart.
The status response includes `cast_hash_backfill.complete` and per-source
`shard_id`, `source_prefix` (3 for legacy, 30 for Hyper), `casts_indexed`,
`last_fid`, and `complete`, plus an `error` when a batch fails and will retry.
The `cast_hash` indexer's `backfill_complete` now means the retained-store walk
has finished, rather than merely that an event checkpoint exists.
During this walk, an unindexed hash can still require a fallback probe. There
is at most one probe at a time, with no waiting queue and a two-second request
budget; busy or timed-out lookups return HTTP 503 and can be retried. Supplying
the author FID avoids probing for existing casts. Once coverage is complete,
unknown hashes return 404 without a full FID scan.

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

### Engagement metrics replacement

The metrics schema upgrade repairs inflated likes, recasts and reply counts in
an independent background worker. Existing counts and trending data keep serving
and receiving live updates while a separate generation is rebuilt. The rebuild
never clears the readable generation first. Only after every shard catches up
does one atomic database write publish the replacement. Retired data is reclaimed
in bounded batches afterward.

Reaction membership and reply identities make repeated events and replay safe;
reply deletions and signer revocations remove their contributions. The replacement
scans canonical hyper-store message records (legacy stores if hyper is unavailable)
in key order, skipping unrelated records and secondary indexes. It does not replay
the entire historical chain or point-fetch every old reaction. Only blocks committed
from the scan's saved live boundary are replayed to catch concurrent changes.

The scan and live tail have independent persistent cursors. Restarts resume both;
failed pages are retried without skipping data. An upgrade from an unfinished v1
block replay builds a fresh generation while preserving the readable index and
v1's partial index until publication. An already completed v1 index is reused.

This one-time schema repair runs automatically whenever metrics is enabled,
independently of the shared startup backfill gate and its legacy
`metrics.backfill_on_startup` flag. Keep blocks from the saved live boundary until
the repair finishes. The status endpoint `GET /v2/farcaster/_status/backfill` includes
`metrics_backfill` with `phase`, generations, and per-shard `rows_scanned`,
`messages_indexed`, `last_fid`, `scan_complete`, `next_block` and `blocks_remaining`.
The scan phase is `scanning`, then `catching_up`, then `ready`. Row counts and FIDs
are scan progress; the tail's block percentage does not measure the historical scan.
Logs report scan and tail progress every five seconds. The generic
`metrics.backfill_complete` becomes true after publication; its legacy
`items_indexed` and `last_event_id` fields are not rebuild progress counters.

### Live daily stats

Daily stats and client attribution consume live events through their own queue
and worker, starting immediately without waiting for search or other startup
backfills. Slow search commits do not share this worker. The historical daily
stats walk continues in the background with its existing date boundary.

After upgrading, new activity appears in `/v2/farcaster/stats/daily?clients=10`;
include `to=YYYY-MM-DD` for today in UTC to see the current partial day. The
`daily_stats` entry at `/v2/farcaster/_status/backfill` reports messages processed
since startup as `items_indexed`.

With daily stats enabled, a one-time repair automatically replays retained
shard blocks from the first client-attribution day (`notes.clients.tracked_from`)
through the UTC day the repair starts. It rebuilds both totals and client data
in a persistent staging database while live collection continues, then replaces
the affected days atomically. Buffered events already included by that repair
are skipped. Older days are kept intact, and an interrupted repair resumes from
its committed per-shard cursors. Keys that cannot be resolved are attributed to
`unresolved`.

Monitor it with:

```bash
curl -s http://localhost:3381/v2/farcaster/_status/backfill | jq '.daily_stats_repair'
```

The object reports `phase`, `complete`, `from`, `to`, `messages_replayed`, shard
cursors and any `error`. Progress is also logged about every five seconds.
Insufficient block retention or a missing source block leaves existing rows
intact and reports a failure. The staging directory lives beside the API DB
(`.rocks/shard-0.daily-stats-repair-*`) and is removed after success. To defer
the repair, set `[api.daily_stats] repair_on_startup = false`; it defaults to
true. The regular historical store-walk backfill has its own checkpoints and
does not need to be reset for this repair.

### Native account registration

Native accounts can register with a custody signature and proof of work from the
new validator fork heights, without an IdRegistry transaction. See
[native registration, activation and client usage](docs/native-registration.md).

### Hypersnap ↔ Hypersnap shuttle

The standalone `shuttle` binary relays compatible signed user messages from each
network's committed blocks to the opposite mempool, with persistent cursors and
loop suppression. Gossip switches to Hypersnap topics at each shard's configured
fork height. See [shuttle setup and fork routing](docs/shuttle.md) and
[`shuttle.example.toml`](shuttle.example.toml).

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

Clone the hypersnap and dependent repos and build hypersnap:
```
git clone git@github.com:CassOnMars/eth-signature-verifier.git
cd eth-signature-verifier
git checkout 8deb4a091982c345949dc66bf8684489d9f11889
cd ..
git clone git@github.com:informalsystems/malachite.git
cd malachite
git checkout 13bca14cd209d985c3adf101a02924acde8723a5
cd ..
git clone git@github.com:farcasterorg/hypersnap.git
cd hypersnap
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
8. Once automated build is complete, confirm the Docker image was [published](https://hub.docker.com/r/farcasterorg/hypersnap)
