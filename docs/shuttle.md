# Hypersnap ↔ Snapchain shuttle

`shuttle` is a standalone process with independent gossip identities for each
network. It polls committed block shard 0 and each configured data shard, extracts
shared user messages, and publishes the original signed messages to the opposite
network's mempool. It does not relay consensus, block certificates, on-chain
events, Fname system transfers, or Hyper envelopes.

## Run

Build with `cargo build --release --bin shuttle` and copy `shuttle.example.toml` to
`shuttle.toml`. The example uses haatz's direct gRPC endpoint, all eight initial
Hypersnap validators from [issue #51](https://github.com/farcasterorg/hypersnap/issues/51)
with peer IDs pinned to their published keys, and `snap.farcaster.xyz` for Snapchain.
You can replace these with your own nodes. RPC must be the gRPC endpoint. Both
nodes must retain blocks from the requested starting heights. The shuttle needs outbound access to both
RPC endpoints and the peers' configured QUIC/UDP or TCP ports.

```sh
./target/release/shuttle --config-path shuttle.toml --check-config
./target/release/shuttle --config-path shuttle.toml
```

The image includes `/app/shuttle`. After configuring `shuttle.toml`, run:

```sh
docker compose -f docker-compose.shuttle.yml up -d
```

Use container-reachable endpoints in that configuration; `127.0.0.1` inside the
shuttle container refers to that container. The example Compose file persists
`/app/.shuttle`, matching the example `state_dir`. Keep that volume across restarts.

Before each Hypersnap shard forks, both relay directions wait while their gossip
connections stay ready. A first launch before the fork reserves that shard's
fork block as its starting cursor, including if Snapchain is already ahead.
A first launch after the fork starts at the source's observed tip plus one.
Set `start_blocks` for each source to replay retained post-fork history, using
inclusive heights. Pre-fork history is never relayed: configured starts and old
cursors below the cutoff are advanced to the fork block. Otherwise an existing
cursor takes precedence over configuration. A missing/pruned
block or a parent-hash mismatch stops that shard's progress with a retry log; the
shuttle never silently jumps past a gap.

## Fork boundary

Hypersnap's `[gossip.topic_cutovers]` in `validators.toml` sets the same per-shard
boundaries as the new validator sets: shard 0 at 50,477,529; shard 1 at 51,161,786;
shard 2 at 50,996,940. These target approximately 2026-11-12 20:52:39 UTC, based
on the observed block rates. Copy the heights into the shuttle's `[topic_cutovers]`.

Votes and proposals use their block height. Decided values use their committed
height. Status messages announce the next height after their committed tip.
Mempool messages follow their destination shard's next local height. Before its
cutoff, that shard uses the existing Snapchain topic; from the cutoff onward it
uses `hypersnap/consensus`, `hypersnap/mempool`, `hypersnap/decided-values`, and
`hypersnap/read-node-peers`. Discovery and Hyper traffic use `contact-info` and
`hyper` before the fork, both legacy and namespaced topics during a mixed-shard
transition, and only `hypersnap/contact-info` and `hypersnap/hyper` afterward.
Nodes establish both meshes beforehand, validate the topic against the payload's
phase before forwarding, and retire legacy subscriptions once all shards cross.
Only local outbound heights advance the node's mempool/discovery phase; remote
status messages cannot trigger an early switch. Mainnet without a configured
schedule retains legacy topics, so custom configurations must include the schedule.

A lagging node still accepts legacy Snapchain status announcements above its
fork boundary so it can find the last shared blocks. The height passed to local
sync is capped at the last pre-fork block; this exception ends when that local
shard reaches the fork. Blocks, proposals and votes keep their height-based
topic checks throughout.

Configure Hypersnap validators to connect to one another before the cutoffs
(using `gossip.bootstrap_peers` or `gossip.direct_peers` with their advertised
addresses). Existing Snapchain validators will not relay the new topics, and a
validator pubkey in `validators.toml` alone does not establish a connection.
Keep legacy connections available for pre-fork consensus while those new meshes form.

Hypersnap's RPC heights activate both directions independently per shard when
the next local block reaches its cutoff. Snapchain's height alone cannot activate
a relay. The shuttle only reads source blocks from the cutoff onward, and only
publishes to Hypersnap's namespaced mempool. Snapchain always uses `mempool`.
The existing sync RPC transport remains compatible for fetching pre-fork history.

## Compatibility, recovery and progress

Both sides use the same Farcaster network ID. Relayed messages must have a known
shared type/body, pass the configured type allowlists and match their original
signed-data hash. `data_bytes` and signatures are preserved verbatim, including
unknown protobuf fields. Every candidate also goes through the destination's
`ValidateMessage` RPC, so unsupported feature versions are skipped. Destination
mempool admission still checks stateful requirements such as registration,
signers and storage. The shuttle cannot transfer those prerequisites between
networks; RPC validation failures are logged and skipped.

A successful publish means gossipsub queued the message to subscribed peers, not
that consensus included it. The shuttle retries without advancing its cursor when no subscriber is available;
timed-out attempts refresh destination heights and select the current topic again.
Transport/RPC failures leave the block cursor in place for retry. Per-message
receipts suppress loops and repeated publishes across restarts; an interrupted
publish may be delivered again, which mempool message hashes deduplicate.
Receipts are retained and grow with relayed traffic. Keep one shuttle instance
per state directory; RocksDB locks it against concurrent use.

Logs report each source, shard, `next_block` and `tip`, plus peer connections,
incompatible messages and retry errors. A growing `next_block` indicates progress;
when it reaches `tip + 1`, that source shard is caught up. Each direction runs
independently. These logs describe shuttle progress, not validator inclusion.
