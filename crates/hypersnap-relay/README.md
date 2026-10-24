# hypersnap-relay

The relay worker of FIP-proof-of-work-tokenization, Appendix A. After the
epoch-1 pivot, snapchain and Hypersnap are separate networks; this process
copies user messages between them.

- **Inbound** (snapchain to Hypersnap): reads finalized snapchain chunks
  (`GetShardChunks`, shards 1 and 2) and shard-0 blocks (`GetBlocks`; snapchain
  routes `KEY_ADD`, `KEY_REMOVE` and `LEND_STORAGE` to shard 0), drops system
  messages (on-chain events, fname transfers, block events), and submits the
  user messages to Hypersnap with `SubmitBulkMessages`. The Hypersnap node
  routes each message (for example `KEY_ADD` to shard 0).
- **Outbound** (Hypersnap to snapchain): reads certified Hypersnap blocks
  through `HypersnapBlockSource`, applies the outbound filter, rewrites
  dual-signed messages to their Ed25519 form (FIP §16.8), and submits them to
  snapchain.

The relay holds no keys and uses only the public gRPC API of each node. Any
number of relays can run; each needs its own `state_dir`. A Hypersnap node
works without a relay.

## Build and run

The crate is a member of the root workspace:

```sh
cargo build --release -p hypersnap-relay
target/release/hypersnap-relay --config relay.toml
```

`RUST_LOG` sets the log filter; `--log-format json` gives JSON logs. SIGINT or
SIGTERM stops the relay at a safe point (no batch is cut in half). Exit code 2
is a configuration error; 1 is a runtime error (for example a state-dir write
failure, which is fatal on purpose).

## Configuration

See [`relay.example.toml`](relay.example.toml). The `[relay]` table has the
keys of FIP A.8 (`snapchain_endpoints`, `hypersnap_endpoints`,
`inbound_enabled`, `outbound_enabled`, `state_dir`, `seen_set_capacity`,
`retry_initial_ms`, `retry_max_ms`) and these additions:

| Key | Default | Meaning |
|---|---|---|
| `network` | `mainnet` | Farcaster network of both sides; other messages are dropped |
| `snapchain_auth`, `hypersnap_auth` | none | `user:password` basic auth |
| `inbound_shards`, `outbound_shards` | `[0, 1, 2]` | Shards per direction |
| `snapchain_version` | `auto` | Selects the outbound type allowlist; `auto` = `GetInfo.version`, re-checked every `version_refresh_secs` |
| `hypersnap_block_source` | `certified` | `certified` (the node's `GetCertifiedBlocks` stream) or `shard_chunks` (interim, devnets) |
| `max_message_attempts` | 20 | Per-message transient / rate-limit errors before `gave_up` |
| `poll_interval_ms`, `fetch_page_size`, `submit_batch_size` | 1000, 50, 100 | Polling and batching |
| `request_timeout_ms`, `connect_timeout_ms`, `max_grpc_message_bytes` | 15000, 5000, 64 MiB | gRPC client |
| `[relay.pivot]` | from the node | `pivot_height` and `fork_heights.shard_{1,2}` (`H_s`) from the `PivotRecord`; without it, the relay reads `GetPivotRecord` of a Hypersnap node at start |
| `[relay.start_heights.{snapchain,hypersnap}]` | none | `shard_{0,1,2}`: explicit first heights |
| `[relay.rate_limits]` | 0 (none) | `{snapchain,hypersnap}_rpcs_per_minute`, `{snapchain,hypersnap}_messages_per_second` |
| `[relay.deferred]` | 1024, 5, 30000 | `capacity`, `max_attempts`, `retry_ms`, `error_patterns` |

Environment variables override the file: `HYPERSNAP_RELAY_<KEY>`, with `__`
for nesting, for example `HYPERSNAP_RELAY_STATE_DIR=/data` or
`HYPERSNAP_RELAY_SNAPCHAIN_ENDPOINTS='["http://a:3383","http://b:3383"]'`.
`HYPERSNAP_RELAY_CONFIG` names the file.

**First cursors.** A persisted cursor always wins. Without one, the relay uses
`start_heights`, else the pivot table: snapchain shard 0 and Hypersnap shard 0
start at `pivot_height`; shard `s` starts at `H_s + 1` on both networks
(FIP §17.2, A.3 step 2, A.4 step 2). A shard with neither is a startup error.
To move a cursor, stop the relay and edit or delete
`cursors/<network>-shard-<s>.json`.

## State and delivery guarantees

```text
<state_dir>/
  LOCK                               one relay process per state dir
  meta.json                          network check
  cursors/<network>-shard-<s>.json   next source height (atomic rewrite)
  seen/inbound/<id>.seg              hashes read from snapchain
  seen/outbound/<id>.seg             hashes read from Hypersnap
  deferred/<direction>-shard-<s>.pb  deferred queue of one shard worker
```

- **Seen sets with origin tags.** The set that holds a hash is the network the
  message came from. A direction never relays a hash that the other set holds,
  so a message never goes back to its origin (FIP A.5). The check of both sets
  and the claim of a hash are one atomic step under one lock, so the two
  directions cannot both take a message that a user sent to both networks.
- **Records.** A segment is append-only `hash(20) || status(1)` records
  (relayed, duplicate, rejected, gave_up, deferred); the last record of a
  hash wins. The relay fsyncs after each batch. A torn or zero-filled tail
  after a crash is dropped on open.
- **Bound.** At more than `seen_set_capacity` hashes the oldest segment is
  deleted (each set keeps 15/16 to 16/16 of the capacity). A lost old hash
  costs one duplicate submission. RAM is roughly 33-66 bytes per entry
  (hash-table load), so the FIP default of 10M per set is about 0.5 GB per
  set when full; 1M covers hours of traffic and is enough for loop prevention.
- **Cursor order.** For each block: seen records (and deferred entries) per
  batch, then the cursor. A crash re-reads at most one block; its recorded
  messages are skipped and only the batch in flight is sent again (the target
  answers duplicate). A graceful stop sends nothing twice. Delivery is at
  least once.

## Error classification

From `SubmitBulkMessages` `MessageError.errCode` or the `x-err-code` metadata
of a `SubmitMessage` status (`HubError.code`, `src/core/error.rs`):

| Code | Class | Action |
|---|---|---|
| `bad_request.duplicate` | duplicate | record, skip |
| `bad_request.rate_limited` | rate limit | back off, retry (charges an attempt) |
| `bad_request.validation_failure` matching `deferred.error_patterns` (`unknown fid`, `invalid signer`, `fname is not registered for fid`) | state-dependent | deferred queue, cursor moves on, retry with doubling delay, then rejected |
| other `bad_request.*` (`validation_failure`, `invalid_param`, `decode_error`, `conflict`, `prunable`, `internal_error`) | rule rejection | record, never resend (includes snapchain rejecting Pro-only content from a non-Pro FID) |
| `not_found` | rule rejection | record, never resend |
| `unavailable*`, `db.*`, `internal*`, `invalid_internal_state`, unknown | transient | back off, fail over, retry (charges an attempt) |

Without a `HubError` code: `AlreadyExists` is a duplicate; `ResourceExhausted`
(the node's per-IP limiter) is a rate limit; `InvalidArgument`, `NotFound`,
`FailedPrecondition`, `OutOfRange` are rule rejections; everything else is
transient. An RPC-level failure (transport, timeout, per-IP limit, auth)
never charges a message: the relay fails over and backs off until an endpoint
answers. A bulk call that fails with `Unimplemented` or `InvalidArgument`
switches that endpoint to `SubmitMessage`.

## Outbound filter

A message goes to snapchain only if: its hash is BLAKE3(`data_bytes`)[..20];
its network is `network`; its type is in the snapchain allowlist of the target
version (`filter::SNAPCHAIN_ALLOWLIST_TABLE`, never a type >= 100, never
`FRAME_ACTION`); `fid < 2^63`; its scheme is `ED25519` or `ED25519_FALCON512`
(`FALCON512` is dropped); a `KEY_ADD` has `key_type = 1` and a 65-byte EIP-712
`custody_signature`; a custody `KEY_REMOVE` has a 65-byte EIP-712 signature.
Then the Ed25519 form keeps the first 64 bytes of `signature` and sets
`SIGNATURE_SCHEME_ED25519`; `data`, `data_bytes`, `hash`, `signer` are unchanged.
Update the allowlist table for each snapchain release.

## Outbound source

`source::hypersnap::HypersnapBlockSource` is the interface the outbound path
needs: a stream of certified blocks per shard from a cursor, plus the certified
tip. `MemoryHypersnapSource` implements it for tests; `GrpcHypersnapBlockSource`
reads the node's `GetCertifiedBlocks` stream and the certified tips of
`GetInfo`. `hypersnap_block_source = "shard_chunks"` reads `GetShardChunks` /
`GetBlocks` from the Hypersnap node, for devnets.

## Metrics

`metrics::RelayMetrics` takes counters and gauges per direction and shard;
plug the node's `StatsdClientWrapper` in with `count_with_shard` /
`gauge_with_shard` (see the module docs). Names are `relay.<direction>.<name>`.
Counters: `relayed`, `duplicate`, `rejected`, `deferred`, `deferred_retry`,
`rate_limited`, `transient`, `gave_up`, `filtered`, `loop_skipped`,
`already_seen`, `system_skipped`, `blocks`, `source_error`, plus endpoint
failovers per network. Gauges: `cursor`, `tip`, `lag` (`tip + 1 - cursor`),
`deferred_queue`, `seen_set`. Until statsd is wired in, the binary logs a
summary every `metrics_log_interval_secs`.

## Deployment

The node image contains the relay binary (`/app/hypersnap-relay`, from the
repo `Dockerfile`), so the relay runs from the same image as the node.

`docker-compose.mainnet.yml` and `docker-compose.nightly.yml` have a `relay`
service in the `relay` profile, with the settings as environment variables.
Start it after the pivot:

```sh
docker compose --profile relay up -d relay
```

The relay's own volume must not be shared with another relay or a node.

## Tests

```sh
cargo test -p hypersnap-relay
```

Unit tests cover the filter and the Ed25519-form rewrite (byte-identical
message and hash), the allowlist table, the error classification, the seen
sets (restart, bound, eviction, torn tails, origin tags), cursors, the
deferred queue and the config. `tests/e2e.rs` runs the relay against
in-process fake snapchain and Hypersnap tonic servers: inbound with system
messages and shard 0, the outbound filter matrix, a round trip with loop
prevention (also after a restart), a crash and a graceful stop mid-stream,
endpoint failover, every error class, the `SubmitMessage` fallback, and the
interim gRPC outbound source.
