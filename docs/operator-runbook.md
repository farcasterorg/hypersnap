# Hypersnap Node Operator Runbook

This runbook covers everything a node operator needs to set up, monitor, and
troubleshoot a **hypersnap** node — including how to enable and manage **Hyper
Mode** (the unbounded execution context introduced alongside the canonical
Snapchain pipeline).

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Installation & Build](#installation--build)
3. [Configuration Reference](#configuration-reference)
4. [Starting the Node](#starting-the-node)
5. [Enabling Hyper Mode](#enabling-hyper-mode)
6. [Monitoring & Metrics](#monitoring--metrics)
7. [CLI Tooling](#cli-tooling)
8. [Divergence Detection & Recovery](#divergence-detection--recovery)
9. [Storage Management](#storage-management)
10. [Upgrading](#upgrading)
11. [Troubleshooting](#troubleshooting)
12. [FAQ](#faq)

---

## Prerequisites

| Requirement | Minimum | Recommended |
|---|---|---|
| OS | Linux x86-64 | Ubuntu 22.04 LTS |
| RAM | 8 GB | 32 GB (hyper mode) |
| Disk | 200 GB SSD | 2 TB NVMe (hyper mode, unbounded) |
| CPU | 4 cores | 16 cores |
| Rust toolchain | 1.78 | stable via `rustup` |
| Docker (optional) | 24.x | latest |

> **Hyper mode** stores every historical message without pruning. Plan disk
> capacity accordingly — budget at least **10× the canonical store size**
> as a starting estimate and monitor growth.

---

## Installation & Build

### From source

```bash
git clone https://github.com/farcasterorg/hypersnap.git
cd hypersnap
cargo build --release
```

Binaries land in `target/release/`:

- `snapchain` — main node daemon
- `hyper` — CLI helper for diff / audit / metrics

### Docker

```bash
docker pull ghcr.io/farcasterorg/hypersnap:latest
# or build locally
docker build -t hypersnap:local .
```

---

## Configuration Reference

Configuration is loaded from `config/` (TOML). The key sections relevant to
hyper mode are:

```toml
[hyper]
# Enable the parallel hyper pipeline alongside the legacy pipeline.
enabled = false

# Soft retention cap: emit an alert when hyper store exceeds this many bytes.
# Does NOT truncate data — hyper mode is always unbounded.
retention_soft_cap_bytes = 107374182400  # 100 GB

# Cadence (seconds) for emitting hyper pipeline metrics.
metrics_interval_secs = 60

[hyper.storage]
# Separate RocksDB path for hyper state (recommended for large deployments).
# Omit to co-locate with the canonical store using key prefixes.
db_path = "/var/lib/hypersnap/hyper"
```

### Full config keys

| Key | Type | Default | Description |
|---|---|---|---|
| `hyper.enabled` | bool | `false` | Activates the hyper pipeline |
| `hyper.retention_soft_cap_bytes` | u64 | `0` (off) | Alert threshold for disk usage |
| `hyper.metrics_interval_secs` | u64 | `60` | Metrics emission cadence |
| `hyper.storage.db_path` | string | (co-located) | Separate DB path for hyper state |

---

## Starting the Node

```bash
# Canonical-only mode (default)
cargo run --release --bin snapchain -- --config config/default.toml

# With hyper mode enabled (set hyper.enabled = true in config first)
cargo run --release --bin snapchain -- --config config/hyper.toml

# Docker
docker run -d \
  -v $(pwd)/config:/config \
  -v /var/lib/hypersnap:/data \
  -p 2283:2283 \
  ghcr.io/farcasterorg/hypersnap:latest \
  --config /config/hyper.toml
```

### Verifying startup

Look for these log lines at startup:

```
INFO snapchain::node: canonical pipeline started
INFO snapchain::hyper: hyper pipeline started  # only when hyper.enabled = true
INFO snapchain::network: CAPABILITY_HYPER advertised to peers
```

---

## Enabling Hyper Mode

1. Set `hyper.enabled = true` in your config file.
2. (Optional) Point `hyper.storage.db_path` at a dedicated NVMe mount.
3. Restart the node — the hyper pipeline starts on the **next** block.
4. Verify peer negotiation:

```bash
cargo run --bin hyper -- metrics --tail
```

You should see `hyper_pipeline_lag` converge to `0` within a few blocks.

> **Note:** Existing canonical data is **not** back-filled into the hyper store
> on first enable. Hyper history begins accumulating from the first block
> processed after enablement.

---

## Monitoring & Metrics

Hypersnap emits StatsD-compatible metrics. Configure your aggregator
(e.g. Datadog, Prometheus via statsd-exporter) to receive them.

### Key metrics

| Metric | Type | Description |
|---|---|---|
| `hyper_pipeline_lag` | gauge | Blocks behind canonical head |
| `hyper_storage_bytes` | gauge | Total hyper store size in bytes |
| `hyper_diff_failures` | counter | Blocks where state roots diverged |
| `hyper_retained_messages` | gauge | Total messages in hyper store |
| `canonical_pruned_messages` | counter | Messages removed by legacy pruning |

### Grafana dashboard

A pre-built dashboard JSON lives in `grafana/`. Import it via:

```bash
curl -X POST http://localhost:3000/api/dashboards/import \
  -H 'Content-Type: application/json' \
  -d @grafana/hypersnap-dashboard.json
```

### Alerting recommendations

- **`hyper_pipeline_lag > 10`** for 5 min → node is falling behind; check CPU/disk I/O.
- **`hyper_diff_failures > 0`** → state divergence detected; see [Divergence Detection](#divergence-detection--recovery).
- **`hyper_storage_bytes > retention_soft_cap_bytes`** → disk planning required.

---

## CLI Tooling

All CLI commands use the `hyper` binary:

```bash
cargo run --bin hyper -- --help
```

### `hyper diff`

Compare canonical vs. hyper state for a specific block:

```bash
cargo run --bin hyper -- diff --block 12345 --context both
```

Output (`HyperDiffReport`):

```
block:       12345
diverged:    false
delta:       +42   # messages retained in hyper but pruned in canonical
notes:       pruned 42 messages in legacy store
```

### `hyper audit`

Walk backwards through recent blocks to verify hyper coverage:

```bash
# Audit the last 500 blocks
cargo run --bin hyper -- audit --latest 500
```

Exits with code `0` if all blocks have matching hyper envelopes, `1` otherwise.

### `hyper metrics`

Stream live pipeline metrics:

```bash
cargo run --bin hyper -- metrics --tail
```

---

## Divergence Detection & Recovery

Divergence occurs when the **hyper state root** recorded in a `HyperEnvelope`
does not match what the local node computed. Causes include:

- Hardware failures (corrupted writes)
- Missed blocks during a restart
- Bugs in hyper-specific validation rules

### Detecting divergence

```bash
# Quick check — exit code 1 means divergence found
cargo run --bin hyper -- audit --latest 100

# Pinpoint the diverging block
cargo run --bin hyper -- diff --block <suspect_block> --context both
```

The `SyncReport` helper (in `src/hyper/mod.rs`) exposes:

- `diverged()` — returns `true` when `hyper_state_root` mismatches
- `summary()` — human-readable one-liner for logging

### Recovery steps

1. Stop the node.
2. Identify the last known-good block using `hyper audit`.
3. If using a **separate hyper DB**, restore from the most recent snapshot
   of the hyper store.
4. If **co-located**, wipe the hyper key prefix and let the node resync:
   ```bash
   snapchain db compact --prefix hyper:
   ```
5. Restart with `hyper.enabled = true` — the pipeline will rebuild from the
   first post-restart block.
6. Run `hyper audit --latest 200` once synced to confirm clean state.

---

## Storage Management

### Canonical store (pruned)

Managed automatically by the legacy pipeline. No operator action needed
beyond routine disk monitoring.

### Hyper store (unbounded)

- Grows indefinitely by design — **do not configure any external pruning**.
- Monitor `hyper_storage_bytes` via metrics.
- Use `retention_soft_cap_bytes` to receive early alerts before disks fill.
- For large deployments, mount the hyper DB on a **dedicated volume**:

```toml
[hyper.storage]
db_path = "/mnt/hypersnap-hyper-nvme/db"
```

### Snapshots

To create a portable snapshot of the hyper store:

```bash
snapchain db snapshot --context hyper --output /backups/hyper-$(date +%Y%m%d).tar.zst
```

---

## Upgrading

1. Review the release notes for any breaking config changes.
2. Stop the node gracefully (`SIGTERM` — the node drains in-flight blocks).
3. Build or pull the new binary.
4. Run DB migrations if listed in the release notes:
   ```bash
   snapchain db migrate --config config/hyper.toml
   ```
5. Start the node and verify logs show the expected version string.
6. Run `hyper audit --latest 50` to confirm hyper integrity post-upgrade.

---

## Troubleshooting

### Node won't start with hyper mode enabled

- Check that `hyper.storage.db_path` is writable by the process user.
- Ensure there is sufficient disk space (run `df -h`).
- Look for `ERROR snapchain::hyper` in logs.

### `hyper_pipeline_lag` keeps growing

- Hyper processing is CPU/disk bound — profile with `top` or `iostat`.
- Consider separating the hyper DB onto a faster NVMe.
- Temporarily set `hyper.metrics_interval_secs` lower to pinpoint the bottleneck.

### Peer not exchanging `HyperEnvelope`

- Both sides must have `hyper.enabled = true`.
- Check that `CAPABILITY_HYPER` appears in the handshake log.
- Firewall rules must allow the gossip port (default `2283/tcp`).

### `hyper diff` reports `diverged: true`

See [Divergence Detection & Recovery](#divergence-detection--recovery).

---

## FAQ

**Q: Does enabling hyper mode affect canonical peers?**
A: No. Legacy peers never receive `HyperEnvelope` payloads and the canonical
pipeline is completely unaffected.

**Q: Can I enable hyper mode on only some nodes in my fleet?**
A: Yes. Hyper mode is strictly additive. Mixed fleets work fine — hyper nodes
will only exchange envelopes with other hyper-capable peers.

**Q: What happens if I run out of disk in hyper mode?**
A: RocksDB will return write errors and the node will log `ERROR` and halt
hyper writes while canonical operation continues. Set `retention_soft_cap_bytes`
to receive advance warning.

**Q: Is the hyper store included in canonical state proofs?**
A: No. Hyper state is node-local and not consensus-critical. The
`hyper_state_root` in `HyperEnvelope` is for bilateral verification between
hyper-capable peers only.

**Q: How does this relate to FIP-19 and FIP-21?**
A: Hyper mode's unbounded retention is a prerequisite for the PoW tokenomics
phased rollout described in FIP-19. FIP-21 (Snap Compute) uses the retained
history to compute activity density scores. See `docs/tokenomics-pow.md` for
the full spec.
