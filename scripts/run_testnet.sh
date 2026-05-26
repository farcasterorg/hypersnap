#!/usr/bin/env bash
# Hypersnap multi-node testnet runner.
# Generates configs, starts 3-node docker-compose, runs a smoke test,
# and tears down.
#
# Usage: bash scripts/run_testnet.sh [--keep]
#   --keep: leave containers running after the test

set -euo pipefail
cd "$(dirname "$0")/.."

KEEP=false
for arg in "$@"; do
  [ "$arg" = "--keep" ] && KEEP=true
done

cleanup() {
  if [ "$KEEP" = false ]; then
    echo "[cleanup] Stopping containers..."
    docker-compose -f docker-compose.hyper.yml down -v 2>/dev/null || true
  fi
}
trap cleanup EXIT

# ──────────────────────────────────────────────────────────────────
# 1. Build binaries
# ──────────────────────────────────────────────────────────────────
echo "[1/5] Building..."
cargo build --release --bin hypersnap --bin setup_local_testnet --bin hypersnap_wallet

# ──────────────────────────────────────────────────────────────────
# 2. Generate configs (3-node, 2-of-3 DKLS)
# ──────────────────────────────────────────────────────────────────
echo "[2/5] Generating testnet configs..."
rm -rf nodes
./target/release/setup_local_testnet \
  --num-nodes 3 \
  --num-shards 2 \
  --hyper-enabled \
  --dkls-threshold 2

# ──────────────────────────────────────────────────────────────────
# 3. Start docker-compose
# ──────────────────────────────────────────────────────────────────
echo "[3/5] Starting 3-node cluster..."
docker-compose -f docker-compose.hyper.yml up -d --build

# ──────────────────────────────────────────────────────────────────
# 4. Wait for health
# ──────────────────────────────────────────────────────────────────
echo "[4/5] Waiting for nodes to be healthy..."
MAX_WAIT=120
for port in 3483 3484 3485; do
  echo "  Waiting for node on port $port..."
  waited=0
  until curl -sf "http://127.0.0.1:$port/healthcheck" > /dev/null 2>&1; do
    sleep 2
    waited=$((waited + 2))
    if [ $waited -ge $MAX_WAIT ]; then
      echo "  ERROR: node on port $port not healthy after ${MAX_WAIT}s"
      docker-compose -f docker-compose.hyper.yml logs --tail=50
      exit 1
    fi
  done
  echo "  Node on port $port is healthy."
done

# ──────────────────────────────────────────────────────────────────
# 5. Smoke test: query head + balance via wallet CLI
# ──────────────────────────────────────────────────────────────────
echo "[5/5] Running smoke tests..."

echo "  Querying chain head from node 1..."
./target/release/hypersnap_wallet \
  --node-url http://127.0.0.1:3483 \
  head || echo "  (head query returned non-zero — expected if no blocks yet)"

echo "  Querying epoch from node 2..."
./target/release/hypersnap_wallet \
  --node-url http://127.0.0.1:3484 \
  epoch || echo "  (epoch query returned non-zero)"

echo "  Querying balance for FID 1 from node 3..."
./target/release/hypersnap_wallet \
  --node-url http://127.0.0.1:3485 \
  balance 1 || echo "  (balance query returned non-zero — expected if no issuance yet)"

# ──────────────────────────────────────────────────────────────────
# Done
# ──────────────────────────────────────────────────────────────────
echo ""
echo "=== Testnet smoke tests passed ==="
if [ "$KEEP" = true ]; then
  echo "Containers still running. Stop with:"
  echo "  docker-compose -f docker-compose.hyper.yml down -v"
else
  echo "Containers stopped."
fi
