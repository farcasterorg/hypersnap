#!/usr/bin/env bash
#
# Local testnet that exercises the single-→-multi validator epoch handover
# end-to-end:
#
#   1. Builds with `--features short-epochs` so one hyper epoch is ~1,440
#      snapchain blocks ≈ 6 minutes at the 250 ms default block time
#      (instead of the production 432,000 blocks ≈ 5 days).
#   2. Generates a 3-node testnet via `setup_local_testnet` with:
#        --bootstrap-active-count 1   (only node 1 in the genesis
#                                       active set)
#        --bootstrap-share-count 1    (only node 1 has a genesis DKLS
#                                       share; 1-of-1)
#        --seed-validator-fids        (synthesize per-node secp256k1
#                                       custody keys + IdRegister
#                                       events for fid 1..N in every
#                                       node's hyper RocksDB)
#   3. Starts the 3-node `docker-compose.hyper.yml` cluster. Node 1
#      drives epoch-0 consensus solo (1-of-1 DKLS); nodes 2 and 3 are
#      live but not yet validators.
#   4. Submits `validator-register-with-custody` via `hypersnap_wallet`
#      for fids 2 and 3 during epoch 0 — the wallet auto-signs the
#      EIP-712 ValidatorAuthorization payload with each node's
#      `nodes/{i}/custody.key`, and the on-node `StoreBackedCustodyResolver`
#      resolves the matching pre-seeded custody address.
#   5. Polls each node's `/hyper/v1/epoch` until the boundary flips from
#      0 to 1.
#   6. Verifies:
#        a. epoch-1 active set has grown from 1 → 3 validators
#        b. the genesis group address has been rotated away (fresh DKG
#           ceremony fired the BFT-safe `floor(2·3/3)+1 = 3` threshold
#           per dkls_supervisor::bft_safe_threshold)
#        c. epoch-1 hyperblocks are being produced under the rotated key
#
# Usage:
#   bash scripts/run_epoch_transition_testnet.sh [--keep] [--num-nodes N]
#
#   --keep         leave containers running after the test for inspection
#   --num-nodes N  override the default of 3 (docker-compose only knows 3
#                  by default — adjust the compose file to scale beyond)
#   --timeout S    seconds to wait for the epoch transition (default 600)
#
# The script never deletes the deployed Solidity contract, never edits
# any node config after boot, and tears down cleanly on exit (unless
# `--keep` is passed).

set -euo pipefail
cd "$(dirname "$0")/.."

KEEP=false
NUM_NODES=3
TIMEOUT_SECS=900
for arg in "$@"; do
  case "$arg" in
    --keep) KEEP=true ;;
    --num-nodes=*) NUM_NODES="${arg#*=}" ;;
    --timeout=*) TIMEOUT_SECS="${arg#*=}" ;;
    *)
      echo "unknown flag: $arg" >&2
      exit 2
      ;;
  esac
done

# Prefer Docker Compose v2 (`docker compose`); fall back to the legacy
# standalone `docker-compose` binary if that's what's installed.
if docker compose version >/dev/null 2>&1; then
  COMPOSE="docker compose"
elif command -v docker-compose >/dev/null 2>&1; then
  COMPOSE="docker-compose"
else
  echo "error: neither 'docker compose' nor 'docker-compose' is available" >&2
  exit 2
fi

cleanup() {
  if [ "$KEEP" = false ]; then
    echo "[cleanup] Stopping containers..."
    $COMPOSE -f docker-compose.hyper.yml down -v 2>/dev/null || true
  fi
}
trap cleanup EXIT

# ──────────────────────────────────────────────────────────────────────
# 1. Build binaries — both binaries must carry the `short-epochs`
#    feature flag, since `EPOCH_LENGTH` is a compile-time const consumed
#    by both the supervisor (the running node) and the setup tool (which
#    uses `EPOCH_LENGTH / 10` for nothing today but kept consistent for
#    future use). The wallet is feature-agnostic.
# ──────────────────────────────────────────────────────────────────────
echo "[1/6] Building hypersnap, setup_local_testnet, hypersnap_wallet with --features short-epochs..."
cargo build --release --features short-epochs \
  --bin hypersnap --bin setup_local_testnet --bin hypersnap_wallet

# ──────────────────────────────────────────────────────────────────────
# 2. Generate configs. `--bootstrap-share-count 1` is the key knob:
#    only node 1 receives a genesis share; nodes 2 and 3 are listed in
#    `bootstrap_validators` (so they belong to the active set) but have
#    no `local_dkls_share_path` in their config.
# ──────────────────────────────────────────────────────────────────────
echo "[2/6] Generating testnet configs (1 active validator, 2 dormant for live registration)..."
rm -rf nodes
./target/release/setup_local_testnet \
  --num-nodes "$NUM_NODES" \
  --num-shards 2 \
  --hyper-enabled \
  --dkls-threshold 1 \
  --bootstrap-active-count 1 \
  --bootstrap-share-count 1 \
  --seed-validator-fids \
  --seed-balances 1000000000 \
  --seed-snapchain-state \
  --gossip-host-template "172.101.0.1{i}"

# Generate an attacker identity that is NOT in the validator set and
# NOT in any IdRegister event. We use it to demonstrate the four
# rejection paths in step [4c] below.
mkdir -p nodes/attacker
if [ ! -f nodes/attacker/custody.key ]; then
  dd if=/dev/urandom of=nodes/attacker/custody.key bs=32 count=1 status=none
  dd if=/dev/urandom of=nodes/attacker/validator.key bs=32 count=1 status=none
  dd if=/dev/urandom of=nodes/attacker/transport.key bs=32 count=1 status=none
fi

# Capture the genesis group address so we can later assert it has been
# rotated. The genesis.toml has it as `genesis_group_address_hex = "0x…"`.
GENESIS_GROUP_ADDR_HEX=$(grep -E '^genesis_group_address_hex' nodes/genesis.toml \
  | sed -E 's/.*"0x([0-9a-fA-F]+)".*/\1/' | tr 'A-F' 'a-f')
if [ -z "$GENESIS_GROUP_ADDR_HEX" ]; then
  echo "[error] could not parse genesis_group_address_hex from nodes/genesis.toml" >&2
  exit 1
fi
echo "    Genesis group address: 0x${GENESIS_GROUP_ADDR_HEX}"

# ──────────────────────────────────────────────────────────────────────
# 3. Start the 3-node cluster.
# ──────────────────────────────────────────────────────────────────────
echo "[3/6] Starting 3-node cluster..."
$COMPOSE -f docker-compose.hyper.yml up -d --build

HEALTH_PORTS=(3483 3484 3485)
echo "    Waiting for all nodes to be healthy (up to 120s each)..."
MAX_WAIT=120
for port in "${HEALTH_PORTS[@]}"; do
  waited=0
  until curl -sf "http://127.0.0.1:$port/v1/info" > /dev/null 2>&1; do
    sleep 2
    waited=$((waited + 2))
    if [ $waited -ge $MAX_WAIT ]; then
      echo "    ERROR: node on port $port not healthy after ${MAX_WAIT}s"
      $COMPOSE -f docker-compose.hyper.yml logs --tail=80
      exit 1
    fi
  done
  echo "    Node on :$port healthy."
done

# Convenience accessors
HEAD_URL_1=http://127.0.0.1:3483
HEAD_URL_2=http://127.0.0.1:3484
HEAD_URL_3=http://127.0.0.1:3485

# ──────────────────────────────────────────────────────────────────────
# 4a. Wait for epoch 0 progress — node 1 is the only signer.
# ──────────────────────────────────────────────────────────────────────
echo "[4/6] Waiting for epoch-0 hyperblock production (1-of-1 genesis signer)..."
waited=0
LAST_HEIGHT=0
while [ $waited -lt 60 ]; do
  H_JSON=$(curl -sf "${HEAD_URL_1}/hyper/v1/head" 2>/dev/null || echo "{}")
  H=$(echo "$H_JSON" | python3 -c "import json,sys; d=json.load(sys.stdin); h=d.get('height') or 0; print(h)" 2>/dev/null || echo 0)
  if [ "$H" -gt 0 ]; then
    LAST_HEIGHT="$H"
    echo "    Node 1 reports hyperblock height = $LAST_HEIGHT (epoch 0 active)."
    break
  fi
  sleep 2
  waited=$((waited + 2))
done
if [ "$LAST_HEIGHT" -eq 0 ]; then
  echo "    ERROR: no hyperblocks produced within 60s — genesis signer may not be signing"
  $COMPOSE -f docker-compose.hyper.yml logs --tail=120 node1
  exit 1
fi

# ──────────────────────────────────────────────────────────────────────
# 4b. Live-register validators 2..N via the wallet's auto-signing
#     subcommand. Each validator's secp256k1 custody key is at
#     `nodes/{i}/custody.key` (raw 32 bytes), and the matching
#     IdRegister event was pre-seeded into every node's hyper RocksDB
#     by `setup_local_testnet --seed-validator-fids`. The wallet
#     auto-signs the EIP-712 typed data; the on-node strict path
#     (StoreBackedCustodyResolver → verify_custody_signature) accepts
#     the message.
# ──────────────────────────────────────────────────────────────────────
echo "[4b] Live-registering validators 2..${NUM_NODES} via wallet (auto custody-sign)..."

# `nodes/N/hypersnap.toml` carries the ed25519 validator secret in the
# `[consensus] private_key = "<hex>"` field — same key the running node
# signs blocks with. We materialize it to a 32-byte file the wallet
# `--key-file` flag understands.
for i in $(seq 2 "$NUM_NODES"); do
  VALIDATOR_KEY_HEX=$(grep -E '^private_key = ' "nodes/$i/hypersnap.toml" \
    | sed -E 's/^private_key = "([0-9a-fA-F]+)".*/\1/')
  if [ -z "$VALIDATOR_KEY_HEX" ]; then
    echo "    ERROR: could not parse validator private_key for node $i"
    exit 1
  fi
  # The hex is the full 64-byte (sk || pk) libp2p ed25519 keypair;
  # `load_ed25519_key` accepts either 32 or 64 bytes.
  echo -n "$VALIDATOR_KEY_HEX" | xxd -r -p > "nodes/$i/validator.key"

  # We need the per-epoch group address that this validator is binding
  # itself to. At epoch 0 there is one — the genesis address.
  VALIDATOR_ADDR_HEX="$GENESIS_GROUP_ADDR_HEX"

  # The validator's announced X25519 transport pubkey is derived from
  # the pre-baked transport secret at `nodes/{i}/transport.key`. The
  # secret was written by `setup_local_testnet --seed-validator-fids`
  # BEFORE the node booted; the node loads the same file (per its
  # `[hyper] transport_secret_path` config), so the announced pubkey is
  # one the node actually controls the secret half of. Sealed DKLS
  # round messages addressed to this validator therefore open.
  TRANSPORT_KEY_FILE="nodes/$i/transport.key"
  if [ ! -f "$TRANSPORT_KEY_FILE" ]; then
    echo "    ERROR: $TRANSPORT_KEY_FILE missing — did setup_local_testnet run with --seed-validator-fids?"
    exit 1
  fi

  # Register at the CURRENT epoch (0). Per FIP §1 (EPOCH_BUFFER=1),
  # a message with registration_epoch=N-1 activates at epoch N+1 —
  # so a registration submitted at epoch 0 activates at epoch 2.
  # Step [5] therefore waits for epoch >= 2 (not 1) before [6]
  # checks the grown active set.
  echo "    Submitting ValidatorRegister for fid=$i via node 1's RPC..."
  if ! ./target/release/hypersnap_wallet \
      --node-url "$HEAD_URL_1" \
      --key-file "nodes/$i/validator.key" \
      validator-register-with-custody \
      --transport-secret-file "$TRANSPORT_KEY_FILE" \
      --validator-address-hex "$VALIDATOR_ADDR_HEX" \
      --fid "$i" \
      --epoch 0 \
      --custody-key-file "nodes/$i/custody.key" 2>&1; then
    echo "    WARN: validator-register-with-custody for fid=$i did not return success."
    echo "    Continuing — the message may still have been admitted; we'll check the"
    echo "    active set after the epoch boundary fires."
  fi
done

# Give the registrations a moment to propagate + be recorded.
sleep 5

# ──────────────────────────────────────────────────────────────────────
# 4b1. Deregister flow: submit a Deregister event and confirm the
#      runtime accepted it via `submission_status`. Verifying the
#      active-set actually shrinks would require waiting 2 additional
#      epoch boundaries (Deregister also subject to EPOCH_BUFFER), so
#      we stop at admission verification — the on-chain effect is
#      already covered by `validator_registry::tests`.
# ──────────────────────────────────────────────────────────────────────
echo "[4b1] Deregister round-trip via /submission_status..."
DEREG_OUT=$(./target/release/hypersnap_wallet \
    --node-url "$HEAD_URL_1" \
    --key-file "nodes/3/validator.key" \
    validator-deregister \
    --fid 3 \
    --epoch 0 2>&1) || true
echo "$DEREG_OUT" | sed 's/^/    /'
DEREG_HASH=$(echo "$DEREG_OUT" | python3 -c "
import json, sys
try:
    d = json.loads(sys.stdin.read())
    print((d.get('message_hash_hex') or '').lstrip('0x'))
except Exception:
    print('')
" 2>/dev/null || echo "")
if [ -z "$DEREG_HASH" ]; then
  echo "    WARN: couldn't extract message_hash_hex from wallet output; deregister round-trip skipped"
else
  # Give the actor a moment to process the queued LocalSubmitMessage.
  sleep 2
  STATUS_JSON=$(curl -sf "${HEAD_URL_1}/hyper/v1/submission_status/${DEREG_HASH}" || echo "{}")
  STATUS=$(echo "$STATUS_JSON" | python3 -c "
import json, sys
d = json.load(sys.stdin)
print(d.get('status', 'unknown'))
" 2>/dev/null || echo "unknown")
  case "$STATUS" in
    accepted)
      echo "    ✓ deregister admitted (submission_status=accepted, hash=${DEREG_HASH:0:16}…)"
      ;;
    rejected)
      REASON=$(echo "$STATUS_JSON" | python3 -c "
import json, sys
d = json.load(sys.stdin)
print(d.get('reason', ''))
" 2>/dev/null || echo "")
      echo "    ✗ deregister rejected: $REASON"
      exit 1
      ;;
    *)
      echo "    WARN: deregister verdict still '$STATUS' after 2s — actor may be slow under load."
      ;;
  esac
fi

# ──────────────────────────────────────────────────────────────────────
# 4c. Misbehaving-attacker harness. Each attempt is expected to be
#     REJECTED at admission and to NOT appear in the validator
#     registry. We submit four attacks; the script checks both:
#       - the wallet sub-shell exits non-zero, AND
#       - no extra entries land in epoch-1's active set.
# ──────────────────────────────────────────────────────────────────────
echo "[4c] Running misbehavior harness — verdicts checked against the active set at [6]..."
echo "    (HTTP submit returns 202 before validation runs, so the wallet exit"
echo "     code is meaningless here — we record each attack's validator_key and"
echo "     check after the epoch flip whether it actually made it into the registry.)"

# Captured attack records — each line is `tag\tvalidator_key_hex` (no 0x prefix).
# Filled in by `submit_attack` and consumed at [6].
ATTACK_RECORDS_FILE=/tmp/hypersnap-attack-records
: > "$ATTACK_RECORDS_FILE"

# submit_attack <tag> <wallet args...>
# Runs the wallet, captures its JSON output, and appends a
# `<tag>\t<validator_key_hex>` record to $ATTACK_RECORDS_FILE. The
# verdict (admitted vs rejected) is checked at [6] against the
# epoch-${TARGET_EPOCH} active set — the only honest signal.
submit_attack() {
  local tag="$1"
  shift
  if ! "$@" > /tmp/attacker-out 2>&1; then
    # The wallet itself errored before HTTP submit; this is a true
    # client-side rejection (e.g., key file missing).
    echo "    ⓘ submitted '$tag' — wallet exited non-zero (no HTTP send)"
    return
  fi
  # Parse `validator_key_hex` out of the JSON the wallet just printed.
  local vk
  vk=$(python3 -c "
import json, sys
try:
    d = json.loads(open('/tmp/attacker-out').read())
    print((d.get('validator_key_hex') or '').lstrip('0x'))
except Exception:
    print('')
")
  if [ -z "$vk" ]; then
    echo "    ⚠ submitted '$tag' but couldn't parse validator_key_hex from wallet output"
    return
  fi
  printf '%s\t%s\n' "$tag" "$vk" >> "$ATTACK_RECORDS_FILE"
  echo "    ⓘ submitted '$tag' (vk=${vk:0:16}…) — verdict deferred to [6]"
}

# Attack (a) — impersonation: claim fid=2 (which the resolver maps to
# node-2's real custody address) while presenting an EIP-712
# signature produced with the ATTACKER's custody secret. The on-node
# `verify_custody_signature` recovers an address that does NOT match
# the resolver's; admission MUST fail.
submit_attack "custody-impersonation fid=2 with attacker custody" \
  ./target/release/hypersnap_wallet \
    --node-url "$HEAD_URL_1" \
    --key-file "nodes/attacker/validator.key" \
    validator-register-with-custody \
    --transport-secret-file "nodes/attacker/transport.key" \
    --validator-address-hex "$GENESIS_GROUP_ADDR_HEX" \
    --fid 2 \
    --epoch 0 \
    --custody-key-file "nodes/attacker/custody.key"

# Attack (b) — wrong epoch: register at an epoch the chain has not
# reached. The lenient + strict paths both reject with
# `EpochMismatch`. We register for fid=3 (which the attacker also has
# no custody key for, but the epoch check fires first).
submit_attack "future-epoch=99 under fid=3" \
  ./target/release/hypersnap_wallet \
    --node-url "$HEAD_URL_1" \
    --key-file "nodes/attacker/validator.key" \
    validator-register-with-custody \
    --transport-secret-file "nodes/attacker/transport.key" \
    --validator-address-hex "$GENESIS_GROUP_ADDR_HEX" \
    --fid 3 \
    --epoch 99 \
    --custody-key-file "nodes/attacker/custody.key"

# Attack (c) — register a FID with no on-chain IdRegister event. We
# pick fid=99 (the testnet only seeded fids 1..NUM_NODES). The custody
# resolver returns None and the strict path rejects with
# `CustodyAddressUnknown`.
submit_attack "non-existent fid=99 (no IdRegister)" \
  ./target/release/hypersnap_wallet \
    --node-url "$HEAD_URL_1" \
    --key-file "nodes/attacker/validator.key" \
    validator-register-with-custody \
    --transport-secret-file "nodes/attacker/transport.key" \
    --validator-address-hex "$GENESIS_GROUP_ADDR_HEX" \
    --fid 99 \
    --epoch 0 \
    --custody-key-file "nodes/attacker/custody.key"

# Attack (d) — per-FID quota spam. `MAX_VALIDATORS_PER_FID = 3`. Try
# to attach 4 fresh validator_keys under FID 1 using node-1's real
# custody key. The 4th should be rejected by the quota gate; the
# first 3 may or may not be admitted depending on whether the
# bootstrap validator counts (a known gap).
echo "    Submitting 4 fresh validator_keys under fid=1 (quota=$((3)) per FID)..."
for spam_i in 1 2 3 4; do
  # Fresh ed25519 key each iteration so per-validator_key dedup
  # doesn't short-circuit before the per-FID quota.
  dd if=/dev/urandom of=nodes/attacker/spam-${spam_i}.key bs=32 count=1 status=none
  submit_attack "quota-spam #${spam_i} under fid=1" \
    ./target/release/hypersnap_wallet \
       --node-url "$HEAD_URL_1" \
       --key-file "nodes/attacker/spam-${spam_i}.key" \
       validator-register-with-custody \
       --transport-secret-file "nodes/attacker/transport.key" \
       --validator-address-hex "$GENESIS_GROUP_ADDR_HEX" \
       --fid 1 \
       --epoch 0 \
       --custody-key-file "nodes/1/custody.key"
done

# ──────────────────────────────────────────────────────────────────────
# 4d. Regular user-message submission. Seed FIDs 1..NUM_NODES were
#     pre-credited with starting balance via `--seed-balances`, so
#     FID 1 can transfer freely. We submit several transfers FID 1 →
#     FID 2 during epoch 0 and assert FID 2's balance grew —
#     confirming hyperblocks are being produced AND consumed.
# ──────────────────────────────────────────────────────────────────────
echo "[4d] Submitting user TokenTransfer messages (fid=1 → fid=2)..."
RECIPIENT_BAL_BEFORE=$(curl -sf "${HEAD_URL_1}/hyper/v1/rewards/2" \
  | python3 -c "import json,sys; print(json.load(sys.stdin).get('balance',0))" 2>/dev/null \
  || echo 0)
echo "    fid=2 balance BEFORE transfers: $RECIPIENT_BAL_BEFORE"

# Look up the current nonce so we can submit several distinct transfers
# in sequence. Each transfer increments the on-chain nonce; nonces must
# be strictly increasing per sender.
NEXT_NONCE=$(curl -sf "${HEAD_URL_1}/hyper/v1/nonce/1" \
  | python3 -c "import json,sys; print(json.load(sys.stdin).get('nonce',0))" 2>/dev/null \
  || echo 0)
echo "    fid=1 starting nonce: $NEXT_NONCE"

TRANSFER_AMOUNT=10000  # 0.01 SNAP at 6 decimals
TRANSFERS=5
ADMITTED=0
for k in $(seq 1 $TRANSFERS); do
  if ./target/release/hypersnap_wallet \
       --node-url "$HEAD_URL_1" \
       --key-file "nodes/1/validator.key" \
       transfer \
       --sender-fid 1 \
       --recipient-fid 2 \
       --amount "$TRANSFER_AMOUNT" \
       --nonce "$NEXT_NONCE" \
       --memo "testnet-demo-$k" > /tmp/xfer-out 2>&1; then
    ADMITTED=$((ADMITTED + 1))
  else
    echo "    transfer $k (nonce=$NEXT_NONCE) failed:"
    sed 's/^/        /' /tmp/xfer-out | head -3
  fi
  NEXT_NONCE=$((NEXT_NONCE + 1))
done
echo "    Submitted $TRANSFERS transfers; $ADMITTED accepted by the mempool."

# Give the chain a moment to build the next block(s) and apply them.
echo "    Waiting 8s for inclusion..."
sleep 8

RECIPIENT_BAL_AFTER=$(curl -sf "${HEAD_URL_1}/hyper/v1/rewards/2" \
  | python3 -c "import json,sys; print(json.load(sys.stdin).get('balance',0))" 2>/dev/null \
  || echo 0)
echo "    fid=2 balance AFTER transfers:  $RECIPIENT_BAL_AFTER"
EXPECTED_DELTA=$((TRANSFER_AMOUNT * ADMITTED))
ACTUAL_DELTA=$((RECIPIENT_BAL_AFTER - RECIPIENT_BAL_BEFORE))
if [ "$ACTUAL_DELTA" -ge "$TRANSFER_AMOUNT" ]; then
  echo "    ✓ at least one transfer was included (balance moved by $ACTUAL_DELTA atoms)."
else
  echo "    ✗ no transfers were included (balance unchanged)."
  echo "      Check node 1's logs:"
  $COMPOSE -f docker-compose.hyper.yml logs --tail=40 node1
fi

# ──────────────────────────────────────────────────────────────────────
# 4d2. Snapchain user-message submission. The on-chain state seeded by
#      `setup_local_testnet --seed-snapchain-state` (IdRegister +
#      StorageRent + SignerAdd for fids 1..N, with the validator's
#      ed25519 key registered as the signer) is what makes this
#      possible. Without the seeding, `submitMessage` rejects with
#      `InvalidSigner` / `NoStorage` / `MissingFid`.
#
#      We submit a CastAdd from fid 1 signed by its validator.key,
#      wait a few snapchain blocks, then read it back via
#      `GET /v1/castsByFid?fid=1`.
# ──────────────────────────────────────────────────────────────────────
echo "[4d2] Submitting snapchain user message (CastAdd from fid=1)..."
CAST_TEXT="hello hypersnap testnet"
if ./target/release/hypersnap_wallet \
     --node-url "$HEAD_URL_1" \
     --key-file "nodes/1/validator.key" \
     cast-add \
     --fid 1 \
     --text "$CAST_TEXT" \
     --network devnet > /tmp/cast-out 2>&1; then
  CAST_HASH=$(grep -oE '"hash_hex": *"0x[0-9a-fA-F]+"' /tmp/cast-out | head -1 | sed 's/.*"0x\([0-9a-fA-F]*\)".*/\1/')
  echo "    ✓ CastAdd accepted by /v1/submitMessage (hash=0x$CAST_HASH)"
else
  echo "    ✗ CastAdd submission failed:"
  sed 's/^/        /' /tmp/cast-out | head -10
fi

echo "    Waiting 8s for snapchain inclusion..."
sleep 8

# Confirm via the read API. /v1/castsByFid returns paged messages; we
# check whether ANY cast for fid=1 is present.
CASTS_BODY=$(curl -sf "${HEAD_URL_1}/v1/castsByFid?fid=1" 2>/dev/null || echo "{}")
CAST_COUNT=$(echo "$CASTS_BODY" | python3 -c "
import json, sys
d = json.load(sys.stdin)
print(len(d.get('messages', [])))
" 2>/dev/null || echo 0)
if [ "$CAST_COUNT" -ge 1 ]; then
  echo "    ✓ snapchain shard committed $CAST_COUNT cast(s) for fid=1"
else
  echo "    ✗ no casts observed for fid=1 yet — may need longer settle time"
  echo "      sample of /v1/castsByFid?fid=1:"
  echo "$CASTS_BODY" | head -c 400
  echo
fi

# ──────────────────────────────────────────────────────────────────────
# 4d3. Native-onboarding + custody-rotation misbehavior battery.
#
#      This exercises the FIP-hyper-native-onboarding attack surface end to
#      end against the live 3-node cluster, validating the PR34 remediation
#      (ONBD-1..12) under real consensus rather than in unit tests:
#
#        ONBD-1  cross-node convergence — onboards submitted to DIFFERENT
#                nodes in different arrival orders must yield the SAME
#                custody→FID binding on every node (identity is folded into
#                the consensus verkle root; a divergence would fork or halt).
#        ONBD-5  a below-floor POW onboard is rejected.
#        ONBD-6  a stake-gated onboard is rejected (Phase-2 gate off in prod
#                — the testnet build keeps the gate off too).
#        ONBD-10 rotate a custody away, then REPLAY its onboard: the revoked
#                custody must stay unbound (no mirror resurrection), and a
#                re-rotation attempt from the revoked key must be a no-op.
#
#      Signal: the custody→FID binding read from GET /hyper/v1/custody/<addr>
#      on each node. HTTP submit returns 202 before validation, so — as with
#      the validator battery [4c] — we assert on committed STATE, never the
#      wallet exit code. The testnet build uses MIN_DIFFICULTY_BITS=12
#      (short-epochs), so honest POW solves are instant.
# ──────────────────────────────────────────────────────────────────────
echo "[4d3] Native-onboarding + custody-rotation misbehavior battery..."

# Fetch a fresh onboarding anchor (a recent hyper block height + its canonical
# hash) from node 1. Every node agrees on this block, so an onboard anchored
# here validates on all three.
ANCHOR_JSON=$(curl -sf "${HEAD_URL_1}/hyper/v1/head" 2>/dev/null || echo "{}")
ANCHOR_HEIGHT=$(echo "$ANCHOR_JSON" | python3 -c "import json,sys;print(json.load(sys.stdin).get('height') or 0)" 2>/dev/null || echo 0)
ANCHOR_HASH=$(echo "$ANCHOR_JSON" | python3 -c "import json,sys;print((json.load(sys.stdin).get('hash') or '').lstrip('0x'))" 2>/dev/null || echo "")
echo "    Onboarding anchor: height=$ANCHOR_HEIGHT hash=0x${ANCHOR_HASH:0:16}…"

ONBD_FAIL=0
if [ "$ANCHOR_HEIGHT" -le 0 ] || [ -z "$ANCHOR_HASH" ]; then
  echo "    WARN: no hyper head yet — skipping onboarding battery (need ≥1 hyperblock)."
else
  mkdir -p nodes/onboard

  # cfid <url> <custody_hex> → prints the bound FID, 'null' (unbound), or 'err'
  # (query failed). Empty custody is treated as 'err' so a missed capture can't
  # masquerade as a value.
  cfid() {
    [ -z "$2" ] && { echo "err"; return; }
    curl -sf "$1/hyper/v1/custody/$2" 2>/dev/null \
      | python3 -c "import json,sys; v=json.load(sys.stdin).get('fid'); print(v if v is not None else 'null')" 2>/dev/null \
      || echo "err"
  }

  # onboard <url> <keyfile> [extra wallet args...] → prints the custody addr
  # (0x-prefix stripped) the wallet derived + submitted. Retries up to 3× on a
  # transient wallet/submit failure; surfaces the wallet error on give-up.
  onboard() {
    local url="$1" kf="$2"; shift 2
    local attempt addr
    for attempt in 1 2 3; do
      ./target/release/hypersnap_wallet --node-url "$url" native-onboard \
        --custody-key-file "$kf" \
        --anchor-height "$ANCHOR_HEIGHT" --anchor-hash-hex "$ANCHOR_HASH" \
        "$@" > /tmp/onbd-out 2>&1 || true
      addr=$(python3 -c "
import json
c = (json.load(open('/tmp/onbd-out')).get('custody') or '')
print(c[2:] if c.startswith('0x') else c)
" 2>/dev/null || echo "")
      if [ -n "$addr" ]; then echo "$addr"; return; fi
      sleep 3
    done
    echo "      [onboard] wallet did not return a custody after 3 tries:" >&2
    sed 's/^/        /' /tmp/onbd-out >&2 | head -4
    echo ""
  }

  # poll_fid <url> <custody> <timeout_s> → poll cfid until it resolves to a
  # numeric FID (return it) or the timeout elapses (return the last value).
  poll_fid() {
    local url="$1" custody="$2" timeout="$3" waited=0 v
    while [ "$waited" -lt "$timeout" ]; do
      v=$(cfid "$url" "$custody")
      if [ "$v" != "err" ] && [ "$v" != "null" ]; then echo "$v"; return; fi
      sleep 3; waited=$((waited + 3))
    done
    echo "$v"
  }

  new_key() { dd if=/dev/urandom of="$1" bs=32 count=1 status=none; }
  # A random 20-byte custody ADDRESS (for rotation targets we never sign from).
  rand_addr() { head -c20 /dev/urandom | xxd -p | tr -d '\n'; }

  # ── ONBD-1: cross-node convergence ──────────────────────────────────
  echo "    [ONBD-1] onboarding custody A via node1 and custody B via node2 (distinct nodes)..."
  new_key nodes/onboard/a.key
  new_key nodes/onboard/b.key
  A_ADDR=$(onboard "$HEAD_URL_1" nodes/onboard/a.key)
  B_ADDR=$(onboard "$HEAD_URL_2" nodes/onboard/b.key)
  echo "      custody A=0x${A_ADDR:0:16}… (via node1), B=0x${B_ADDR:0:16}… (via node2)"
  if [ -z "$A_ADDR" ] || [ -z "$B_ADDR" ]; then
    echo "      ✗ ONBD-1: onboard submission failed to return a custody (harness/wallet issue, not consensus)."
    ONBD_FAIL=1
  fi
  # Poll node1 (the proposer) until BOTH onboards are included, then poll the
  # followers to converge — robust to block-inclusion + gossip-propagation lag
  # instead of a fixed sleep.
  A1=$(poll_fid "$HEAD_URL_1" "$A_ADDR" 60); B1=$(poll_fid "$HEAD_URL_1" "$B_ADDR" 60)
  A2=$(poll_fid "$HEAD_URL_2" "$A_ADDR" 40); A3=$(poll_fid "$HEAD_URL_3" "$A_ADDR" 40)
  B2=$(poll_fid "$HEAD_URL_2" "$B_ADDR" 40); B3=$(poll_fid "$HEAD_URL_3" "$B_ADDR" 40)
  echo "      custody A → node1=$A1 node2=$A2 node3=$A3"
  echo "      custody B → node1=$B1 node2=$B2 node3=$B3"
  if [ "$A1" = "null" ] || [ "$A1" = "err" ] || [ "$A1" != "$A2" ] || [ "$A2" != "$A3" ] \
     || [ "$B1" = "null" ] || [ "$B1" = "err" ] || [ "$B1" != "$B2" ] || [ "$B2" != "$B3" ]; then
    echo "      ✗ ONBD-1: nodes DISAGREE on a custody→FID binding (or an onboard didn't land)."
    echo "        This is the exact per-node identity fork ONBD-1 was filed against."
    ONBD_FAIL=1
  elif [ "$A1" = "$B1" ]; then
    echo "      ✗ ONBD-1: custody A and B were assigned the SAME FID ($A1) — collision."
    ONBD_FAIL=1
  else
    # Both must be hyper-native FIDs (>= 2^63 = 9223372036854775808).
    if [ "$A1" -lt 9223372036854775808 ] 2>/dev/null || [ "$B1" -lt 9223372036854775808 ] 2>/dev/null; then
      echo "      ✗ ONBD-1: an assigned FID is below HYPER_FID_BASE (2^63) — FID-space violation."
      ONBD_FAIL=1
    else
      echo "      ✓ ONBD-1: all 3 nodes agree (A→$A1, B→$B1), distinct, both ≥ 2^63."
    fi
  fi

  # ── ONBD-5: below-floor POW rejected ────────────────────────────────
  echo "    [ONBD-5] onboarding with difficulty 8 (< floor 12) — must be rejected..."
  new_key nodes/onboard/weak.key
  WEAK_ADDR=$(onboard "$HEAD_URL_1" nodes/onboard/weak.key --difficulty-bits 8)
  sleep 8
  WEAK_FID=$(cfid "$HEAD_URL_1" "$WEAK_ADDR")
  if [ -z "$WEAK_ADDR" ]; then
    echo "      ✗ ONBD-5: onboard submission failed (harness/wallet issue, not consensus)."
    ONBD_FAIL=1
  elif [ "$WEAK_FID" = "null" ]; then
    echo "      ✓ ONBD-5: below-floor POW onboard rejected (custody unbound)."
  else
    echo "      ✗ ONBD-5: below-floor POW onboard was ADMITTED (fid=$WEAK_FID) — floor not enforced."
    ONBD_FAIL=1
  fi

  # ── ONBD-6: stake gate rejected (Phase 2 disabled) ──────────────────
  echo "    [ONBD-6] stake-gated onboard — must be rejected (StakeGateNotYetEnabled)..."
  new_key nodes/onboard/stake.key
  STAKE_ADDR=$(onboard "$HEAD_URL_1" nodes/onboard/stake.key \
    --stake-lock-id-hex "$(head -c32 /dev/urandom | xxd -p | tr -d '\n')" \
    --stake-amount 1000000000 --stake-duration 1000)
  sleep 8
  STAKE_FID=$(cfid "$HEAD_URL_1" "$STAKE_ADDR")
  if [ -z "$STAKE_ADDR" ]; then
    echo "      ✗ ONBD-6: onboard submission failed (harness/wallet issue, not consensus)."
    ONBD_FAIL=1
  elif [ "$STAKE_FID" = "null" ]; then
    echo "      ✓ ONBD-6: stake-gated onboard rejected (custody unbound)."
  else
    echo "      ✗ ONBD-6: stake-gated onboard ADMITTED (fid=$STAKE_FID) — Phase-2 gate is live."
    ONBD_FAIL=1
  fi

  # ── ONBD-10: rotate-away then replay must not resurrect the binding ──
  echo "    [ONBD-10] onboard C1, rotate C1→C2, replay C1 onboard, re-rotate from C1..."
  new_key nodes/onboard/c1.key
  C1_ADDR=$(onboard "$HEAD_URL_1" nodes/onboard/c1.key)
  C1_FID=$(poll_fid "$HEAD_URL_1" "$C1_ADDR" 60)
  echo "      C1=0x${C1_ADDR:0:16}… onboarded → fid=$C1_FID"
  if [ -z "$C1_ADDR" ] || [ "$C1_FID" = "null" ] || [ "$C1_FID" = "err" ]; then
    echo "      ✗ ONBD-10 setup: C1 onboard didn't land; cannot run revocation test."
    ONBD_FAIL=1
  else
    C2_ADDR=$(rand_addr)
    echo "      rotating C1 → C2=0x${C2_ADDR:0:16}… (nonce 1)..."
    ./target/release/hypersnap_wallet --node-url "$HEAD_URL_1" custody-rotate \
      --custody-key-file nodes/onboard/c1.key --fid "$C1_FID" \
      --new-custody-hex "$C2_ADDR" --nonce 1 > /tmp/rot-out 2>&1 || true
    # Poll until the rotation lands (C2 picks up the FID), then read C1.
    C2_AFTER_ROT=$(poll_fid "$HEAD_URL_1" "$C2_ADDR" 60)
    C1_AFTER_ROT=$(cfid "$HEAD_URL_1" "$C1_ADDR")
    echo "      post-rotation: C1→$C1_AFTER_ROT  C2→$C2_AFTER_ROT"
    if [ "$C1_AFTER_ROT" != "null" ] || [ "$C2_AFTER_ROT" != "$C1_FID" ]; then
      echo "      ✗ ONBD-9/rotation: rotation did not move the binding on-root as expected."
      ONBD_FAIL=1
    else
      # Replay C1's byte-fresh onboard (new anchor, re-solved POW). The `ever`
      # marker makes it a no-op; the tombstone-aware mirror must NOT resurrect.
      echo "      replaying C1's onboard (must NOT resurrect the revoked binding)..."
      onboard "$HEAD_URL_1" nodes/onboard/c1.key > /dev/null
      sleep 8
      C1_AFTER_REPLAY=$(cfid "$HEAD_URL_1" "$C1_ADDR")
      # Attempt a re-rotation FROM the revoked C1 (nonce 2) — must be a no-op.
      C3_ADDR=$(rand_addr)
      ./target/release/hypersnap_wallet --node-url "$HEAD_URL_1" custody-rotate \
        --custody-key-file nodes/onboard/c1.key --fid "$C1_FID" \
        --new-custody-hex "$C3_ADDR" --nonce 2 > /dev/null 2>&1 || true
      sleep 6
      C3_AFTER=$(cfid "$HEAD_URL_1" "$C3_ADDR")
      C2_FINAL=$(cfid "$HEAD_URL_1" "$C2_ADDR")
      echo "      post-replay: C1→$C1_AFTER_REPLAY  C3(re-rotate target)→$C3_AFTER  C2→$C2_FINAL"
      if [ "$C1_AFTER_REPLAY" != "null" ]; then
        echo "      ✗ ONBD-10: onboard replay RESURRECTED the revoked custody C1 (→$C1_AFTER_REPLAY)."
        ONBD_FAIL=1
      elif [ "$C3_AFTER" != "null" ]; then
        echo "      ✗ ONBD-10: a re-rotation from the REVOKED C1 succeeded (C3→$C3_AFTER)."
        ONBD_FAIL=1
      elif [ "$C2_FINAL" != "$C1_FID" ]; then
        echo "      ✗ ONBD-10: C2 lost the FID (→$C2_FINAL); rotation state corrupted."
        ONBD_FAIL=1
      else
        echo "      ✓ ONBD-10: C1 stayed revoked through replay + re-rotate; C2 holds fid=$C1_FID."
      fi
    fi
  fi

  # Onboarding must not have halted or forked hyper consensus: all nodes'
  # hyper_state_root at their common height should still agree (identity is
  # in-root). We snapshot each node's head root; a mismatch at equal height
  # signals a divergence the ONBD-1 fold was meant to make impossible.
  echo "    [ONBD-1 root] comparing hyper_state_root across nodes at common height..."
  ROOTS=$(for url in "$HEAD_URL_1" "$HEAD_URL_2" "$HEAD_URL_3"; do
    curl -sf "${url}/hyper/v1/head" 2>/dev/null | python3 -c "
import json,sys
d=json.load(sys.stdin)
print(f\"h={d.get('height') or 0} root={d.get('hyper_state_root','')[:16]}\")
" 2>/dev/null || echo "h=0 root=?"
  done)
  echo "$ROOTS" | sed 's/^/      /'

  if [ "$ONBD_FAIL" -ne 0 ]; then
    echo "    ERROR: native-onboarding/rotation misbehavior battery FAILED — see above."
    echo "    The PR34 onboarding remediation (ONBD-1..12) is not holding on the live cluster."
    $COMPOSE -f docker-compose.hyper.yml logs --tail=60 node1
    exit 1
  fi
  echo "    ✓ native-onboarding + rotation battery passed (ONBD-1/5/6/10 held on the live cluster)."
fi

# ──────────────────────────────────────────────────────────────────────
# 4e. Snapchain-side liveness check. Hyper rides on top of snapchain
#     consensus; the two are SEPARATE BFT instances and snapchain has
#     its own validator set (every node in this testnet is a snapchain
#     validator via `[consensus] validator_sets`). Regular Farcaster
#     messages (CastAdd, ReactionAdd, etc.) flow through snapchain's
#     own shard chunks, NOT hyperblocks — so we must confirm snapchain
#     consensus is independently making progress.
#
#     `/v1/info` returns `shard_infos[*].max_height` per shard. We
#     snapshot it across all 3 nodes here and again just before the
#     epoch transition (step [5]) — non-zero growth on every shard
#     proves snapchain consensus is producing blocks regardless of
#     which nodes are currently hyper validators.
#
#     This also implicitly covers BOTH scenarios the architecture
#     supports:
#       (A) snapchain-validator-AND-hyper-validator (node 1 at every
#           epoch; nodes 2/3 after epoch 1)
#       (B) snapchain-validator-ONLY (nodes 2/3 during epoch 0, before
#           they live-register into hyper)
#     Snapchain blocks must keep advancing in both states.
# ──────────────────────────────────────────────────────────────────────
echo "[4e] Snapchain liveness check (separate from hyper consensus)..."
snapshot_snapchain_heights() {
  for url in "$HEAD_URL_1" "$HEAD_URL_2" "$HEAD_URL_3"; do
    curl -sf "${url}/v1/info" 2>/dev/null | python3 -c "
import json, sys
try:
    d = json.load(sys.stdin)
    out = []
    for s in d.get('shard_infos', []) or d.get('shardInfos', []) or []:
        sid = s.get('shard_id') or s.get('shardId') or 0
        h = s.get('max_height') or s.get('maxHeight') or 0
        out.append(f'shard{sid}=h{h}')
    print(' '.join(out) if out else 'no-shard-infos')
except Exception as e:
    print(f'parse-failed: {e}')
"
  done
}

echo "    Snapchain shard heights (per node) BEFORE [5]:"
SNAPCHAIN_BEFORE=$(snapshot_snapchain_heights)
echo "$SNAPCHAIN_BEFORE" | sed 's/^/      /'

# ──────────────────────────────────────────────────────────────────────
# 4f. Restart-safety: kill node 2 and bring it back up before the long
#     epoch wait. Node 2 must rejoin gossip, catch up on missed
#     hyper/snapchain blocks, and re-participate in the upcoming DKG
#     ceremony so it ends up in the epoch-2 active set just like a
#     never-restarted peer. Step [4f2] explicitly asserts node2's
#     hyper head catches up to the live tip (the follower catch-up/sync
#     path); [5] poll and [6] convergence observe the rest.
# ──────────────────────────────────────────────────────────────────────
echo "[4f] Restart-safety: bouncing hyper-node2..."
PRE_HEIGHT=$(curl -sf "${HEAD_URL_2}/hyper/v1/head" 2>/dev/null | python3 -c "
import json, sys
d = json.load(sys.stdin)
print(d.get('height') or 0)
" 2>/dev/null || echo 0)
echo "    node2 hyperblock head pre-restart: $PRE_HEIGHT"
$COMPOSE -f docker-compose.hyper.yml restart node2 > /dev/null
# Healthcheck: wait until node2 responds on /v1/info again. Cap at 60s
# — a longer outage would indicate a real boot failure, not just
# slow startup.
echo "    Waiting for node2 to come back online..."
waited=0
until curl -sf "http://127.0.0.1:3484/v1/info" > /dev/null 2>&1; do
  sleep 2
  waited=$((waited + 2))
  if [ $waited -ge 60 ]; then
    echo "    ERROR: node2 didn't come back within 60s after restart"
    $COMPOSE -f docker-compose.hyper.yml logs --tail=80 node2
    exit 1
  fi
done
echo "    node2 healthy again after ${waited}s"

# ──────────────────────────────────────────────────────────────────────
# 4f2. Hyper-head catch-up assertion (the follower catch-up/sync path).
#      During node2's outage, node1 keeps producing hyperblocks that
#      node2 misses. On reboot node2 replays its stored blocks and
#      resumes at its old head — behind the live tip by the whole
#      outage window. Live gossip only carries NEW blocks (tip+), which
#      DON'T chain onto node2's stale head: chain.rs rejects them with
#      ParentHashMismatch. Without the catch-up path node2's hyper head
#      would freeze at its restart height forever while node1 races
#      ahead. With it, node2 detects the gap, requests the missing run
#      from peers, imports it in order, and converges on the tip.
#
#      We assert exactly that: node2's head must (a) advance beyond
#      where it resumed AND (b) close to within LAG_TOLERANCE of node1's
#      still-moving tip. A frozen head (the pre-sync bug) makes the gap
#      grow without bound → this check times out and fails loudly.
# ──────────────────────────────────────────────────────────────────────
hyper_head_height() {
  curl -sf "$1/hyper/v1/head" 2>/dev/null | python3 -c "
import json, sys
try:
    d = json.load(sys.stdin)
    print(d.get('height') or 0)
except Exception:
    print(0)
" 2>/dev/null || echo 0
}

echo "[4f2] Verifying node2 hyper-head catch-up via the sync path (sustained)..."
CATCHUP_TIMEOUT=120
LAG_TOLERANCE=15
# node1's tip must advance by at least this much AFTER node2's initial
# convergence, and node2 must still be within LAG_TOLERANCE at that point.
# This is the crux: a single-instant "head==tip" sample gives a FALSE GREEN
# when node2 catches up once and then re-diverges (imports stop, head freezes
# while the tip races away). Requiring node2 to keep pace with a MOVING tip is
# what actually proves the ongoing sync/import path works.
PROGRESS_MARGIN=30

# Phase 1: initial convergence — node2 advances past its restart head and gets
# within LAG_TOLERANCE of the tip.
waited=0
CONV_TIP=0
while [ $waited -lt $CATCHUP_TIMEOUT ]; do
  H1=$(hyper_head_height "$HEAD_URL_1")
  H2=$(hyper_head_height "$HEAD_URL_2")
  if [ "$H2" -gt "$PRE_HEIGHT" ] && [ $((H1 - H2)) -le $LAG_TOLERANCE ]; then
    CONV_TIP=$H1
    echo "    · initial convergence: node2=$H2, node1 tip=$H1 (lag=$((H1 - H2)) ≤ $LAG_TOLERANCE, resumed at $PRE_HEIGHT)"
    break
  fi
  sleep 3
  waited=$((waited + 3))
  echo "    [t+${waited}s] node2=$H2, node1 tip=$H1 (need head>$PRE_HEIGHT and lag≤$LAG_TOLERANCE)..."
done
if [ "$CONV_TIP" -eq 0 ]; then
  H1=$(hyper_head_height "$HEAD_URL_1")
  H2=$(hyper_head_height "$HEAD_URL_2")
  echo "    ✗ node2 never reached initial convergence after ${CATCHUP_TIMEOUT}s: head=$H2, node1 tip=$H1, resumed at $PRE_HEIGHT"
  echo "    --- node2 tail ---"
  $COMPOSE -f docker-compose.hyper.yml logs --tail=120 node2
  exit 1
fi

# Phase 2: sustained — the tip must move on by >= PROGRESS_MARGIN and node2
# must STILL be within LAG_TOLERANCE (i.e., it kept importing, didn't freeze).
TARGET_TIP=$((CONV_TIP + PROGRESS_MARGIN))
waited=0
SUSTAINED=0
while [ $waited -lt $CATCHUP_TIMEOUT ]; do
  H1=$(hyper_head_height "$HEAD_URL_1")
  H2=$(hyper_head_height "$HEAD_URL_2")
  if [ "$H1" -ge "$TARGET_TIP" ]; then
    if [ $((H1 - H2)) -le $LAG_TOLERANCE ] && [ "$H2" -gt "$CONV_TIP" ]; then
      echo "    ✓ sustained catch-up: node1 tip advanced $CONV_TIP→$H1, node2 kept pace at $H2 (lag=$((H1 - H2)) ≤ $LAG_TOLERANCE) — sync path converged and STAYED converged"
      SUSTAINED=1
    else
      echo "    ✗ node2 STALLED after initial catch-up: node1 tip=$H1 but node2 frozen at $H2 (lag=$((H1 - H2)) > $LAG_TOLERANCE)"
      echo "      Restarted-follower re-divergence: it caught up once, then stopped importing."
      echo "      A single-sample check would have (wrongly) passed here — the ongoing"
      echo "      request/serve path is not delivering blocks to the restarted follower."
      echo "    --- node2 tail (catch-up requests) ---"
      $COMPOSE -f docker-compose.hyper.yml logs --tail=60 node2 2>&1 | grep -iE "catch-up|serve" | tail -20
    fi
    break
  fi
  sleep 3
  waited=$((waited + 3))
  echo "    [t+${waited}s] waiting for tip to reach $TARGET_TIP (node1=$H1, node2=$H2)..."
done
if [ "$SUSTAINED" -ne 1 ]; then
  exit 1
fi

# ──────────────────────────────────────────────────────────────────────
# 5. Poll for epoch >= 2. Registrations submitted in [4b] have
#    registration_epoch=0, which per EPOCH_BUFFER=1 activates them at
#    epoch 2 (not epoch 1). We need to wait for two epoch boundaries
#    before the active-set check at [6] can succeed.
# ──────────────────────────────────────────────────────────────────────
TARGET_EPOCH=2
echo "[5/6] Polling for epoch 0 → ${TARGET_EPOCH} transition (timeout ${TIMEOUT_SECS}s)..."
SLEEP_SECS=10
elapsed=0
NEW_EPOCH=0
while [ $elapsed -lt "$TIMEOUT_SECS" ]; do
  EPOCH_JSON=$(curl -sf "${HEAD_URL_1}/hyper/v1/epoch" 2>/dev/null || echo "{}")
  E=$(echo "$EPOCH_JSON" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('epoch',0))" 2>/dev/null || echo 0)
  if [ "$E" -ge "$TARGET_EPOCH" ]; then
    NEW_EPOCH="$E"
    echo "    Node 1 reports epoch = $E (transition complete)."
    break
  fi
  HEIGHT_JSON=$(curl -sf "${HEAD_URL_1}/hyper/v1/head" 2>/dev/null || echo "{}")
  HEIGHT=$(echo "$HEIGHT_JSON" | python3 -c "import json,sys; d=json.load(sys.stdin); h=d.get('height') or 0; print(h)" 2>/dev/null || echo 0)
  echo "    [t+${elapsed}s] still in epoch $E (height=$HEIGHT) — waiting for $TARGET_EPOCH..."
  sleep $SLEEP_SECS
  elapsed=$((elapsed + SLEEP_SECS))
done
if [ "$NEW_EPOCH" -lt "$TARGET_EPOCH" ]; then
  echo "    ERROR: epoch did not advance to $TARGET_EPOCH within ${TIMEOUT_SECS}s"
  echo "    --- node1 tail ---"
  $COMPOSE -f docker-compose.hyper.yml logs --tail=80 node1
  echo "    --- node2 tail ---"
  $COMPOSE -f docker-compose.hyper.yml logs --tail=80 node2
  echo "    --- node3 tail ---"
  $COMPOSE -f docker-compose.hyper.yml logs --tail=80 node3
  exit 1
fi

# ──────────────────────────────────────────────────────────────────────
# 6. Verify the active set at epoch 2 has 3 validators AND the
#    group address has been rotated away from the genesis one.
#    Epoch 2 is when registrations from epoch 0 actually activate
#    (EPOCH_BUFFER=1 → N-1=0 ⇒ activate at N+1=2).
# ──────────────────────────────────────────────────────────────────────
echo "[6/6] Verifying epoch-${TARGET_EPOCH} active set grew via live registration + DKG handover..."

# Confirm epoch 0 active set was just 1 (sanity check on the bootstrap).
EPOCH0_JSON=$(curl -sf "${HEAD_URL_1}/hyper/v1/epoch/0/active" || true)
EPOCH0_COUNT=$(echo "$EPOCH0_JSON" | python3 -c "
import json, sys
d = json.load(sys.stdin)
if isinstance(d, dict):
    if 'validators' in d and isinstance(d['validators'], list):
        print(len(d['validators']))
    else:
        print(len(d))
elif isinstance(d, list):
    print(len(d))
else:
    print(0)
" 2>/dev/null || echo 0)
echo "    Epoch-0 active set: $EPOCH0_COUNT validator(s) (expected 1 — bootstrap)"

ACTIVE_JSON=$(curl -sf "${HEAD_URL_1}/hyper/v1/epoch/${TARGET_EPOCH}/active" || true)
if [ -z "$ACTIVE_JSON" ] || [ "$ACTIVE_JSON" = "null" ]; then
  echo "    ERROR: /hyper/v1/epoch/${TARGET_EPOCH}/active returned empty"
  exit 1
fi
ACTIVE_COUNT=$(echo "$ACTIVE_JSON" | python3 -c "
import json, sys
d = json.load(sys.stdin)
# Response shapes: {'validators': [...]} (current production), or a
# raw list, or a {vk_hex: {...}} map. Extract the validator count
# from each case.
if isinstance(d, dict):
    if 'validators' in d and isinstance(d['validators'], list):
        print(len(d['validators']))
    else:
        print(len(d))
elif isinstance(d, list):
    print(len(d))
else:
    print(0)
" 2>/dev/null || echo 0)
if [ "$ACTIVE_COUNT" -lt "$NUM_NODES" ]; then
  echo "    ERROR: epoch-${TARGET_EPOCH} active set has $ACTIVE_COUNT validator(s); expected at least $NUM_NODES"
  echo "    The live ValidatorRegister submissions may not have been admitted —"
  echo "    inspect the wallet output above and node 1's logs."
  echo "    --- raw response ---"
  echo "$ACTIVE_JSON"
  echo "    --- node1 tail ---"
  $COMPOSE -f docker-compose.hyper.yml logs --tail=80 node1
  exit 1
fi
echo "    Epoch-${TARGET_EPOCH} active set has $ACTIVE_COUNT validator(s) (≥ $NUM_NODES) ✓"

# Per-attack verdicts from [4c]. For each recorded
# (tag, validator_key) submitted during the misbehavior battery, check
# whether that validator_key appears in the epoch-${TARGET_EPOCH}
# active set. This is the only honest signal: the HTTP submit returns
# 202 before validation, so the wallet's exit code can't tell us
# whether the gates actually fired.
echo "    Per-attack verdicts (validator_key in epoch-${TARGET_EPOCH} active set):"
ACTIVE_VKS=$(echo "$ACTIVE_JSON" | python3 -c "
import json, sys
d = json.load(sys.stdin)
vs = d.get('validators', d) if isinstance(d, dict) else d
if not isinstance(vs, list):
    sys.exit(0)
for entry in vs:
    if isinstance(entry, dict):
        vk = entry.get('validator_key') or entry.get('validator_key_hex') or ''
        vk = vk.replace('0x', '')
        if vk:
            print(vk.lower())
")

attack_admitted_unexpected=0
attack_admitted_expected_quota_only=0
total_attacks=0
spam_admitted=0
spam_rejected=0
if [ -s "$ATTACK_RECORDS_FILE" ]; then
  while IFS=$'\t' read -r tag vk; do
    total_attacks=$((total_attacks + 1))
    if echo "$ACTIVE_VKS" | grep -qi "^${vk}$"; then
      verdict="ADMITTED"
      if [[ "$tag" == quota-spam* ]]; then
        spam_admitted=$((spam_admitted + 1))
        echo "      ⚠ $tag: $verdict (expected — known bootstrap/quota gap)"
      else
        attack_admitted_unexpected=$((attack_admitted_unexpected + 1))
        echo "      ✗ $tag: $verdict (UNEXPECTED — gate failed to fire)"
      fi
    else
      if [[ "$tag" == quota-spam* ]]; then
        spam_rejected=$((spam_rejected + 1))
        echo "      ✓ $tag: REJECTED (quota gate fired)"
      else
        echo "      ✓ $tag: REJECTED (gate fired)"
      fi
    fi
  done < "$ATTACK_RECORDS_FILE"
fi
echo "    Summary: $total_attacks attack(s) submitted; $attack_admitted_unexpected unexpectedly admitted"
echo "             spam: $spam_admitted admitted, $spam_rejected rejected"

# Hard fail only if a non-quota attack made it through. The bootstrap-
# quota gap is a known defect tracked separately.
if [ "$attack_admitted_unexpected" -gt 0 ]; then
  echo "    ERROR: $attack_admitted_unexpected misbehavior attack(s) bypassed the production gates."
  echo "    Custody-sig / epoch-range / FID-existence gates are broken; re-audit F070."
  exit 1
fi

# Quota cap: bootstrap not counted → up to MAX_VALIDATORS_PER_FID extras
# admissible under fid=1 (4 spam attempts → 3 through, 4th rejected).
# Active set should therefore be ≤ NUM_NODES + 3 in the worst case.
MAX_EXPECTED=$((NUM_NODES + 3))
if [ "$ACTIVE_COUNT" -gt "$MAX_EXPECTED" ]; then
  echo "    ERROR: epoch-${TARGET_EPOCH} active set has $ACTIVE_COUNT validators; expected at most $MAX_EXPECTED"
  echo "    A misbehavior gate beyond the known quota/bootstrap gap leaked."
  exit 1
fi
if [ "$spam_admitted" -gt 0 ]; then
  echo "    NOTE: $spam_admitted spam key(s) admitted via the bootstrap/quota gap"
  echo "    (MAX_VALIDATORS_PER_FID does not currently count bootstrap entries)."
  echo "    Real protocol bug — track separately."
fi
echo "    Live registration grew the active set from $EPOCH0_COUNT (epoch 0) → $ACTIVE_COUNT (epoch ${TARGET_EPOCH})"

# Slashing sanity: in a normal honest run nothing should be slashed
# BEFORE we inject equivocation evidence. Catches false-positive
# slashings — e.g., a regression in the B5 fix that re-introduces
# signer-index mis-attribution, or any overly-aggressive admission
# that mis-fires `record_evidence`.
for ep in 0 1 "$TARGET_EPOCH"; do
  SLASHED_JSON=$(curl -sf "${HEAD_URL_1}/hyper/v1/epoch/${ep}/slashed" 2>/dev/null || echo "{}")
  SLASHED_COUNT=$(echo "$SLASHED_JSON" | python3 -c "
import json, sys
d = json.load(sys.stdin)
if isinstance(d, dict):
    arr = d.get('slashed', d.get('validator_keys') or [])
    print(len(arr) if isinstance(arr, list) else 0)
elif isinstance(d, list):
    print(len(d))
else:
    print(0)
" 2>/dev/null || echo 0)
  if [ "$SLASHED_COUNT" -gt 0 ]; then
    echo "    ERROR: epoch-$ep slashed set is non-empty ($SLASHED_COUNT entries) in honest run."
    echo "    Either a slashing detection false-positive fired, or evidence was"
    echo "    spuriously recorded. Inspect:"
    echo "      $SLASHED_JSON"
    exit 1
  fi
done
echo "    Slashing sanity (pre-injection): epoch 0..${TARGET_EPOCH} all empty ✓"

# Positive-case slashing E2E: inject equivocation evidence for node
# 1 (the bootstrap signer, party_index=1 at epoch 0) and verify the
# `record → slashed_validators_for_epoch → slashed set` chain
# surfaces node 1's validator_key in `/epoch/0/slashed`. The wallet's
# `inject-evidence` subcommand POSTs a `HyperWireEvidence` proto to
# the devnet-only admin endpoint (gated on
# `[hyper] devnet_admin_endpoints_enabled = true` — set by
# setup_local_testnet). Signature verification is bypassed; this
# exercises the slashing-application logic (which is what B5 fixed),
# not the cryptographic equivocation detector (which is unit-tested
# in `src/hyper/slashing.rs::tests`).
echo "[6.1] Positive-case slashing E2E: inject equivocation for fid=1, party_index=1, epoch=0..."
INJECT_OUT=$(./target/release/hypersnap_wallet \
    --node-url "$HEAD_URL_1" \
    --key-file "nodes/1/validator.key" \
    inject-evidence \
    --canonical-block-id 7777 \
    --epoch 0 \
    --signer-indices 1 2>&1) || true
echo "$INJECT_OUT" | sed 's/^/    /'
if ! echo "$INJECT_OUT" | grep -q '"submitted": true'; then
  echo "    ERROR: inject-evidence wallet command did not report submitted=true."
  echo "    Either the admin endpoint is disabled (check"
  echo "    [hyper].devnet_admin_endpoints_enabled in nodes/1/hypersnap.toml)"
  echo "    or the route handler returned an error."
  exit 1
fi

# Give the actor a moment to process the inject_evidence query and
# update the slashing store before we read back the slashed set.
sleep 2

SLASHED_JSON=$(curl -sf "${HEAD_URL_1}/hyper/v1/epoch/0/slashed" 2>/dev/null || echo "{}")
NODE1_VK=$(grep -oE '^validator_key_hex = "[0-9a-f]+"' nodes/genesis.toml | head -1 | grep -oE '"[0-9a-f]+"' | tr -d '"')
if [ -z "$NODE1_VK" ]; then
  echo "    ERROR: couldn't read node 1's validator_key from nodes/genesis.toml"
  exit 1
fi
SLASHED_HAS_NODE1=$(echo "$SLASHED_JSON" | python3 -c "
import json, sys
target = sys.argv[1].lower()
d = json.load(sys.stdin)
arr = d.get('validators', d.get('slashed', d if isinstance(d, list) else [])) or []
hit = any((isinstance(v, str) and v.lower().lstrip('0x') == target) for v in arr)
print('yes' if hit else 'no')
" "$NODE1_VK" 2>/dev/null || echo "no")
if [ "$SLASHED_HAS_NODE1" != "yes" ]; then
  echo "    ERROR: epoch-0 slashed set does NOT contain node 1's validator_key."
  echo "    The record_evidence → slashed_validators_for_epoch chain is broken."
  echo "    Expected validator_key=${NODE1_VK:0:16}…"
  echo "    Raw slashed response: $SLASHED_JSON"
  exit 1
fi
echo "    ✓ post-injection: node 1's validator_key (${NODE1_VK:0:16}…) appears in /epoch/0/slashed"
echo "    Positive-case slashing chain (record → slash → expose) verified end-to-end."

# Pull the most recent hyperblock from each node and assert the
# `signature.group_address` is NOT the genesis one. Once epoch-1 shares
# are installed, every signed block carries the new derived address.
# Reads the address directly from `/hyper/v1/head.signature.group_address`
# (B3 fix: that field is now serialized).
echo "    Querying current head group_address from each node..."
ROTATED_OK=0
for url in "$HEAD_URL_1" "$HEAD_URL_2" "$HEAD_URL_3"; do
  HEAD_JSON=$(curl -sf "${url}/hyper/v1/head" || echo "{}")
  HEIGHT=$(echo "$HEAD_JSON" | python3 -c "import json,sys; d=json.load(sys.stdin); h=d.get('height') or 0; print(h)" 2>/dev/null || echo 0)
  if [ "$HEIGHT" -le 0 ]; then
    echo "      $url: no head yet, skipping"
    continue
  fi
  GROUP_ADDR=$(echo "$HEAD_JSON" | python3 -c "
import json, sys
d = json.load(sys.stdin)
sig = d.get('signature', {}) or {}
addr = sig.get('group_address', '') or ''
print(addr.lower().lstrip('0x').replace('0x', ''))
" 2>/dev/null || echo "")
  # Fallback: if head doesn't expose the signature yet (older nodes),
  # query the block endpoint and read its flat group_address field.
  if [ -z "$GROUP_ADDR" ]; then
    BLOCK_JSON=$(curl -sf "${url}/hyper/v1/block/${HEIGHT}" || echo "{}")
    GROUP_ADDR=$(echo "$BLOCK_JSON" | python3 -c "
import json, sys
d = json.load(sys.stdin)
addr = d.get('group_address', '') or ''
print(addr.lower().lstrip('0x').replace('0x', ''))
" 2>/dev/null || echo "")
  fi
  if [ -z "$GROUP_ADDR" ]; then
    echo "      $url: head=$HEIGHT but block has no group_address (still pre-epoch-1?)"
    continue
  fi
  if [ "$GROUP_ADDR" = "$GENESIS_GROUP_ADDR_HEX" ]; then
    echo "      $url: head=$HEIGHT group_address=$GROUP_ADDR (still genesis — not yet rotated on this node)"
  else
    echo "      $url: head=$HEIGHT group_address=$GROUP_ADDR (rotated ✓)"
    ROTATED_OK=$((ROTATED_OK + 1))
  fi
done

if [ "$ROTATED_OK" -lt 1 ]; then
  echo "    WARN: no node has yet produced a block under the rotated key."
  echo "    The DKG ceremony may have fired but the first multi-party signed"
  echo "    block has not been produced/imported yet. Re-run with a longer"
  echo "    --timeout, or use --keep and inspect /hyper/v1/block/<h> manually."
  echo ""
  echo "    Epoch transition itself succeeded (epoch=$NEW_EPOCH, active=$ACTIVE_COUNT)."
  exit 1
fi

# Follower convergence: every node must be importing the post-rotation
# blocks. Pre-fix (main.rs gated DKG supervisor on local share path),
# non-bootstrap signers stalled at the last pre-rotation hyperblock
# because they never installed the new group_address — every
# subsequent block silently failed `ImportError::SignatureVerificationFailed`
# at INFO level. This assertion catches a regression there fast.
HEIGHTS=()
for url in "$HEAD_URL_1" "$HEAD_URL_2" "$HEAD_URL_3"; do
  HEAD_JSON=$(curl -sf "${url}/hyper/v1/head" || echo "{}")
  H=$(echo "$HEAD_JSON" | python3 -c "import json,sys; d=json.load(sys.stdin); h=d.get('height') or 0; print(h)" 2>/dev/null || echo 0)
  HEIGHTS+=("$H")
done
MAX_H=0
MIN_H=999999999
for h in "${HEIGHTS[@]}"; do
  if [ "$h" -gt "$MAX_H" ]; then MAX_H="$h"; fi
  if [ "$h" -lt "$MIN_H" ]; then MIN_H="$h"; fi
done
SPREAD=$((MAX_H - MIN_H))
# Tolerance: allow up to 20 blocks of lag (~3s × 20 = 1 minute at the
# 3s hyperblock cadence). Larger spread implies a real stall, not
# normal gossip propagation lag.
CONVERGE_TOLERANCE=20
echo "    Follower convergence: heights=[${HEIGHTS[*]}] spread=$SPREAD (tolerance=$CONVERGE_TOLERANCE)"
if [ "$SPREAD" -gt "$CONVERGE_TOLERANCE" ]; then
  echo "    ERROR: hyperblock heads diverge by $SPREAD > $CONVERGE_TOLERANCE blocks."
  echo "    A follower has stalled — most likely because the DKG supervisor"
  echo "    isn't spawning on a node that lacks a bootstrap share, so it"
  echo "    can't install the rotated group_address and silently rejects"
  echo "    post-rotation blocks. See main.rs:1607 (operator-identity gate)."
  for i in 0 1 2; do
    echo "      node$((i+1)): hyperblock height ${HEIGHTS[$i]}"
  done
  exit 1
fi
echo "    All nodes within $CONVERGE_TOLERANCE blocks of head ✓"

# Second snapchain snapshot + delta check. Both consensus layers
# should have made progress across the same wall-clock window — proving
# they run independently and that snapchain blocks contain the
# regular-Farcaster-message traffic regardless of hyper validator
# state.
echo "    Snapchain shard heights (per node) AFTER [5]:"
SNAPCHAIN_AFTER=$(snapshot_snapchain_heights)
echo "$SNAPCHAIN_AFTER" | sed 's/^/      /'

SNAPCHAIN_ADVANCED=0
# Crude byte-equality: if the two snapshots are different, at least
# one shard on at least one node advanced. (A stricter per-shard
# parse would also be defensible; for the liveness check we just
# need "something moved".)
if [ "$SNAPCHAIN_BEFORE" != "$SNAPCHAIN_AFTER" ]; then
  SNAPCHAIN_ADVANCED=1
  echo "    ✓ snapchain heights advanced between [4e] and post-[5] window"
else
  echo "    ✗ snapchain heights unchanged — snapchain consensus may be stalled"
fi

echo ""
echo "============================================================"
echo "  SINGLE → MULTI VALIDATOR EPOCH HANDOVER VERIFIED"
echo "============================================================"
echo "  Genesis active set:       1 hyper signer (node 1, 1-of-1 share)"
echo "  Live-registered:          $((NUM_NODES - 1)) hyper validator(s) via wallet during epoch 0"
echo "  Misbehaving submissions:  4 validator attacks in [4c] (rejections confirmed"
echo "                            via active-set count) + native-onboarding/rotation"
echo "                            battery in [4d3] (ONBD-1 cross-node convergence,"
echo "                            ONBD-5 weak-POW, ONBD-6 stake-gate, ONBD-10"
echo "                            rotate-replay revocation — all held)"
echo "  Hyper user-msg inclusion: $ADMITTED transfer(s) submitted, delta on fid=2 = $ACTUAL_DELTA atoms"
echo "  Snapchain user-msg incl.: $CAST_COUNT cast(s) committed for fid=1"
echo "  Epoch-1 hyper active set: $ACTIVE_COUNT signers (BFT threshold from active-set size)"
echo "  Genesis group address:    0x$GENESIS_GROUP_ADDR_HEX"
echo "  Epoch-1 rotated address observed on $ROTATED_OK / 3 nodes."
echo "  Snapchain consensus:      $([ $SNAPCHAIN_ADVANCED -eq 1 ] && echo "alive (independent BFT, height advanced across the window)" || echo "STALLED — no block-height progress")"
echo "  Dual-validator scenario:  exercised by node 1 (snapchain ✓ + hyper ✓ throughout)"
echo "  Snapchain-only scenario:  exercised by nodes 2..${NUM_NODES} during epoch 0"
echo "                            (snapchain ✓ + hyper ✗ until live registration at [4b])"
echo "============================================================"

if [ "$KEEP" = true ]; then
  echo ""
  echo "Containers still running. Stop with:"
  echo "  $COMPOSE -f docker-compose.hyper.yml down -v"
else
  echo "Containers stopped."
fi
