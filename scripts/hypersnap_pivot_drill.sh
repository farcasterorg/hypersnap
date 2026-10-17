#!/bin/bash
# Real-process pivot drill (plan WS8, HYPERSNAP_PIVOT_RUNBOOK.md §5): a
# snapchain devnet, four read nodes that stop at an overridden pivot height,
# a failed pivot (2 of 4 validators restart), a rollback to a higher height,
# and the Hypersnap network at that height.
#
#   cargo build --bin hypersnap --bin setup_local_testnet --bin hypersnap_pivot
#   scripts/hypersnap_pivot_drill.sh
#
# BIN (default target/debug) and DRILL_DIR (default nodes/pivot-drill) can be
# set. It uses ports 3383-3386, 3483-3486, 3591-3594, 3691-3694, 3791-3794,
# 50051-50054 and 50161-50164, and needs `cast` and `grpcurl`.
set -euo pipefail
REPO=$(cd "$(dirname "$0")/.." && pwd)
BIN=${BIN:-$REPO/target/debug}
PROTO=$REPO/proto/definitions
D=${DRILL_DIR:-$REPO/nodes/pivot-drill}
AUTH=$(printf 'admin:pw' | base64)

log() { echo "[$(date +%H:%M:%S)] $*"; }
grpc() { grpcurl -plaintext -import-path $PROTO "$@"; }
shard0_height() { # $1 = http port
  curl -s -m 5 "http://127.0.0.1:$1/v1/info" | python3 -I -c 'import json,sys; d=json.load(sys.stdin); print([s["maxHeight"] for s in d["shardInfos"] if s["shardId"]==0][0])' 2>/dev/null || echo 0
}
wait_exit() { # $1 = pid, $2 = timeout seconds
  for _ in $(seq 1 "$2"); do kill -0 "$1" 2>/dev/null || return 0; sleep 1; done
  return 1
}

pkill -f "$BIN/hypersnap --config" 2>/dev/null || true
rm -rf $D && mkdir -p $D && cd $D

# 1. Snapchain devnet: 4 validators.
$BIN/setup_local_testnet --num-nodes 4 --block-time 500ms >/dev/null
for i in 1 2 3 4; do
  sed -i '' "1s/^/admin_rpc_auth=\"admin:pw\"\n/" nodes/$i/hypersnap.toml
  RUST_LOG=warn nohup $BIN/hypersnap --config-path nodes/$i/hypersnap.toml >nodes/$i/node.log 2>&1 &
done
log "snapchain validators started"
until [ "$(shard0_height 3483)" -gt 10 ]; do sleep 1; done
log "snapchain shard 0 at $(shard0_height 3483)"

# 2. FIDs 1..4 with known custody keys (IdRegister through the admin RPC).
for i in 1 2 3 4; do
  key=$(printf '%064x' $((1000 + i)))
  echo "$key" > eth$i.key
  addr=$(cast wallet address --private-key 0x$key)
  to=$(python3 -I -c "import base64,sys; print(base64.b64encode(bytes.fromhex('${addr#0x}')).decode())")
  tx=$(python3 -I -c "import base64; print(base64.b64encode(bytes([$i]*32)).decode())")
  grpc -H "authorization: Basic $AUTH" -proto admin_rpc.proto -d "{
    \"type\": \"EVENT_TYPE_ID_REGISTER\", \"chain_id\": 10, \"block_number\": $((100 + i)),
    \"block_hash\": \"$tx\", \"block_timestamp\": 1700000000, \"transaction_hash\": \"$tx\",
    \"log_index\": 0, \"fid\": $i, \"tx_index\": 0, \"version\": 2,
    \"id_register_event_body\": {\"to\": \"$to\", \"event_type\": \"ID_REGISTER_EVENT_TYPE_REGISTER\"}
  }" 127.0.0.1:3383 AdminService/SubmitOnChainEvent >/dev/null
done
log "registered FIDs 1-4"
sleep 5

# 3. Genesis validator file: keys and entries of FIDs 1..4.
NOW=$(python3 -I -c 'import time; print(int(time.time()) - 1609459200)')
for i in 1 2 3 4; do
  $BIN/hypersnap_pivot keys --out keys$i >/dev/null
  $BIN/hypersnap_pivot entry --fid $i --keys keys$i --network devnet \
    --deadline $((NOW + 86400)) --eth-key-file eth$i.key --out entry$i.pb >/dev/null
done
$BIN/hypersnap_pivot assemble --network devnet --out genesis_validators.pb entry*.pb
log "genesis validator file assembled"

# 4. Read nodes r1..r4, one per Hypersnap validator.
VSETS=$(grep '^validator_sets' nodes/1/hypersnap.toml)
VPEERS=$(for i in 1 2 3 4; do printf '/ip4/127.0.0.1/udp/%d/quic-v1,' $((50050 + i)); done)
HPEERS=$(for i in 1 2 3 4; do printf '/ip4/127.0.0.1/udp/%d/quic-v1,' $((50160 + i)); done)
read_config() { # $1 = index, $2 = pivot height
  cat > r$1/config.toml <<EOF
rpc_address = "127.0.0.1:$((3690 + $1))"
http_address = "127.0.0.1:$((3790 + $1))"
rocksdb_dir = "$D/r$1/.rocks"
fc_network = "Devnet"
read_node = true

[statsd]
prefix = "drill-r$1"
addr = "127.0.0.1:8125"

[gossip]
address = "/ip4/127.0.0.1/udp/$((50160 + $1))/quic-v1"
bootstrap_peers = "${VPEERS%,}"

[consensus]
private_key = "$(cat r$1/p2p.key)"
shard_ids = [1, 2]
num_shards = 2
$VSETS
pivot_height_override = $2
content_replay = true

[snapshot]
load_db_from_snapshot = false

[hypersnap]
genesis_validators_file = "$D/genesis_validators.pb"
consensus_key_file = "$D/keys$1/consensus.falcon"
node_key_file = "$D/keys$1/node.falcon"
epoch_length = 30
scoring_delay = 5
bootstrap_peers = "${HPEERS%,}"
submit_address = "127.0.0.1:$((3590 + $1))"
EOF
}
start_read() { # $1 = index
  RUST_LOG=info nohup $BIN/hypersnap --config-path r$1/config.toml >>r$1/node.log 2>&1 &
  echo $! > r$1/pid
}

P=$(( $(shard0_height 3483) + 60 ))
log "phase A: read nodes stop at the fork block of P=$P"
for i in 1 2 3 4; do
  mkdir -p r$i
  python3 -I -c 'import os; print(os.urandom(32).hex())' > r$i/p2p.key
  read_config $i $P; start_read $i
done
for i in 1 2 3 4; do
  wait_exit "$(cat r$i/pid)" 600 || { log "r$i did not stop"; exit 1; }
  grep -q "restart as a Hypersnap node" r$i/node.log || { log "r$i stopped without the marker"; exit 1; }
done
log "phase A done: four markers"

log "phase B: only r1 and r2 restart at P (2 of 4: no certificate)"
for i in 1 2; do start_read $i; done
sleep 30
for i in 1 2; do grep -q "Built the genesis state" r$i/node.log || { log "r$i built no genesis"; exit 1; }; done
if grep -q "pivot block is certified" r1/node.log; then log "unexpected certificate"; exit 1; fi
for i in 1 2; do kill "$(cat r$i/pid)"; wait_exit "$(cat r$i/pid)" 30 || true; done
log "phase B done: genesis built, no certificate"

P2=$((P + 40))
log "phase C: release with P2=$P2 (rollback)"
for i in 1 2 3 4; do read_config $i $P2; start_read $i; done
for i in 1 2 3 4; do
  wait_exit "$(cat r$i/pid)" 600 || { log "r$i did not stop at P2"; exit 1; }
done
for i in 1 2 3 4; do grep -q "Rollback: the pivot marker is removed" r$i/node.log || { log "r$i: no rollback"; exit 1; }; done
for i in 1 2; do ls -d r$i/.rocks/hypersnap.abandoned-$P >/dev/null || { log "r$i: no abandoned dir"; exit 1; }; done
log "phase C done: rollback, new markers"

log "phase D: all four restart at P2"
for i in 1 2 3 4; do start_read $i; done
for _ in $(seq 1 120); do
  n=$( (grep -l "pivot block is certified" r*/node.log 2>/dev/null || true) | wc -l | tr -d ' ')
  [ "$n" = 4 ] && break; sleep 2
done
[ "$n" = 4 ] || { log "only $n nodes saw the certified pivot block"; exit 1; }
sleep 20
for i in 1 2 3 4; do
  rec=$(grpc -proto rpc.proto 127.0.0.1:$((3690 + i)) HubService/GetPivotRecord | python3 -I -c 'import json,sys,hashlib; print(hashlib.sha256(json.dumps(json.load(sys.stdin),sort_keys=True).encode()).hexdigest()[:16])')
  tips=$(grpc -proto rpc.proto 127.0.0.1:$((3690 + i)) HubService/GetInfo | python3 -I -c 'import json,sys; d=json.load(sys.stdin); print(sorted((s.get("shardId",0), s.get("maxHeight",0)) for s in d["shardInfos"]))')
  log "r$i record=$rec tips=$tips"
done
log "drill done"
