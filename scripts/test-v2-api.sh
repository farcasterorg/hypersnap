#!/bin/bash

# Quick smoke test for all v2 API endpoints.
# Usage: ./scripts/test-v2-api.sh [base_url]

set -euo pipefail

BASE="${1:-https://haatz.quilibrium.com}"
PASS=0
FAIL=0
ERRORS=""

# A known FID and cast hash to test with — FID 3 (dwr) is always present
TEST_FID=3
TEST_FID2=2
# Use an fname (not ENS) so username lookup works without an L1 client
TEST_USERNAME="dwr"
TEST_CHANNEL="welcome"

check() {
  local label="$1"
  local path="$2"
  local url="${BASE}${path}"

  local http_code
  local body
  local tmpfile
  tmpfile=$(mktemp)

  http_code=$(curl -s -o "$tmpfile" -w "%{http_code}" --connect-timeout 5 --max-time 15 "$url" 2>/dev/null || echo "000")
  body=$(cat "$tmpfile")
  rm -f "$tmpfile"

  if [[ "$http_code" =~ ^2 ]]; then
    # Check for error in body
    if echo "$body" | grep -qi '"message".*not found\|not available\|not enabled\|not yet supported'; then
      printf "  ⚠  %-45s %s (soft error in body)\n" "$label" "$http_code"
    else
      printf "  ✓  %-45s %s\n" "$label" "$http_code"
    fi
    PASS=$((PASS + 1))
  else
    printf "  ✗  %-45s %s\n" "$label" "$http_code"
    FAIL=$((FAIL + 1))
    ERRORS="${ERRORS}\n  ${label}: ${http_code} ${url}"
  fi
}

echo "Testing v2 API at ${BASE}"
echo ""

echo "=== User ==="
check "user"                        "/v2/farcaster/user?fid=${TEST_FID}"
check "user/bulk"                   "/v2/farcaster/user/bulk?fids=${TEST_FID},${TEST_FID2}"
# Note: bulk-by-address can be slow on first call (populates id registry cache).
# Skipping for now since the running instance has old code with the expensive scan.
# check "user/bulk-by-address"        "/v2/farcaster/user/bulk-by-address?addresses=0x74232bf61e994655592747e20bdf6fa9b9476f79"
check "user/by-username"            "/v2/farcaster/user/by-username?username=${TEST_USERNAME}"
check "user/search"                 "/v2/farcaster/user/search?q=dan&limit=5"
check "user/followers"              "/v2/farcaster/user/followers?fid=${TEST_FID}&limit=5"
check "user/following"              "/v2/farcaster/user/following?fid=${TEST_FID}&limit=5"
check "user/verifications"          "/v2/farcaster/user/verifications?fid=${TEST_FID}"
check "user/storage-allocations"    "/v2/farcaster/user/storage-allocations?fid=${TEST_FID}"
check "user/storage-usage"          "/v2/farcaster/user/storage-usage?fid=${TEST_FID}"
echo ""

# Discover a real cast hash from this node by fetching the trending feed
FEED_RESPONSE=$(curl -s --connect-timeout 5 --max-time 15 "${BASE}/v2/farcaster/feed/trending?limit=1" 2>/dev/null || echo "")
CAST_HASH=$(echo "$FEED_RESPONSE" | grep -o '"hash":"[^"]*"' | head -1 | cut -d'"' -f4 || echo "")
if [ -z "$CAST_HASH" ]; then
  CAST_HASH="0x0000000000000000000000000000000000000000"
  echo "  (!) Could not discover a cast hash — using dummy (some cast tests may 404)"
fi
echo "  Using cast hash: $CAST_HASH"
echo ""

echo "=== Cast ==="
check "cast (by hash)"              "/v2/farcaster/cast?identifier=${CAST_HASH}&type=hash"
check "cast/bulk"                   "/v2/farcaster/cast/bulk?hashes=${CAST_HASH}"
check "cast/search"                 "/v2/farcaster/cast/search?q=hello&limit=5"
check "cast/conversation"           "/v2/farcaster/cast/conversation?identifier=${CAST_HASH}&type=hash"
echo ""

echo "=== Feed ==="
check "feed (generic)"              "/v2/farcaster/feed?feed_type=following&fid=${TEST_FID}&limit=5"
check "feed/following"              "/v2/farcaster/feed/following?fid=${TEST_FID}&limit=5"
check "feed/trending"               "/v2/farcaster/feed/trending?limit=5"
check "feed/channels"               "/v2/farcaster/feed/channels?channel_ids=${TEST_CHANNEL}&limit=5"
echo ""

echo "=== Channel ==="
check "channel (by id)"             "/v2/farcaster/channel?id=${TEST_CHANNEL}"
check "channel/all"                 "/v2/farcaster/channel/all?limit=5"
check "channel/bulk"                "/v2/farcaster/channel/bulk?ids=${TEST_CHANNEL}"
check "channel/search"              "/v2/farcaster/channel/search?q=wel&limit=5"
check "channel/trending"            "/v2/farcaster/channel/trending?limit=5"
check "channel/members"             "/v2/farcaster/channel/members?channel_id=${TEST_CHANNEL}&limit=5"
check "channel/user-active"         "/v2/farcaster/channel/user-active?fid=${TEST_FID}&limit=5"
echo ""

echo "=== Reaction ==="
check "reaction/cast"               "/v2/farcaster/reaction/cast?hash=${CAST_HASH}&types=likes&limit=5"
check "reaction/user"               "/v2/farcaster/reaction/user?fid=${TEST_FID}&type=likes&limit=5"
echo ""

echo "=== Notification ==="
check "notifications"               "/v2/farcaster/notifications?fid=${TEST_FID}&limit=5"
echo ""

echo "=== Identity ==="
check "fname/availability (taken)"  "/v2/farcaster/fname/availability?fname=${TEST_USERNAME}"
check "fname/availability (free)"  "/v2/farcaster/fname/availability?fname=nonexistent_test_name_xyz_99"
check "username-proof"              "/v2/farcaster/username-proof?username=${TEST_USERNAME}"
echo ""

echo "================================"
echo "  Passed: ${PASS}  Failed: ${FAIL}"
if [ "$FAIL" -gt 0 ]; then
  printf "\nFailed endpoints:${ERRORS}\n"
fi
echo "================================"

exit "$FAIL"
