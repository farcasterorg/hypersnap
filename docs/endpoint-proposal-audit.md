# Hypersnap v2 Endpoint Proposal — Audit & Implementation Plan

## Context

herocast (open-source Farcaster client) is integrating with Hypersnap's v2
API to eliminate Neynar dependency. Three new endpoints were requested.
This document audits whether they're actually needed vs. already covered,
then provides implementation plans for what's genuinely missing.

---

## Audit: Do We Actually Need These?

### Requested 1: `GET /v2/farcaster/feed/user?fid=X&limit=25&cursor=...`

**Verdict: ALREADY EXISTS — no changes needed.**

The `hyper-api` branch already has `GET /v2/farcaster/feed/user/casts?fid=X&limit=N&cursor=...`
(registered at `http.rs:523,1024`, handler at `http.rs:3374`). It queries
`get_casts_by_fid`, hydrates via `message_to_cast`, enriches with metrics,
returns `FeedResponse { casts, next: { cursor } }`.

The Neynar canonical path is `/v2/farcaster/feed/user/casts/` — not `/feed/user`.
herocast should call the path that already exists.

Neynar's `include_replies` param defaults to `true` (confirmed via
[Neynar OpenAPI spec](https://github.com/neynarxyz/oas)). Hypersnap
returns all casts including replies, which matches Neynar's default.

**Action: None. herocast uses `/feed/user/casts` (existing path).**

---

### Requested 2: `GET /v2/farcaster/user/reactions?fid=X&type=likes&limit=25&cursor=...`

**Verdict: EXISTS at `/reactions/user` but response shape doesn't match the
Neynar spec — needs fix.**

The existing `GET /v2/farcaster/reactions/user?fid=X&type=likes` (registered
at `http.rs:546,1083`, handler at `http.rs:2538`) returns a `ReactionsResponse`
where `Reaction.cast` is a `ReactionCastRef { hash, fid }` — just a pointer.

Per the [Neynar OpenAPI spec](https://github.com/neynarxyz/oas), `cast` is
a **required** field of type `Cast` (full hydrated cast object, same schema
as in feed responses). The current `ReactionCastRef` shape is non-compliant.
Any client written against the Neynar SDK/types expects a full `Cast` here.

The requested path `/v2/farcaster/user/reactions` doesn't match the Neynar
convention (`/v2/farcaster/reactions/user`). Don't add a new path — fix the
existing one.

**Action: Fix `Reaction.cast` to return full `Cast` objects per Neynar spec.**

---

### Requested 3: `GET /v2/farcaster/feed/filter?fids=1,2,3&limit=25&cursor=...`

**Verdict: PATH IS WRONG — but the capability is genuinely missing.**

Neynar uses the generic `/feed` endpoint with query parameters:
```
GET /v2/farcaster/feed?feed_type=filter&filter_type=fids&fids=1,2,3&limit=25
```

Hypersnap already has `/v2/farcaster/feed` (registered at `http.rs:517,991`)
with `handle_feed` (line 2222), but it only handles `feed_type=following` and
falls through to trending for everything else.

**Action: Add `filter` case to existing `handle_feed` dispatch.**

---

## Summary

| Requested | Neynar Canonical Path | Existing Coverage | Action |
|-----------|----------------------|-------------------|--------|
| `/feed/user?fid=X` | `/feed/user/casts?fid=X` | **Fully covered** | None |
| `/user/reactions?fid=X&type=likes` | `/reactions/user?fid=X&type=likes` | **Exists** but `cast` field is non-compliant | Fix to match Neynar spec |
| `/feed/filter?fids=1,2,3` | `/feed?feed_type=filter&fids=...` | **Missing** from `handle_feed` | Add `filter` case |

**Net: 0 new endpoints, 1 spec compliance fix, 1 new case in existing dispatch.**

---

## Implementation Plan

### Change 1: Fix `Reaction.cast` — Return Full Cast per Neynar Spec

**File:** `src/api/types.rs` + `src/api/http.rs`

The Neynar `ReactionWithCastInfo` schema defines `cast` as a required `Cast`
object. Hypersnap currently returns `ReactionCastRef { hash, fid }` which
doesn't match the spec.

**Type change in `types.rs`:**

```rust
pub struct Reaction {
    pub object: String,
    pub reaction_type: String,
    pub reaction_timestamp: String,
    pub user: User,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cast: Option<Cast>,  // was Option<ReactionCastRef>
}
```

`ReactionCastRef` struct and its import can be removed.

**Handler change in `handle_reactions_by_user` (~line 2538):**

Replace `ReactionCastRef` construction with full cast hydration:

```rust
let hydrated_cast = match &data.body {
    Some(proto::message_data::Body::ReactionBody(body)) => {
        match &body.target {
            Some(proto::reaction_body::Target::TargetCastId(id)) => {
                if let Some(msg) = hub.get_cast_by_hash(&id.hash, Some(id.fid)).await {
                    let mut cast = self.message_to_cast(&msg).await;
                    if let Some(ref metrics) = self.metrics {
                        if let Ok(m) = metrics.get_cast_metrics(id.fid, &id.hash) {
                            cast.reactions = CastReactions {
                                likes_count: m.likes,
                                recasts_count: m.recasts,
                                likes: Vec::new(),
                                recasts: Vec::new(),
                            };
                            cast.replies = CastReplies { count: m.replies };
                        }
                    }
                    Some(cast)
                } else {
                    None // cast was deleted
                }
            }
            _ => None,
        }
    }
    _ => None,
};
```

**Handler change in `handle_reactions_by_cast` (~line 2454):**

All reactions in this handler target the **same cast**. Hydrate it once
before the loop, clone for each reaction:

```rust
// Hydrate target cast once, before the reaction loop
let target_cast: Option<Cast> = {
    if let Some(msg) = hub.get_cast_by_hash(&hash, Some(target_fid)).await {
        let mut cast = self.message_to_cast(&msg).await;
        if let Some(ref metrics) = self.metrics {
            if let Ok(m) = metrics.get_cast_metrics(target_fid, &hash) {
                cast.reactions = CastReactions {
                    likes_count: m.likes,
                    recasts_count: m.recasts,
                    likes: Vec::new(),
                    recasts: Vec::new(),
                };
                cast.replies = CastReplies { count: m.replies };
            }
        }
        Some(cast)
    } else {
        None
    }
};

// In the reaction loop:
reactions.push(Reaction {
    // ...
    cast: target_cast.clone(),
});
```

**Complexity:** ~40 lines changed across 2 handlers + 1 type change.

**Performance:** For `reactions/user` with limit=25, adds 25 `get_cast_by_hash`
calls. With `fid_hint` (from reaction body), each is O(1) RocksDB. ~25ms total.
For `reactions/cast`, net improvement (1 hydration instead of 0, but now the
response is spec-compliant).

**Deleted casts:** When a liked cast has been deleted, `get_cast_by_hash`
returns `None`, so `reaction.cast` will be `null` in the JSON. This is
expected — the reaction exists but the cast is gone.

**Pagination:** Still returns `cursor: None`. Pre-existing limitation —
`get_reactions_by_fid` doesn't wire through `page_token` even though the
underlying `ReactionStore` supports it. Separate concern.

---

### Change 2: Add `feed_type=filter` to `handle_feed`

**File:** `src/api/http.rs`

No route registration changes — `/v2/farcaster/feed` is already registered
and dispatches through `handle_feed`.

**Add `"filter"` arm to `handle_feed` (line ~2222):**

```rust
"filter" => {
    let fids_str = match params.get("fids") {
        Some(f) => f.as_str(),
        None => return Ok(Self::error_response(
            StatusCode::BAD_REQUEST,
            "fids parameter required for filter feed",
        )),
    };
    self.handle_filter_feed(fids_str, cursor, limit).await
}
```

**New handler `handle_filter_feed`:**

Uses the same lazy-hydration pattern as `feeds.rs:get_following_feed` —
collect raw `Message` objects into a `BinaryHeap`, pop only `limit` winners,
hydrate only those.

```rust
/// GET /v2/farcaster/feed?feed_type=filter&filter_type=fids&fids=1,2,3
async fn handle_filter_feed(
    &self,
    fids_str: &str,
    cursor: Option<&str>,
    limit: usize,
) -> Result<Response<BoxBody<Bytes, Infallible>>, Infallible> {
    let hub = self.hub_query.read().unwrap().clone();
    let Some(hub) = hub else {
        return Ok(Self::error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "Hub query service not available",
        ));
    };

    let fids: Vec<u64> = fids_str
        .split(',')
        .filter_map(|s| s.trim().parse().ok())
        .take(100)
        .collect();

    if fids.is_empty() {
        return Ok(Self::error_response(
            StatusCode::BAD_REQUEST,
            "fids parameter must contain valid FIDs",
        ));
    }

    let cursor_ts: Option<u32> = cursor.and_then(|c| c.parse().ok());

    // Phase 1: Collect raw messages into a max-heap (newest first).
    // This avoids hydrating casts we'll discard.
    use std::collections::BinaryHeap;
    use std::cmp::Ordering;

    struct TsCast { ts: u32, fid: u64, msg: crate::proto::Message }
    impl Eq for TsCast {}
    impl PartialEq for TsCast {
        fn eq(&self, other: &Self) -> bool { self.ts == other.ts }
    }
    impl Ord for TsCast {
        fn cmp(&self, other: &Self) -> Ordering { self.ts.cmp(&other.ts) }
    }
    impl PartialOrd for TsCast {
        fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
            Some(self.cmp(other))
        }
    }

    let mut heap = BinaryHeap::new();

    for &fid in &fids {
        match hub.get_casts_by_fid(fid, limit, None, true).await {
            Ok((messages, _)) => {
                for msg in messages {
                    let ts = msg.data.as_ref()
                        .map(|d| d.timestamp).unwrap_or(0);
                    if let Some(before) = cursor_ts {
                        if ts >= before { continue; }
                    }
                    heap.push(TsCast { ts, fid, msg });
                }
            }
            Err(_) => continue,
        }
    }

    // Phase 2: Pop only `limit` items, hydrate only those.
    let mut casts = Vec::with_capacity(limit);
    let mut last_ts = None;

    while let Some(tc) = heap.pop() {
        if casts.len() >= limit { break; }
        let mut cast = self.message_to_cast(&tc.msg).await;
        if let Some(ref metrics) = self.metrics {
            if let Ok(m) = metrics.get_cast_metrics(tc.fid, &tc.msg.hash) {
                cast.reactions = CastReactions {
                    likes_count: m.likes,
                    recasts_count: m.recasts,
                    likes: Vec::new(),
                    recasts: Vec::new(),
                };
                cast.replies = CastReplies { count: m.replies };
            }
        }
        last_ts = Some(tc.ts);
        casts.push(cast);
    }

    let next_cursor = if !heap.is_empty() {
        last_ts.map(|ts| ts.to_string())
    } else {
        None
    };

    let response = FeedResponse {
        casts,
        next: NextCursor { cursor: next_cursor },
    };
    Ok(Self::json_response(StatusCode::OK, &response))
}
```

**Complexity:** ~75 lines new handler + ~8 lines dispatch.

**Design notes:**
- **Lazy hydration:** Raw `Message` objects go into the heap. Only the `limit`
  winners get hydrated. For 100 FIDs x 25 casts = 2,500 raw messages but only
  25 hydrations. Matches the `feeds.rs:get_following_feed` pattern.
- **100 FID cap:** Matches Neynar's limit.
- **Timestamp cursor limitation:** On page 2+, we re-fetch `limit` most-recent
  casts per FID and filter `ts >= cursor`. If a FID's recent casts are all above
  the cursor, their older casts are missed. Same tradeoff as `feed/following`.
  Acceptable for herocast's use case (short FID lists for custom user lists).
  Deep pagination would require per-FID page_token tracking — a v2 concern.
- **Sequential fetch:** Fine for v1. Can parallelize with `tokio::spawn` +
  chunk_size=50 (same pattern as `feeds.rs`) if performance matters.

---

## Files Changed

| File | Change | LOC |
|------|--------|-----|
| `src/api/types.rs` | `Reaction.cast`: `Option<ReactionCastRef>` → `Option<Cast>`, remove `ReactionCastRef` | ~5 |
| `src/api/http.rs` | `handle_reactions_by_user`: hydrate full casts | ~30 |
| `src/api/http.rs` | `handle_reactions_by_cast`: hydrate once, clone for each | ~20 |
| `src/api/http.rs` | `handle_feed`: add `"filter"` arm | ~8 |
| `src/api/http.rs` | New `handle_filter_feed` method | ~75 |
| `scripts/test-v2-api.sh` | Add test cases | ~10 |

**Total: ~148 lines changed/added.**

---

## Testing Plan

1. Existing tests pass: `scripts/test-v2-api.sh`
2. `/reactions/user?fid=3&type=likes&limit=5` — each `reaction.cast` is a
   full Cast object (has `author`, `text`, `reactions`, etc.), not `{ hash, fid }`
3. `/reactions/user?fid=3&type=likes&limit=5` — `cast: null` for deleted casts
4. `/reactions/cast?hash=X&types=likes&limit=5` — each reaction has same
   full Cast object (hydrated once, cloned)
5. `/feed?feed_type=filter&filter_type=fids&fids=3,2&limit=5` — returns casts
   from both FIDs sorted by timestamp
6. `/feed?feed_type=filter&fids=` → 400
7. `/feed?feed_type=filter&fids=3` → works like single-user feed
