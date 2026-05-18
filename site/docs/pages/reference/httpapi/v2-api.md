# Farcaster v2 HTTP API

Hypersnap serves a [Farcaster v2–compatible HTTP API](https://docs.farcaster.xyz/reference) on the same port as the hub API (default `3381`). These routes live under `/v2/farcaster/...` and return JSON shaped for v2 clients.

## Enabling the v2 API

The v2 API is part of the optional indexing layer. Enable it in your node config:

```toml
[api]
enabled = true
```

Individual features (social graph, feeds, search, etc.) have their own toggles under `[api.*]`. See `config/sample.toml` in the repository for defaults.

## casts/following

Returns a paginated timeline of cast adds from users that the given FID follows. Results are merged across shards, filtered by optional timestamp bounds, and sorted by cast timestamp (newest first by default). The requesting user's own casts are not included.

When building each page, the hub fetches at most **`limit` casts per followed FID** on each shard (hard maximum **1000**), merges and sorts the results, then returns at most **`limit` casts** for the page. Requests with `limit` greater than 1000 are rejected with HTTP `400`.

This endpoint is computationally expensive because it loads casts for every followed FID. It is **enabled by default** when `[api.feeds]` is configured.

### Configuration

```toml
[api]
enabled = true

[api.feeds]
enabled = true
# casts_by_following_enabled = true  # default; set false to disable
```

| Setting | Default | Description |
| ------- | ------- | ----------- |
| `[api] enabled` | `false` | Master switch for the v2 API and indexing |
| `[api.feeds] casts_by_following_enabled` | `true` | Enables `GET /v2/farcaster/casts/following` and gRPC `GetCastsByFollowing` |

Set `casts_by_following_enabled = false` to turn it off. When disabled, the HTTP route returns `503` and gRPC returns `FAILED_PRECONDITION`.

### HTTP

**`GET /v2/farcaster/casts/following`**

| Parameter | Required | Default | Description |
| --------- | -------- | ------- | ----------- |
| `fid` | Yes | — | FID whose `follow` links define the timeline |
| `limit` | No | `100` | Max casts per page (minimum `1`, maximum `1000`; values above `1000` return `400`) |
| `cursor` | No | — | Pagination cursor from `next.cursor` (hex-encoded page token) |
| `reverse` | No | `true` | `true` = newest first; `false` = oldest first |
| `start_timestamp` | No | — | Inclusive lower bound (Farcaster time, same as message timestamps) |
| `stop_timestamp` | No | — | Inclusive upper bound (Farcaster time) |

**Example**

```bash
curl "http://127.0.0.1:3381/v2/farcaster/casts/following?fid=6833&limit=50&start_timestamp=48994400&stop_timestamp=48994500"
```

**Response**

```json
{
  "casts": [
    {
      "object": "cast",
      "hash": "0xd2b1ddc6c88e865a33cb1a565e0058d757042974",
      "author": { "object": "user", "fid": 42 },
      "text": "Cast from someone you follow",
      "timestamp": "2024-01-15T12:00:00.000Z"
    }
  ],
  "next": {
    "cursor": "7b22706f6666736574223a35307d"
  }
}
```

Pass `next.cursor` as the `cursor` query parameter on the next request. An empty or omitted cursor means no further pages.

### gRPC

**`GetCastsByFollowing(CastsByFollowingRequest) → MessagesResponse`**

Same semantics as the HTTP endpoint. Request fields: `fid`, `page_size` (default 100), `page_token`, `reverse` (default `true`), `start_timestamp`, `stop_timestamp`. Gated by `[api.feeds] casts_by_following_enabled`.

See [Casts gRPC API](/reference/grpcapi/casts) for message field details.

### Notes

- Only active `follow` links are considered (link type `"follow"`).
- This is distinct from `GET /v2/farcaster/feed/following`, which uses the on-demand feed service and social graph indexer when `[api.feeds] enabled = true`.
- The former hub route `GET /v1/castsByFollowing` is not available; use this v2 route instead.
