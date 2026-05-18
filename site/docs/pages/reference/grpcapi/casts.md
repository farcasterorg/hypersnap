# Casts API

Used to retrieve valid casts or tombstones for deleted casts

## API

| Method Name             | Request Type         | Response Type    | Description                                                    |
| ----------------------- | -------------------- | ---------------- | -------------------------------------------------------------- |
| GetCast                 | CastId               | Message          | Returns a specific Cast                                        |
| GetCastsByFid           | FidRequest           | MessagesResponse | Returns CastAdds for an Fid in reverse chron order             |
| GetCastsByParent        | CastsByParentRequest | MessagesResponse | Returns CastAdd replies to a given Cast in reverse chron order |
| GetCastsByMention       | FidRequest              | MessagesResponse | Returns CastAdds that mention an Fid in reverse chron order    |
| GetCastsByFollowing     | CastsByFollowingRequest | MessagesResponse | Returns CastAdds from users an Fid follows (enabled by default; see [v2 HTTP docs](/reference/httpapi/v2-api)) |
| GetAllCastMessagesByFid | FidTimestampRequest     | MessagesResponse | Returns Casts for an Fid with optional timestamp filtering     |

## CastsByParentRequest

| Field          | Type              | Label    | Description                                    |
| -------------- | ----------------- | -------- | ---------------------------------------------- |
| parent_cast_id | [CastId](#CastId) |          | Parent cast ID to find replies for (optional)  |
| parent_url     | [string](#string) |          | Parent URL to find replies for (optional)      |
| page_size      | [uint32](#uint32) | optional | Number of results to return per page           |
| page_token     | [bytes](#bytes)   | optional | Token for pagination                           |
| reverse        | [bool](#bool)     | optional | Whether to return results in reverse order     |

## CastsByFollowingRequest

| Field           | Type              | Label    | Description                                                         |
| --------------- | ----------------- | -------- | ------------------------------------------------------------------- |
| fid             | [uint64](#uint64) | optional | FID whose following list is used to build the timeline              |
| page_size       | [uint32](#uint32) | optional | Number of results per page (default: 100, min: 10, max: 1000)       |
| page_token      | [bytes](#bytes)   | optional | Opaque cursor (per-FID scan positions + timeline boundary); see below |
| reverse         | [bool](#bool)     | optional | Sort order; defaults to `true` (newest casts first)                 |
| start_timestamp | [uint64](#uint64) | optional | Inclusive lower bound on cast timestamp (Farcaster time)            |
| stop_timestamp  | [uint64](#uint64) | optional | Inclusive upper bound on cast timestamp (Farcaster time)            |

Returns cast adds authored by FIDs that `fid` follows (link type `follow`). Casts are merged with a k-way merge, sorted by `(timestamp, hash)`, and paginated via an opaque `page_token` that continues each followed FID's RocksDB scan and carries a `(timestamp, hash)` boundary (not an offset). Each request reads only enough per-FID batches to produce **`page_size`** results (`page_size` must be 10–1000). The requesting user's own casts are not included.

At most **`[api.feeds] following_limit`** followed FIDs (default **500**) are considered per request. Each followed FID lives on one shard, so cost scales with that cap, not with total shards. This is a convenience endpoint; clients that need full or low-latency following feeds should index their own data.

Enabled by default when `[api.feeds]` is configured. Set `[api.feeds] casts_by_following_enabled = false` to disable (also gates the v2 HTTP route `GET /v2/farcaster/casts/following`). Configure `following_limit` under `[api.feeds]`.

## FidTimestampRequest

| Field            | Type              | Label    | Description                                    |
| ---------------- | ----------------- | -------- | ---------------------------------------------- |
| fid              | [uint64](#uint64) |          | Farcaster ID                                   |
| page_size        | [uint32](#uint32) | optional | Number of results to return per page           |
| page_token       | [bytes](#bytes)   | optional | Token for pagination                           |
| reverse          | [bool](#bool)     | optional | Whether to return results in reverse order     |
| start_timestamp  | [uint64](#uint64) | optional | Optional timestamp to start filtering from     |
| stop_timestamp   | [uint64](#uint64) | optional | Optional timestamp to stop filtering at        |
