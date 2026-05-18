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
| page_size       | [uint32](#uint32) | optional | Number of results per page (default: 100, min: 1, max: 1000)        |
| page_token      | [bytes](#bytes)   | optional | Token for pagination                                                |
| reverse         | [bool](#bool)     | optional | Sort order; defaults to `true` (newest casts first)                 |
| start_timestamp | [uint64](#uint64) | optional | Inclusive lower bound on cast timestamp (Farcaster time)            |
| stop_timestamp  | [uint64](#uint64) | optional | Inclusive upper bound on cast timestamp (Farcaster time)            |

Returns cast adds authored by FIDs that `fid` follows (link type `follow`). Casts are merged across shards, sorted by timestamp, and paginated. Up to **`page_size` casts per followed FID** are read per shard (hard cap **1000**), then the merged timeline is capped to **`page_size`** results. Requests with `page_size` above 1000 return `INVALID_ARGUMENT`. The requesting user's own casts are not included.

Enabled by default when `[api.feeds]` is configured. Set `[api.feeds] casts_by_following_enabled = false` to disable (also gates the v2 HTTP route `GET /v2/farcaster/casts/following`).

## FidTimestampRequest

| Field            | Type              | Label    | Description                                    |
| ---------------- | ----------------- | -------- | ---------------------------------------------- |
| fid              | [uint64](#uint64) |          | Farcaster ID                                   |
| page_size        | [uint32](#uint32) | optional | Number of results to return per page           |
| page_token       | [bytes](#bytes)   | optional | Token for pagination                           |
| reverse          | [bool](#bool)     | optional | Whether to return results in reverse order     |
| start_timestamp  | [uint64](#uint64) | optional | Optional timestamp to start filtering from     |
| stop_timestamp   | [uint64](#uint64) | optional | Optional timestamp to stop filtering at        |
