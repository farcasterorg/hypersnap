# Casts API

Used to retrieve valid casts or tombstones for deleted casts

## API

| Method Name             | Request Type         | Response Type    | Description                                                    |
| ----------------------- | -------------------- | ---------------- | -------------------------------------------------------------- |
| GetCast                 | CastId               | Message          | Returns a specific Cast                                        |
| GetCastsByFid           | FidRequest           | MessagesResponse | Returns CastAdds for an Fid in reverse chron order             |
| GetCastsByParent        | CastsByParentRequest | MessagesResponse | Returns CastAdd replies to a given Cast in reverse chron order |
| GetCastsByMention       | FidRequest              | MessagesResponse | Returns CastAdds that mention an Fid in reverse chron order    |
| GetCastsByFollowing     | CastsByFollowingRequest | MessagesResponse | Returns CastAdds from users an Fid follows, with optional time filter |
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
| page_size       | [uint32](#uint32) | optional | Number of results to return per page (default: 100)                 |
| page_token      | [bytes](#bytes)   | optional | Token for pagination                                                |
| reverse         | [bool](#bool)     | optional | Sort order; defaults to `true` (newest casts first)                 |
| start_timestamp | [uint64](#uint64) | optional | Inclusive lower bound on cast timestamp (Farcaster time)            |
| stop_timestamp  | [uint64](#uint64) | optional | Inclusive upper bound on cast timestamp (Farcaster time)            |

Returns cast adds authored by FIDs that `fid` follows (link type `follow`). Casts are merged across shards, sorted by timestamp, and paginated. The requesting user's own casts are not included.

## FidTimestampRequest

| Field            | Type              | Label    | Description                                    |
| ---------------- | ----------------- | -------- | ---------------------------------------------- |
| fid              | [uint64](#uint64) |          | Farcaster ID                                   |
| page_size        | [uint32](#uint32) | optional | Number of results to return per page           |
| page_token       | [bytes](#bytes)   | optional | Token for pagination                           |
| reverse          | [bool](#bool)     | optional | Whether to return results in reverse order     |
| start_timestamp  | [uint64](#uint64) | optional | Optional timestamp to start filtering from     |
| stop_timestamp   | [uint64](#uint64) | optional | Optional timestamp to stop filtering at        |
