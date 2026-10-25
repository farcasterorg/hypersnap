# Trending cast filters

`GET /v2/farcaster/feed/trending` accepts optional signer app filters:

| Parameter | Meaning |
| --- | --- |
| `include_signer_fids` | Return casts signed by keys registered by any of these app FIDs. |
| `exclude_signer_fids` | Skip casts signed by keys registered by any of these app FIDs. |

Each parameter accepts up to 100 distinct positive FIDs, separated by commas.
Both can be supplied together; exclusions take precedence. Missing or empty
lists impose no restriction. Invalid values return HTTP 400.

For example, exclude Warpcast/Farcaster signers (app FID `9152`):

```sh
curl 'http://localhost:3381/v2/farcaster/feed/trending?exclude_signer_fids=9152&limit=25'
```

Include multiple apps, with an exclusion:

```sh
curl 'http://localhost:3381/v2/farcaster/feed/trending?include_signer_fids=9152,309857&exclude_signer_fids=9152&time_window=6h'
```

These FIDs identify the apps that registered the signing keys, rather than the
cast authors or the keys' public bytes. On-chain keys use `requestFid` from their
SignedKeyRequest metadata; gasless keys use their stored `request_fid`. Casts
whose app is unknown are omitted when an inclusion list is supplied and retained
when only exclusions are supplied.

Filtering scans the existing ranking of up to 1,000 casts per time window,
preserving engagement order and selecting matches before fetching cast bodies.
Use the returned `next.cursor` with the same filters and `time_window` for the
next page. Casts deleted after the ranking was built can produce a short or empty
page. Filters do not expand the ranking beyond its existing cap.

The first filtered request loads signer app metadata once per ranking snapshot;
concurrent requests share that work. Subsequent filtered requests use the cached
metadata and fetch only their selected page of casts. Metadata is refreshed with
each new ranking snapshot. Unfiltered requests never load or wait for signer app
metadata, and ranking refreshes retain signing keys from their existing cast
reads without additional database lookups.

The same parameters work on trending feed aliases: `/v2/farcaster/feed?feed_type=trending`,
`/v2/farcaster/feed/for_you`, and `/v2/farcaster/feed/topic`.
