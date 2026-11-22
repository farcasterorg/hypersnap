# Ogre

Ogre rolls a build onto a seeded devnet the way a release reaches mainnet, and
checks the network keeps working. It runs on every pull request and every push
to `main` (`.github/workflows/ogre.yml`), next to Verify.

## What it runs

Ten nodes on one machine: seven validators and three read nodes, with haatz's
API configuration (`docker-compose.mainnet.yml`) on the read nodes.

The chain holds real mainnet accounts. `ogre seed` exports the newest follows of
a few accounts from a mainnet node's HTTP API (onchain events, fname proofs,
profiles, verifications, follows, casts, likes and recasts) and rebuilds each
message's protobuf from the JSON, keeping only messages that hash to their
original hash, so the devnet stores them with their original signatures. A
devnet accepts messages signed for mainnet. Messages signed by gasless keys are
left out, since the API doesn't return KEY_ADD messages; ENS names, contract
verifications and anything else that needs an L1 or L2 client is refused by the
devnet and reported. `ogre chain` fails when the base release refuses more than
10% of the seed's onchain events, fname proofs or messages (a mainnet seed loses
about 1% of its messages and nothing else); the counts go to the job summary.
Each run starts from the same chain; nothing is uploaded as a snapshot.

`ogre chain` builds that chain on the release mainnet runs
(`farcasterorg/hypersnap:latest`) and stops it. CI caches the seed (refreshed
daily) and the chain (per base release, seed and Ogre source), so a run starts
from a stopped network, the way an operator's node is upgraded. A new seed and
chain are cached only after they passed a rollout, and a change to the exporter
(`seed.rs`, `convert.rs`) exports a new seed.

`ogre run` then:

1. Starts validators 1-4 and one read node on the base release and the rest on
   the build under test, and measures how long the network takes to make blocks
   again.
2. Calls every read endpoint on the read node under test and on the base read
   node, and fails when the build returns an error or an empty result, drops a
   field, empties an array or changes a value's JSON type where the base release
   has data. On values, it fails when an array has fewer items than the base
   release's, or a count (a field named `*count` or `*units`) drops by more
   than 2% (any drop below 50); array items are matched by their hash or fid, since nodes
   can order ties differently. Other different values are warnings, and fields
   that differ between nodes on the same release (heights, peers, indexer work
   counters) are ignored. Endpoints where the base release has no data are
   listed as not compared, and the run fails when fewer than `--min-compared`
   endpoints had base data (a reference node that errs can't turn every check
   into a skip). A failing endpoint is retried for 6 seconds.
3. Signs up a native account with a gasless signer, as new users do, and sends
   casts, a reply, a mention, a like, a recast and follows from it and from a
   real seeded account, through the read node's HTTP API. It checks every node
   at the tip stores each of those messages, and both read nodes show them:
   following feed, following list, notifications, conversation, author feed,
   profile counts, like count, recast count, recasters and search.
4. Restarts validators 1-4 on the build one at a time (a rolling upgrade),
   compares every endpoint again, then sends the writes again through the base
   read node, this time following an account the native account didn't follow.
5. Kills a validator and restarts it. A read node that started with an empty
   database replays the chain from block 1 on the build the whole time; it has
   to keep making progress (a debug build replays too slowly to reach the tip
   in a run).

It fails on any of those, on a shard going longer than `--max-stall` without a
block, on a node exiting on its own (found when it is next stopped, including
before a planned restart), on a node of the build under test that doesn't stop
within 30 seconds of SIGTERM (a base release node that hangs is a warning), and
on a panic while nodes run (panics during a
graceful stop are reported as warnings). The report goes to the job summary,
and node logs are uploaded when it fails.

## Intended API changes

Ogre compares against the release mainnet runs, so a pull request that changes
an answer on purpose (drops a field, changes a type or a count) fails it until
that change ships in a release. List such a change in
`src/bin/ogre/accepted.txt` in the same pull request: the route, the JSON path without array indexes (an
entry covers everything under it), and why. Ogre then reports it as accepted
instead of failing. Remove the entry once `farcasterorg/hypersnap:latest`
includes the change, so the path is checked again. The chain cache key leaves
the file out, so an entry doesn't rebuild the cached chain.

## Endpoints left out

Ogre calls every read route of both HTTP routers (`src/network/http_server.rs`
and `src/api/http.rs`), including the POST batch reads, except these:

- `/v1/channel*`, `/v1/isFollowingChannel`: Hypersnap's own channel messages,
  which a seed exported from the HTTP API doesn't hold.
- `/v1/currentPeers`, `/v1/mesh`, `/v1/mesh/ui`: each node's own peers; `mesh`
  needs the admin login.
- `/v2/farcaster/user/power_users`, `/v2/farcaster/user/balance`,
  `/v2/farcaster/user/subscribed_to`, `/v2/farcaster/user/subscribers`,
  `/v2/farcaster/user/subscriptions_created`, `/v2/farcaster/ban/list`,
  `/v2/farcaster/channel/member/invite/list`, `/v2/farcaster/topic/trending`,
  `/v2/farcaster/cast/conversation/summary`: fixed empty answers, no data
  behind them.
- `/v2/farcaster/cast/embed/crawl`: fetches the open web.
- `/v2/farcaster/stats/daily`: its indexer is off in
  `docker-compose.mainnet.yml`, the configuration the read nodes use.
- Writes and managed-service stubs (`/v1/submitMessage` is what the write checks
  use): `/v1/submitBulkMessages`, `/v1/validateMessage`, `/v2/farcaster/action`,
  `/v2/farcaster/app_host/*`, `/v2/farcaster/auth_address/*`,
  `/v2/farcaster/ban`, `/v2/farcaster/block`, `/v2/farcaster/channel/follow`,
  `/v2/farcaster/channel/member`, `/v2/farcaster/channel/member/invite`,
  `/v2/farcaster/follow`, `/v2/farcaster/frame/*`, `/v2/farcaster/fungible*`,
  `/v2/farcaster/login/*`, `/v2/farcaster/message`, `/v2/farcaster/mute`,
  `/v2/farcaster/nft/*`, `/v2/farcaster/notifications/mark_seen`,
  `/v2/farcaster/notifications/seen`, `/v2/farcaster/signer/*`,
  `/v2/farcaster/storage/buy`, `/v2/farcaster/user/follow`,
  `/v2/farcaster/user/register`, `/v2/farcaster/user/verification`.

## Running it locally

```sh
cargo build --profile test --bin hypersnap --bin ogre
B=target/debug/hypersnap
target/debug/ogre seed --out /tmp/ogre/seed.bin
target/debug/ogre chain --seed /tmp/ogre/seed.bin --base $B --work /tmp/ogre/chain
cp -R /tmp/ogre/chain /tmp/ogre/run
target/debug/ogre run --seed /tmp/ogre/seed.bin --base $B --under-test $B --work /tmp/ogre/run
```

`--base docker:<image>` runs a release image instead of a binary. Nodes use
ports 4010-4102. A debug build verifies signatures slowly, so for a large seed
build the chain on a release binary or image, or export a smaller seed
(`--fids 2,3 --max-fids 2`).
