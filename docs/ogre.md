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
devnet and reported. Each run starts from the same chain; nothing is uploaded
as a snapshot.

`ogre chain` builds that chain on the release mainnet runs
(`farcasterorg/hypersnap:latest`) and stops it. CI caches the seed (refreshed
daily) and the chain (per base release and seed), so a run starts from a
stopped network, the way an operator's node is upgraded.

`ogre run` then:

1. Starts validators 1-4 and one read node on the base release and the rest on
   the build under test, and measures how long the network takes to make blocks
   again.
2. Calls every read endpoint on the read node under test and on the base read
   node, and fails when the build returns an error, an empty result or fewer
   fields than the base release does. Endpoints where the base release has no
   data are listed as not compared, and different values are warnings.
3. Signs up a native account with a gasless signer, as new users do, and sends
   casts, a reply, a mention, a like, a recast and follows from it and from a
   real seeded account, through the read node's HTTP API. It checks every node
   at the tip stores them and the API shows them: following feed, notifications,
   conversation, author feed, profile counts, like count and search.
4. Restarts validators 1-4 on the build one at a time (a rolling upgrade),
   then sends the writes again through the base read node.
5. Kills a validator and restarts it. A read node that started with an empty
   database replays the chain from block 1 on the build the whole time; it has
   to keep making progress (a debug build replays too slowly to reach the tip
   in a run).

It fails on any of those, on a shard going longer than `--max-stall` without a
block, on a node exiting, and on a panic while nodes run (panics during a
graceful stop are reported as warnings). The report goes to the job summary,
and node logs are uploaded when it fails.

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
