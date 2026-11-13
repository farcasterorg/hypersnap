# Peer discovery and stalled-vote recovery

Validators also serve as discovery bootstraps. The default Hypersnap seeds are
cassie/haatz, kmacb, derekhoiem, arfonzo, mvr and wake. Infinitehomie and ivy remain
validators but are not bootstrap seeds. Bootstrap service confers no voting power.

Implementation plan:

1. Keep the existing Snapchain bootstrap configuration for the transition. Add
   a separate Hypersnap seed list, DNS transport, Identify and a Kademlia protocol
   scoped to Hypersnap and the Farcaster network. Feed verified Identify addresses
   into Kademlia and use bounded discovery queries to grow an ordinary gossip mesh.
2. Accept authenticated contact advertisements on validators and readers. Bind
   the advertised identity to the signed gossip author, check network/version/time,
   expire and cap address records, persist verified addresses, and limit concurrent
   dials with exponential backoff. No pairwise direct-peer configuration is required.
3. Discover disconnected sync validators on demand, admitting their statuses to
   the sync pool only after connection. Supplement vote-set requests with bounded
   requests to other connected eligible peers and periodic rebroadcast of the
   existing signed prevote/precommit. Preserve signature, height and quorum checks.
4. Test sparse bootstrap discovery, identity rejection, bounded retry/persistence,
   vote recovery and progress with eight validators and two offline proposers.

The rollout requires upgrading the participating nodes. Existing Snapchain
bootstraps need no changes. Consensus topic cutovers still follow each shard's
configured fork height. With eight equal validators, six must remain online;
discovery and vote recovery cannot create quorum when fewer than six participate.

## Operation

The shipped `validators.toml` enables `[gossip.discovery]`. Keep existing
`gossip.bootstrap_peers` during the fork transition; it can continue reaching
legacy Snapchain nodes. The new `gossip.discovery.bootstrap_peers` list pins the
six Hypersnap seed identities. A validator skips its own seed entry. Each seed
needs its normal public QUIC/UDP port 3382 reachable and an accurate
`gossip.announce_address`; no additional process, port or direct-peer list is
needed. All upgraded nodes serve the Hypersnap DHT, so bootstrap service is not a
privileged role. Kademlia and Identify advertisements are scoped by network;
consensus gossip still obeys the existing per-shard topic cutovers.

Discovery maintains up to 512 candidates with four addresses per peer, normally
seeking 12 connected discovered peers, capped at 32 connections initiated by the
discovery scheduler (including on-demand sync connections). It allows four
discovery dials at a time, with retry backoff from 2 seconds to 5 minutes plus jitter. Addresses expire after
24 hours. Contact advertisements must match their signed author, network and
protocol version and be no more than 30 minutes old (5 minutes clock skew).
Unspecified, multicast, loopback and private IP addresses are not discovered on
mainnet; devnet permits loopback/private addresses for testing.

Authenticated Identify and signed contact addresses are saved atomically once a
minute in `<rocksdb_dir>/discovered-peers-<network>.json`. Set `cache_path` explicitly to
change that location. The cache survives ordinary container restarts when the
RocksDB directory is mounted persistently. A cached address still has to
re-authenticate over libp2p after restart.

Missing-vote recovery keeps Malachite's normal vote-set requests and adds up to
three supplementary requests to other connected eligible sync peers. Replies
must match the requested peer, height and round; votes then pass the normal
consensus signature and membership checks. Validators also rebroadcast their
original signed prevotes and precommits every 2–2.5 seconds until committed,
retaining at most eight votes per shard across recent rounds. Recovery never signs another value or
changes quorum. An offline proposer times out through the existing nil-vote and
round-rotation rules.

Useful statsd metrics are `gossip.discovery.known_peers`,
`gossip.discovery.pending_dials`, `gossip.vote_rebroadcast`, and
`sync.vote_recovery_request` (per shard). The existing connected-peer, consensus
mesh and block-delay metrics remain useful for verifying recovery after rollout.

## Validation

`cargo test --lib discovery` covers cache limits/restart, identity/address/time
checks and the six-seed/eight-validator configuration. `cargo test --lib
vote_recovery` covers both vote phases, unchanged signatures/quorum and fanout
with an unanswered primary plus mismatched reply envelopes. `cargo test --lib
network_connector` checks discovery of a disconnected sync peer without admitting
it prematurely. `cargo test --test consensus_test test_discovery_sparse` starts
six of eight validators with one seed each and no explicit peers, drops a real
prevote and requires continued block production. These networking tests need
local TCP/UDP socket access.

Verified locally: 37 discovery, gossip, routing, participation and vote-recovery
regression tests passed; the sparse six-of-eight consensus test passed with a
dropped prevote and six distinct valid signatures on each stored block.
`cargo check --bins --offline` passed.
