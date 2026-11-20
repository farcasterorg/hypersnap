# Hypersnap Malachite source

Source: https://github.com/informalsystems/malachite
Revision: 13bca14cd209d985c3adf101a02924acde8723a5

This is Hypersnap's own copy of the previously pinned Informal Systems source,
not the Farcaster/Neynar fork. The archive includes the upstream `code/` tree
and license, plus the upstream test specifications referenced by symlinks. Consensus algorithms and certificate verification are unchanged.

Local compatibility changes:
- `code/Cargo.toml`: libp2p 0.55 -> 0.56 and prometheus-client 0.22 -> 0.23.1.
- `code/crates/network/Cargo.toml`: explicitly enable GossipSub metrics.
- `code/crates/network/src/behaviour.rs`: adapt metrics construction to the new
  GossipSub builder API.
- The broadcast transport's libp2p compatibility patch lives separately in
  `../libp2p-scatter`, with a root Cargo patch overriding crates.io.

Historical upstream lockfiles are omitted; Hypersnap’s root `Cargo.lock` is authoritative.
All runtime builds, Docker builds, and CI use these checked-in sources.
