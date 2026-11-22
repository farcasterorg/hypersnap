# Per-FID message admission limits

The scheduled fixed quota is 1,008 messages per hour per FID, with a burst
capacity of 1,008. Tokens replenish continuously at 0.28 messages/second.
Casts, reactions, links, verifications, username proofs, user data (including
LIVE_AT), storage lends, and channel messages share this bucket across signers.
Storage ownership and `mempool.enable_rate_limits` do not affect this quota.

KEY_ADD retains its separate one-per-minute limit. KEY_REMOVE and native
onboarding are exempt from the shared bucket.

The rollout heights live in `validators.toml` under
`[mempool.fixed_rate_limit_activation_heights]`. A node switches when its next
candidate height for the receiving shard reaches that shard's configured
height. A nonempty schedule must cover shard 0 and every message shard with
positive heights. An empty schedule preserves the previous admission behavior.
Operators must distribute the updated binary and this file together; Docker
Compose appends `validators.toml` to the generated node configuration.

These are local validator mempool admission limits for both RPC submissions and
gossiped messages. Read nodes forward submissions to validators. Tokens are
charged once at admission, never when pulling messages to build a proposal.
The limiter does not alter consensus block validation or historical replay.

Counters are in memory per node, reset on restart, and are not a global network
counter. Idle buckets expire after two hours; the cache holds up to one million
FIDs and may evict entries under pressure. The rate is an admission guardrail,
not a cryptographically enforced network-wide throughput ceiling.
