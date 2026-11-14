# Native account API admission repair

Reference time: **2026-11-14 19:58:08 UTC**. Target: **2026-11-15 19:58:08 UTC** (24 hours).

This release preserves the previous mainnet admission behavior until the destination data shard reaches its new cutoff. Admission uses the next height after the locally committed tip. It then carries the destination shard ID, native registration configuration, and shard-zero authority into the temporary validation engine for single and bulk submission.

The schedule is loaded from `[consensus.native_registration.api_activation_heights]` in `validators.toml`. Deploy the updated binary together with this file before these heights. An absent API schedule retains the previous admission behavior. The original validator, gossip, and native-registration fork schedules must be retained.

| Data shard | First height using repaired admission |
|---|---:|
| 1 | 51,311,487 |
| 2 | 51,146,724 |

```toml
[consensus.native_registration.api_activation_heights]
"1" = 51_311_487
"2" = 51_146_724
```

Activation is by height. The UTC time is a projection; changes in block rate can move activation earlier or later.

## Public validator observations

Six public RPCs responded during the sample: Haatz, kmac, Derek, arfonzo, mvr, and wake. All reported version `0.17.12`; their shard tips were within two blocks. Homie (`46.110.19.50:3383`) and ivy (`procat.ivyastrix.com:3383`) timed out; this only establishes public RPC reachability.

Timestamp and hash comparisons used Haatz (`85.237.203.140:3383`), kmac (`85.209.231.221:3383`), and wake (`51.79.77.116:3383`). All three returned identical hashes and timestamps at both ends of each sample.

| Shard | Earlier height | Sample height | Seconds for 3,600 blocks | Blocks/second | Projected target height |
|---|---:|---:|---:|---:|---:|
| 0 | 50,578,303 | 50,581,903 | 5,659 | 0.636154798 | 50,636,844 |
| 1 | 51,252,966 | 51,256,566 | 5,661 | 0.635930048 | 51,311,487 |
| 2 | 51,088,174 | 51,091,774 | 5,658 | 0.636267232 | 51,146,724 |

Shard 0 is included as a network reference; its API admission path is already configured correctly and this repair does not change its behavior.

Projection: `sample_height + ceil(3600 * (target_unix_time - sample_unix_time) / elapsed_seconds)`. The target Unix time is `1794772688`. Shard timestamps use the Farcaster epoch (`1609459200`).

## Verification

- Regression covers native FIDs assigned by the production hash router to each data shard, immediately before and at the new repair boundary.
- The original registration boundary must also be active; advancing the repair boundary alone cannot activate native accounts.
- Both single and bulk submission accept registered native accounts after activation and reject unregistered FIDs.
- Existing RPC server tests cover legacy compatibility.

Live reproduction before this patch: fresh FID `4294967298` registered successfully on Haatz and received a gasless signer. Its cast submission returned `bad_request.validation_failure/unknown fid`. FIDs `4294967296` and `4294967298` both map to data shard 1.
