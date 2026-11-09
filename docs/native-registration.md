# Native account registration at the validator fork

This selectively ports `pow`'s native registration: custody-authorized proof of
work, validator-assigned FIDs beginning at `4294967296` (`2^32`), and a
native custody registry. Existing gasless `KEY_ADD` / `KEY_REMOVE` messages manage
account signers. No IdRegistry transaction is required for a native account.

The port includes no token, staking, reward, fee-market, Falcon, or validator-election
changes. Native custody is immutable in this release, with one native FID per
custody address; custody rotation is not enabled. Legacy registrations and signers
continue to work through the existing contract-backed path.

## Activation

`validators.toml` configures `[consensus.native_registration.activation_heights]`
with the same boundaries as the new validator sets and gossip topic switch:

| Shard | First fork block |
| --- | ---: |
| 0 | 50,433,538 |
| 1 | 51,119,199 |
| 2 | 50,954,121 |

Every fork validator and read node must run this code and load the updated
configuration before activation. Startup rejects a registration schedule that
differs from gossip or lacks a matching validator transition. With no registration
schedule configured, native registration stays disabled.

Shard 0 assigns identities from its activation block onward. Each data shard
applies the registry and signer updates from its own activation block onward.
Post-fork cross-shard events start in a separate sequence range (`2^48 + 1`) so
legacy events processed during the staggered cutover cannot mask new events.
The receiver waits for its shard's cutoff, fills actual event gaps, and skips the
reserved gap between legacy and post-fork sequence numbers. Post-fork events are
checked against the committed shard-0 event store before a data shard applies them.

Existing account keys and pre-fork roots are preserved. Native FID keys use a
zero-FID escape followed by the full 64-bit ID, preventing truncation/collisions
with legacy FIDs. Historical replay keeps the old 32-bit encoding until each
shard's cutoff, including historical on-chain events with high FIDs.
Registration receipts commit their assigned FID, originating
message and block height into the trie; identity assignment is replayable and
persists through restarts and snapshots. No existing account data is deleted.

## Register and look up an account

```sh
cargo build --release --bin native_register
./target/release/native_register --rpc http://127.0.0.1:3383 --network 1
```

Set `HYPERSNAP_CUSTODY_PRIVATE_KEY` in the client's environment first. The tool
mines the work locally, EIP-712 signs with the custody key, submits to shard 0,
and prints the assigned FID after inclusion. The container image also includes
`/app/native_register`. `--private-key-env` selects a different environment variable.

Read endpoints:

```text
GET /v1/nativeRegistration
GET /v1/nativeAccount?custody=0x<20-byte-custody-address>
GET /v1/nativeAccount?fid=4294967296
```

The first returns whether the next shard-0 block admits registration, the current
anchor height/hash, the minimum work difficulty and anchor window. The account
endpoint returns the assigned FID, custody, originating message and registration
height. The equivalent gRPC methods are `GetNativeRegistrationInfo` and
`GetNativeAccount`. `GetFids` enumeration also includes native accounts.

Native FIDs start just above the 32-bit legacy range and can grow beyond
JavaScript's exact integer range. The JSON account/message responses emit all
native FIDs as decimal strings; use `BigInt` or strings in clients.
Legacy IDs retain their numeric JSON representation. Protobuf IDs remain `uint64`.

## Protocol and storage policy

Registration is `MessageType::NativeOnboard` (160), with `fid = 0`, BLAKE3-20
message hashing, and no outer signer/signature. `MessageData.native_onboard_body`
is field 1160 containing the serialized `HyperNativeOnboardBody`; its wire
encoding matches `pow`. Keeping this extension outside the legacy body oneof
prevents it from replacing a cast or link body on legacy messages. Their unknown
registration extensions are ignored as they are by Snapchain.

The body carries custody, its EIP-712 signature, a recent committed shard-0
anchor height/hash, and a `PowSolution`. Stake and Falcon fields are reserved and
not implemented. The release uses a 22-bit minimum difficulty and retains `pow`'s
1,024-block anchor window, with EIP-712 domain `HypersnapNativeOnboard`, version
`1`, chain ID `10`. Custody signs the anchor and gate commitment. Hash domains,
byte order and leading-zero-bit checks follow `pow`'s onboarding code.

The minimum targets mobile onboarding within 30 seconds: at 500,000 nonce
attempts/second, the expected mining time is 8.4 seconds and the 95th percentile
is 25.1 seconds. These are probability calculations, not measured iPhone
performance. An iPhone benchmark of the exact client is still required to
confirm that target; fixed-difficulty proof of work has no guaranteed maximum
completion time. The node advertises the minimum through the registration info
endpoint, and the CLI mines that advertised difficulty.

Storage slots stop affecting admission, storage-derived message rate limits,
verification quotas, and quota pruning at each shard's configured fork height.
This applies to both native and legacy accounts. A native user can add a signer
and post, react, follow, or update their profile with no rented or lent storage.
Historical blocks still replay the original storage rules before their shard's
fork. Storage-lend records may still be carried for compatibility, but their
allocations do not affect post-fork access. Storage-limit APIs report unlimited
limits (`uint64::MAX`) and no required storage units after the fork.

Miniapp JFS authentication accepts both onchain keys and gasless keys, including
native-account keys. Gasless keys must be unexpired and not revoked; JFS
verification does not refresh their sliding TTL. Custody transfer and rotation
remain out of scope.

Neither native registrations nor messages authored by native FIDs are
relayed to Snapchain by the shuttle, and they are never published on legacy gossip
topics before activation.
