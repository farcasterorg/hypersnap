# Sign-in authorization for gasless keys

Status: prototype. Gated by `ProtocolFeature::SignInKeyAuthorization`, which is parked on the
its own engine version (V25, provisional), which has no mainnet or testnet schedule.

## Problem

A gasless `KEY_ADD` must carry an EIP-712 `KeyAdd` signature from the account's custody address.
For an account created in the Farcaster app, that key lives inside the app, and the app does not
sign Hypersnap's `KeyAdd` payload. The only way to add a key today is to export the recovery
phrase and type it into another client. Many people will not do that.

The one signature such an app does produce for third parties is Sign In With Farcaster (FIP-11):
an [EIP-4361](https://eips.ethereum.org/EIPS/eip-4361) message signed by the custody address. The
requesting client chooses two things in it: the nonce, and the domain the app shows in its
approval prompt.

## Rule

A `KEY_ADD` may set `authorization_type = 200`. Then:

- `authorization_message` is the exact EIP-4361 text that was signed.
- `custody_signature` is its EIP-191 (`personal_sign`) signature, 65 bytes.
- The message's domain must be `grant-account-access.hypersnap`.
- The message's `Nonce` must equal the lowercase hex EIP-712 signing hash of this message's
  `KeyAdd` typed data, the same hash a custody signature signs. The approval therefore commits to
  the fid, key, key type, scopes, ttl, nonce and deadline, and cannot be reused for anything else.
- The signer must be the fid's custody address.
- The message must follow the FIP-11 layout exactly: statement `Farcaster Auth`, `Version: 1`,
  `Chain ID: 10`, exactly one `farcaster://fid/<fid>` resource naming this fid, and the address
  line equal to the recovered signer. It is accepted only if it re-serializes to the signed bytes.
- `Issued At` must be within one hour before the `KEY_ADD`'s timestamp (ten minutes of skew is
  allowed the other way). `Expiration Time` and `Not Before` are honoured when present.

`authorization_type` 0 or 1 is the existing custody path. The `SignedKeyRequest` metadata, the
user nonce, collision checks and the per-fid cap are unchanged and apply to both paths.

A `KEY_REMOVE` may set `signature_type = 200`, with the same construction: `authorization_message`
is a sign-in to `revoke-account-access.hypersnap` whose nonce is the EIP-712 signing hash of the
`KeyRemove` typed data, signed by the custody address. It removes any gasless key of the fid,
however that key was added, and uses the user nonce like a custody removal.

## Why a reserved domain

Without it, any site offering Sign In With Farcaster could pick a nonce that commits to its own
key and turn an ordinary login into a posting key, with a prompt that says nothing unusual. With
it, a sign-in to any real site carries that site's domain and authorizes nothing. To obtain a key
an attacker has to put a prompt in front of the user that reads
`grant-account-access.hypersnap wants you to sign in`, which is the consent screen.

The domains are labels. Nothing resolves or fetches them. The add and remove domains differ so
an approval of one kind can never be presented as the other.

## What a sign-in key is

- **Scopes: the same as any gasless key.** Whatever `validate_key_add_body` admits may be granted.
  A key added this way is not a lesser key.
- **Lifetime: at most 30 days, fixed.** The cap is 30 days (custody: 90), and the window runs from
  the `KEY_ADD`'s timestamp; using the key does not extend it. Every other gasless key keeps its
  sliding window. A key obtained by tricking someone therefore cannot be kept alive by whoever
  holds it. The account renews by approving again, which is one tap.
- **Removable the way it was added.** `KEY_REMOVE` type 200 needs only another approval in the same
  app, so an account that never exports its custody key can still revoke.
- **Attributable.** The stored record embeds the whole `KEY_ADD`. The HTTP API returns
  `authorizationType` and `authorizationMessage` on such keys so clients can list and label them.

## Numbering

The new proto fields are numbered from 200 (`KeyAddBody.authorization_type = 200`,
`KeyAddBody.authorization_message = 201`, `KeyRemoveBody.authorization_message = 200`), and the
sign-in value of both type fields is 200, so nothing added on the snapchain side can collide.

## Activation safety

Older binaries do not know the new fields and treat every `KEY_ADD` as custody-authorized. Until
the feature is active this binary does the same: it does not read `authorization_type` at all,
including to reject unknown values, and static validation is untouched. A sign-in `KEY_ADD`
submitted early fails on both old and new binaries with `invalid signature`. A type 200
`KEY_REMOVE` submitted early is rejected by both with `invalid signature type`.

The fixed-expiry rule keys off the same test the merge used: `authorization_type = 200` on the
stored `KEY_ADD` and the feature active at that `KEY_ADD`'s timestamp. A custody-authorized
`KEY_ADD` from before activation that happens to carry 200 in the then-unread field keeps
sliding.

The authorization check runs on shard 0 at admission and again on the fid's data shard at replay;
both hold the fid's custody record.

## Tested against the Farcaster app

On 2026-11-16 Farcaster's relay (`relay.farcaster.xyz/v1/channel`) issued a sign-in request with
a 64-character nonce and a made-up domain, the app approved it for an account that is banned from
posting there, and the returned message and signature passed this verifier unchanged. The app
signed with the custody address. The relay also accepts `acceptAuthAddress: false`.

## Open questions

1. **A user who approves without reading.** The reserved domain makes the grant visible; it
   cannot make anyone read it. How prominently Farcaster's app shows the domain is theirs to
   decide.
2. **Farcaster can stop issuing these.** If the relay is shut or filters the reserved domains,
   no new keys can be added or removed this way. Existing keys run to their fixed expiry.
3. **Custody changes after the fork** are invisible to Hypersnap, which no longer reads the
   Optimism IdRegistry. This affects every authorization path equally.
4. **Smart-contract custody** (ERC-1271) is not supported on this path.
5. **Engine version and domain names.** V25 is provisional, and the two reserved names are
   placeholders.
6. **Snapchain compatibility.** Snapchain does not know this authorization, so a key added this
   way does not exist there and messages it signs will not be accepted if relayed.
