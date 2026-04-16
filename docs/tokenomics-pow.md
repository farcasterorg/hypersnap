# Proof-of-Work Tokenomics for Hypersnap

> **Status:** Draft proposal — aligned with [FIP #19](https://github.com/orgs/farcasterorg/discussions/19) and [FIP #21](https://github.com/orgs/farcasterorg/discussions/21)  
> **Author:** dare1.eth (FID 612066) | [Proposal #12](https://github.com/orgs/farcasterorg/discussions/12)  
> **Last updated:** April 2026

---

## Overview

This document specifies a commitment-weighted, hybrid Proof-of-Work (PoW) + Proof-of-Stake (PoS) token emission model for Hypersnap — the hyperdimensional fork of the Farcaster Snapchain network. It extends the three-market emission model from FIP #19 with a phased rollout strategy, an activity-density credibility scalar, and explicit alignment with Snap Compute (FIP #21).

The core principle: **tokens are earned by performing verifiable work that benefits the network**, not by holding an old account or grinding hash functions. Age is a sybil anchor, not a reward signal.

---

## 1. Work Markets

Three protocol-native work markets define what counts as token-earning work:

| Market | Work Definition | Emission Share |
|---|---|---|
| **DA-PoW** | Storing and serving chain data reliably via challenge-response proofs | 50% |
| **App-PoW** | Building miniapps that generate credible, sustained usage by real users | 30% |
| **Growth-PoW** | Maintaining integration of new users into the social graph over time | 20% |

### Phased Rollout (critical)

Do **not** launch all three markets simultaneously. Each market is an independent anti-sybil problem. If Growth-PoW breaks, it should not be able to drain the DA or App emission pools.

**Recommended activation sequence:**

- **Phase 1 — Genesis:** DA-PoW only. Validators earn. Infrastructure has to work before growth matters.
- **Phase 2 — Epoch 6–12 (~1–2 months):** Add App-PoW once the miniapp ecosystem has enough usage data to calibrate the credibility weighting.
- **Phase 3 — Epoch 12–24 (~2–4 months):** Add Growth-PoW after the spectral clustering and trust score pipeline from Proof of Quality has been validated against live sybil pressure.

The 50/20/30 split is the target steady-state. During Phase 1, unused Growth and App shares accumulate in a reserve pool and are released when each market activates.

---

## 2. Credibility Scalar (Identity Weighting)

Every reward in every work market is multiplied by a per-FID credibility scalar `W(fid)`. Without this, sybil attacks trivially drain emission.

### Proposed Formula

```
W(fid) = 0.20 x age_factor
       + 0.30 x trust_score
       + 0.25 x activity_density
       + 0.15 x stake_factor
       + 0.10 x interaction_entropy
```

### Components

| Component | Source | Weight | Description |
|---|---|---|---|
| `age_factor` | FID age (FIP #19 §2) | 0.20 | `min(1.0, effective_age / 180 days)` — sybil anchor, not primary reward signal |
| `trust_score` | Proof of Quality FIP | 0.30 | EigenTrust + spectral clustering score |
| `activity_density` | Computed per epoch | 0.25 | `min(1.0, total_messages / (effective_age_days x MIN_DAILY_THRESHOLD))` |
| `stake_factor` | Token balance staked | 0.15 | `min(1.0, staked / STAKE_MATURITY_AMOUNT)` — skin in the game |
| `interaction_entropy` | Shannon entropy of interaction partners | 0.10 | High entropy = diverse interactions, low entropy = bot-like |

### Why activity_density instead of client_diversity

The original FIP #19 formula allocates 0.10 to `client_diversity`, which requires client identifier metadata in messages to be measurable. If clients are not tagging messages, this component silently scores 0 for all users and the effective weights shift. `activity_density` is directly computable from existing trie state (message counts + FID age) with no additional instrumentation required.

### Anti-Gaming Properties

- A 3-year-old account with 10 lifetime casts scores lower than a 1-year-old account posting daily — correct behavior.
- No single factor dominates: a maximally old account with perfect trust but zero activity scores at most `0.20 + 0.30 = 0.50`.
- `stake_factor` at 0.15 creates meaningful skin-in-the-game without letting token holders dominate over active contributors.

---

## 3. Emission Schedule

### Total Supply

**2,000,000,000 tokens (2B fixed cap)**

Rationale: Large enough for three simultaneous work markets with meaningful per-epoch rewards. Small enough to be taken seriously. Peer range with proven infrastructure tokens (Filecoin: 2B, Optimism: 4.29B). Helium's 223M proved too tight for multi-market emission.

### Emission Curve

Bitcoin-style halving every 2 years:

```
emission_per_epoch(epoch) = INITIAL_EPOCH_EMISSION x 0.5^(epoch / EPOCHS_PER_HALVING)
```

- Year 1 target: 500M tokens (25% of total supply)
- `EPOCHS_PER_HALVING` = number of epochs in 2 years (~146 epochs at 5-day epochs)

### Fee Distribution

| Destination | Phase 1 Rate | Steady-State Rate | Rationale |
|---|---|---|---|
| Burned | 60–65% | 50% | Higher burn rate in Year 1 offsets retro vest circulating supply |
| Block proposer | 20–25% | 30% | Direct validator incentive |
| Protocol treasury | 15–20% | 20% | Infrastructure, bridge subsidies, ecosystem grants |

The burn rate should step down from 65% → 50% over the first 12 epochs as token utility demand catches up to emission.

---

## 4. Retroactive Genesis Distribution

### Pool Size

```
RETROACTIVE_POOL = TOTAL_SUPPLY x 0.10  // 200M tokens
```

### Scoring

Applies the same credibility-weighted scoring formula to historical data:

```
retro_score(fid) = retro_W(fid) x (
  0.40 x retro_growth_score(fid) +
  0.60 x retro_app_score(fid)
)
```

Note: `stake_factor = 0` for all FIDs at retroactive evaluation (no tokens existed). Maximum retroactive credibility ceiling is therefore **0.90** — no one had skin in the game yet. The retroactive distribution is effectively a **trust-weighted social graph snapshot**, not a pure activity reward. This should be stated explicitly in documentation.

### Exclusions

`RETROACTIVE_EXCLUDED_FIDS_APP = [1, 309857]`

FIDs 1 and 309857 are excluded from retroactive App-PoW scoring. Under Farcaster Classic, these FIDs were used as managed signers for nearly all users of the primary client — a structural advantage that no other participant could replicate. They remain eligible for Growth-PoW retroactive scoring.

### Vesting

Linear vesting over 36 epochs (~6 months). Allocations are claimable, not airdropped. Inactive FIDs do not receive tokens until a controlling key actively claims.

---

## 5. Snap Compute Alignment (FIP #21)

`SnapExecutionBundle` records from FIP #21 are on-chain execution records for every Snap Compute miniapp interaction. These **must** automatically qualify as App-PoW receipts without requiring a separate `AppUsageReceipt` submission.

If snap-based miniapps must submit redundant overhead while their usage is already more verifiable (on-chain via SnapVM) than server-side apps, the protocol structurally penalizes the more decentralized option.

**Required alignment before launch:**
- `SnapExecutionBundle` → counted as `AppUsageReceipt` with `action_weight = 0.5` (same as signed receipt)
- SnapVM execution records must be accessible to the App-PoW scoring function via the same trie lookup used for `AppUsageReceipt` messages
- Rate limiting (`MAX_RECEIPTS_PER_USER_PER_APP_PER_EPOCH = 100`) applies equally to both paths

---

## 6. Bridge Fast-Path

The default 5-day outbound bridge latency (epoch boundary anchor) will reduce casual cross-chain usage. A defined fast-path anchor frequency must be a first-class protocol parameter:

| Parameter | Default | Fast-path |
|---|---|---|
| `ANCHOR_FREQUENCY` | 1 per epoch (~5 days) | Every 500 blocks (~1.7 hours at 12s) |
| `FAST_ANCHOR_GAS_SUBSIDY` | None | Treasury-funded for first 6 months |
| `MAX_ROOT_AGE` | 6 epochs | Same |

**Open question:** If a relayer misses 6 epochs of root posting, can a valid root for that epoch be submitted and claimed against later? The spec must explicitly address this for users who submit a `TokenLock` and go offline.

---

## 7. Parameter Summary

### Credibility Scalar

| Parameter | Value | Description |
|---|---|---|
| `AGE_MATURITY_SECONDS` | 15,552,000 (180 days) | Age factor reaches 1.0 |
| `MIN_DAILY_THRESHOLD` | 0.5 messages/day | Baseline for activity_density calculation |
| `STAKE_MATURITY_AMOUNT` | TBD | Token amount at which stake_factor reaches 1.0 |

### Emission

| Parameter | Value | Description |
|---|---|---|
| `TOTAL_SUPPLY` | 2,000,000,000 | Fixed cap |
| `INITIAL_EPOCH_EMISSION` | ~3,425,000 | Calibrated for 500M Year 1 at 5-day epochs |
| `EPOCHS_PER_HALVING` | ~146 | 2-year halving at 5-day epochs |
| `DA_EMISSION_SHARE` | 0.50 | DA-PoW share |
| `APP_EMISSION_SHARE` | 0.30 | App-PoW share |
| `GROWTH_EMISSION_SHARE` | 0.20 | Growth-PoW share |
| `FEE_BURN_RATE_PHASE1` | 0.65 | Year 1 burn rate |
| `FEE_BURN_RATE_STEADY` | 0.50 | Steady-state burn rate |

### Retroactive

| Parameter | Value | Description |
|---|---|---|
| `RETROACTIVE_SHARE` | 0.10 | 10% of total supply (200M tokens) |
| `RETROACTIVE_VESTING_EPOCHS` | 36 | ~6 months linear vest |
| `RETRO_GROWTH_WEIGHT` | 0.40 | Growth weight in retro composite score |
| `RETRO_APP_WEIGHT` | 0.60 | App weight in retro composite score |

---

## 8. Open Questions

1. **`MIN_DAILY_THRESHOLD` calibration** — what baseline activity level should activity_density use? Too low and it doesn't differentiate. Too high and it penalizes legitimate low-frequency users (e.g., Keccers-style high-signal, low-volume posters).

2. **DA-PoW proof propagation model** — at 50 validators with 10 challenges each per epoch, that's 500 DA proofs in gossip. If every node verifies every other node's proof, that's O(N^2) gossip load. Specify the propagation model explicitly before the validator set scales.

3. **Validator readiness attestation before epoch genesis cutover** — a 2/3+ pre-activation signal from validators before `EPOCH_GENESIS_HEIGHT` fires would prevent a consensus split if any validators are on the old binary.

4. **Channel/community App-PoW** — channel creators whose channels generate sustained unique-user interactions across epochs are doing verifiable protocol-native work. A `ChannelWork` record analogous to `AppUsageReceipt` would capture this signal.

5. **App onboarding credit** — apps that are a new user's first meaningful interaction point should receive a retroactive onboarding credit, triggered only after the new user passes Growth-PoW quality evaluation. This closes the gap between app and growth markets.

---

## References

- [FIP #19: Proof of Work Tokenization](https://github.com/orgs/farcasterorg/discussions/19)
- [FIP #21: Snap Compute](https://github.com/orgs/farcasterorg/discussions/21)
- [Hyper Mode Architecture](./hyper.md)
- [Tokenomics Proposal v2 — dare1.eth](https://github.com/orgs/farcasterorg/discussions/12)
