# Hypersnap Bridge Deployer UI

A single-page React app that deterministically deploys `HypersnapBridge`
across multiple EVM chains via [CreateX](https://createx.rocks). Each
chain is a button click; the wallet handles signing, CreateX handles
address derivation. Idempotent — already-deployed chains are detected
and shown with a checkmark.

## What it does

1. **Connect** an injected wallet or via WalletConnect.
2. **Predict** the deterministic proxy + impl addresses your EOA will
   land on (same on every chain).
3. **Deploy per chain** by clicking the button — the app switches your
   wallet to that chain (if needed), then sends two CreateX deploy
   transactions (impl, then proxy with atomic `initialize`).
4. **Detect already-deployed chains** automatically and short-circuit.

This is the same flow as `forge script script/Deploy.s.sol`, just with a
GUI and per-chain wallet prompts instead of CLI broadcasting.

## What it does NOT do

- Build the initial merkle tree from a snapshot (use the
  `bridge-ceremony` CLI: `cargo run -p hypersnap-bridge-ceremony --
  build-tree --input ... --output ...`).
- Sign the initial root update / rotation / pause / upgrade payloads
  (use the CLI's `digest` + `sign` subcommands, or sign externally with
  `cast wallet sign --no-hash`).
- Distribute claim calldata to relayers (use the CLI's `bundle claim`).

These steps either require offline data processing (snapshot → tree) or
threshold-MPC ceremony coordination (DKLS23 acceptance sigs) that don't
fit a click-a-button UX.

## One-time setup

```bash
# 1. Install deps.
cd contracts/deployer-ui
npm install

# 2. Compile contracts so we can read the bytecode artifacts.
cd ..
forge build

# 3. (Optional) Override the WalletConnect projectId.
#    The default project id is baked into src/wagmi.ts and shared with
#    the genesis ceremony app. To use your own (e.g., for a fork or
#    custom Reown project), set VITE_WALLETCONNECT_PROJECT_ID:
cd deployer-ui
echo "VITE_WALLETCONNECT_PROJECT_ID=your_project_id_here" > .env.local
```

WalletConnect is the primary connection method (mobile wallets via QR
code). Injected browser-extension wallets (MetaMask, Rabby) are also
supported as a fallback for desktop testing.

## Run

```bash
npm run dev
```

Opens at http://localhost:5173 by default. The first `npm run dev`
auto-runs `npm run prepare-bytecode` to refresh `src/bytecode.ts` and
`src/abis.ts` from the latest `forge build` artifacts.

## Production build

```bash
npm run build
```

Outputs to `dist/`. Serve with any static host (nginx, Vercel, etc.).

## Workflow

1. Open the app, connect your hardware wallet.
2. Verify the predicted proxy address matches what you computed
   offline (e.g., via `forge script script/Deploy.s.sol --rpc-url
   $RPC_URL` dry-run).
3. Click **Deploy on Ethereum** — wallet will prompt twice (impl, then
   proxy). Wait for confirmations.
4. Repeat for each chain you want to support. The app switches your
   wallet automatically when you click a button for a different chain.
5. After all chains show ✓, proceed to the off-chain ceremony steps via
   the `bridge-ceremony` CLI.

## Determinism guarantees

Same proxy address on every chain as long as:

1. CreateX is deployed at `0xba5Ed099633D3B313e4D5F7bdc1305d3c28ba5Ed`
   (true for ~50 major chains today; the app shows an error if not).
2. The same EOA broadcasts each deploy.
3. The salt tag (currently `hypersnap.v1`) is unchanged.

The salt is constructed exactly as `Deploy.s.sol::_saltFor` does it:
`bytes20(deployer) || 0x00 || bytes11(keccak(tag))`. Bytes 0..19 give
CreateX frontrun protection (only your deployer can deploy at the
address); byte 20 = 0x00 disables CreateX's chain-id mixing.

## Security model

- The app is a thin client over CreateX. It does not custody keys or
  private data. Wallet signing happens entirely in your wallet.
- Bytecode and ABIs are baked in at build time from the
  contracts you've built locally. Re-run `npm run prepare-bytecode`
  after every `forge build` to refresh them.
- The app's correctness depends on the byte-for-byte match between its
  salt computation and `Deploy.s.sol::_saltFor`. Any drift would mean
  the predicted addresses don't match what the contract derives —
  caught on first deploy attempt.

## Limitations

- Per-chain deploy is a discrete user action. The app does NOT batch
  deploy across chains — each chain requires its own wallet signature
  flow. (This is fundamental: each chain's wallet provider is separate.)
- The app uses the chain's default public RPC. For mainnet at scale
  you may want to point your wallet at a private RPC endpoint;
  configure that in your wallet, not the app.
