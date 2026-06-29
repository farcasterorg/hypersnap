import { createConfig } from "wagmi";
import { fallback, http } from "viem";
import {
  mainnet,
  base,
  arbitrum,
  optimism,
  polygon,
  sepolia,
  baseSepolia,
  arbitrumSepolia,
  optimismSepolia,
} from "wagmi/chains";
import { injected, walletConnect } from "wagmi/connectors";

// Reown / WalletConnect Cloud project id — shared with the genesis
// ceremony app (`~/src/hypersnap-genesis-ceremony/src/App.tsx`) and
// qconsole-web. Hardcoded so the UI works out of the box; override with
// `VITE_WALLETCONNECT_PROJECT_ID` if running a fork that needs its own
// Reown project.
const DEFAULT_WALLETCONNECT_PROJECT_ID = "76606b4360b3c1d0d5d908fd255438d2";
const projectId =
  (import.meta.env.VITE_WALLETCONNECT_PROJECT_ID as string | undefined) ||
  DEFAULT_WALLETCONNECT_PROJECT_ID;

// Order matters: production chains first, then testnets. The UI groups
// by mainnet/testnet using the `testnet` flag on the chain object.
export const SUPPORTED_CHAINS = [
  mainnet,
  base,
  arbitrum,
  optimism,
  polygon,
  sepolia,
  baseSepolia,
  arbitrumSepolia,
  optimismSepolia,
] as const;

// Public, CORS-friendly RPC endpoints. publicnode + drpc are both reliable
// for browser usage; we put them first and fall back to chain defaults so
// any single endpoint going down doesn't break reads. Override per-chain
// with env vars if needed (e.g., for private RPCs):
//   VITE_RPC_1, VITE_RPC_8453, VITE_RPC_42161, etc. (use the chainId)
const DEFAULT_RPCS: Record<number, string[]> = {
  [mainnet.id]: [
    "https://ethereum-rpc.publicnode.com",
    "https://eth.drpc.org",
    "https://cloudflare-eth.com",
  ],
  [base.id]: [
    "https://base-rpc.publicnode.com",
    "https://base.drpc.org",
    "https://mainnet.base.org",
  ],
  [arbitrum.id]: [
    "https://arbitrum-one-rpc.publicnode.com",
    "https://arbitrum.drpc.org",
    "https://arb1.arbitrum.io/rpc",
  ],
  [optimism.id]: [
    "https://optimism-rpc.publicnode.com",
    "https://optimism.drpc.org",
    "https://mainnet.optimism.io",
  ],
  [polygon.id]: [
    "https://polygon-bor-rpc.publicnode.com",
    "https://polygon.drpc.org",
    "https://polygon-rpc.com",
  ],
  [sepolia.id]: [
    "https://ethereum-sepolia-rpc.publicnode.com",
    "https://sepolia.drpc.org",
    "https://rpc.sepolia.org",
  ],
  [baseSepolia.id]: [
    "https://base-sepolia-rpc.publicnode.com",
    "https://base-sepolia.drpc.org",
    "https://sepolia.base.org",
  ],
  [arbitrumSepolia.id]: [
    "https://arbitrum-sepolia-rpc.publicnode.com",
    "https://arbitrum-sepolia.drpc.org",
    "https://sepolia-rollup.arbitrum.io/rpc",
  ],
  [optimismSepolia.id]: [
    "https://optimism-sepolia-rpc.publicnode.com",
    "https://optimism-sepolia.drpc.org",
    "https://sepolia.optimism.io",
  ],
};

function transportFor(chainId: number) {
  // Per-chain env override (e.g. VITE_RPC_1=https://my-private-rpc).
  const envOverride = (
    import.meta.env as unknown as Record<string, string | undefined>
  )[`VITE_RPC_${chainId}`];

  const urls = envOverride
    ? [envOverride, ...(DEFAULT_RPCS[chainId] ?? [])]
    : DEFAULT_RPCS[chainId] ?? [];

  if (urls.length === 0) return http(); // fall back to viem's default
  return fallback(
    urls.map((url) =>
      http(url, {
        timeout: 10_000,
        retryCount: 1,
      }),
    ),
    { rank: false },
  );
}

export const config = createConfig({
  chains: SUPPORTED_CHAINS,
  // WalletConnect listed first so it's the default option in the UI.
  // Injected stays available as a fallback for desktop wallet extensions.
  connectors: [
    walletConnect({
      projectId,
      metadata: {
        name: "Hypersnap Bridge Deployer",
        description:
          "Deterministic cross-chain deployer for HypersnapBridge",
        url: typeof window !== "undefined" ? window.location.origin : "",
        icons: [],
      },
      showQrModal: true,
    }),
    injected({ shimDisconnect: true }),
  ],
  transports: Object.fromEntries(
    SUPPORTED_CHAINS.map((c) => [c.id, transportFor(c.id)]),
  ) as Record<
    (typeof SUPPORTED_CHAINS)[number]["id"],
    ReturnType<typeof transportFor>
  >,
});

declare module "wagmi" {
  interface Register {
    config: typeof config;
  }
}
