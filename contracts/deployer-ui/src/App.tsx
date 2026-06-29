import { useState } from "react";
import { useAccount, useConnect, useDisconnect } from "wagmi";
import type { Hex } from "viem";
import { SUPPORTED_CHAINS } from "./wagmi";

/**
 * Wipe stale WalletConnect session state from localStorage. Helpful when
 * a previous pairing got stuck and new pairings keep replaying old session
 * references. Mirrors the same pattern in `hypersnap-genesis-ceremony`.
 */
function resetWalletConnectStorage() {
  if (typeof localStorage === "undefined") return;
  const keysToRemove: string[] = [];
  for (let i = 0; i < localStorage.length; i++) {
    const key = localStorage.key(i);
    if (!key) continue;
    if (
      key.startsWith("wc@2:") ||
      key.startsWith("wagmi.walletconnect") ||
      key.startsWith("wagmi.recentConnectorId") ||
      key.startsWith("wagmi.store") ||
      key === "WALLETCONNECT_DEEPLINK_CHOICE"
    ) {
      keysToRemove.push(key);
    }
  }
  for (const k of keysToRemove) {
    try {
      localStorage.removeItem(k);
    } catch {
      // ignore
    }
  }
  // Reload so wagmi re-initializes from clean state.
  if (typeof window !== "undefined") window.location.reload();
}
import { ChainCard } from "./components/ChainCard";
import {
  MerkleTreeBuilder,
  type BuiltTree,
} from "./components/MerkleTreeBuilder";
import { RootSigner } from "./components/RootSigner";
import { ClaimRunner } from "./components/ClaimRunner";
import { BurnRunner } from "./components/BurnRunner";
import { VerifySection } from "./components/VerifySection";

type Tab = "deploy" | "verify" | "publish";

export function App() {
  const { address, isConnected, chainId } = useAccount();
  const { connectors, connect, status, error } = useConnect();
  const { disconnect } = useDisconnect();
  const [tab, setTab] = useState<Tab>("deploy");

  const [tree, setTree] = useState<BuiltTree | null>(null);
  const [rootSig, setRootSig] = useState<Hex | null>(null);
  const [rootSigBlock, setRootSigBlock] = useState<bigint>(1n);

  const mainnetChains = SUPPORTED_CHAINS.filter((c) => !c.testnet);
  const testnetChains = SUPPORTED_CHAINS.filter((c) => c.testnet);

  return (
    <div className="page">
      <header>
        <h1>Hypersnap Bridge Deployer</h1>
        <p className="subtitle">
          Deterministic cross-chain deployment via{" "}
          <a
            href="https://createx.rocks"
            target="_blank"
            rel="noreferrer"
          >
            CreateX
          </a>{" "}
          + end-to-end ceremony verification.
        </p>
      </header>

      <section className="connect-bar">
        {isConnected ? (
          <>
            <div>
              <div className="addr-row">
                <span className="addr-label">Connected:</span>
                <code>{address}</code>
              </div>
              <div className="addr-row">
                <span className="addr-label">Wallet on chain:</span>
                <code>{chainId}</code>
              </div>
            </div>
            <button onClick={() => disconnect()} className="secondary">
              Disconnect
            </button>
          </>
        ) : (
          <div className="connect-options">
            <p>
              <strong>Connect a wallet</strong> — use a fresh,
              hardware-walleted EOA dedicated to this ceremony. The same EOA
              must be used on every chain to get matching addresses.
            </p>
            <div className="buttons">
              {/* WalletConnect first (primary), then injected as fallback. */}
              {(() => {
                const wc = connectors.find((c) => c.id === "walletConnect");
                const injected = connectors.find((c) => c.id === "injected");
                return (
                  <>
                    {wc && (
                      <button
                        onClick={() => connect({ connector: wc })}
                        disabled={status === "pending"}
                      >
                        {status === "pending"
                          ? "Pairing via WalletConnect…"
                          : "Connect mobile wallet (WalletConnect)"}
                      </button>
                    )}
                    {injected && (
                      <button
                        className="secondary"
                        onClick={() => connect({ connector: injected })}
                        disabled={status === "pending"}
                      >
                        {injected.name === "Injected"
                          ? "Browser extension wallet"
                          : injected.name}
                      </button>
                    )}
                  </>
                );
              })()}
              <button
                className="secondary"
                onClick={resetWalletConnectStorage}
                disabled={status === "pending"}
                title="Clear stale WalletConnect session state. Use if pairing fails repeatedly."
              >
                Reset WC state
              </button>
            </div>
            {status === "pending" && (
              <p className="status loading">Connecting…</p>
            )}
            {error && <p className="status error">{error.message}</p>}
          </div>
        )}
      </section>

      {isConnected && (
        <>
          <nav className="tabs">
            <button
              className={tab === "deploy" ? "tab active" : "tab"}
              onClick={() => setTab("deploy")}
            >
              1. Deploy
            </button>
            <button
              className={tab === "verify" ? "tab active" : "tab"}
              onClick={() => setTab("verify")}
            >
              2. Verify (tree → sign → claim → burn)
            </button>
            <button
              className={tab === "publish" ? "tab active" : "tab"}
              onClick={() => setTab("publish")}
            >
              3. Publish (Etherscan + metadata)
            </button>
          </nav>

          {tab === "deploy" && (
            <>
              <section>
                <h2>Mainnets</h2>
                <div className="chain-grid">
                  {mainnetChains.map((chain) => (
                    <ChainCard key={chain.id} chain={chain} />
                  ))}
                </div>
              </section>

              <section>
                <h2>Testnets</h2>
                <div className="chain-grid">
                  {testnetChains.map((chain) => (
                    <ChainCard key={chain.id} chain={chain} />
                  ))}
                </div>
              </section>
            </>
          )}

          {tab === "verify" && (
            <>
              <section className="hint-block">
                <p>
                  Use these flows to verify the deployment on a testnet
                  before going to production. Each step exercises a real
                  on-chain code path:
                </p>
                <ol>
                  <li>
                    Build a small merkle tree of locks (1–10 leaves is
                    plenty).
                  </li>
                  <li>
                    Sign the root-update digest offline with your deployer
                    key (Ledger blind-sign or{" "}
                    <code>cast wallet sign --no-hash</code>) and paste the
                    signature back.
                  </li>
                  <li>
                    Submit a claim for one of the leaves — the recipient
                    receives SNAP, and <code>claimed[lockId]</code> flips on
                    the bridge.
                  </li>
                  <li>
                    Burn some of the minted SNAP back — the bridge emits a{" "}
                    <code>Burned</code> event your validators-side observer
                    will pick up.
                  </li>
                </ol>
              </section>

              <MerkleTreeBuilder onTree={setTree} />

              <RootSigner
                root={tree?.root ?? null}
                expectedSigner={address ?? null}
                onSig={(sig, block) => {
                  setRootSig(sig);
                  setRootSigBlock(block);
                }}
              />

              <ClaimRunner
                tree={tree}
                rootSig={rootSig}
                blockNumber={rootSigBlock}
                deployer={address ?? null}
              />

              <BurnRunner deployer={address ?? null} />
            </>
          )}

          {tab === "publish" && (
            <>
              <section className="hint-block">
                <p>
                  After your contracts are deployed and you've run the verify
                  flows, publish them so block explorers and wallets show the
                  source code, token metadata, and logo. The contract bytecode
                  is already on-chain — these steps add a human-readable
                  shell around it.
                </p>
              </section>
              <VerifySection />
            </>
          )}

          <section className="footer-note">
            <h2>Notes</h2>
            <ul>
              <li>
                Proxy and implementation addresses are derived from{" "}
                <code>(deployer EOA, salt tag)</code>. Same on every chain.
              </li>
              <li>
                Each <strong>Deploy</strong> click sends two transactions
                via CreateX (impl, then proxy with atomic{" "}
                <code>initialize</code>). Idempotent on re-run.
              </li>
              <li>
                The verify flows assume the bridge has been deployed on
                whatever chain you're targeting. If the bridge isn't there,
                claims and burns will fail with no-bridge errors.
              </li>
              <li>
                After all flows are verified on testnet, repeat the deploy
                step on mainnet — same EOA, same salts → same canonical
                addresses.
              </li>
            </ul>
          </section>
        </>
      )}
    </div>
  );
}
