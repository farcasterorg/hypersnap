import { useEffect, useState } from "react";
import { useAccount, useSwitchChain } from "wagmi";
import { readContract, writeContract, waitForTransactionReceipt, getPublicClient } from "@wagmi/core";
import { erc20Abi, type Address, type Hex } from "viem";
import { config, SUPPORTED_CHAINS } from "../wagmi";
import { BRIDGE_ABI } from "../abis";
import type { BuiltTree } from "./MerkleTreeBuilder";
import { CREATEX, CREATEX_ABI } from "../createx";
import {
  IMPL_SALT_TAG,
  PROXY_SALT_TAG,
  guardedCrossChainSalt,
  saltFor,
} from "../salt";

interface Props {
  tree: BuiltTree | null;
  rootSig: Hex | null;
  blockNumber: bigint;
  deployer: Address | null;
}

export function ClaimRunner({ tree, rootSig, blockNumber, deployer }: Props) {
  const { chainId: connectedChainId } = useAccount();
  const { switchChainAsync } = useSwitchChain();
  const [selectedIdx, setSelectedIdx] = useState(0);
  const [bridgeAddress, setBridgeAddress] = useState<Address | null>(null);
  const [busy, setBusy] = useState(false);
  const [log, setLog] = useState<string[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [recipientBalance, setRecipientBalance] = useState<bigint | null>(null);

  // Find the bridge address for the leaf's destination chain.
  const selected = tree?.entries[selectedIdx] ?? null;
  const targetChain = selected
    ? SUPPORTED_CHAINS.find((c) => c.id === selected.parsed.destinationChainId)
    : null;

  useEffect(() => {
    setBridgeAddress(null);
    setRecipientBalance(null);
    if (!selected || !deployer) return;
    (async () => {
      try {
        const proxySalt = saltFor(deployer, PROXY_SALT_TAG);
        const proxyGuarded = guardedCrossChainSalt(deployer, proxySalt);
        const proxy = (await readContract(config, {
          chainId: selected.parsed.destinationChainId as never,
          address: CREATEX,
          abi: CREATEX_ABI,
          functionName: "computeCreate3Address",
          args: [proxyGuarded, CREATEX],
        })) as Address;
        setBridgeAddress(proxy);

        // Also fetch the recipient's current SNAP balance (if bridge is deployed).
        const publicClient = getPublicClient(config, {
          chainId: selected.parsed.destinationChainId as never,
        });
        if (publicClient) {
          const code = await publicClient.getCode({ address: proxy });
          if (code && code !== "0x") {
            const bal = (await readContract(config, {
              chainId: selected.parsed.destinationChainId as never,
              address: proxy,
              abi: erc20Abi,
              functionName: "balanceOf",
              args: [selected.parsed.recipient],
            })) as bigint;
            setRecipientBalance(bal);
          }
        }
      } catch (e) {
        setError(e instanceof Error ? e.message : String(e));
      }
    })();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedIdx, deployer, tree?.root]);

  // Suppress unused-warning until we wire it into a UI element.
  void IMPL_SALT_TAG;

  if (!tree) {
    return (
      <div className="claim-runner">
        <h2>Submit Claim</h2>
        <p className="hint">Build a merkle tree first.</p>
      </div>
    );
  }

  if (!rootSig) {
    return (
      <div className="claim-runner">
        <h2>Submit Claim</h2>
        <p className="hint">
          Sign the root update first — claims need an owner-signed root to
          advance <code>latestRoot</code> on the first attempt.
        </p>
      </div>
    );
  }

  async function submitClaim() {
    if (!selected || !rootSig || !tree || !bridgeAddress || !targetChain) return;
    setBusy(true);
    setError(null);
    setLog([]);
    try {
      if (connectedChainId !== selected.parsed.destinationChainId) {
        setLog((l) => [...l, `Switching wallet to ${targetChain.name}…`]);
        await switchChainAsync({
          chainId: selected.parsed.destinationChainId as Parameters<
            typeof switchChainAsync
          >[0]["chainId"],
        });
      }

      setLog((l) => [...l, "Sign claim transaction in your wallet…"]);
      const txHash = await writeContract(config, {
        chainId: selected.parsed.destinationChainId as never,
        address: bridgeAddress,
        abi: BRIDGE_ABI as readonly unknown[],
        functionName: "claim",
        args: [
          blockNumber,
          tree.root,
          rootSig,
          selected.parsed.lockId,
          selected.parsed.recipient,
          selected.parsed.amount,
          selected.parsed.destinationChainId,
          selected.proof,
        ],
      } as never);
      setLog((l) => [...l, `Claim tx: ${txHash}`]);
      await waitForTransactionReceipt(config, {
        chainId: selected.parsed.destinationChainId as never,
        hash: txHash,
      });
      setLog((l) => [...l, "Claim confirmed"]);

      // Re-fetch balance to show the mint.
      const bal = (await readContract(config, {
        chainId: selected.parsed.destinationChainId as never,
        address: bridgeAddress,
        abi: erc20Abi,
        functionName: "balanceOf",
        args: [selected.parsed.recipient],
      })) as bigint;
      setRecipientBalance(bal);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="claim-runner">
      <h2>Submit Claim (deploys the root)</h2>
      <p className="hint">
        Pick a leaf to claim. <strong>The first claim per chain advances{" "}
        <code>latestRoot</code> on-chain</strong> — using the signature you
        just produced — so this is the action that "deploys" your merkle
        root. Subsequent claims at the same block reuse that stored root
        and don't need a fresh signature.
      </p>

      <div className="form-row">
        <label>Pick a leaf</label>
        <select
          value={selectedIdx}
          onChange={(e) => setSelectedIdx(Number(e.target.value))}
        >
          {tree.entries.map((e, i) => (
            <option key={i} value={i}>
              {`#${i} → ${e.parsed.recipient.slice(0, 10)}… on chain ${e.parsed.destinationChainId} (${e.parsed.amount} wei)`}
            </option>
          ))}
        </select>
      </div>

      {selected && (
        <div className="leaf-summary">
          <div className="addr-row">
            <span className="addr-label">leaf hash:</span>
            <code>{selected.leafHash}</code>
          </div>
          <div className="addr-row">
            <span className="addr-label">recipient:</span>
            <code>{selected.parsed.recipient}</code>
          </div>
          <div className="addr-row">
            <span className="addr-label">target chain:</span>
            <code>
              {targetChain?.name ?? "(unsupported)"} ({selected.parsed.destinationChainId})
            </code>
          </div>
          <div className="addr-row">
            <span className="addr-label">amount:</span>
            <code>{selected.parsed.amount.toString()} wei</code>
          </div>
          <div className="addr-row">
            <span className="addr-label">proof depth:</span>
            <code>{selected.proof.length}</code>
          </div>
          <div className="addr-row">
            <span className="addr-label">bridge addr:</span>
            <code>{bridgeAddress ?? "(loading…)"}</code>
          </div>
          {recipientBalance !== null && (
            <div className="addr-row">
              <span className="addr-label">recipient balance:</span>
              <code>{recipientBalance.toString()} SNAP units</code>
            </div>
          )}
        </div>
      )}

      <button
        className="deploy-btn"
        disabled={busy || !bridgeAddress || !targetChain}
        onClick={submitClaim}
      >
        {busy
          ? "Submitting…"
          : connectedChainId === selected?.parsed.destinationChainId
            ? "Submit Claim"
            : `Switch + claim on ${targetChain?.name ?? "chain"}`}
      </button>

      {log.length > 0 && (
        <ul className="log">
          {log.map((m, i) => (
            <li key={i}>{m}</li>
          ))}
        </ul>
      )}
      {error && <div className="status error">{error}</div>}
    </div>
  );
}
