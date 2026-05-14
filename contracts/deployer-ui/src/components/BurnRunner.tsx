import { useEffect, useState } from "react";
import { useAccount, useSwitchChain } from "wagmi";
import {
  readContract,
  writeContract,
  waitForTransactionReceipt,
  getPublicClient,
} from "@wagmi/core";
import { erc20Abi, isHex, type Address, type Hex } from "viem";
import { config, SUPPORTED_CHAINS } from "../wagmi";
import { BRIDGE_ABI } from "../abis";
import { CREATEX, CREATEX_ABI } from "../createx";
import {
  PROXY_SALT_TAG,
  guardedCrossChainSalt,
  saltFor,
} from "../salt";

interface Props {
  deployer: Address | null;
}

export function BurnRunner({ deployer }: Props) {
  const { address: connected, chainId: connectedChainId } = useAccount();
  const { switchChainAsync } = useSwitchChain();

  const [chainIdStr, setChainIdStr] = useState<string>(
    connectedChainId ? String(connectedChainId) : "1",
  );
  const [amountStr, setAmountStr] = useState("100");
  const [recipientStr, setRecipientStr] = useState("");

  const [bridgeAddress, setBridgeAddress] = useState<Address | null>(null);
  const [balance, setBalance] = useState<bigint | null>(null);
  const [busy, setBusy] = useState(false);
  const [log, setLog] = useState<string[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (connectedChainId) setChainIdStr(String(connectedChainId));
  }, [connectedChainId]);

  const targetChainId = (() => {
    const n = Number(chainIdStr);
    return Number.isInteger(n) && n > 0 ? n : null;
  })();
  const targetChain = SUPPORTED_CHAINS.find((c) => c.id === targetChainId) ?? null;

  // Resolve bridge address + connected user's balance.
  useEffect(() => {
    setBridgeAddress(null);
    setBalance(null);
    if (!deployer || !targetChainId || !connected) return;
    (async () => {
      try {
        const proxySalt = saltFor(deployer, PROXY_SALT_TAG);
        const proxyGuarded = guardedCrossChainSalt(deployer, proxySalt);
        const proxy = (await readContract(config, {
          chainId: targetChainId as never,
          address: CREATEX,
          abi: CREATEX_ABI,
          functionName: "computeCreate3Address",
          args: [proxyGuarded, CREATEX],
        })) as Address;

        const publicClient = getPublicClient(config, {
          chainId: targetChainId as never,
        });
        if (!publicClient) return;
        const code = await publicClient.getCode({ address: proxy });
        if (!code || code === "0x") {
          setBridgeAddress(null);
          return;
        }
        setBridgeAddress(proxy);

        const bal = (await readContract(config, {
          chainId: targetChainId as never,
          address: proxy,
          abi: erc20Abi,
          functionName: "balanceOf",
          args: [connected],
        })) as bigint;
        setBalance(bal);
      } catch (e) {
        setError(e instanceof Error ? e.message : String(e));
      }
    })();
  }, [deployer, targetChainId, connected]);

  async function submitBurn() {
    if (!targetChainId || !targetChain || !bridgeAddress || !connected) return;
    if (!isHex(recipientStr) || recipientStr.length !== 66) {
      setError("hypersnapRecipient must be a 32-byte hex value (0x + 64 chars)");
      return;
    }
    let amount: bigint;
    try {
      amount = BigInt(amountStr);
      if (amount <= 0n) throw new Error("amount must be positive");
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      return;
    }

    setBusy(true);
    setError(null);
    setLog([]);
    try {
      if (connectedChainId !== targetChainId) {
        setLog((l) => [...l, `Switching wallet to ${targetChain.name}…`]);
        await switchChainAsync({
          chainId: targetChainId as Parameters<
            typeof switchChainAsync
          >[0]["chainId"],
        });
      }
      setLog((l) => [...l, "Sign burn in your wallet…"]);
      const txHash = await writeContract(config, {
        chainId: targetChainId as never,
        address: bridgeAddress,
        abi: BRIDGE_ABI as readonly unknown[],
        functionName: "burn",
        args: [amount, recipientStr as Hex],
      } as never);
      setLog((l) => [...l, `Burn tx: ${txHash}`]);
      await waitForTransactionReceipt(config, {
        chainId: targetChainId as never,
        hash: txHash,
      });
      setLog((l) => [
        ...l,
        "Burn confirmed. Validators-side observer must now credit the Hypersnap recipient.",
      ]);
      // Refresh balance.
      const bal = (await readContract(config, {
        chainId: targetChainId as never,
        address: bridgeAddress,
        abi: erc20Abi,
        functionName: "balanceOf",
        args: [connected],
      })) as bigint;
      setBalance(bal);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="burn-runner">
      <h2>Burn (EVM → Hypersnap)</h2>
      <p className="hint">
        Burn SNAP on the destination chain to bridge value back. The
        validator set's L1 observer picks up the resulting <code>Burned</code>
        event off-chain at finality and credits the Hypersnap recipient via
        threshold-signed hyperblock inclusion.
      </p>

      <div className="form-row">
        <label>chainId</label>
        <input
          type="text"
          value={chainIdStr}
          onChange={(e) => setChainIdStr(e.target.value)}
          spellCheck={false}
        />
      </div>

      <div className="form-row">
        <label>amount (in SNAP wei)</label>
        <input
          type="text"
          value={amountStr}
          onChange={(e) => setAmountStr(e.target.value)}
          spellCheck={false}
        />
      </div>

      <div className="form-row">
        <label>hypersnapRecipient (32-byte hex; opaque to bridge)</label>
        <input
          type="text"
          placeholder="0x… 64 hex chars"
          value={recipientStr}
          onChange={(e) => setRecipientStr(e.target.value)}
          spellCheck={false}
        />
      </div>

      {bridgeAddress && balance !== null && (
        <div className="addr-row">
          <span className="addr-label">your balance:</span>
          <code>{balance.toString()} SNAP units</code>
        </div>
      )}

      {!bridgeAddress && targetChainId && (
        <div className="status error">
          No bridge deployed at the deterministic address on chainId{" "}
          {targetChainId}.
        </div>
      )}

      <button
        className="deploy-btn"
        onClick={submitBurn}
        disabled={busy || !bridgeAddress}
      >
        {busy
          ? "Submitting…"
          : connectedChainId === targetChainId
            ? "Burn"
            : `Switch + burn on ${targetChain?.name ?? "chain"}`}
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
