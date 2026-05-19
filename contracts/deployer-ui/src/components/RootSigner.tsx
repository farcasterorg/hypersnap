import { useEffect, useState } from "react";
import { useWalletClient } from "wagmi";
import { isHex, type Address, type Hex } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { rootUpdateDigest } from "../lib/leaf";
import { ceremonySignCommand, recoverFromRawDigest } from "../lib/recover";

interface Props {
  root: Hex | null;
  expectedSigner: Address | null;
  onSig: (sig: Hex | null, blockNumber: bigint) => void;
}

type SignMode = "wallet" | "key" | "paste";

export function RootSigner({ root, expectedSigner, onSig }: Props) {
  const { data: walletClient } = useWalletClient();
  const [blockStr, setBlockStr] = useState("1");
  const [mode, setMode] = useState<SignMode>("wallet");
  const [sigInput, setSigInput] = useState("");
  const [pkInput, setPkInput] = useState("");
  const [recovered, setRecovered] = useState<Address | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const blockNumber = (() => {
    try {
      const n = BigInt(blockStr);
      return n > 0n ? n : null;
    } catch {
      return null;
    }
  })();

  const digest = root && blockNumber !== null ? rootUpdateDigest(blockNumber, root) : null;

  // When the user has a sig (from any mode) and a digest, try to recover.
  useEffect(() => {
    setRecovered(null);
    setError(null);
    if (!digest || !sigInput) return;
    if (!isHex(sigInput) || sigInput.length !== 132) return;
    (async () => {
      try {
        const r = await recoverFromRawDigest(digest, sigInput as Hex);
        setRecovered(r);
        if (expectedSigner && r.toLowerCase() !== expectedSigner.toLowerCase()) {
          setError(
            `Recovered ${r} ≠ connected wallet ${expectedSigner}. Sign with the correct key.`,
          );
          onSig(null, blockNumber!);
        } else {
          onSig(sigInput as Hex, blockNumber!);
        }
      } catch (e) {
        const msg = e instanceof Error ? e.message : String(e);
        setError(`recover failed: ${msg}`);
      }
    })();
  }, [digest, sigInput, expectedSigner, blockNumber, onSig]);

  async function signWithWallet() {
    if (!digest || !walletClient || !expectedSigner) return;
    setBusy(true);
    setError(null);
    try {
      // Raw 32-byte hash signing via the WalletConnect-bridged provider.
      // The contract's ECDSA.recover expects this exact format (no
      // EIP-191 wrapping). Wallet support varies:
      //   ✓ Rabby, Rainbow, Trust, Frame, Ledger Live (with blind sign)
      //   ✗ MetaMask blocks eth_sign by default
      const sig = (await walletClient.request({
        method: "eth_sign",
        params: [expectedSigner, digest],
      } as never)) as Hex;
      if (!sig || !isHex(sig) || sig.length !== 132) {
        throw new Error(`wallet returned malformed signature: ${sig}`);
      }
      setSigInput(sig);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      if (
        /eth_sign|method not (supported|found)|disabled|user rejected|not allowed/i.test(
          msg,
        )
      ) {
        setError(
          `Your wallet rejected the eth_sign request. This is a wallet-` +
            `level limitation, not a bug in this app. Workarounds:\n` +
            `  • In MetaMask: Settings → Advanced → enable "eth_sign requests" (not recommended for production keys).\n` +
            `  • Switch wallet to Rabby / Rainbow / Frame / Ledger Live which allow eth_sign by default.\n` +
            `  • Use the "Sign with private key" tab (testnet only).\n` +
            `  • Use the "Paste signature" tab and sign with bridge-ceremony CLI.`,
        );
      } else {
        setError(msg);
      }
    } finally {
      setBusy(false);
    }
  }

  async function signWithPrivateKey() {
    if (!digest) return;
    setBusy(true);
    setError(null);
    try {
      const trimmed = pkInput.trim();
      const pk = (
        trimmed.startsWith("0x") ? trimmed : "0x" + trimmed
      ) as Hex;
      if (!isHex(pk) || pk.length !== 66) {
        throw new Error("private key must be 32 bytes (0x + 64 hex chars)");
      }
      const account = privateKeyToAccount(pk);
      // Raw 32-byte hash signing via viem — no EIP-191 prefix.
      const sig = await account.sign({ hash: digest });
      setSigInput(sig);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  function copyToClipboard(text: string) {
    void navigator.clipboard.writeText(text);
  }

  if (!root) {
    return (
      <div className="root-signer">
        <h2>Root Update Signature</h2>
        <p className="hint">Build a merkle tree first.</p>
      </div>
    );
  }

  const sigOk =
    !!recovered &&
    !!expectedSigner &&
    recovered.toLowerCase() === expectedSigner.toLowerCase();

  return (
    <div className="root-signer">
      <h2>Root Update Signature</h2>
      <p className="hint">
        The deployer EOA signs <code>(blockNumber, merkleRoot)</code>. The
        first <code>claim()</code> using this signature advances{" "}
        <code>latestRoot</code> on-chain — that's how the root gets
        "deployed". Pick a signing method below.
      </p>

      <div className="form-row">
        <label>
          blockNumber (Hypersnap block — pick any uint64; first claim must
          use this exact value)
        </label>
        <input
          type="text"
          value={blockStr}
          onChange={(e) => setBlockStr(e.target.value)}
          spellCheck={false}
        />
      </div>

      {digest && (
        <>
          <div className="form-row">
            <label>Digest to sign</label>
            <div className="copy-line">
              <code className="block-code">{digest}</code>
              <button
                className="secondary tiny"
                onClick={() => copyToClipboard(digest)}
                title="Copy digest hex"
              >
                copy
              </button>
            </div>
          </div>

          <div className="signer-modes">
            <button
              className={`tab ${mode === "wallet" ? "active" : ""}`}
              onClick={() => setMode("wallet")}
            >
              Sign with connected wallet
            </button>
            <button
              className={`tab ${mode === "key" ? "active" : ""}`}
              onClick={() => setMode("key")}
            >
              Sign with private key (testnet)
            </button>
            <button
              className={`tab ${mode === "paste" ? "active" : ""}`}
              onClick={() => setMode("paste")}
            >
              Paste signature
            </button>
          </div>

          {mode === "wallet" && (
            <>
              <p className="hint">
                Click the button to ask your connected wallet to sign the
                digest via <code>eth_sign</code> (raw 32-byte hash signing,
                what the bridge contract expects). The wallet may show a
                blind-signing warning — that's expected; the digest is the
                merkle root binding shown above.
              </p>
              <p className="hint">
                <strong>Wallet compatibility:</strong> Rabby, Rainbow, Trust,
                Frame, and Ledger Live forward <code>eth_sign</code> to the
                underlying key. MetaMask blocks it by default — if your
                wallet is MetaMask, switch to a different mode below.
              </p>
              <button
                className="deploy-btn"
                onClick={signWithWallet}
                disabled={busy || !walletClient}
              >
                {busy
                  ? "Waiting for wallet…"
                  : "Sign Root Update via Connected Wallet"}
              </button>
            </>
          )}

          {mode === "key" && (
            <>
              <p className="hint">
                Browser-based signing. Paste the deployer's private key (32
                bytes hex) and click Sign — the digest is signed locally
                via viem with no EIP-191 wrapping. <strong>Use only with
                test/throwaway keys</strong> — production keys should sign
                via the paste path with a hardware wallet.
              </p>
              <div className="form-row">
                <label>Private key</label>
                <input
                  type="password"
                  placeholder="0x… 64 hex chars"
                  value={pkInput}
                  onChange={(e) => setPkInput(e.target.value)}
                  spellCheck={false}
                  autoComplete="off"
                />
              </div>
              <button
                className="deploy-btn"
                onClick={signWithPrivateKey}
                disabled={busy || !pkInput}
              >
                {busy ? "Signing…" : "Sign Root Update"}
              </button>
            </>
          )}

          {mode === "paste" && (
            <>
              <p className="hint">
                For production: sign the digest with the in-house{" "}
                <code>bridge-ceremony</code> CLI (raw 32-byte hash signing,
                no third-party dependency), then paste the resulting 65-byte
                signature here. The key is read from{" "}
                <code>HYPERSNAP_DEPLOYER_KEY</code> if set, otherwise from
                stdin (no-echo prompt when interactive, plain readline when
                piped). It's never taken as a CLI flag.
              </p>
              <div className="form-row">
                <label>CLI command (interactive — will prompt)</label>
                <div className="copy-line">
                  <code className="block-code">
                    {ceremonySignCommand(digest)}
                  </code>
                  <button
                    className="secondary tiny"
                    onClick={() => copyToClipboard(ceremonySignCommand(digest))}
                  >
                    copy
                  </button>
                </div>
                <p className="hint" style={{ marginTop: 6 }}>
                  Or skip the digest hop:{" "}
                  <code>
                    bridge-ceremony sign root-update --root {root.slice(0, 12)}…
                    --block {blockStr}
                  </code>
                </p>
              </div>
              <div className="form-row">
                <label>Signature (65 bytes hex)</label>
                <input
                  type="text"
                  placeholder="0x…"
                  value={sigInput}
                  onChange={(e) => setSigInput(e.target.value)}
                  spellCheck={false}
                />
              </div>
            </>
          )}

          {sigInput && recovered && (
            <div
              className={`status ${sigOk ? "deployed" : "error"}`}
              style={{ marginTop: 12 }}
            >
              <div className="addr-row">
                <span className="addr-label">Sig recovers to:</span>
                <code>{recovered}</code>
              </div>
              {sigOk ? (
                <div className="check">
                  ✓ matches connected wallet — ready to submit claim below
                </div>
              ) : (
                <div>
                  ✗ does NOT match connected wallet ({expectedSigner}). Sign
                  with the right key.
                </div>
              )}
            </div>
          )}

          {error && <div className="status error">{error}</div>}
        </>
      )}
    </div>
  );
}
