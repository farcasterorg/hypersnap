import { useEffect, useState } from "react";
import { useAccount } from "wagmi";
import { readContract, getPublicClient } from "@wagmi/core";
import {
  encodeAbiParameters,
  encodeFunctionData,
  parseAbiParameters,
  type Address,
  type Hex,
} from "viem";
import { config, SUPPORTED_CHAINS } from "../wagmi";
import { CREATEX, CREATEX_ABI } from "../createx";
import { BRIDGE_ABI } from "../abis";
import {
  IMPL_SALT_TAG,
  PROXY_SALT_TAG,
  guardedCrossChainSalt,
  saltFor,
} from "../salt";

const TOKEN_NAME = "Hypersnap";
const TOKEN_SYMBOL = "SNAP";

interface PerChainVerifyState {
  chainId: number;
  chainName: string;
  implAddress: Address;
  proxyAddress: Address;
  implDeployed: boolean;
  proxyDeployed: boolean;
  initCalldata: Hex;
  proxyConstructorArgs: Hex;
}

export function VerifySection() {
  const { address: deployer } = useAccount();
  const [perChain, setPerChain] = useState<PerChainVerifyState[]>([]);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!deployer) return;
    setLoading(true);
    (async () => {
      const states = await Promise.all(
        SUPPORTED_CHAINS.map(async (chain) => {
          try {
            const implSalt = saltFor(deployer, IMPL_SALT_TAG);
            const proxySalt = saltFor(deployer, PROXY_SALT_TAG);
            const implGuarded = guardedCrossChainSalt(deployer, implSalt);
            const proxyGuarded = guardedCrossChainSalt(deployer, proxySalt);

            const [implAddress, proxyAddress] = await Promise.all([
              readContract(config, {
                chainId: chain.id as never,
                address: CREATEX,
                abi: CREATEX_ABI,
                functionName: "computeCreate3Address",
                args: [implGuarded, CREATEX],
              }) as Promise<Address>,
              readContract(config, {
                chainId: chain.id as never,
                address: CREATEX,
                abi: CREATEX_ABI,
                functionName: "computeCreate3Address",
                args: [proxyGuarded, CREATEX],
              }) as Promise<Address>,
            ]);

            const publicClient = getPublicClient(config, {
              chainId: chain.id as never,
            });
            let implDeployed = false;
            let proxyDeployed = false;
            if (publicClient) {
              const [implCode, proxyCode] = await Promise.all([
                publicClient.getCode({ address: implAddress }),
                publicClient.getCode({ address: proxyAddress }),
              ]);
              implDeployed = !!implCode && implCode !== "0x";
              proxyDeployed = !!proxyCode && proxyCode !== "0x";
            }

            const initCalldata = encodeFunctionData({
              abi: BRIDGE_ABI as readonly unknown[],
              functionName: "initialize",
              args: [deployer, TOKEN_NAME, TOKEN_SYMBOL],
            } as never);
            const proxyConstructorArgs = encodeAbiParameters(
              parseAbiParameters("address, bytes"),
              [implAddress, initCalldata],
            );

            return {
              chainId: chain.id,
              chainName: chain.name,
              implAddress,
              proxyAddress,
              implDeployed,
              proxyDeployed,
              initCalldata,
              proxyConstructorArgs,
            } as PerChainVerifyState;
          } catch {
            return null;
          }
        }),
      );
      setPerChain(states.filter((s): s is PerChainVerifyState => s !== null));
      setLoading(false);
    })();
  }, [deployer]);

  if (!deployer) {
    return (
      <div className="verify-section">
        <h2>Verify on Etherscan</h2>
        <p className="hint">Connect a wallet first.</p>
      </div>
    );
  }

  const deployedStates = perChain.filter(
    (s) => s.implDeployed || s.proxyDeployed,
  );

  return (
    <div className="verify-section">
      <h2>Verify on Etherscan-family explorers</h2>
      <p className="hint">
        After deploying, run the commands below in your{" "}
        <code>contracts/</code> directory to publish source code to each
        chain's block explorer. Each chain has its own API key — get them
        from Etherscan, BaseScan, Arbiscan, etc. Set <code>ETHERSCAN_API_KEY</code>{" "}
        per command, or configure all of them in{" "}
        <code>foundry.toml</code> under <code>[etherscan]</code>.
      </p>

      {loading && <div className="status loading">Loading on-chain state…</div>}

      {!loading && deployedStates.length === 0 && (
        <div className="status loading">
          No deployments detected yet. Run the Deploy step first.
        </div>
      )}

      {deployedStates.map((s) => (
        <ChainVerifyCard key={s.chainId} state={s} />
      ))}

      <details className="metadata-section">
        <summary>Token metadata (off-chain submissions)</summary>
        <p className="hint">
          The icon, description, website, and social links shown on
          Etherscan token pages and in wallets are submitted via off-chain
          forms — not on-chain. The contract is verified on-chain; metadata
          gets attached separately.
        </p>
        <ol>
          <li>
            <strong>Etherscan token info form</strong> — after contract
            verification, the proxy's token page on Etherscan shows an
            "Update Token Info" link. Submit logo (PNG, &lt;200KB),
            description, official website, social links, category. Approval
            takes 1–3 days.
          </li>
          <li>
            <strong>Coingecko</strong> —{" "}
            <a
              href="https://www.coingecko.com/en/coins/new"
              target="_blank"
              rel="noreferrer"
            >
              new-coin form
            </a>
            . Submit after listing on at least one DEX with meaningful
            liquidity.
          </li>
          <li>
            <strong>CoinMarketCap</strong> —{" "}
            <a
              href="https://coinmarketcap.com/request/"
              target="_blank"
              rel="noreferrer"
            >
              request form
            </a>
            . Same DEX-listing requirement.
          </li>
          <li>
            <strong>Token Lists</strong> —{" "}
            <a
              href="https://tokenlists.org"
              target="_blank"
              rel="noreferrer"
            >
              tokenlists.org
            </a>
            . Submit a JSON list to get auto-detection in MetaMask, Uniswap,
            and similar UIs.
          </li>
          <li>
            <strong>MetaMask Token API</strong> — open a PR against{" "}
            <a
              href="https://github.com/MetaMask/contract-metadata"
              target="_blank"
              rel="noreferrer"
            >
              MetaMask/contract-metadata
            </a>{" "}
            with your logo + metadata. Adds to MetaMask's auto-suggest.
          </li>
        </ol>
      </details>

      <details className="metadata-section">
        <summary>Total supply notes</summary>
        <p className="hint">
          The contract has no settable total supply — <code>totalSupply()</code>{" "}
          is the running <code>sum(claim amounts) - sum(burn amounts)</code>.
          For an initial launch allocation (treasury, LP, team), build the
          genesis merkle tree using the Verify tab's Tree Builder. Each leaf
          is one initial allocation; total supply post-claim equals the sum
          of leaves.
        </p>
        <p className="hint">
          If you want a <em>hard cap</em> on supply (so even validators can't
          exceed it), that requires a contract modification — currently not
          implemented. Ask before deploying if this matters.
        </p>
      </details>
    </div>
  );
}

function ChainVerifyCard({ state }: { state: PerChainVerifyState }) {
  const implCmd = formatVerifyCmd({
    chainId: state.chainId,
    address: state.implAddress,
    contract: "src/HypersnapBridge.sol:HypersnapBridge",
  });

  const proxyCmd = formatVerifyCmd({
    chainId: state.chainId,
    address: state.proxyAddress,
    contract:
      "lib/openzeppelin-contracts/contracts/proxy/ERC1967/ERC1967Proxy.sol:ERC1967Proxy",
    constructorArgs: state.proxyConstructorArgs,
  });

  return (
    <div className="verify-card">
      <div className="verify-header">
        <h3>{state.chainName}</h3>
        <span className="chain-id">chainId {state.chainId}</span>
      </div>

      <VerifyCmdRow
        label="Implementation"
        address={state.implAddress}
        deployed={state.implDeployed}
        cmd={implCmd}
      />
      <VerifyCmdRow
        label="Proxy (ERC1967)"
        address={state.proxyAddress}
        deployed={state.proxyDeployed}
        cmd={proxyCmd}
      />
    </div>
  );
}

function VerifyCmdRow({
  label,
  address,
  deployed,
  cmd,
}: {
  label: string;
  address: Address;
  deployed: boolean;
  cmd: string;
}) {
  const [copied, setCopied] = useState(false);

  function copy() {
    navigator.clipboard.writeText(cmd);
    setCopied(true);
    setTimeout(() => setCopied(false), 1200);
  }

  return (
    <div className="verify-row">
      <div className="verify-meta">
        <span className="verify-label">{label}:</span>
        <code>{address}</code>
        <span
          className={`verify-deployed ${deployed ? "yes" : "no"}`}
          title={deployed ? "deployed" : "not deployed yet"}
        >
          {deployed ? "deployed ✓" : "not deployed"}
        </span>
      </div>
      <div className="verify-cmd-wrapper">
        <pre className="verify-cmd">{cmd}</pre>
        <button
          className="secondary copy-btn"
          onClick={copy}
          disabled={!deployed}
          title={
            deployed
              ? "Copy to clipboard"
              : "Deploy this contract first"
          }
        >
          {copied ? "Copied ✓" : "Copy"}
        </button>
      </div>
    </div>
  );
}

function formatVerifyCmd(opts: {
  chainId: number;
  address: Address;
  contract: string;
  constructorArgs?: Hex;
}): string {
  const lines = [
    "forge verify-contract \\",
    `  --chain ${opts.chainId} \\`,
    `  --etherscan-api-key $ETHERSCAN_API_KEY \\`,
    `  --watch \\`,
  ];
  if (opts.constructorArgs) {
    lines.push(`  --constructor-args ${opts.constructorArgs} \\`);
  }
  lines.push(`  ${opts.address} \\`);
  lines.push(`  ${opts.contract}`);
  return lines.join("\n");
}
