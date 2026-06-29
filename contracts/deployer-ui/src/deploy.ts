import {
  encodeAbiParameters,
  encodeFunctionData,
  parseAbiParameters,
  type Address,
  type Hex,
} from "viem";
import {
  getPublicClient,
  readContract,
  waitForTransactionReceipt,
  writeContract,
} from "@wagmi/core";
import { config } from "./wagmi";
import { CREATEX, CREATEX_ABI } from "./createx";
import { BRIDGE_ABI } from "./abis";
import { BRIDGE_BYTECODE, PROXY_BYTECODE } from "./bytecode";
import {
  IMPL_SALT_TAG,
  PROXY_SALT_TAG,
  guardedCrossChainSalt,
  saltFor,
} from "./salt";

export type DeployStatus =
  | { kind: "loading" }
  | { kind: "no-createx" }
  | { kind: "deployed"; proxy: Address; impl: Address }
  | {
      kind: "pending";
      expectedProxy: Address;
      expectedImpl: Address;
      implSalt: Hex;
      proxySalt: Hex;
    };

export type DeployResult =
  | { kind: "already-deployed"; proxy: Address; impl: Address }
  | {
      kind: "deployed";
      proxy: Address;
      impl: Address;
      implTxHash: Hex;
      proxyTxHash: Hex;
    };

/**
 * Discrete phases of a deploy run. ChainCard maps these into a visual
 * step indicator so the user can tell at a glance which transaction the
 * wallet is currently asking them to sign.
 */
export type DeployPhase =
  | { step: "impl"; status: "checking" }
  | { step: "impl"; status: "already-exists"; address: Address }
  | { step: "impl"; status: "signing"; address: Address }
  | { step: "impl"; status: "pending"; address: Address; tx: Hex }
  | { step: "impl"; status: "confirmed"; address: Address; tx: Hex }
  | { step: "proxy"; status: "preparing"; address: Address }
  | { step: "proxy"; status: "signing"; address: Address }
  | { step: "proxy"; status: "pending"; address: Address; tx: Hex }
  | { step: "proxy"; status: "confirmed"; address: Address; tx: Hex };

export interface DeployCallbacks {
  onPhase: (phase: DeployPhase) => void;
  onLog: (msg: string) => void;
}

const TOKEN_NAME = "Hypersnap";
const TOKEN_SYMBOL = "SNAP";

async function predictAddresses(deployer: Address, chainId: number) {
  // The "raw" salts are what we pass to `deployCreate3`. CreateX
  // internally guards them via `_guard(salt)` before doing the CREATE2.
  // For address prediction, we must apply the same `_guard` transform
  // ourselves and pass the guarded result to the pure two-arg
  // `computeCreate3Address` — see [`guardedCrossChainSalt`] for why.
  const implSalt = saltFor(deployer, IMPL_SALT_TAG);
  const proxySalt = saltFor(deployer, PROXY_SALT_TAG);

  const implGuarded = guardedCrossChainSalt(deployer, implSalt);
  const proxyGuarded = guardedCrossChainSalt(deployer, proxySalt);

  const [expectedImpl, expectedProxy] = await Promise.all([
    readContract(config, {
      chainId: chainId as never,
      address: CREATEX,
      abi: CREATEX_ABI,
      functionName: "computeCreate3Address",
      args: [implGuarded, CREATEX],
    }),
    readContract(config, {
      chainId: chainId as never,
      address: CREATEX,
      abi: CREATEX_ABI,
      functionName: "computeCreate3Address",
      args: [proxyGuarded, CREATEX],
    }),
  ]);

  return { expectedImpl, expectedProxy, implSalt, proxySalt };
}

export async function checkDeployStatus(
  deployer: Address,
  chainId: number,
): Promise<DeployStatus> {
  const publicClient = getPublicClient(config, { chainId: chainId as never });
  if (!publicClient) return { kind: "no-createx" };

  const createxCode = await publicClient.getCode({ address: CREATEX });
  if (!createxCode || createxCode === "0x") {
    return { kind: "no-createx" };
  }

  const { expectedImpl, expectedProxy, implSalt, proxySalt } =
    await predictAddresses(deployer, chainId);

  const proxyCode = await publicClient.getCode({ address: expectedProxy });
  if (proxyCode && proxyCode !== "0x" && proxyCode.length > 2) {
    return { kind: "deployed", proxy: expectedProxy, impl: expectedImpl };
  }

  return {
    kind: "pending",
    expectedProxy,
    expectedImpl,
    implSalt,
    proxySalt,
  };
}

export async function deploy(
  deployer: Address,
  chainId: number,
  callbacks: DeployCallbacks,
): Promise<DeployResult> {
  const onProgress = callbacks.onLog;
  const onPhase = callbacks.onPhase;
  const status = await checkDeployStatus(deployer, chainId);

  if (status.kind === "no-createx") {
    throw new Error(
      "CreateX is not deployed at the canonical address on this chain. Deployment cannot proceed deterministically.",
    );
  }
  if (status.kind === "deployed") {
    return {
      kind: "already-deployed",
      proxy: status.proxy,
      impl: status.impl,
    };
  }
  if (status.kind === "loading") {
    throw new Error("status still loading");
  }

  const { expectedImpl, expectedProxy, implSalt, proxySalt } = status;

  const publicClient = getPublicClient(config, { chainId: chainId as never });
  if (!publicClient) throw new Error("no public client for chain");

  // 1. Implementation. Skip the call if the impl already exists at its
  //    expected address (someone else may have deployed it from a
  //    previous half-completed run).
  onPhase({ step: "impl", status: "checking" });
  const existingImplCode = await publicClient.getCode({
    address: expectedImpl,
  });
  let implTxHash: Hex;
  if (existingImplCode && existingImplCode !== "0x") {
    onProgress("Implementation already exists at expected address");
    onPhase({
      step: "impl",
      status: "already-exists",
      address: expectedImpl,
    });
    implTxHash = "0x" as Hex;
  } else {
    onPhase({ step: "impl", status: "signing", address: expectedImpl });
    onProgress("Sign implementation deploy in your wallet…");
    implTxHash = await writeContract(config, {
      chainId: chainId as never,
      address: CREATEX,
      abi: CREATEX_ABI,
      functionName: "deployCreate3",
      args: [implSalt, BRIDGE_BYTECODE as Hex],
    });
    onPhase({
      step: "impl",
      status: "pending",
      address: expectedImpl,
      tx: implTxHash,
    });
    onProgress(`Implementation tx submitted: ${implTxHash}`);
    const implReceipt = await waitForTransactionReceipt(config, {
      chainId: chainId as never,
      hash: implTxHash,
    });
    if (implReceipt.status !== "success") {
      throw new Error(
        `Implementation tx ${implTxHash} reverted (status: ${implReceipt.status}). ` +
          `Inspect the tx on the chain explorer for the revert reason. ` +
          `Common cause: the deployer EOA has previously used this CreateX salt — ` +
          `try rotating HYPERSNAP_SALT_TAG (e.g. to 'hypersnap.v2').`,
      );
    }
    onPhase({
      step: "impl",
      status: "confirmed",
      address: expectedImpl,
      tx: implTxHash,
    });
    onProgress("Implementation tx confirmed");
  }

  // **Critical guard**: re-check the impl actually has code at the
  // predicted address before we encode that address into the proxy's
  // constructor args. If we predicted X but the impl somehow ended up
  // elsewhere (or didn't deploy at all), the proxy's
  // `_setImplementation` would revert under `code.length == 0` — and
  // wallets correctly flag this as "likely to fail" during simulation.
  const finalImplCode = await publicClient.getCode({ address: expectedImpl });
  if (!finalImplCode || finalImplCode === "0x") {
    throw new Error(
      `Implementation address ${expectedImpl} has no code after impl tx. ` +
        `This means the predicted CREATE3 address didn't match the actual ` +
        `deployment, or the deploy tx reverted silently. Aborting before ` +
        `the proxy step (which would also revert).`,
    );
  }
  onProgress(`Implementation verified at ${expectedImpl}`);

  // 2. Proxy with atomic initialize.
  onPhase({ step: "proxy", status: "preparing", address: expectedProxy });
  const initCalldata = encodeFunctionData({
    abi: BRIDGE_ABI as readonly unknown[],
    functionName: "initialize",
    args: [deployer, TOKEN_NAME, TOKEN_SYMBOL],
  } as never);
  const proxyConstructorArgs = encodeAbiParameters(
    parseAbiParameters("address, bytes"),
    [expectedImpl, initCalldata],
  );
  const proxyInitCode = (PROXY_BYTECODE +
    proxyConstructorArgs.slice(2)) as Hex;

  onPhase({ step: "proxy", status: "signing", address: expectedProxy });
  onProgress("Sign proxy deploy in your wallet…");
  const proxyTxHash = await writeContract(config, {
    chainId: chainId as never,
    address: CREATEX,
    abi: CREATEX_ABI,
    functionName: "deployCreate3",
    args: [proxySalt, proxyInitCode],
  });
  onPhase({
    step: "proxy",
    status: "pending",
    address: expectedProxy,
    tx: proxyTxHash,
  });
  onProgress(`Proxy tx submitted: ${proxyTxHash}`);
  const proxyReceipt = await waitForTransactionReceipt(config, {
    chainId: chainId as never,
    hash: proxyTxHash,
  });
  if (proxyReceipt.status !== "success") {
    throw new Error(
      `Proxy tx ${proxyTxHash} reverted (status: ${proxyReceipt.status}). ` +
        `Inspect on the chain explorer. The impl is at ${expectedImpl}; ` +
        `if it has code there, the proxy revert is most likely a CreateX ` +
        `salt collision (proxy already exists at ${expectedProxy} with ` +
        `different code). Try a new HYPERSNAP_SALT_TAG.`,
    );
  }

  // Final sanity: confirm the proxy actually exists at the predicted address.
  const finalProxyCode = await publicClient.getCode({ address: expectedProxy });
  if (!finalProxyCode || finalProxyCode === "0x") {
    throw new Error(
      `Proxy address ${expectedProxy} has no code after proxy tx mined ` +
        `successfully. This shouldn't happen — please report.`,
    );
  }
  onPhase({
    step: "proxy",
    status: "confirmed",
    address: expectedProxy,
    tx: proxyTxHash,
  });
  onProgress(`Proxy verified at ${expectedProxy}`);

  return {
    kind: "deployed",
    proxy: expectedProxy,
    impl: expectedImpl,
    implTxHash,
    proxyTxHash,
  };
}
