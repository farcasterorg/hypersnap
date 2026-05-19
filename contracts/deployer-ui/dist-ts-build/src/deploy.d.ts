import { type Address, type Hex } from "viem";
export type DeployStatus = {
    kind: "loading";
} | {
    kind: "no-createx";
} | {
    kind: "deployed";
    proxy: Address;
    impl: Address;
} | {
    kind: "pending";
    expectedProxy: Address;
    expectedImpl: Address;
    implSalt: Hex;
    proxySalt: Hex;
};
export type DeployResult = {
    kind: "already-deployed";
    proxy: Address;
    impl: Address;
} | {
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
export type DeployPhase = {
    step: "impl";
    status: "checking";
} | {
    step: "impl";
    status: "already-exists";
    address: Address;
} | {
    step: "impl";
    status: "signing";
    address: Address;
} | {
    step: "impl";
    status: "pending";
    address: Address;
    tx: Hex;
} | {
    step: "impl";
    status: "confirmed";
    address: Address;
    tx: Hex;
} | {
    step: "proxy";
    status: "preparing";
    address: Address;
} | {
    step: "proxy";
    status: "signing";
    address: Address;
} | {
    step: "proxy";
    status: "pending";
    address: Address;
    tx: Hex;
} | {
    step: "proxy";
    status: "confirmed";
    address: Address;
    tx: Hex;
};
export interface DeployCallbacks {
    onPhase: (phase: DeployPhase) => void;
    onLog: (msg: string) => void;
}
export declare function checkDeployStatus(deployer: Address, chainId: number): Promise<DeployStatus>;
export declare function deploy(deployer: Address, chainId: number, callbacks: DeployCallbacks): Promise<DeployResult>;
