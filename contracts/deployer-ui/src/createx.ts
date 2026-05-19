// CreateX canonical address (https://createx.rocks/deployments). Same on
// every major EVM chain.
export const CREATEX = "0xba5Ed099633D3B313e4D5F7bdc1305d3c28ba5Ed" as const;

export const CREATEX_ABI = [
  {
    type: "function",
    name: "deployCreate3",
    inputs: [
      { name: "salt", type: "bytes32" },
      { name: "initCode", type: "bytes" },
    ],
    outputs: [{ name: "newContract", type: "address" }],
    stateMutability: "payable",
  },
  {
    type: "function",
    name: "computeCreate3Address",
    inputs: [
      { name: "salt", type: "bytes32" },
      { name: "deployer", type: "address" },
    ],
    outputs: [{ name: "computedAddress", type: "address" }],
    stateMutability: "view",
  },
] as const;
