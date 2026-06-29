// Verifies the off-chain `guardedCrossChainSalt` matches a known
// on-chain value pinned from a real CreateX deployment.
//
// Run after any change to `src/salt.ts`:
//   npm run verify-salt-guard
//
// The pinned vector is taken from the impl deploy on Ethereum mainnet,
// tx 0xbfe275510311b25cb328fd49a83f80dc6cafef33b3366b6f3a7f5053dd4e150f:
//
//   - msg.sender:    0x32d1550efcf63edd8f570b8418ac7c21fc6785e8
//   - raw salt:      0x32d1550efcf63edd8f570b8418ac7c21fc6785e800d7ebb9e98db13126f7b3dd
//   - guarded salt:  0xd33c6a9f1ca8ab0e32c7bc2128c0a998c36a4bd47c6bbf6e53cb1e1adf35b802
//     (extracted from the indexed `salt` topic on CreateX's
//     `Create3ProxyContractCreation` event in the receipt)
//
// The salt-guard logic is inlined here (rather than imported from src/)
// so this Node script doesn't need DOM types, but it must stay byte-
// identical to `src/salt.ts::guardedCrossChainSalt`.

import {
  encodePacked,
  keccak256,
  pad,
  type Address,
  type Hex,
} from "viem";

function guardedCrossChainSalt(deployer: Address, rawSalt: Hex): Hex {
  return keccak256(
    encodePacked(
      ["bytes32", "bytes32"],
      [pad(deployer, { size: 32 }), rawSalt],
    ),
  );
}

const RAW_SALT =
  "0x32d1550efcf63edd8f570b8418ac7c21fc6785e800d7ebb9e98db13126f7b3dd" as const;
const DEPLOYER = "0x32d1550efcf63edd8f570b8418ac7c21fc6785e8" as const;
const EXPECTED_GUARDED =
  "0xd33c6a9f1ca8ab0e32c7bc2128c0a998c36a4bd47c6bbf6e53cb1e1adf35b802" as const;

const computed = guardedCrossChainSalt(DEPLOYER, RAW_SALT);

if (computed.toLowerCase() !== EXPECTED_GUARDED.toLowerCase()) {
  console.error("guardedCrossChainSalt drift!");
  console.error("  computed:", computed);
  console.error("  expected:", EXPECTED_GUARDED);
  process.exit(1);
}
console.log("guardedCrossChainSalt: OK (matches on-chain pin)");
