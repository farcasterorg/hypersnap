import {
  encodePacked,
  keccak256,
  pad,
  toBytes,
  type Address,
  type Hex,
} from "viem";

/**
 * Compose a CreateX salt with frontrun protection (deployer in bytes
 * 0..19) and cross-chain consistency enabled (byte 20 = 0x00).
 *
 * Layout: deployer(20) || 0x00(1) || keccak256(tag)[0..10](11)
 *
 * This is the **raw** salt as understood by CreateX. CreateX further
 * transforms it via `_guard` before the underlying CREATE2 — see
 * [`guardedCrossChainSalt`] for the address-prediction-relevant value.
 */
export function saltFor(deployer: Address, tag: string): Hex {
  const entropyHash = keccak256(toBytes(tag));
  const first11 = ("0x" + entropyHash.slice(2, 24)) as Hex;
  return encodePacked(
    ["address", "bytes1", "bytes11"],
    [deployer, "0x00", first11],
  );
}

/**
 * Apply CreateX's `_guard` transformation for the case our salts use:
 *   - bytes 0..19 == deployer (msg.sender)        → SenderBytes.MsgSender
 *   - byte 20      == 0x00 (cross-chain enabled)  → RedeployProtectionFlag.False
 *
 * Per CreateX (https://github.com/pcaversaccio/createx, see `_guard`):
 *
 *   guardedSalt = _efficientHash(
 *     bytes32(uint256(uint160(msgSender))),  // 32-byte left-padded address
 *     salt                                   // 32-byte raw salt
 *   )
 *   = keccak256(64 bytes: pad32(msgSender) || salt)
 *
 * This guarded salt is what `computeCreate3Address(bytes32, address)`
 * needs to receive in order to predict the address that
 * `deployCreate3(rawSalt, ...)` will actually deploy at. The two-arg
 * `computeCreate3Address` is `pure` and does NOT apply `_guard` itself —
 * it just runs the CREATE3 derivation on whatever salt you hand it.
 *
 * The single-arg `computeCreate3Address(bytes32)` does apply `_guard`,
 * but because `_guard` reads `_msgSender()`, it returns the wrong address
 * over public RPC where most providers default the `from` field to
 * `address(0)` regardless of what the eth_call request specifies. So we
 * compute the guard ourselves and use the two-arg version.
 */
export function guardedCrossChainSalt(deployer: Address, rawSalt: Hex): Hex {
  return keccak256(
    encodePacked(
      ["bytes32", "bytes32"],
      [pad(deployer, { size: 32 }), rawSalt],
    ),
  );
}

export const SALT_TAG_PREFIX = "hypersnap.v1";
export const IMPL_SALT_TAG = `${SALT_TAG_PREFIX}.impl`;
export const PROXY_SALT_TAG = `${SALT_TAG_PREFIX}.proxy`;
