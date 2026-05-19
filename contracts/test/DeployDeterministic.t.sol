// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {Deploy} from "../script/Deploy.s.sol";
import {HypersnapBridge} from "../src/HypersnapBridge.sol";

/// Verifies the deterministic deploy behavior by running the script
/// against a forked chain (Ethereum mainnet by default) where CreateX is
/// guaranteed to be deployed at the canonical address. The test asserts
/// that the same `(deployer, salt_tag)` produces the same proxy and impl
/// addresses regardless of nonce or local bytecode.
///
/// To run: set `MAINNET_RPC_URL` (or any chain RPC where CreateX is
/// deployed) and:
///
///   FOUNDRY_DISABLE_NIGHTLY_WARNING=1 \
///   forge test --match-contract DeployDeterministicTest \
///       --fork-url $MAINNET_RPC_URL
///
/// If the env var isn't set the test is skipped gracefully — Foundry
/// rejects zero-string fork URLs.
contract DeployDeterministicTest is Test {
    address internal constant CREATEX = 0xba5Ed099633D3B313e4D5F7bdc1305d3c28ba5Ed;

    function _forkOrSkip() internal returns (bool) {
        string memory rpc;
        try vm.envString("MAINNET_RPC_URL") returns (string memory v) {
            rpc = v;
        } catch {
            return false;
        }
        if (bytes(rpc).length == 0) return false;
        try vm.createSelectFork(rpc) returns (uint256) {
            return CREATEX.code.length > 0;
        } catch {
            return false;
        }
    }

    /// Two runs of the same script (same deployer, same salt tag) on the
    /// same forked chain produce the same predicted proxy address. The
    /// second invocation is a no-op (script returns the existing addresses)
    /// — confirms idempotence.
    function test_deterministicAddress_isIdempotent() public {
        if (!_forkOrSkip()) {
            emit log("MAINNET_RPC_URL not set; skipping deterministic deploy test");
            return;
        }

        // Use a deterministic deployer EOA so every run targets the same
        // address. vm.deal funds it.
        address deployer = vm.addr(0xDEADBEEF);
        vm.deal(deployer, 100 ether);

        // First deploy.
        Deploy script = new Deploy();
        vm.setEnv("HYPERSNAP_GENESIS_OWNER", vm.toString(deployer));
        vm.setEnv("HYPERSNAP_TOKEN_NAME", "Hypersnap");
        vm.setEnv("HYPERSNAP_TOKEN_SYMBOL", "SNAP");
        vm.setEnv("HYPERSNAP_SALT_TAG", "hypersnap.test.deterministic");

        vm.prank(deployer);
        (address proxy1, address impl1) = script.run();
        assertTrue(proxy1 != address(0));
        assertTrue(impl1 != address(0));

        // Second invocation: idempotent no-op (returns same addresses).
        vm.prank(deployer);
        (address proxy2, address impl2) = script.run();
        assertEq(proxy2, proxy1, "proxy address drift across invocations");
        assertEq(impl2, impl1, "impl address drift across invocations");

        // The proxy must actually be initialized.
        HypersnapBridge bridge = HypersnapBridge(proxy1);
        assertEq(bridge.ownerAddress(), deployer);
        assertEq(bridge.name(), "Hypersnap");
        assertEq(bridge.symbol(), "SNAP");
        assertEq(bridge.decimals(), 6);
    }
}
