// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.24;

import {BridgeTest} from "./utils/BridgeTest.sol";
import {HypersnapBridge} from "../src/HypersnapBridge.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

contract InitializeTest is BridgeTest {
    function test_initialState() public view {
        assertEq(bridge.ownerAddress(), ownerEOA);
        assertEq(bridge.latestBlock(), 0);
        assertEq(bridge.latestRoot(), bytes32(0));
        assertEq(bridge.burnNonce(), 0);
        assertEq(bridge.pauseExpiry(), 0);
        assertEq(bridge.pendingImplementation(), address(0));
        assertEq(bridge.pendingUpgradeEffectiveAt(), 0);
        assertEq(bridge.totalSupply(), 0);
        assertEq(bridge.name(), "Hypersnap");
        assertEq(bridge.symbol(), "SNAP");
        assertEq(bridge.decimals(), 6);
    }

    function test_cannotReinitialize() public {
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        bridge.initialize(attackerEOA, "Evil", "EVIL");
    }

    function test_cannotInitializeWithZeroOwner() public {
        HypersnapBridge fresh = new HypersnapBridge();
        bytes memory badInit = abi.encodeCall(
            HypersnapBridge.initialize,
            (address(0), "X", "Y")
        );
        vm.expectRevert(HypersnapBridge.ZeroAddress.selector);
        new ERC1967Proxy(address(fresh), badInit);
    }

    function test_implementationCannotBeInitialized() public {
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        impl.initialize(ownerEOA, "x", "y");
    }

    function test_implementationOwnerIsZero() public view {
        // The impl contract was constructed with `_disableInitializers`; its
        // own ownerAddress is permanently 0. Any sig-gated function called
        // directly on impl reverts because ECDSA.recover never returns 0.
        assertEq(impl.ownerAddress(), address(0));
    }

    function test_initializeEmitsOwnerRotated() public {
        HypersnapBridge fresh = new HypersnapBridge();
        vm.expectEmit(true, true, false, false);
        emit HypersnapBridge.OwnerRotated(0, ownerEOA);
        bytes memory init = abi.encodeCall(
            HypersnapBridge.initialize,
            (ownerEOA, "Hypersnap", "SNAP")
        );
        new ERC1967Proxy(address(fresh), init);
    }
}
