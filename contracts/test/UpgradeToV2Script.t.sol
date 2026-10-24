// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.24;

import {BridgeV2Test} from "./utils/BridgeV2Test.sol";
import {UpgradeToV2} from "../script/UpgradeToV2.s.sol";
import {HypersnapBridge} from "../src/HypersnapBridge.sol";

/// Phases 2 and 3 of `script/UpgradeToV2.s.sol` on a local v1 proxy. Phase 1
/// needs CreateX; the fork rehearsal covers the deployment path.
contract UpgradeToV2ScriptTest is BridgeV2Test {
    UpgradeToV2 internal script;

    function setUp() public override {
        super.setUp();
        script = new UpgradeToV2();
    }

    function test_script_digestMatchesV1() public view {
        assertEq(
            script.upgradeDigest(address(bridge), address(v2Impl), 7),
            _upgradeDigest(7, address(v2Impl))
        );
    }

    function test_script_proposeThenExecute() public {
        bytes32 lockId = keccak256("script-lock");
        bytes32 leaf = _lockLeafEvm(lockId, uint32(block.chainid), lpEOA, 2_000_000);
        bridge.claim(
            1,
            leaf,
            _signRootUpdate(1, leaf, OWNER_PK),
            lockId,
            lpEOA,
            2_000_000,
            uint32(block.chainid),
            new bytes32[](0)
        );

        script.propose(
            address(bridge), address(v2Impl), 2, _signUpgrade(2, address(v2Impl), OWNER_PK)
        );
        assertEq(bridge.pendingImplementation(), address(v2Impl));

        vm.expectRevert("UpgradeToV2: delay not elapsed");
        script.execute(address(bridge));

        vm.warp(bridge.pendingUpgradeEffectiveAt());
        script.execute(address(bridge));

        assertEq(v2.setRoot(1), SET_ROOT_1);
        assertEq(v2.totalWeight(1), WEIGHT_1);
        assertEq(v2.balanceOf(lpEOA), 2_000_000);
        assertTrue(v2.claimed(lockId));
    }

    function test_script_proposeRejectsOtherSigner() public {
        bytes memory sig = _signUpgrade(1, address(v2Impl), ATTACKER_PK);
        vm.expectRevert("UpgradeToV2: signature is not by ownerAddress");
        script.propose(address(bridge), address(v2Impl), 1, sig);
    }

    function test_script_rejectsStaleBlockNumber() public {
        bridge.pause(5, _signPause(5, OWNER_PK));
        vm.expectRevert("UpgradeToV2: blockNumber <= latestBlock");
        script.upgradeDigest(address(bridge), address(v2Impl), 5);
    }

    function test_script_rejectsNonV2Implementation() public {
        HypersnapBridge otherV1 = new HypersnapBridge();
        vm.expectRevert();
        script.upgradeDigest(address(bridge), address(otherV1), 1);
    }

    function test_script_executeRequiresPending() public {
        vm.expectRevert("UpgradeToV2: no pending upgrade");
        script.execute(address(bridge));
    }
}
