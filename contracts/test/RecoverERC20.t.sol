// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.24;

import {BridgeTest} from "./utils/BridgeTest.sol";
import {HypersnapBridge} from "../src/HypersnapBridge.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/// Plain test ERC20 with a public mint so we can seed the bridge.
contract MockERC20 is ERC20 {
    constructor() ERC20("Mock", "MOCK") {}
    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

/// ERC20 whose `transfer` always returns false. SafeERC20 should detect and
/// revert.
contract MisbehavingERC20 is ERC20 {
    constructor() ERC20("Bad", "BAD") {}
    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
    function transfer(address, uint256) public pure override returns (bool) {
        return false;
    }
}

contract RecoverERC20Test is BridgeTest {
    MockERC20 internal token;

    function setUp() public override {
        super.setUp();
        token = new MockERC20();
        token.mint(address(bridge), 1000e18);
    }

    function test_recover_happyPath() public {
        bytes memory sig = _signRecoverErc20(
            block.chainid, 1, address(token), lpEOA, 250e18, OWNER_PK
        );

        vm.expectEmit(true, true, true, true);
        emit HypersnapBridge.ERC20Recovered(1, address(token), lpEOA, 250e18);

        bridge.recoverERC20(1, address(token), lpEOA, 250e18, sig);

        assertEq(token.balanceOf(lpEOA), 250e18);
        assertEq(token.balanceOf(address(bridge)), 750e18);
        assertEq(bridge.latestBlock(), 1);
    }

    function test_recover_cannotRecoverWrappedToken_reverts() public {
        bytes memory sig = _signRecoverErc20(
            block.chainid, 1, address(bridge), lpEOA, 100, OWNER_PK
        );
        vm.expectRevert(HypersnapBridge.CannotRecoverWrappedToken.selector);
        bridge.recoverERC20(1, address(bridge), lpEOA, 100, sig);
    }

    function test_recover_zeroRecipient_reverts() public {
        bytes memory sig = _signRecoverErc20(
            block.chainid, 1, address(token), address(0), 100, OWNER_PK
        );
        vm.expectRevert(HypersnapBridge.ZeroAddress.selector);
        bridge.recoverERC20(1, address(token), address(0), 100, sig);
    }

    function test_recover_badSig_reverts() public {
        bytes memory sig = _signRecoverErc20(
            block.chainid, 1, address(token), lpEOA, 100, ATTACKER_PK
        );
        vm.expectRevert(HypersnapBridge.BadOwnerSignature.selector);
        bridge.recoverERC20(1, address(token), lpEOA, 100, sig);
    }

    function test_recover_chainBound_reverts() public {
        // Sig produced for chainId 1, but we'll set chainid to 8453 before
        // calling. The contract recomputes the digest with `block.chainid`,
        // which differs from the chainId baked into the sig.
        bytes memory sig = _signRecoverErc20(
            1, 1, address(token), lpEOA, 100, OWNER_PK
        );
        vm.chainId(8453);
        vm.expectRevert(HypersnapBridge.BadOwnerSignature.selector);
        bridge.recoverERC20(1, address(token), lpEOA, 100, sig);
    }

    function test_recover_staleBlock_reverts() public {
        bridge.pause(5, _signPause(5, OWNER_PK)); // advance latestBlock=5
        bytes memory sig = _signRecoverErc20(
            block.chainid, 3, address(token), lpEOA, 100, OWNER_PK
        );
        vm.expectRevert(
            abi.encodeWithSelector(HypersnapBridge.StaleBlock.selector, 5, 3)
        );
        bridge.recoverERC20(3, address(token), lpEOA, 100, sig);
    }

    function test_recover_safeTransferDetectsBadToken_reverts() public {
        MisbehavingERC20 bad = new MisbehavingERC20();
        bad.mint(address(bridge), 100);
        bytes memory sig = _signRecoverErc20(
            block.chainid, 1, address(bad), lpEOA, 50, OWNER_PK
        );
        // SafeERC20 reverts SafeERC20FailedOperation when transfer returns false.
        vm.expectRevert();
        bridge.recoverERC20(1, address(bad), lpEOA, 50, sig);
    }

    function test_recover_isPermissionlessRelay() public {
        // Owner signs; anyone can submit.
        bytes memory sig = _signRecoverErc20(
            block.chainid, 1, address(token), lpEOA, 250e18, OWNER_PK
        );
        vm.prank(attackerEOA);
        bridge.recoverERC20(1, address(token), lpEOA, 250e18, sig);
        assertEq(token.balanceOf(lpEOA), 250e18);
    }
}
