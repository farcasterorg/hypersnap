// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.24;

import {Vm} from "forge-std/Vm.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {ERC1967Utils} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Utils.sol";
import {BridgeV2Test} from "./utils/BridgeV2Test.sol";
import {MerkleHelper} from "./utils/MerkleHelper.sol";
import {HypersnapBridge} from "../src/HypersnapBridge.sol";
import {HypersnapBridgeV2} from "../src/HypersnapBridgeV2.sol";
import {ICertificateVerifier} from "../src/interfaces/ICertificateVerifier.sol";

/// The v1 → v2 upgrade on a v1 proxy deployed like `script/Deploy.s.sol`,
/// and the storage layout of v2 against v1.
contract HypersnapBridgeV2UpgradeTest is BridgeV2Test {
    // OpenZeppelin 5.0.2 ERC-7201 namespaces (shared by v1 and v2).
    bytes32 internal constant ERC20_NS =
        0x52c63247e1f47db19d5ce0460030c497f067ca4cebf71ba98eeadabe20bace00;
    bytes32 internal constant EIP712_NS =
        0xa16a46d94261c7517cc8ff89f61c0ce93598e3c849801011dee649a6a557d100;
    bytes32 internal constant NONCES_NS =
        0x5ab42ced628888259c08ac98db1eb0cf702fc1501344311d8b100cd1bfe4bb00;
    bytes32 internal constant INITIALIZABLE_NS =
        0xf0c57e16840df040f15088dc2f81fe391c3923bec73e23a9662efc9c229c6a00;

    bytes32 internal constant PERMIT_TYPEHASH = keccak256(
        "Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"
    );

    bytes32 internal constant RETRO_A = keccak256("retro-a");
    bytes32 internal constant RETRO_B = keccak256("retro-b");
    bytes32 internal constant RETRO_C = keccak256("retro-c"); // never claimed in v1

    address internal alice; // = lpEOA (has a key, for permit)
    address internal bob = makeAddr("bob");
    address internal carol = makeAddr("carol");

    bytes32[] internal retroLeaves;
    bytes32 internal retroRoot;

    struct Snapshot {
        uint256 totalSupply;
        uint256 balAlice;
        uint256 balBob;
        uint256 balCarol;
        uint256 allowanceAliceCarol;
        uint256 allowanceAliceBob;
        uint256 nonceAlice;
        string name;
        string symbol;
        uint8 decimals;
        bytes32 domainSeparator;
        uint256 burnNonce;
        uint64 pauseExpiry;
        bool claimedA;
        bool claimedB;
        bool claimedC;
        bytes32[50] slots; // contract-declared slots 0..49
        bytes32[9] namespaced;
    }

    function setUp() public override {
        super.setUp();
        alice = lpEOA;
    }

    // -----------------------------------------------------------------------
    // v1 state
    // -----------------------------------------------------------------------

    function _retroProof(uint256 i) internal view returns (bytes32[] memory) {
        return MerkleHelper.proofFor(retroLeaves, i);
    }

    function _retroIndex(bytes32 leaf) internal view returns (uint256) {
        for (uint256 i = 0; i < retroLeaves.length; i++) {
            if (retroLeaves[i] == leaf) return i;
        }
        revert("missing");
    }

    function _permit(uint256 ownerPk, address spender, uint256 value) internal {
        address owner_ = vm.addr(ownerPk);
        uint256 deadline = block.timestamp + 1 days;
        bytes32 structHash = keccak256(
            abi.encode(PERMIT_TYPEHASH, owner_, spender, value, bridge.nonces(owner_), deadline)
        );
        bytes32 digest =
            keccak256(abi.encodePacked("\x19\x01", bridge.DOMAIN_SEPARATOR(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPk, digest);
        bridge.permit(owner_, spender, value, deadline, v, r, s);
    }

    /// Retro claims (owner-signed root), transfers, an allowance, a permit,
    /// burns, and an expired pause.
    function _populateV1() internal {
        bytes32 leafA = _lockLeafEvm(RETRO_A, uint32(block.chainid), alice, 8_000_000);
        bytes32 leafB = _lockLeafEvm(RETRO_B, uint32(block.chainid), bob, 3_000_000);
        bytes32 leafC = _lockLeafEvm(RETRO_C, uint32(block.chainid), carol, 1_000_000);
        retroLeaves.push(leafA);
        retroLeaves.push(leafB);
        retroLeaves.push(leafC);
        MerkleHelper.sortAscending(retroLeaves);
        retroRoot = MerkleHelper.root(retroLeaves);

        bridge.claim(
            1,
            retroRoot,
            _signRootUpdate(1, retroRoot, OWNER_PK),
            RETRO_A,
            alice,
            8_000_000,
            uint32(block.chainid),
            _retroProof(_retroIndex(leafA))
        );
        bridge.claim(
            1,
            retroRoot,
            "",
            RETRO_B,
            bob,
            3_000_000,
            uint32(block.chainid),
            _retroProof(_retroIndex(leafB))
        );

        vm.prank(alice);
        bridge.transfer(bob, 1_000_000);
        vm.prank(alice);
        bridge.approve(carol, 2_000_000);
        _permit(LP_PK, bob, 500_000);
        vm.prank(alice);
        bridge.burn(1_500_000, bytes32(uint256(111)));
        vm.prank(bob);
        bridge.burn(250, bytes32(uint256(222))); // v1 has no minimum

        bridge.pause(2, _signPause(2, OWNER_PK));
        vm.warp(bridge.pauseExpiry());
    }

    function _namespacedSlots() internal view returns (bytes32[9] memory s) {
        address p = address(bridge);
        s[0] = vm.load(p, keccak256(abi.encode(alice, ERC20_NS))); // _balances[alice]
        s[1] = vm.load(p, keccak256(abi.encode(bob, ERC20_NS))); // _balances[bob]
        s[2] = vm.load(
            p, keccak256(abi.encode(carol, keccak256(abi.encode(alice, uint256(ERC20_NS) + 1))))
        ); // _allowances[alice][carol]
        s[3] = vm.load(p, bytes32(uint256(ERC20_NS) + 2)); // _totalSupply
        s[4] = vm.load(p, bytes32(uint256(ERC20_NS) + 3)); // _name
        s[5] = vm.load(p, bytes32(uint256(ERC20_NS) + 4)); // _symbol
        s[6] = vm.load(p, EIP712_NS); // _hashedName
        s[7] = vm.load(p, bytes32(uint256(EIP712_NS) + 2)); // _name
        s[8] = vm.load(p, keccak256(abi.encode(alice, NONCES_NS))); // _nonces[alice]
    }

    function _snapshot() internal view returns (Snapshot memory s) {
        s.totalSupply = bridge.totalSupply();
        s.balAlice = bridge.balanceOf(alice);
        s.balBob = bridge.balanceOf(bob);
        s.balCarol = bridge.balanceOf(carol);
        s.allowanceAliceCarol = bridge.allowance(alice, carol);
        s.allowanceAliceBob = bridge.allowance(alice, bob);
        s.nonceAlice = bridge.nonces(alice);
        s.name = bridge.name();
        s.symbol = bridge.symbol();
        s.decimals = bridge.decimals();
        s.domainSeparator = bridge.DOMAIN_SEPARATOR();
        s.burnNonce = bridge.burnNonce();
        s.pauseExpiry = bridge.pauseExpiry();
        s.claimedA = bridge.claimed(RETRO_A);
        s.claimedB = bridge.claimed(RETRO_B);
        s.claimedC = bridge.claimed(RETRO_C);
        for (uint256 i = 0; i < 50; i++) {
            s.slots[i] = vm.load(address(bridge), bytes32(i));
        }
        s.namespaced = _namespacedSlots();
    }

    function _implementation() internal view returns (address) {
        return address(uint160(uint256(vm.load(address(bridge), ERC1967Utils.IMPLEMENTATION_SLOT))));
    }

    // -----------------------------------------------------------------------
    // Upgrade path
    // -----------------------------------------------------------------------

    function test_upgrade_v1ToV2_preservesState() public {
        _populateV1();
        assertEq(bridge.totalSupply(), 11_000_000 - 1_500_000 - 250);
        assertEq(bridge.burnNonce(), 2);
        assertEq(bridge.nonces(alice), 1);
        Snapshot memory pre = _snapshot();
        assertEq(_implementation(), address(impl));
        assertEq(uint256(vm.load(address(bridge), INITIALIZABLE_NS)), 1);
        // v1 slot 0 = latestBlock (2) << 160 | owner.
        assertEq(pre.slots[0], bytes32((uint256(2) << 160) | uint256(uint160(ownerEOA))));

        // The v1 owner's last proposeUpgrade → UPGRADE_DELAY → executeUpgrade.
        uint64 blockNumber = bridge.latestBlock() + 1;
        bytes memory sig = _signUpgrade(blockNumber, address(v2Impl), OWNER_PK);
        vm.prank(attackerEOA); // any relayer
        bridge.proposeUpgrade(blockNumber, address(v2Impl), sig);
        assertEq(bridge.pendingUpgradeEffectiveAt(), block.timestamp + 48 hours);
        vm.warp(block.timestamp + 48 hours - 1);
        vm.expectRevert();
        bridge.executeUpgrade();
        vm.warp(block.timestamp + 1);
        vm.prank(attackerEOA);
        bridge.executeUpgrade();
        assertEq(_implementation(), address(v2Impl));

        vm.expectEmit(true, false, false, true, address(v2));
        emit HypersnapBridgeV2.EpochAdvanced(1, SET_ROOT_1, WEIGHT_1);
        vm.expectEmit(false, false, false, true, address(v2));
        emit Initializable.Initialized(2);
        vm.prank(attackerEOA); // permissionless; values are fixed by the implementation
        v2.initializeV2(SET_ROOT_1, WEIGHT_1);

        Snapshot memory post = _snapshot();

        // ERC-20, EIP-712 and nonces.
        assertEq(post.totalSupply, pre.totalSupply);
        assertEq(post.balAlice, pre.balAlice);
        assertEq(post.balBob, pre.balBob);
        assertEq(post.balCarol, pre.balCarol);
        assertEq(post.allowanceAliceCarol, pre.allowanceAliceCarol);
        assertEq(post.allowanceAliceBob, pre.allowanceAliceBob);
        assertEq(post.nonceAlice, pre.nonceAlice);
        assertEq(post.name, "Hypersnap");
        assertEq(post.symbol, "SNAP");
        assertEq(post.decimals, 6);
        assertEq(post.domainSeparator, pre.domainSeparator);
        for (uint256 i = 0; i < 9; i++) {
            assertEq(post.namespaced[i], pre.namespaced[i]);
        }
        assertEq(uint256(vm.load(address(bridge), INITIALIZABLE_NS)), 2);

        // Bridge state.
        assertEq(post.burnNonce, 2);
        assertEq(post.pauseExpiry, pre.pauseExpiry);
        assertTrue(post.claimedA && post.claimedB && !post.claimedC);

        // Raw slots: 1..5 unchanged, 0 cleared, 6..9 new, 10..49 empty.
        assertEq(post.slots[0], bytes32(0), "v1 owner slot cleared");
        for (uint256 i = 1; i <= 5; i++) {
            assertEq(post.slots[i], pre.slots[i]);
        }
        assertEq(post.slots[1], retroRoot, "v1 retro root kept in slot 1");
        assertEq(post.slots[6], bytes32(0));
        assertEq(post.slots[7], bytes32(0));
        assertEq(post.slots[8], bytes32(uint256(1) << 64), "latestEpoch = 1 at slot 8 offset 8");
        assertEq(post.slots[9], bytes32(0));
        for (uint256 i = 10; i < 50; i++) {
            assertEq(post.slots[i], bytes32(0));
        }

        // v2 state.
        assertEq(v2.setRoot(1), SET_ROOT_1);
        assertEq(v2.totalWeight(1), WEIGHT_1);
        assertEq(v2.latestEpoch(), 1);
    }

    function test_upgrade_v2WorksOnMigratedState() public {
        _populateV1();
        _upgradeToV2();

        // Burn IDs continue from v1.
        vm.recordLogs();
        vm.prank(alice);
        uint256 id = v2.burn(1_000_000, bytes32(uint256(333)));
        assertEq(id, 3);
        Vm.Log[] memory logs = vm.getRecordedLogs();
        assertEq(uint256(logs[logs.length - 1].topics[1]), 3);

        // Allowances and permit nonces continue.
        vm.prank(carol);
        v2.transferFrom(alice, carol, 2_000_000);
        assertEq(v2.balanceOf(carol), 2_000_000);
        _permit(LP_PK, carol, 7);
        assertEq(v2.nonces(alice), 2);
        assertEq(v2.allowance(alice, carol), 7);

        // An anchored v2 lock claims on top of the migrated supply.
        uint256 supply = v2.totalSupply();
        bytes32 leaf = _leafV2(keccak256("v2-lock"), carol, 4_000_000);
        _anchor(PIVOT + 1, 1, leaf);
        v2.claim(keccak256("v2-lock"), carol, 4_000_000, uint32(block.chainid), new bytes32[](0));
        assertEq(v2.totalSupply(), supply + 4_000_000);
    }

    /// The v1 retro root is not a v2 claim root, and lock IDs claimed in v1
    /// stay claimed.
    function test_upgrade_retroClaimPathClosed() public {
        _populateV1();
        _upgradeToV2();
        bytes32 leafC = _lockLeafEvm(RETRO_C, uint32(block.chainid), carol, 1_000_000);
        bytes32[] memory proofC = _retroProof(_retroIndex(leafC));

        // No anchor yet: nothing is claimable.
        vm.expectRevert(HypersnapBridgeV2.BadMerkleProof.selector);
        v2.claim(RETRO_C, carol, 1_000_000, uint32(block.chainid), proofC);

        // After an anchor, the retro proof is still not against latestLockRoot.
        _anchor(PIVOT + 1, 1, keccak256("unrelated-lock-root"));
        vm.expectRevert(HypersnapBridgeV2.BadMerkleProof.selector);
        v2.claim(RETRO_C, carol, 1_000_000, uint32(block.chainid), proofC);

        // A lock ID that was claimed in v1 cannot be claimed in v2, even if
        // a v2 root contained it.
        bytes32 leafA = _leafV2(RETRO_A, alice, 8_000_000);
        _anchor(PIVOT + 2, 1, leafA);
        vm.expectRevert(abi.encodeWithSelector(HypersnapBridgeV2.AlreadyClaimed.selector, RETRO_A));
        v2.claim(RETRO_A, alice, 8_000_000, uint32(block.chainid), new bytes32[](0));

        // The v1 claim entry point is gone.
        (bool ok,) = address(v2)
            .call(
                abi.encodeCall(
                    HypersnapBridge.claim,
                    (1, retroRoot, "", RETRO_C, carol, 1_000_000, uint32(block.chainid), proofC)
                )
            );
        assertFalse(ok);
        assertFalse(v2.claimed(RETRO_C));
    }

    /// No v1 owner path exists in v2.
    function test_upgrade_ownerAuthorityRemoved() public {
        _upgradeToV2();
        uint64 bn = 100;
        bytes[] memory calls = new bytes[](10);
        calls[0] = abi.encodeWithSignature("ownerAddress()");
        calls[1] = abi.encodeCall(
            HypersnapBridge.rotateOwner,
            (
                bn,
                newOwnerEOA,
                _signOwnerUpdate(bn, newOwnerEOA, OWNER_PK),
                _signOwnerAcceptance(newOwnerEOA, NEW_OWNER_PK)
            )
        );
        calls[2] = abi.encodeCall(
            HypersnapBridge.proposeUpgrade,
            (bn, address(v2Impl), _signUpgrade(bn, address(v2Impl), OWNER_PK))
        );
        calls[3] = abi.encodeCall(
            HypersnapBridge.cancelUpgrade,
            (bn, address(v2Impl), _signUpgradeCancel(bn, address(v2Impl), OWNER_PK))
        );
        calls[4] = abi.encodeCall(HypersnapBridge.pause, (bn, _signPause(bn, OWNER_PK)));
        calls[5] = abi.encodeCall(
            HypersnapBridge.recoverERC20,
            (
                bn,
                address(1),
                ownerEOA,
                1,
                _signRecoverErc20(block.chainid, bn, address(1), ownerEOA, 1, OWNER_PK)
            )
        );
        calls[6] = abi.encodeWithSignature("latestBlock()");
        calls[7] = abi.encodeWithSignature("latestRoot()");
        calls[8] = abi.encodeCall(HypersnapBridge.initialize, (ownerEOA, "X", "X"));
        bytes32 root = keccak256("r");
        calls[9] = abi.encodeCall(
            HypersnapBridge.claim,
            (
                bn,
                root,
                _signRootUpdate(bn, root, OWNER_PK),
                bytes32(0),
                ownerEOA,
                1,
                uint32(block.chainid),
                new bytes32[](0)
            )
        );
        for (uint256 i = 0; i < calls.length; i++) {
            (bool ok,) = address(v2).call(calls[i]);
            assertFalse(ok, "v1 entry point still reachable");
        }
        assertEq(vm.load(address(v2), bytes32(0)), bytes32(0));
        assertEq(v2.pauseExpiry(), 0);
        assertEq(v2.pendingImplementation(), address(0));
    }

    // -----------------------------------------------------------------------
    // initializeV2
    // -----------------------------------------------------------------------

    function test_initializeV2_frontRunWithOtherValues_reverts() public {
        _executeV1UpgradeToV2();
        vm.startPrank(attackerEOA);
        vm.expectRevert(HypersnapBridgeV2.GenesisMismatch.selector);
        v2.initializeV2(keccak256("attacker-set"), WEIGHT_1);
        vm.expectRevert(HypersnapBridgeV2.GenesisMismatch.selector);
        v2.initializeV2(SET_ROOT_1, 1);
        vm.stopPrank();
        v2.initializeV2(SET_ROOT_1, WEIGHT_1);
        assertEq(v2.setRoot(1), SET_ROOT_1);
    }

    function test_initializeV2_onlyOnce() public {
        _upgradeToV2();
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        v2.initializeV2(SET_ROOT_1, WEIGHT_1);
    }

    function test_initializeV2_implementationLocked() public {
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        v2Impl.initializeV2(SET_ROOT_1, WEIGHT_1);
    }

    function test_implementationCommitsGenesis() public view {
        assertEq(address(v2Impl.CERTIFICATE_VERIFIER()), address(verifier));
        assertEq(v2Impl.SET_ROOT_EPOCH1(), SET_ROOT_1);
        assertEq(v2Impl.TOTAL_WEIGHT_EPOCH1(), WEIGHT_1);
        assertEq(v2Impl.proxiableUUID(), ERC1967Utils.IMPLEMENTATION_SLOT);
    }

    function test_constructor_rejectsBadParams() public {
        vm.expectRevert(
            abi.encodeWithSelector(HypersnapBridgeV2.VerifierNotContract.selector, address(0xbeef))
        );
        new HypersnapBridgeV2(ICertificateVerifier(address(0xbeef)), SET_ROOT_1, WEIGHT_1);
        vm.expectRevert(HypersnapBridgeV2.BadGenesisParams.selector);
        new HypersnapBridgeV2(verifier, bytes32(0), WEIGHT_1);
        vm.expectRevert(HypersnapBridgeV2.BadGenesisParams.selector);
        new HypersnapBridgeV2(verifier, SET_ROOT_1, 0);
    }

    /// Between v1 `executeUpgrade` and `initializeV2`, no set is known: no
    /// anchor, handoff, action or claim can land. Burns still work.
    function test_beforeInitializeV2_nothingVerifies() public {
        _populateV1();
        _executeV1UpgradeToV2();

        bytes memory h = _header(PIVOT + 1, 1, keccak256("r"));
        HypersnapBridgeV2.Certificate memory c = _certWith(h, PIVOT + 1, 1, SET_ROOT_1, WEIGHT_1, 0);
        vm.expectRevert(abi.encodeWithSelector(HypersnapBridgeV2.UnknownEpoch.selector, uint64(1)));
        v2.advanceRoot(h, c);

        bytes memory rec = _record(1, PIVOT, SET_ROOT_2, WEIGHT_2);
        bytes memory bh = _boundaryHeader(PIVOT, 1, bytes32(0), rec);
        HypersnapBridgeV2.Certificate memory bc = _certWith(bh, PIVOT, 1, SET_ROOT_1, WEIGHT_1, 0);
        vm.expectRevert(
            abi.encodeWithSelector(HypersnapBridgeV2.WrongEpoch.selector, uint64(0), uint64(1))
        );
        v2.advanceEpoch(bh, rec, bc);

        bytes memory ah =
            _actionHeader(PIVOT + 2, 1, v2.bridgeActionHash(v2.ACTION_PAUSE(), 0, address(0)));
        HypersnapBridgeV2.Certificate memory ac =
            _certWith(ah, PIVOT + 2, 1, SET_ROOT_1, WEIGHT_1, 0);
        vm.expectRevert(abi.encodeWithSelector(HypersnapBridgeV2.UnknownEpoch.selector, uint64(1)));
        v2.pause(ah, ac, 0);

        vm.expectRevert(HypersnapBridgeV2.BadMerkleProof.selector);
        v2.claim(bytes32(0), alice, 1, uint32(block.chainid), new bytes32[](0));

        vm.prank(alice);
        assertEq(v2.burn(1_000_000, bytes32(uint256(1))), 3);
    }

    // -----------------------------------------------------------------------
    // Storage layout
    // -----------------------------------------------------------------------

    function _slot8() internal view returns (uint256) {
        return uint256(vm.load(address(v2), bytes32(uint256(8))));
    }

    /// Every v2 state variable is at the slot and offset of the layout
    /// table in HypersnapBridgeV2.sol, and v2 reads v1-written slots 2..5.
    function test_storageLayout_slotBySlot() public {
        _populateV1();
        _upgradeToV2();
        address p = address(v2);

        // v1 slots read through v2 getters.
        assertEq(uint256(vm.load(p, bytes32(uint256(2)))), v2.burnNonce());
        uint256 s3 = uint256(vm.load(p, bytes32(uint256(3))));
        assertEq(uint64(s3), v2.pauseExpiry());
        assertEq(address(uint160(s3 >> 64)), v2.pendingImplementation());
        assertEq(uint256(vm.load(p, keccak256(abi.encode(RETRO_A, uint256(5))))), 1);
        assertTrue(v2.claimed(RETRO_A));

        // setRoot (slot 6), totalWeight (slot 7), latestEpoch (slot 8 offset 8).
        _handoff(1, SET_ROOT_2, WEIGHT_2, keccak256("root-1"));
        assertEq(vm.load(p, keccak256(abi.encode(uint256(1), uint256(6)))), SET_ROOT_1);
        assertEq(vm.load(p, keccak256(abi.encode(uint256(2), uint256(6)))), SET_ROOT_2);
        assertEq(uint256(vm.load(p, keccak256(abi.encode(uint256(1), uint256(7))))), WEIGHT_1);
        assertEq(uint256(vm.load(p, keccak256(abi.encode(uint256(2), uint256(7))))), WEIGHT_2);
        assertEq(uint64(_slot8() >> 64), 2);

        // latestHeight (slot 8 offset 0), latestLockRoot (slot 9).
        _anchor(PIVOT + 77, 1, keccak256("root-2"));
        assertEq(uint64(_slot8()), PIVOT + 77);
        assertEq(vm.load(p, bytes32(uint256(9))), keccak256("root-2"));

        // lastActionHeight (slot 8 offset 16), pauseExpiry (slot 3 offset 0).
        _pauseV2(PIVOT + 55);
        assertEq(uint64(_slot8() >> 128), PIVOT + 55);
        assertEq(_slot8() >> 192, 0);
        assertEq(uint64(uint256(vm.load(p, bytes32(uint256(3))))), v2.pauseExpiry());
        vm.warp(v2.pauseExpiry());

        // pendingImplementation (slot 3 offset 8), pendingUpgradeEffectiveAt (slot 4).
        HypersnapBridgeV2 next = new HypersnapBridgeV2(verifier, SET_ROOT_1, WEIGHT_1);
        _proposeV2(PIVOT + 56, address(next));
        s3 = uint256(vm.load(p, bytes32(uint256(3))));
        assertEq(address(uint160(s3 >> 64)), address(next));
        assertEq(uint256(vm.load(p, bytes32(uint256(4)))), v2.pendingUpgradeEffectiveAt());

        // claimed (slot 5) for a v2 claim; burnNonce (slot 2).
        bytes32 leaf = _leafV2(keccak256("x"), carol, 1_000_000);
        _anchor(PIVOT + 78, 1, leaf);
        v2.claim(keccak256("x"), carol, 1_000_000, uint32(block.chainid), new bytes32[](0));
        assertEq(uint256(vm.load(p, keccak256(abi.encode(keccak256("x"), uint256(5))))), 1);
        vm.prank(carol);
        v2.burn(1_000_000, bytes32(uint256(9)));
        assertEq(uint256(vm.load(p, bytes32(uint256(2)))), 3);

        // Slot 0 stays clear; slot 1 keeps the v1 retro root; the gap is empty.
        assertEq(vm.load(p, bytes32(0)), bytes32(0));
        assertEq(vm.load(p, bytes32(uint256(1))), retroRoot);
        for (uint256 i = 10; i < 50; i++) {
            assertEq(vm.load(p, bytes32(i)), bytes32(0));
        }
    }

    /// `forge inspect ... storageLayout` comparison. Needs FFI:
    ///
    ///   HYPERSNAP_LAYOUT_FFI=true forge test --ffi \
    ///     --match-test test_storageLayout_forgeInspect
    function test_storageLayout_forgeInspect() public {
        if (!vm.envOr("HYPERSNAP_LAYOUT_FFI", false)) {
            vm.skip(true, "set HYPERSNAP_LAYOUT_FFI=true and pass --ffi");
            return;
        }
        string memory l1 = _inspect("src/HypersnapBridge.sol:HypersnapBridge");
        string memory l2 = _inspect("src/HypersnapBridgeV2.sol:HypersnapBridgeV2");

        // v1: 8 variables, then __gap[44] at slot 6.
        // v2: the same 8 (slot, offset, type), 6 new ones, then __gap[40] at slot 10.
        for (uint256 i = 0; i < 8; i++) {
            string memory k = string.concat(".storage[", vm.toString(i), "]");
            assertEq(
                vm.parseJsonString(l2, string.concat(k, ".slot")),
                vm.parseJsonString(l1, string.concat(k, ".slot")),
                k
            );
            assertEq(
                vm.parseJsonUint(l2, string.concat(k, ".offset")),
                vm.parseJsonUint(l1, string.concat(k, ".offset")),
                k
            );
            assertEq(
                vm.parseJsonString(l2, string.concat(k, ".type")),
                vm.parseJsonString(l1, string.concat(k, ".type")),
                k
            );
        }
        assertEq(vm.parseJsonString(l1, ".storage[8].label"), "__gap");
        assertEq(vm.parseJsonString(l1, ".storage[8].slot"), "6");
        assertEq(vm.parseJsonString(l1, ".storage[8].type"), "t_array(t_uint256)44_storage");
        string[6] memory labels = [
            "setRoot",
            "totalWeight",
            "latestHeight",
            "latestEpoch",
            "lastActionHeight",
            "latestLockRoot"
        ];
        string[6] memory slots = ["6", "7", "8", "8", "8", "9"];
        for (uint256 i = 0; i < 6; i++) {
            string memory k = string.concat(".storage[", vm.toString(i + 8), "]");
            assertEq(vm.parseJsonString(l2, string.concat(k, ".label")), labels[i]);
            assertEq(vm.parseJsonString(l2, string.concat(k, ".slot")), slots[i]);
        }
        assertEq(vm.parseJsonString(l2, ".storage[14].label"), "__gap");
        assertEq(vm.parseJsonString(l2, ".storage[14].slot"), "10");
        assertEq(vm.parseJsonString(l2, ".storage[14].type"), "t_array(t_uint256)40_storage");
    }

    function _inspect(string memory target) internal returns (string memory) {
        // A separate build dir (under the git-ignored cache/): the outer
        // `forge test` build has no storageLayout in its artifacts.
        string[] memory cmd = new string[](9);
        cmd[0] = "forge";
        cmd[1] = "inspect";
        cmd[2] = target;
        cmd[3] = "storageLayout";
        cmd[4] = "--json";
        cmd[5] = "--out";
        cmd[6] = "cache/layout-out";
        cmd[7] = "--cache-path";
        cmd[8] = "cache/layout-cache";
        return string(vm.ffi(cmd));
    }
}
