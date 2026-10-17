// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {HypersnapProto} from "../src/libraries/HypersnapProto.sol";
import {
    ProtoEnc,
    HypersnapProtoEncoder,
    HeaderFields,
    RecordFields
} from "./utils/HypersnapProtoEncoder.sol";

/// Exposes the internal library decoders on calldata.
contract ProtoHarness {
    function header(bytes calldata b) external pure returns (HypersnapProto.Header memory) {
        return HypersnapProto.decodeHeader(b);
    }

    function record(bytes calldata b)
        external
        pure
        returns (HypersnapProto.EpochBoundaryRecord memory)
    {
        return HypersnapProto.decodeEpochBoundaryRecord(b);
    }
}

/// Known-answer vectors are `protoc --encode` (libprotoc 34.1) output for the
/// messages in `proto/definitions/hypersnap.proto`:
///
///   VEC_HEADER_CURRENT  HypersnapBlockHeader, the §17.7 fields 1..13:
///     height 123456789, timestamp 1767225600, parent_hash 0x11×32, epoch 3,
///     state_root 0x22×32, messages_root 0x33×32, last_commit_hash 0x44×32,
///     version 1, shard_links {1, 1000, 0x55×32, 0x56×32} and
///     {2, 2000, 0x57×32, 0x58×32}, bridge_lock_root 0x77×32
///   VEC_HEADER_PROPOSED the same, plus epoch_record_hash = 14 (0x88×32) and
///     bridge_action_hash = 15 (0x99×32), with those two fields added to a
///     scratch copy of the schema
///   VEC_HEADER_SHARD1   shard_id 1, height 4242, timestamp 1767225612,
///     parent_hash 0x12×32, epoch 7, state_root 0x23×32, version 1,
///     epoch_ref_height 123456789
///   VEC_RECORD          EpochBoundaryRecord: epoch 3, state_root 0x22×32,
///     block_height 123456789, next_set_root 0xaa×32, next_total_weight 7
contract HypersnapProtoTest is Test {
    ProtoHarness internal harness;

    bytes internal constant VEC_HEADER_CURRENT =
        hex"10959aef3a1880f2d6ca06222011111111111111111111111111111111111111111111111111111111111111112803322022222222222222222222222222222222222222222222222222222222222222223a2033333333333333333333333333333333333333333333333333333333333333334220444444444444444444444444444444444444444444444444444444444444444448015a49080110e8071a205555555555555555555555555555555555555555555555555555555555555555222056565656565656565656565656565656565656565656565656565656565656565a49080210d00f1a2057575757575757575757575757575757575757575757575757575757575757572220585858585858585858585858585858585858585858585858585858585858585862207777777777777777777777777777777777777777777777777777777777777777";
    bytes internal constant VEC_HEADER_PROPOSED =
        hex"10959aef3a1880f2d6ca06222011111111111111111111111111111111111111111111111111111111111111112803322022222222222222222222222222222222222222222222222222222222222222223a2033333333333333333333333333333333333333333333333333333333333333334220444444444444444444444444444444444444444444444444444444444444444448015a49080110e8071a205555555555555555555555555555555555555555555555555555555555555555222056565656565656565656565656565656565656565656565656565656565656565a49080210d00f1a2057575757575757575757575757575757575757575757575757575757575757572220585858585858585858585858585858585858585858585858585858585858585862207777777777777777777777777777777777777777777777777777777777777777722088888888888888888888888888888888888888888888888888888888888888887a209999999999999999999999999999999999999999999999999999999999999999";
    bytes internal constant VEC_HEADER_SHARD1 =
        hex"0801109221188cf2d6ca0622201212121212121212121212121212121212121212121212121212121212121212280732202323232323232323232323232323232323232323232323232323232323232323480150959aef3a";
    bytes internal constant VEC_RECORD =
        hex"08031220222222222222222222222222222222222222222222222222222222222222222218959aef3a2220aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2807";

    // A minimal valid header: height 5, epoch 1.
    bytes internal constant MIN_HEADER = hex"10052801";

    function setUp() public {
        harness = new ProtoHarness();
    }

    function _rep(bytes1 b) internal pure returns (bytes32 r) {
        for (uint256 i = 0; i < 32; i++) {
            r |= bytes32(b) >> (8 * i);
        }
    }

    function _expectHeaderRevert(bytes memory data, bytes memory err) internal {
        vm.expectRevert(err);
        harness.header(data);
    }

    function _expectRecordRevert(bytes memory data, bytes memory err) internal {
        vm.expectRevert(err);
        harness.record(data);
    }

    function _badValue(uint256 field) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(HypersnapProto.ProtoBadValue.selector, field);
    }

    function _order(uint256 field) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(HypersnapProto.ProtoFieldOrder.selector, field);
    }

    function _wire(uint256 field, uint256 wt) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(HypersnapProto.ProtoBadWireType.selector, field, wt);
    }

    function _missing(uint256 field) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(HypersnapProto.ProtoMissingField.selector, field);
    }

    function _truncated() internal pure returns (bytes memory) {
        return abi.encodeWithSelector(HypersnapProto.ProtoTruncated.selector);
    }

    function _badVarint() internal pure returns (bytes memory) {
        return abi.encodeWithSelector(HypersnapProto.ProtoBadVarint.selector);
    }

    function _badTag() internal pure returns (bytes memory) {
        return abi.encodeWithSelector(HypersnapProto.ProtoBadTag.selector);
    }

    // -----------------------------------------------------------------------
    // protoc vectors
    // -----------------------------------------------------------------------

    function test_vector_currentHeader() public view {
        HypersnapProto.Header memory h = harness.header(VEC_HEADER_CURRENT);
        assertEq(h.shardId, 0);
        assertEq(h.height, 123_456_789);
        assertEq(h.epoch, 3);
        assertEq(h.bridgeLockRoot, _rep(0x77));
        assertEq(h.epochRecordHash, bytes32(0));
        assertEq(h.bridgeActionHash, bytes32(0));
        assertEq(h.blockHash, 0xd647b5a0d51bf456d89c5c5c78c9dc3065074045b2c7b8e9374839924f3627ad);
    }

    function test_vector_proposedHeader() public view {
        HypersnapProto.Header memory h = harness.header(VEC_HEADER_PROPOSED);
        assertEq(h.shardId, 0);
        assertEq(h.height, 123_456_789);
        assertEq(h.epoch, 3);
        assertEq(h.bridgeLockRoot, _rep(0x77));
        assertEq(h.epochRecordHash, _rep(0x88));
        assertEq(h.bridgeActionHash, _rep(0x99));
        assertEq(h.blockHash, 0x0b9bfcbba9a8819dbcca71c1d35e466b47984f84d76d19540309aac898f1f949);
    }

    function test_vector_shard1Header() public view {
        HypersnapProto.Header memory h = harness.header(VEC_HEADER_SHARD1);
        assertEq(h.shardId, 1);
        assertEq(h.height, 4242);
        assertEq(h.epoch, 7);
        assertEq(h.bridgeLockRoot, bytes32(0));
        assertEq(h.blockHash, 0x19825f00ec4db9fba9de9d4810101b37184ee500c35d197a92cb10659b748918);
    }

    function test_vector_record() public view {
        HypersnapProto.EpochBoundaryRecord memory r = harness.record(VEC_RECORD);
        assertEq(r.epoch, 3);
        assertEq(r.blockHeight, 123_456_789);
        assertEq(r.nextSetRoot, _rep(0xaa));
        assertEq(r.nextTotalWeight, 7);
        assertEq(
            keccak256(VEC_RECORD),
            0x0c87ed4b8c3db55a16378b03770bd1687dc50cdfee677eb9dde8feb4d900689d
        );
    }

    /// The Solidity test encoder produces the protoc bytes, so the bridge
    /// tests that use it exercise canonical encodings.
    function test_encoderMatchesProtoc() public pure {
        HeaderFields memory f;
        f.height = 123_456_789;
        f.timestamp = 1_767_225_600;
        f.parentHash = _rep(0x11);
        f.epoch = 3;
        f.stateRoot = _rep(0x22);
        f.messagesRoot = _rep(0x33);
        f.lastCommitHash = _rep(0x44);
        f.version = 1;
        f.bridgeLockRoot = _rep(0x77);
        bytes[] memory links = new bytes[](2);
        links[0] = HypersnapProtoEncoder.encodeShardLink(1, 1000, _rep(0x55), _rep(0x56));
        links[1] = HypersnapProtoEncoder.encodeShardLink(2, 2000, _rep(0x57), _rep(0x58));
        assertEq(HypersnapProtoEncoder.encodeHeader(f, links), VEC_HEADER_CURRENT);

        f.epochRecordHash = _rep(0x88);
        f.bridgeActionHash = _rep(0x99);
        assertEq(HypersnapProtoEncoder.encodeHeader(f, links), VEC_HEADER_PROPOSED);

        HeaderFields memory s1;
        s1.shardId = 1;
        s1.height = 4242;
        s1.timestamp = 1_767_225_612;
        s1.parentHash = _rep(0x12);
        s1.epoch = 7;
        s1.stateRoot = _rep(0x23);
        s1.version = 1;
        s1.epochRefHeight = 123_456_789;
        assertEq(HypersnapProtoEncoder.encodeHeader(s1), VEC_HEADER_SHARD1);

        RecordFields memory r = RecordFields({
            epoch: 3,
            stateRoot: _rep(0x22),
            blockHeight: 123_456_789,
            nextSetRoot: _rep(0xaa),
            nextTotalWeight: 7
        });
        assertEq(HypersnapProtoEncoder.encodeRecord(r), VEC_RECORD);
    }

    // -----------------------------------------------------------------------
    // Header: accepted shapes
    // -----------------------------------------------------------------------

    function test_header_minimal() public view {
        HypersnapProto.Header memory h = harness.header(MIN_HEADER);
        assertEq(h.height, 5);
        assertEq(h.epoch, 1);
        assertEq(h.blockHash, keccak256(MIN_HEADER));
    }

    function test_header_maxUint64Varint() public view {
        // height = 2^64 - 1 (10-byte varint, last byte 0x01).
        HypersnapProto.Header memory h = harness.header(hex"10ffffffffffffffffff012801");
        assertEq(h.height, type(uint64).max);
    }

    function test_header_maxUint32ShardId() public view {
        HypersnapProto.Header memory h = harness.header(hex"08ffffffff0f10052801");
        assertEq(h.shardId, type(uint32).max);
    }

    function test_header_emptyShardLinkElementAllowed() public view {
        // shard_links {} {} — repeated element with all defaults.
        HypersnapProto.Header memory h = harness.header(hex"100528015a005a00");
        assertEq(h.height, 5);
    }

    function test_header_allZeroLockRootAccepted() public view {
        bytes memory b = bytes.concat(MIN_HEADER, hex"6220", new bytes(32));
        HypersnapProto.Header memory h = harness.header(b);
        assertEq(h.bridgeLockRoot, bytes32(0));
    }

    function test_header_unknownFieldsSkipped() public view {
        bytes memory b = bytes.concat(
            VEC_HEADER_PROPOSED,
            hex"8001" // 16 varint 42
            hex"2a",
            hex"8a01" // 17 LEN 3
            hex"03" hex"010203",
            hex"9101" // 18 I64
            hex"0102030405060708",
            hex"9d01" // 19 I32
            hex"01020304",
            hex"a001" // 20 varint
            hex"01",
            hex"a001" // 20 again (unknown repeated)
            hex"02"
        );
        HypersnapProto.Header memory h = harness.header(b);
        assertEq(h.height, 123_456_789);
        assertEq(h.bridgeActionHash, _rep(0x99));
        assertEq(h.blockHash, keccak256(b));
    }

    // -----------------------------------------------------------------------
    // Header: rejected shapes
    // -----------------------------------------------------------------------

    function test_header_empty_reverts() public {
        _expectHeaderRevert("", _missing(2));
    }

    function test_header_missingHeight_reverts() public {
        _expectHeaderRevert(hex"2801", _missing(2));
    }

    function test_header_missingEpoch_reverts() public {
        _expectHeaderRevert(hex"1005", _missing(5));
    }

    function test_header_nonMinimalVarint_reverts() public {
        _expectHeaderRevert(hex"1085002801", _badVarint()); // 5 as 0x85 0x00
        _expectHeaderRevert(hex"9000052801", _badVarint()); // tag 2 as 0x90 0x00
    }

    function test_header_overlongVarint_reverts() public {
        _expectHeaderRevert(hex"10ffffffffffffffffff022801", _badVarint()); // 10th byte 2
        _expectHeaderRevert(hex"10ffffffffffffffffff81012801", _badVarint()); // 11 bytes
    }

    function test_header_truncatedVarint_reverts() public {
        _expectHeaderRevert(hex"1095", _truncated());
        _expectHeaderRevert(hex"10052880", _truncated());
    }

    function test_header_zeroTag_reverts() public {
        _expectHeaderRevert(hex"100528010000", _badTag());
    }

    function test_header_tagAbove32Bits_reverts() public {
        // A varint tag of 2^32 (field 2^29, wire 0).
        _expectHeaderRevert(bytes.concat(MIN_HEADER, hex"808080801001"), _badTag());
    }

    function test_header_outOfOrder_reverts() public {
        _expectHeaderRevert(hex"28011005", _order(2)); // epoch before height
        _expectHeaderRevert(bytes.concat(MIN_HEADER, hex"0801"), _order(1));
    }

    function test_header_duplicateSingular_reverts() public {
        _expectHeaderRevert(hex"100510062801", _order(2));
        bytes memory root = abi.encodePacked(bytes32(uint256(1)));
        _expectHeaderRevert(bytes.concat(MIN_HEADER, hex"6220", root, hex"6220", root), _order(12));
    }

    function test_header_unknownBeforeKnown_reverts() public {
        _expectHeaderRevert(hex"10058001012801", _order(5));
    }

    function test_header_wrongWireTypeForKnownField_reverts() public {
        _expectHeaderRevert(hex"1201052801", _wire(2, 2)); // height as LEN
        _expectHeaderRevert(hex"100528016001", _wire(12, 0)); // bridge_lock_root as varint
        _expectHeaderRevert(hex"1005280158015a00", _wire(11, 0)); // shard_links as varint
        _expectHeaderRevert(hex"100520012801", _wire(4, 0)); // parent_hash as varint
    }

    function test_header_groupAndUndefinedWireTypes_reverts() public {
        _expectHeaderRevert(bytes.concat(MIN_HEADER, hex"8301"), _wire(16, 3));
        _expectHeaderRevert(bytes.concat(MIN_HEADER, hex"8401"), _wire(16, 4));
        _expectHeaderRevert(bytes.concat(MIN_HEADER, hex"8601"), _wire(16, 6));
        _expectHeaderRevert(bytes.concat(MIN_HEADER, hex"8701"), _wire(16, 7));
    }

    function test_header_explicitDefaults_reverts() public {
        _expectHeaderRevert(hex"080010052801", _badValue(1)); // shard_id = 0
        _expectHeaderRevert(hex"10002801", _badValue(2)); // height = 0
        _expectHeaderRevert(hex"10052800", _badValue(5)); // epoch = 0
        _expectHeaderRevert(hex"100518002801", _badValue(3)); // timestamp = 0
        _expectHeaderRevert(hex"100522002801", _badValue(4)); // parent_hash empty
        _expectHeaderRevert(hex"100528016200", _badValue(12)); // bridge_lock_root empty
        _expectHeaderRevert(hex"100528016a00", _badValue(13)); // pivot_record_hash empty
    }

    function test_header_uint32Overflow_reverts() public {
        _expectHeaderRevert(
            hex"088080808010" // shard_id 2^32
            hex"10052801",
            _badValue(1)
        );
        _expectHeaderRevert(hex"10052801488080808010", _badValue(9)); // version 2^32
    }

    function test_header_bytes32WrongLength_reverts() public {
        _expectHeaderRevert(bytes.concat(MIN_HEADER, hex"621f", new bytes(31)), _badValue(12));
        _expectHeaderRevert(bytes.concat(MIN_HEADER, hex"6221", new bytes(33)), _badValue(12));
        _expectHeaderRevert(bytes.concat(MIN_HEADER, hex"7210", new bytes(16)), _badValue(14));
        _expectHeaderRevert(bytes.concat(MIN_HEADER, hex"7a01", hex"00"), _badValue(15));
    }

    function test_header_truncatedLength_reverts() public {
        _expectHeaderRevert(bytes.concat(MIN_HEADER, hex"6220", new bytes(31)), _truncated());
        _expectHeaderRevert(bytes.concat(MIN_HEADER, hex"5a05", hex"0801"), _truncated());
        _expectHeaderRevert(bytes.concat(MIN_HEADER, hex"8a0105", hex"01"), _truncated());
        _expectHeaderRevert(bytes.concat(MIN_HEADER, hex"9101", hex"01020304"), _truncated());
        _expectHeaderRevert(bytes.concat(MIN_HEADER, hex"9d01", hex"0102"), _truncated());
        // A length near 2^64 cannot wrap the cursor.
        _expectHeaderRevert(bytes.concat(MIN_HEADER, hex"8a01ffffffffffffffffff01"), _truncated());
    }

    // -----------------------------------------------------------------------
    // EpochBoundaryRecord
    // -----------------------------------------------------------------------

    function _rec(RecordFields memory r) internal pure returns (bytes memory) {
        return HypersnapProtoEncoder.encodeRecord(r);
    }

    function _validRec() internal pure returns (RecordFields memory) {
        return RecordFields({
            epoch: 3,
            stateRoot: _rep(0x22),
            blockHeight: 99,
            nextSetRoot: _rep(0xaa),
            nextTotalWeight: 7
        });
    }

    function test_record_missingFields_reverts() public {
        RecordFields memory r = _validRec();
        r.epoch = 0;
        _expectRecordRevert(_rec(r), _missing(1));
        r = _validRec();
        r.blockHeight = 0;
        _expectRecordRevert(_rec(r), _missing(3));
        r = _validRec();
        r.nextSetRoot = 0;
        _expectRecordRevert(_rec(r), _missing(4));
        r = _validRec();
        r.nextTotalWeight = 0;
        _expectRecordRevert(_rec(r), _missing(5));
        _expectRecordRevert("", _missing(1));
    }

    function test_record_stateRootOptional() public view {
        RecordFields memory r = _validRec();
        r.stateRoot = 0;
        HypersnapProto.EpochBoundaryRecord memory d = harness.record(_rec(r));
        assertEq(d.nextSetRoot, _rep(0xaa));
    }

    function test_record_zeroSetRoot_reverts() public {
        bytes memory b = bytes.concat(hex"0803", hex"1863", hex"2220", new bytes(32), hex"2807");
        _expectRecordRevert(b, _badValue(4));
    }

    function test_record_duplicateAndOrder_reverts() public {
        _expectRecordRevert(bytes.concat(VEC_RECORD, hex"2808"), _order(5));
        _expectRecordRevert(bytes.concat(hex"1863", VEC_RECORD), _order(1));
    }

    function test_record_wrongWireType_reverts() public {
        _expectRecordRevert(hex"0a0103", _wire(1, 2));
        _expectRecordRevert(bytes.concat(hex"08031863", hex"2001"), _wire(4, 0));
    }

    function test_record_unknownFieldsSkipped() public view {
        bytes memory b = bytes.concat(VEC_RECORD, hex"3001", hex"3a0101", hex"3a0102");
        HypersnapProto.EpochBoundaryRecord memory r = harness.record(b);
        assertEq(r.nextTotalWeight, 7);
    }

    // -----------------------------------------------------------------------
    // Fuzz
    // -----------------------------------------------------------------------

    function testFuzz_header_roundTrip(
        uint64 height,
        uint64 epoch,
        uint64 timestamp,
        bytes32 lockRoot,
        bytes32 recordHash,
        bytes32 actionHash,
        uint8 links
    ) public view {
        vm.assume(height != 0 && epoch != 0);
        HeaderFields memory f = HypersnapProtoEncoder.shardZero(height, epoch, lockRoot);
        f.timestamp = timestamp;
        f.shardLinkCount = uint8(bound(links, 0, 3));
        f.epochRecordHash = recordHash;
        f.bridgeActionHash = actionHash;
        bytes memory b = HypersnapProtoEncoder.encodeHeader(f);
        HypersnapProto.Header memory h = harness.header(b);
        assertEq(h.shardId, 0);
        assertEq(h.height, height);
        assertEq(h.epoch, epoch);
        assertEq(h.bridgeLockRoot, lockRoot);
        assertEq(h.epochRecordHash, recordHash);
        assertEq(h.bridgeActionHash, actionHash);
        assertEq(h.blockHash, keccak256(b));
    }

    function testFuzz_record_roundTrip(
        uint64 epoch,
        bytes32 stateRoot,
        uint64 height,
        bytes32 nextSetRoot,
        uint64 weight
    ) public view {
        vm.assume(epoch != 0 && height != 0 && nextSetRoot != 0 && weight != 0);
        HypersnapProto.EpochBoundaryRecord memory r =
            harness.record(_rec(RecordFields(epoch, stateRoot, height, nextSetRoot, weight)));
        assertEq(r.epoch, epoch);
        assertEq(r.blockHeight, height);
        assertEq(r.nextSetRoot, nextSetRoot);
        assertEq(r.nextTotalWeight, weight);
    }

    function _isProtoError(bytes memory err) internal pure returns (bool) {
        if (err.length < 4) return false;
        bytes4 sel = bytes4(err);
        return sel == HypersnapProto.ProtoTruncated.selector
            || sel == HypersnapProto.ProtoBadVarint.selector
            || sel == HypersnapProto.ProtoBadTag.selector
            || sel == HypersnapProto.ProtoBadWireType.selector
            || sel == HypersnapProto.ProtoFieldOrder.selector
            || sel == HypersnapProto.ProtoBadValue.selector
            || sel == HypersnapProto.ProtoMissingField.selector;
    }

    /// Arbitrary input either decodes to a header with the required fields,
    /// or reverts with a typed decoder error (never a panic or OOB read).
    function testFuzz_header_arbitraryBytes(bytes calldata data) public view {
        try harness.header(data) returns (HypersnapProto.Header memory h) {
            assertGt(h.height, 0);
            assertGt(h.epoch, 0);
            assertEq(h.blockHash, keccak256(data));
        } catch (bytes memory err) {
            assertTrue(_isProtoError(err), "untyped revert");
        }
    }

    function testFuzz_record_arbitraryBytes(bytes calldata data) public view {
        try harness.record(data) returns (HypersnapProto.EpochBoundaryRecord memory r) {
            assertGt(r.epoch, 0);
            assertGt(r.nextTotalWeight, 0);
            assertTrue(r.nextSetRoot != bytes32(0));
        } catch (bytes memory err) {
            assertTrue(_isProtoError(err), "untyped revert");
        }
    }

    /// Mutations of a valid header hit every decoder branch.
    function testFuzz_header_mutatedVector(uint256 index, uint8 value, uint256 cut) public view {
        bytes memory b = VEC_HEADER_PROPOSED;
        index = bound(index, 0, b.length - 1);
        b[index] = bytes1(value);
        cut = bound(cut, 0, b.length);
        assembly ("memory-safe") {
            mstore(b, cut)
        }
        try harness.header(b) returns (HypersnapProto.Header memory h) {
            assertEq(h.blockHash, keccak256(b));
        } catch (bytes memory err) {
            assertTrue(_isProtoError(err), "untyped revert");
        }
    }
}
