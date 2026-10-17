// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.24;

/// Canonical (prost / proto3) protobuf encoder for tests: fields in number
/// order, defaults omitted, minimal varints. The decoder tests also check
/// this encoder against `protoc --encode` output.
library ProtoEnc {
    function varint(uint256 v) internal pure returns (bytes memory out) {
        out = new bytes(10);
        uint256 n;
        while (v >= 0x80) {
            out[n++] = bytes1(uint8((v & 0x7f) | 0x80));
            v >>= 7;
        }
        out[n++] = bytes1(uint8(v));
        assembly ("memory-safe") {
            mstore(out, n)
        }
    }

    function tag(uint256 field, uint256 wireType) internal pure returns (bytes memory) {
        return varint((field << 3) | wireType);
    }

    function uintField(uint256 field, uint256 v) internal pure returns (bytes memory) {
        if (v == 0) return "";
        return bytes.concat(tag(field, 0), varint(v));
    }

    function bytesField(uint256 field, bytes memory v) internal pure returns (bytes memory) {
        if (v.length == 0) return "";
        return bytes.concat(tag(field, 2), varint(v.length), v);
    }

    /// A 32-byte `bytes` field; zero means absent (test convenience).
    function b32Field(uint256 field, bytes32 v) internal pure returns (bytes memory) {
        if (v == bytes32(0)) return "";
        return bytesField(field, abi.encodePacked(v));
    }
}

/// Fields of `HypersnapBlockHeader` (§17.7) plus the two proposed fields.
struct HeaderFields {
    uint32 shardId;
    uint64 height;
    uint64 timestamp;
    bytes32 parentHash;
    uint64 epoch;
    bytes32 stateRoot;
    bytes32 messagesRoot;
    bytes32 lastCommitHash;
    uint32 version;
    uint64 epochRefHeight;
    uint8 shardLinkCount; // links for shards 1..count, synthesized
    bytes32 bridgeLockRoot;
    bytes32 pivotRecordHash;
    bytes32 epochRecordHash; // proposed field 14
    bytes32 bridgeActionHash; // proposed field 15
}

struct RecordFields {
    uint64 epoch;
    bytes32 stateRoot;
    uint64 blockHeight;
    bytes32 nextSetRoot;
    uint64 nextTotalWeight;
}

library HypersnapProtoEncoder {
    function encodeShardLink(uint32 shardId, uint64 height, bytes32 blockHash, bytes32 stateRoot)
        internal
        pure
        returns (bytes memory)
    {
        return bytes.concat(
            ProtoEnc.uintField(1, shardId),
            ProtoEnc.uintField(2, height),
            ProtoEnc.b32Field(3, blockHash),
            ProtoEnc.b32Field(4, stateRoot)
        );
    }

    /// Shard links for shards 1..count of a shard-0 header at `height`.
    function syntheticLinks(uint8 count, uint64 height)
        internal
        pure
        returns (bytes[] memory links)
    {
        links = new bytes[](count);
        for (uint32 s = 1; s <= count; s++) {
            links[s - 1] = encodeShardLink(
                s, height, keccak256(abi.encode("link", s, height)), keccak256(abi.encode("sr", s))
            );
        }
    }

    function encodeHeader(HeaderFields memory f) internal pure returns (bytes memory) {
        return encodeHeader(f, syntheticLinks(f.shardLinkCount, f.height));
    }

    /// Encode with explicit, already-encoded `ShardLink` messages
    /// (`f.shardLinkCount` is ignored).
    function encodeHeader(HeaderFields memory f, bytes[] memory links)
        internal
        pure
        returns (bytes memory out)
    {
        // Concatenated in small groups to stay within the legacy codegen stack.
        out = bytes.concat(
            ProtoEnc.uintField(1, f.shardId),
            ProtoEnc.uintField(2, f.height),
            ProtoEnc.uintField(3, f.timestamp),
            ProtoEnc.b32Field(4, f.parentHash)
        );
        out = bytes.concat(
            out,
            ProtoEnc.uintField(5, f.epoch),
            ProtoEnc.b32Field(6, f.stateRoot),
            ProtoEnc.b32Field(7, f.messagesRoot)
        );
        out = bytes.concat(
            out,
            ProtoEnc.b32Field(8, f.lastCommitHash),
            ProtoEnc.uintField(9, f.version),
            ProtoEnc.uintField(10, f.epochRefHeight)
        );
        for (uint256 i = 0; i < links.length; i++) {
            out = bytes.concat(out, ProtoEnc.tag(11, 2), ProtoEnc.varint(links[i].length), links[i]);
        }
        out = bytes.concat(
            out, ProtoEnc.b32Field(12, f.bridgeLockRoot), ProtoEnc.b32Field(13, f.pivotRecordHash)
        );
        out = bytes.concat(
            out, ProtoEnc.b32Field(14, f.epochRecordHash), ProtoEnc.b32Field(15, f.bridgeActionHash)
        );
    }

    function encodeRecord(RecordFields memory r) internal pure returns (bytes memory) {
        return bytes.concat(
            ProtoEnc.uintField(1, r.epoch),
            ProtoEnc.b32Field(2, r.stateRoot),
            ProtoEnc.uintField(3, r.blockHeight),
            ProtoEnc.b32Field(4, r.nextSetRoot),
            ProtoEnc.uintField(5, r.nextTotalWeight)
        );
    }

    /// A realistic shard-0 header: all §17.7 fields that a shard-0 block has.
    function shardZero(uint64 height, uint64 epoch, bytes32 lockRoot)
        internal
        pure
        returns (HeaderFields memory f)
    {
        f.height = height;
        f.timestamp = 1_767_225_600 + (height % 1e12) * 12;
        f.parentHash = keccak256(abi.encode("parent", height));
        f.epoch = epoch;
        f.stateRoot = keccak256(abi.encode("state", height));
        f.messagesRoot = keccak256(abi.encode("messages", height));
        f.lastCommitHash = keccak256(abi.encode("commit", height));
        f.version = 1;
        f.shardLinkCount = 2;
        f.bridgeLockRoot = lockRoot;
    }
}
