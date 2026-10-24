// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.24;

import {ICertificateVerifier} from "../../src/interfaces/ICertificateVerifier.sol";

/// Stand-in for the CERT-STARK verifier (plan R3). A "proof" is valid iff it
/// is the 32-byte commitment `proofFor` of all five public inputs, so a test
/// that changes any input (epoch, set root, weight, digest, bitmap) sees the
/// proof fail, as a real verifier would. An empty bitmap never verifies.
contract MockCertificateVerifier is ICertificateVerifier {
    bytes32 public constant MOCK_DOMAIN = keccak256("MOCK_CERT_STARK_V1");

    function proofFor(
        uint64 epoch,
        bytes32 setRoot,
        uint64 totalWeight,
        bytes32 payloadDigest,
        bytes memory signerBitmap
    ) public pure returns (bytes memory) {
        return abi.encodePacked(
            keccak256(
                abi.encode(
                    MOCK_DOMAIN, epoch, setRoot, totalWeight, payloadDigest, keccak256(signerBitmap)
                )
            )
        );
    }

    function verifyCertificate(
        uint64 epoch,
        bytes32 setRoot,
        uint64 totalWeight,
        bytes32 payloadDigest,
        bytes calldata signerBitmap,
        bytes calldata proof
    ) external pure returns (bool) {
        if (signerBitmap.length == 0 || proof.length != 32) return false;
        return keccak256(proof)
            == keccak256(proofFor(epoch, setRoot, totalWeight, payloadDigest, signerBitmap));
    }
}
