// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.24;

import {Script, console} from "forge-std/Script.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {HypersnapBridge} from "../src/HypersnapBridge.sol";

/// Minimal interface to CreateX (https://createx.rocks/), the canonical
/// deterministic deployment factory deployed at the same address on every
/// major EVM chain.
interface ICreateX {
    /// CREATE3: address depends only on `(this contract, salt)` — NOT on
    /// `initCode`. Two chains with CreateX at the same address and the same
    /// `(deployer, salt)` produce the same contract address regardless of
    /// compiler, metadata hash, or constructor arg differences.
    function deployCreate3(bytes32 salt, bytes calldata initCode)
        external
        payable
        returns (address newContract);

    /// Off-chain helper: predict the CREATE3 address for `(salt, this)`.
    function computeCreate3Address(bytes32 salt, address deployer)
        external
        view
        returns (address computedAddress);
}

/// @title Deploy
/// @notice Cross-chain-deterministic deployment of HypersnapBridge.
///
/// Uses CreateX CREATE3 so the proxy and implementation addresses are
/// identical on every chain, with no nonce alignment, no bytecode
/// reproducibility requirements, and no chain-id-mixing in the address
/// derivation.
///
/// ## How the address is determined
///
/// CreateX CREATE3 derives the contract address from `(CreateX, salt)`
/// alone — bytecode does not factor in. Salt format (CreateX convention):
///
///   bytes 0..19 : deployer address (frontrun protection — if non-zero,
///                  CreateX requires `msg.sender == deployer`)
///   byte 20     : cross-chain protection flag
///                   0x00 → same address on every chain (what we want)
///                   0x01 → mixed with chainid, different per chain
///   bytes 21..31: arbitrary entropy
///
/// Two separate salts (one for impl, one for proxy) → two predictable
/// addresses, identical across every chain.
///
/// ## Determinism guarantees
///
/// As long as:
///   - CreateX is deployed at `0xba5Ed099633D3B313e4D5F7bdc1305d3c28ba5Ed`
///     on the target chain (true for all major EVM chains today),
///   - the same `HYPERSNAP_DEPLOYER_EOA` broadcasts the script on each chain,
///   - the same `HYPERSNAP_GENESIS_OWNER`, name, and symbol are used,
///
/// the proxy and impl addresses are bit-for-bit identical across all
/// deployments. Different deployer EOA → different addresses.
///
/// ## Environment variables
///
/// | Var | Required | Default | Notes |
/// |---|---|---|---|
/// | `HYPERSNAP_GENESIS_OWNER` | optional | broadcaster EOA | Initial bridge owner; rotated to threshold address post-DKG |
/// | `HYPERSNAP_TOKEN_NAME`    | optional | `"Hypersnap"` | Affects the proxy's runtime state, NOT its address |
/// | `HYPERSNAP_TOKEN_SYMBOL`  | optional | `"SNAP"` | |
/// | `HYPERSNAP_SALT_TAG`      | optional | `"hypersnap.v1"` | Versioning string mixed into both salts. Bump for a fresh address space (e.g., `v2` if you ever need to redeploy at new addresses). |
///
/// ## Run
///
/// ```bash
/// # Production: hardware wallet, broadcast, verify on Etherscan.
/// forge script script/Deploy.s.sol \
///     --rpc-url $RPC_URL \
///     --broadcast \
///     --verify --etherscan-api-key $ETHERSCAN_KEY \
///     --ledger --sender $DEPLOYER_ADDR
/// ```
contract Deploy is Script {
    /// CreateX canonical address. See https://createx.rocks/deployments
    /// for the per-chain availability table — the address is the same
    /// (`0xba5Ed099633D3B313e4D5F7bdc1305d3c28ba5Ed`) on Ethereum,
    /// Base, Arbitrum, Optimism, Polygon, and ~50 other chains.
    address internal constant CREATEX = 0xba5Ed099633D3B313e4D5F7bdc1305d3c28ba5Ed;

    function run() external returns (address proxy, address implementation) {
        address genesisOwner;
        try vm.envAddress("HYPERSNAP_GENESIS_OWNER") returns (address a) {
            genesisOwner = a;
        } catch {
            genesisOwner = msg.sender;
        }
        require(genesisOwner != address(0), "Deploy: genesis owner is zero");

        string memory tokenName = _envStringOr("HYPERSNAP_TOKEN_NAME", "Hypersnap");
        string memory tokenSymbol = _envStringOr("HYPERSNAP_TOKEN_SYMBOL", "SNAP");
        string memory saltTag = _envStringOr("HYPERSNAP_SALT_TAG", "hypersnap.v1");

        // Verify CreateX is present at the canonical address. If it isn't,
        // we're on a chain CreateX hasn't reached — abort rather than fall
        // back to non-deterministic deployment.
        require(
            CREATEX.code.length > 0,
            "Deploy: CreateX not deployed on this chain at 0xba5Ed099633D3B313e4D5F7bdc1305d3c28ba5Ed"
        );

        // Predict addresses up-front, applying CreateX's `_guard` so the
        // pure two-arg `computeCreate3Address` returns the same address
        // CreateX will actually deploy at. See `_guardedCrossChainSalt`.
        (address expectedImpl, address expectedProxy) = _predictAddresses(saltTag);

        // Idempotence: re-running on a chain that already has these
        // addresses occupied is a no-op. Useful when re-running across
        // many chains where some are already done.
        if (expectedImpl.code.length > 0 && expectedProxy.code.length > 0) {
            console.log("===== Already deployed (no-op) =====");
            console.log("Chain id:       ", block.chainid);
            console.log("Implementation: ", expectedImpl);
            console.log("Proxy:          ", expectedProxy);
            return (expectedProxy, expectedImpl);
        }

        (implementation, proxy) = _broadcastDeploys(
            expectedImpl,
            expectedProxy,
            saltTag,
            genesisOwner,
            tokenName,
            tokenSymbol
        );

        _sanityCheck(proxy, genesisOwner, tokenName, tokenSymbol);
        _logDeployment(proxy, implementation, genesisOwner, tokenName, tokenSymbol, saltTag);
    }

    function _predictAddresses(string memory saltTag)
        internal
        view
        returns (address expectedImpl, address expectedProxy)
    {
        bytes32 implGuarded = _guardedCrossChainSalt(
            msg.sender,
            _saltFor(msg.sender, string.concat(saltTag, ".impl"))
        );
        bytes32 proxyGuarded = _guardedCrossChainSalt(
            msg.sender,
            _saltFor(msg.sender, string.concat(saltTag, ".proxy"))
        );
        ICreateX createx = ICreateX(CREATEX);
        expectedImpl = createx.computeCreate3Address(implGuarded, CREATEX);
        expectedProxy = createx.computeCreate3Address(proxyGuarded, CREATEX);
    }

    function _broadcastDeploys(
        address expectedImpl,
        address expectedProxy,
        string memory saltTag,
        address genesisOwner,
        string memory tokenName,
        string memory tokenSymbol
    ) internal returns (address impl, address proxyOut) {
        ICreateX createx = ICreateX(CREATEX);
        bytes32 implSalt = _saltFor(msg.sender, string.concat(saltTag, ".impl"));
        bytes32 proxySalt = _saltFor(msg.sender, string.concat(saltTag, ".proxy"));

        vm.startBroadcast();

        impl = createx.deployCreate3(implSalt, type(HypersnapBridge).creationCode);
        require(
            impl == expectedImpl,
            "Deploy: impl address mismatch (CreateX salt collision or wrong factory)"
        );

        bytes memory initCalldata = abi.encodeCall(
            HypersnapBridge.initialize,
            (genesisOwner, tokenName, tokenSymbol)
        );
        bytes memory proxyInitCode = abi.encodePacked(
            type(ERC1967Proxy).creationCode,
            abi.encode(impl, initCalldata)
        );
        proxyOut = createx.deployCreate3(proxySalt, proxyInitCode);
        require(proxyOut == expectedProxy, "Deploy: proxy address mismatch");

        vm.stopBroadcast();
    }

    function _sanityCheck(
        address proxy,
        address genesisOwner,
        string memory tokenName,
        string memory tokenSymbol
    ) internal view {
        HypersnapBridge bridge = HypersnapBridge(proxy);
        require(bridge.ownerAddress() == genesisOwner, "Deploy: owner mismatch post-init");
        require(
            keccak256(bytes(bridge.name())) == keccak256(bytes(tokenName)),
            "Deploy: name mismatch"
        );
        require(
            keccak256(bytes(bridge.symbol())) == keccak256(bytes(tokenSymbol)),
            "Deploy: symbol mismatch"
        );
        require(bridge.decimals() == 6, "Deploy: decimals mismatch");
        require(bridge.totalSupply() == 0, "Deploy: nonzero supply");
        require(bridge.latestBlock() == 0, "Deploy: nonzero latestBlock");
        require(bridge.pendingImplementation() == address(0), "Deploy: nonzero pending impl");
    }

    function _logDeployment(
        address proxy,
        address implementation,
        address genesisOwner,
        string memory tokenName,
        string memory tokenSymbol,
        string memory saltTag
    ) internal view {
        console.log("===== HypersnapBridge deployed (deterministic) =====");
        console.log("Chain id:       ", block.chainid);
        console.log("Implementation: ", implementation);
        console.log("Proxy:          ", proxy);
        console.log("Genesis owner:  ", genesisOwner);
        console.log("Token name:     ", tokenName);
        console.log("Token symbol:   ", tokenSymbol);
        console.log("Salt tag:       ", saltTag);
        console.log("");
        console.log("These addresses are reproducible on every chain where:");
        console.log("  - CreateX is deployed at 0xba5Ed099633D3B313e4D5F7bdc1305d3c28ba5Ed");
        console.log("  - msg.sender (deployer) is the same EOA");
        console.log("  - HYPERSNAP_SALT_TAG is unchanged");
    }

    /// Compose a CreateX salt with frontrun protection (deployer in bytes
    /// 0..19) and cross-chain enabled (byte 20 = 0x00).
    /// Bytes 21..31 are the keccak prefix of `tag` for entropy.
    function _saltFor(address deployer, string memory tag) internal pure returns (bytes32) {
        bytes32 entropyHash = keccak256(bytes(tag));
        // Layout: deployer(20) || 0x00(1) || entropyHash[0..10](11)
        return bytes32(abi.encodePacked(
            bytes20(deployer),
            bytes1(0x00),
            bytes11(entropyHash)
        ));
    }

    /// Apply CreateX's `_guard` for the (MsgSender + cross-chain-enabled)
    /// salt shape. This must match the off-chain prediction code in
    /// `deployer-ui/src/salt.ts::guardedCrossChainSalt`.
    function _guardedCrossChainSalt(address deployer, bytes32 rawSalt) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(bytes32(uint256(uint160(deployer))), rawSalt));
    }

    function _envStringOr(string memory key, string memory fallback_)
        internal
        view
        returns (string memory)
    {
        try vm.envString(key) returns (string memory v) {
            return v;
        } catch {
            return fallback_;
        }
    }
}
