// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {Ed25519} from "./Ed25519.sol";

/// @title WebwayRegistry
/// @notice Permanent, global index for webway names.
///
///         A webway publisher is an ed25519 key (the same one that signs BEP44
///         names in the DHT). `bind` lets that key name the Ethereum account
///         that publishes for it: the contract verifies, on-chain, an ed25519
///         signature by `pk` over
///             "webway-bind:<chainId>:<0x lowercase address>:<epoch>"
///         and only then records `owner[pk] = (msg.sender, epoch)`. Each new
///         binding must carry a strictly higher epoch, so re-binding from a
///         fresh account revokes a compromised one, and nobody but the key
///         holder can ever change the owner. There is nothing to squat, scan,
///         or hint: one key, one owner, verified by the chain itself.
///
///         Records and bootstrap nodes are keyed by the account.
contract WebwayRegistry {
    struct Record {
        bytes20 infohash;
        string license;
        uint64 seq;
        uint64 updatedAt;
    }

    struct Owner {
        address addr;
        uint64 epoch;
        bool set;
    }

    uint256 public constant MAX_NAME = 128;
    uint256 public constant MAX_LICENSE = 64;
    uint256 public constant MAX_NODES = 20;
    uint256 public constant MAX_NODE_LEN = 64;

    mapping(bytes32 => Owner) private _owner;
    mapping(address => mapping(bytes32 => Record)) private _records;
    mapping(address => string[]) private _nodes;

    event Bound(bytes32 indexed pk, address indexed addr, uint64 epoch);
    event Published(address indexed addr, bytes32 indexed nameHash, string name, bytes20 infohash, string license, uint64 seq);
    event NodesSet(address indexed addr);

    error BadSignatureLength();
    error BadSignature();
    error EpochNotIncreasing(uint64 have, uint64 got);
    error BadName();
    error BadLicense();
    error BadNodes();
    error SeqNotIncreasing(uint64 have, uint64 got);

    /// @notice The exact bytes a publisher key must sign to bind `addr` at `epoch` on this chain.
    function bindingMessage(address addr, uint64 epoch) public view returns (bytes memory) {
        return abi.encodePacked("webway-bind:", _dec(block.chainid), ":0x", _hex(addr), ":", _dec(epoch));
    }

    /// @notice Pre-flight: would `bind(pk, sig, epoch)` from `addr` pass signature verification?
    ///         Runs the exact on-chain verifier without touching state (epoch ordering is not checked here).
    function checkBinding(bytes32 pk, address addr, uint64 epoch, bytes calldata sig) external view returns (bool) {
        if (sig.length != 64) return false;
        return Ed25519.verify(pk, sig, bindingMessage(addr, epoch));
    }

    /// @notice Set `owner[pk] = (msg.sender, epoch)` if `sig` is pk's ed25519 signature over
    ///         bindingMessage(msg.sender, epoch) and `epoch` exceeds the current one (any epoch for a first bind).
    function bind(bytes32 pk, bytes calldata sig, uint64 epoch) external {
        if (sig.length != 64) revert BadSignatureLength();
        Owner storage o = _owner[pk];
        if (o.set && epoch <= o.epoch) revert EpochNotIncreasing(o.epoch, epoch);
        if (!Ed25519.verify(pk, sig, bindingMessage(msg.sender, epoch))) revert BadSignature();
        o.addr = msg.sender;
        o.epoch = epoch;
        o.set = true;
        emit Bound(pk, msg.sender, epoch);
    }

    /// @notice Publish a name under msg.sender. `seq` must strictly increase per (msg.sender, name).
    function publish(string calldata name, bytes20 infohash, string calldata license, uint64 seq) external {
        uint256 nlen = bytes(name).length;
        if (nlen == 0 || nlen > MAX_NAME) revert BadName();
        if (bytes(license).length > MAX_LICENSE) revert BadLicense();
        bytes32 nameHash = keccak256(bytes(name));
        Record storage r = _records[msg.sender][nameHash];
        if (seq <= r.seq) revert SeqNotIncreasing(r.seq, seq);
        r.infohash = infohash;
        r.license = license;
        r.seq = seq;
        r.updatedAt = uint64(block.timestamp);
        emit Published(msg.sender, nameHash, name, infohash, license, seq);
    }

    /// @notice Replace msg.sender's advertised DHT bootstrap nodes ("host:port" strings).
    function setNodes(string[] calldata nodes) external {
        if (nodes.length > MAX_NODES) revert BadNodes();
        delete _nodes[msg.sender];
        string[] storage dst = _nodes[msg.sender];
        for (uint256 i = 0; i < nodes.length; i++) {
            if (bytes(nodes[i]).length == 0 || bytes(nodes[i]).length > MAX_NODE_LEN) revert BadNodes();
            dst.push(nodes[i]);
        }
        emit NodesSet(msg.sender);
    }

    // ---- views ----

    function ownerOf(bytes32 pk) external view returns (address addr, uint64 epoch, bool set) {
        Owner storage o = _owner[pk];
        return (o.addr, o.epoch, o.set);
    }

    function resolve(address addr, bytes32 nameHash) external view returns (bytes20 infohash, string memory license, uint64 seq) {
        Record storage r = _records[addr][nameHash];
        return (r.infohash, r.license, r.seq);
    }

    function updatedAt(address addr, bytes32 nameHash) external view returns (uint64) {
        return _records[addr][nameHash].updatedAt;
    }

    function nodesOf(address addr) external view returns (string[] memory) {
        return _nodes[addr];
    }

    // ---- string helpers ----

    function _dec(uint256 v) private pure returns (bytes memory) {
        if (v == 0) return "0";
        uint256 n = v;
        uint256 len;
        while (n != 0) { len++; n /= 10; }
        bytes memory out = new bytes(len);
        while (v != 0) { out[--len] = bytes1(uint8(48 + v % 10)); v /= 10; }
        return out;
    }

    function _hex(address a) private pure returns (bytes memory out) {
        bytes16 alphabet = "0123456789abcdef";
        out = new bytes(40);
        uint160 v = uint160(a);
        for (uint256 i = 0; i < 20; i++) {
            uint8 b = uint8(v >> (8 * (19 - i)));
            out[2 * i] = alphabet[b >> 4];
            out[2 * i + 1] = alphabet[b & 0x0f];
        }
    }
}
