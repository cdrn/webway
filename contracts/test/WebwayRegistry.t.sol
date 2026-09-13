// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {WebwayRegistry} from "../src/WebwayRegistry.sol";

contract WebwayRegistryTest is Test {
    WebwayRegistry reg;
    string json;
    address alice = address(0xA11CE);
    address bob = address(0xB0B);
    bytes20 constant IH = bytes20(uint160(0x1234));

    // bind vectors (test/vectors/ed25519.json .bind[i]): signed "webway-bind:<chainId>:<addr>:<epoch>" by two keys
    struct B { address addr; uint256 chainId; uint256 epoch; bytes msg; bytes32 pk; bytes sig; }

    event Bound(bytes32 indexed pk, address indexed addr, uint64 epoch);
    event Published(address indexed addr, bytes32 indexed nameHash, string name, bytes20 infohash, string license, uint64 seq);
    event NodesSet(address indexed addr);

    function setUp() public {
        reg = new WebwayRegistry();
        json = vm.readFile("test/vectors/ed25519.json");
        assertEq(block.chainid, 31337);
    }

    function _b(uint256 i) internal view returns (B memory b) {
        string memory k = string.concat(".bind[", vm.toString(i), "].");
        b.addr = vm.parseJsonAddress(json, string.concat(k, "addr"));
        b.chainId = vm.parseJsonUint(json, string.concat(k, "chainId"));
        b.epoch = vm.parseJsonUint(json, string.concat(k, "epoch"));
        b.msg = vm.parseJsonBytes(json, string.concat(k, "msg"));
        b.pk = vm.parseJsonBytes32(json, string.concat(k, "pk"));
        b.sig = vm.parseJsonBytes(json, string.concat(k, "sig"));
    }

    function _bind(uint256 i) internal {
        B memory b = _b(i);
        vm.prank(b.addr);
        reg.bind(b.pk, b.sig, uint64(b.epoch));
    }

    // ---- binding message ----

    function test_bindingMessage_matches_client() public view {
        for (uint256 i = 0; i < 8; i++) {
            B memory b = _b(i);
            if (b.chainId != 31337) continue;
            assertEq(reg.bindingMessage(b.addr, uint64(b.epoch)), b.msg, string.concat("vector ", vm.toString(i)));
        }
        assertEq(reg.bindingMessage(address(0), 0), bytes("webway-bind:31337:0x0000000000000000000000000000000000000000:0"));
        assertEq(reg.bindingMessage(address(type(uint160).max), type(uint64).max), bytes("webway-bind:31337:0xffffffffffffffffffffffffffffffffffffffff:18446744073709551615"));
    }

    // ---- bind ----

    function test_bind_happy_and_event() public {
        B memory b = _b(0);
        (,, bool set) = reg.ownerOf(b.pk);
        assertFalse(set);
        vm.expectEmit(true, true, false, true);
        emit Bound(b.pk, b.addr, 0);
        vm.prank(b.addr);
        uint256 g = gasleft();
        reg.bind(b.pk, b.sig, uint64(b.epoch));
        uint256 used = g - gasleft();
        (address a, uint64 e, bool s) = reg.ownerOf(b.pk);
        assertEq(a, b.addr);
        assertEq(e, 0);
        assertTrue(s);
        assertLt(used, 3_000_000);
    }

    function test_bind_rejects_bad_signature() public {
        B memory b = _b(0);
        bytes memory flipped = b.sig;
        flipped[10] ^= 0x01;
        vm.prank(b.addr);
        vm.expectRevert(WebwayRegistry.BadSignature.selector);
        reg.bind(b.pk, flipped, uint64(b.epoch));
        vm.prank(b.addr);
        vm.expectRevert(WebwayRegistry.BadSignature.selector);
        reg.bind(b.pk, new bytes(64), uint64(b.epoch));
        (,, bool set) = reg.ownerOf(b.pk);
        assertFalse(set);
    }

    function test_bind_rejects_wrong_length() public {
        B memory b = _b(0);
        vm.prank(b.addr);
        vm.expectRevert(WebwayRegistry.BadSignatureLength.selector);
        reg.bind(b.pk, new bytes(63), 0);
        vm.prank(b.addr);
        vm.expectRevert(WebwayRegistry.BadSignatureLength.selector);
        reg.bind(b.pk, "", 0);
    }

    function test_bind_rejects_wrong_sender() public {
        // vector 0 binds account 0; submitting it from account 1 means the message names the wrong address
        B memory b = _b(0);
        B memory other = _b(2);
        vm.prank(other.addr);
        vm.expectRevert(WebwayRegistry.BadSignature.selector);
        reg.bind(b.pk, b.sig, uint64(b.epoch));
        // squatter: any address with any bytes
        vm.prank(bob);
        vm.expectRevert(WebwayRegistry.BadSignature.selector);
        reg.bind(b.pk, b.sig, 0);
    }

    function test_bind_rejects_wrong_epoch_in_message() public {
        B memory b = _b(0);
        vm.prank(b.addr);
        vm.expectRevert(WebwayRegistry.BadSignature.selector);
        reg.bind(b.pk, b.sig, 1);
    }

    function test_bind_rejects_wrong_chain() public {
        B memory b = _b(5);
        assertEq(b.chainId, 31338);
        vm.prank(b.addr);
        vm.expectRevert(WebwayRegistry.BadSignature.selector);
        reg.bind(b.pk, b.sig, uint64(b.epoch));
        // on the chain it was signed for, it works
        vm.chainId(31338);
        vm.prank(b.addr);
        reg.bind(b.pk, b.sig, uint64(b.epoch));
        (address a,,) = reg.ownerOf(b.pk);
        assertEq(a, b.addr);
    }

    function test_bind_epoch_must_increase_and_rotation() public {
        _bind(0); // account 0, epoch 0
        B memory v0 = _b(0);
        // same epoch again → revert
        vm.prank(v0.addr);
        vm.expectRevert(abi.encodeWithSelector(WebwayRegistry.EpochNotIncreasing.selector, uint64(0), uint64(0)));
        reg.bind(v0.pk, v0.sig, 0);
        _bind(1); // account 0, epoch 1
        (address a, uint64 e,) = reg.ownerOf(v0.pk);
        assertEq(a, v0.addr);
        assertEq(e, 1);
        _bind(2); // rotate to account 1, epoch 2
        (a, e,) = reg.ownerOf(v0.pk);
        assertEq(a, _b(2).addr);
        assertEq(e, 2);
        // lower epoch from account 1 → revert
        B memory low = _b(3);
        vm.prank(low.addr);
        vm.expectRevert(abi.encodeWithSelector(WebwayRegistry.EpochNotIncreasing.selector, uint64(2), uint64(1)));
        reg.bind(low.pk, low.sig, uint64(low.epoch));
        // the old account cannot re-take the key with its old signature (epoch 1 <= 2)
        B memory old = _b(1);
        vm.prank(old.addr);
        vm.expectRevert(abi.encodeWithSelector(WebwayRegistry.EpochNotIncreasing.selector, uint64(2), uint64(1)));
        reg.bind(old.pk, old.sig, uint64(old.epoch));
        _bind(4); // rotate to account 2, epoch 5
        (a, e,) = reg.ownerOf(v0.pk);
        assertEq(a, _b(4).addr);
        assertEq(e, 5);
    }

    function test_first_bind_at_nonzero_epoch() public {
        B memory b = _b(4); // key A, account 2, epoch 5, never bound before
        (,, bool set) = reg.ownerOf(b.pk);
        assertFalse(set);
        vm.prank(b.addr);
        reg.bind(b.pk, b.sig, uint64(b.epoch));
        (address a, uint64 e, bool s) = reg.ownerOf(b.pk);
        assertEq(a, b.addr);
        assertEq(e, 5);
        assertTrue(s);
        // epochs 0..5 are now dead for this key
        B memory v0 = _b(0);
        vm.prank(v0.addr);
        vm.expectRevert(abi.encodeWithSelector(WebwayRegistry.EpochNotIncreasing.selector, uint64(5), uint64(0)));
        reg.bind(v0.pk, v0.sig, 0);
    }

    function test_checkBinding_preflight_matches_bind() public {
        B memory b = _b(0);
        assertTrue(reg.checkBinding(b.pk, b.addr, uint64(b.epoch), b.sig));
        assertFalse(reg.checkBinding(b.pk, bob, uint64(b.epoch), b.sig), "wrong address");
        assertFalse(reg.checkBinding(b.pk, b.addr, uint64(b.epoch) + 1, b.sig), "wrong epoch");
        assertFalse(reg.checkBinding(b.pk, b.addr, uint64(b.epoch), new bytes(64)), "zero sig");
        assertFalse(reg.checkBinding(b.pk, b.addr, uint64(b.epoch), new bytes(63)), "wrong length");
        // identity key + identity R, S = 0: a cofactored off-chain verifier accepts this; the contract does not
        bytes32 idPk = hex"0100000000000000000000000000000000000000000000000000000000000000";
        bytes memory idSig = abi.encodePacked(idPk, bytes32(0));
        assertFalse(reg.checkBinding(idPk, b.addr, 0, idSig));
        vm.prank(b.addr);
        vm.expectRevert(WebwayRegistry.BadSignature.selector);
        reg.bind(idPk, idSig, 0);
        // pre-flight does not check epoch ordering (that is bind's job)
        vm.prank(b.addr);
        reg.bind(b.pk, b.sig, uint64(b.epoch));
        assertTrue(reg.checkBinding(b.pk, b.addr, uint64(b.epoch), b.sig), "still a valid signature");
        vm.prank(b.addr);
        vm.expectRevert(abi.encodeWithSelector(WebwayRegistry.EpochNotIncreasing.selector, uint64(0), uint64(0)));
        reg.bind(b.pk, b.sig, uint64(b.epoch));
    }

    function test_bind_uint64_max_epoch_then_frozen() public {
        _bind(6); // key B, epoch 0
        _bind(7); // key B, epoch uint64.max
        B memory b = _b(7);
        (, uint64 e,) = reg.ownerOf(b.pk);
        assertEq(e, type(uint64).max);
        vm.prank(b.addr);
        vm.expectRevert(abi.encodeWithSelector(WebwayRegistry.EpochNotIncreasing.selector, type(uint64).max, type(uint64).max));
        reg.bind(b.pk, b.sig, type(uint64).max);
    }

    function test_keys_independent() public {
        _bind(0);
        _bind(6);
        (address a0,,) = reg.ownerOf(_b(0).pk);
        (address a6,,) = reg.ownerOf(_b(6).pk);
        assertEq(a0, _b(0).addr);
        assertEq(a6, _b(6).addr);
        (,, bool set) = reg.ownerOf(keccak256("nobody"));
        assertFalse(set);
    }

    // ---- publish follows the owner ----

    function test_resolution_follows_owner_across_rotation() public {
        _bind(0);
        B memory v = _b(0);
        bytes32 nh = keccak256("acme/m");
        vm.prank(v.addr);
        reg.publish("acme/m", IH, "mit", type(uint64).max); // old account maxes out its seq
        (address owner,,) = reg.ownerOf(v.pk);
        (bytes20 ih,, uint64 seq) = reg.resolve(owner, nh);
        assertEq(ih, IH);
        assertEq(seq, type(uint64).max);
        _bind(2); // rotate to account 1
        (owner,,) = reg.ownerOf(v.pk);
        (ih,, seq) = reg.resolve(owner, nh);
        assertEq(ih, bytes20(0), "new owner has not published yet: no record, not the old one");
        assertEq(seq, 0);
        vm.prank(owner);
        reg.publish("acme/m", bytes20(uint160(9)), "", 1);
        (ih,, seq) = reg.resolve(owner, nh);
        assertEq(ih, bytes20(uint160(9)));
        assertEq(seq, 1);
    }

    // ---- publish ----

    function test_publish_and_resolve() public {
        vm.warp(1_700_000_000);
        bytes32 nh = keccak256("acme/tiny");
        vm.expectEmit(true, true, false, true);
        emit Published(alice, nh, "acme/tiny", IH, "apache-2.0", 7);
        vm.prank(alice);
        reg.publish("acme/tiny", IH, "apache-2.0", 7);
        (bytes20 ih, string memory lic, uint64 seq) = reg.resolve(alice, nh);
        assertEq(ih, IH);
        assertEq(lic, "apache-2.0");
        assertEq(seq, 7);
        assertEq(reg.updatedAt(alice, nh), 1_700_000_000);
    }

    function test_publish_per_address_independent() public {
        vm.prank(alice);
        reg.publish("n", IH, "", 3);
        vm.prank(bob);
        reg.publish("n", bytes20(uint160(2)), "", 1);
        (bytes20 ih1,, uint64 s1) = reg.resolve(alice, keccak256("n"));
        (bytes20 ih2,, uint64 s2) = reg.resolve(bob, keccak256("n"));
        assertEq(ih1, IH);
        assertEq(s1, 3);
        assertEq(ih2, bytes20(uint160(2)));
        assertEq(s2, 1);
    }

    function test_publish_seq_must_strictly_increase() public {
        vm.startPrank(alice);
        reg.publish("n", IH, "", 5);
        vm.expectRevert(abi.encodeWithSelector(WebwayRegistry.SeqNotIncreasing.selector, uint64(5), uint64(5)));
        reg.publish("n", IH, "", 5);
        vm.expectRevert(abi.encodeWithSelector(WebwayRegistry.SeqNotIncreasing.selector, uint64(5), uint64(4)));
        reg.publish("n", IH, "", 4);
        vm.expectRevert(abi.encodeWithSelector(WebwayRegistry.SeqNotIncreasing.selector, uint64(5), uint64(0)));
        reg.publish("n", IH, "", 0);
        reg.publish("n", bytes20(uint160(9)), "mit", 6);
        vm.stopPrank();
        (bytes20 ih, string memory lic, uint64 seq) = reg.resolve(alice, keccak256("n"));
        assertEq(ih, bytes20(uint160(9)));
        assertEq(lic, "mit");
        assertEq(seq, 6);
    }

    function test_publish_seq_zero_first_reverts() public {
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(WebwayRegistry.SeqNotIncreasing.selector, uint64(0), uint64(0)));
        reg.publish("n", IH, "", 0);
    }

    function test_publish_max_seq() public {
        vm.startPrank(alice);
        reg.publish("n", IH, "", type(uint64).max - 1);
        reg.publish("n", IH, "", type(uint64).max);
        vm.expectRevert(abi.encodeWithSelector(WebwayRegistry.SeqNotIncreasing.selector, type(uint64).max, type(uint64).max));
        reg.publish("n", IH, "", type(uint64).max);
        vm.stopPrank();
    }

    function test_publish_names_independent() public {
        vm.startPrank(alice);
        reg.publish("a", IH, "", 10);
        reg.publish("b", IH, "", 1);
        vm.stopPrank();
        (,, uint64 sa) = reg.resolve(alice, keccak256("a"));
        (,, uint64 sb) = reg.resolve(alice, keccak256("b"));
        assertEq(sa, 10);
        assertEq(sb, 1);
    }

    function test_publish_name_bounds() public {
        vm.startPrank(alice);
        vm.expectRevert(WebwayRegistry.BadName.selector);
        reg.publish("", IH, "", 1);
        reg.publish(new string(128), IH, "", 1);
        vm.expectRevert(WebwayRegistry.BadName.selector);
        reg.publish(new string(129), IH, "", 1);
        vm.stopPrank();
    }

    function test_publish_license_bounds() public {
        vm.startPrank(alice);
        reg.publish("n", IH, new string(64), 1);
        vm.expectRevert(WebwayRegistry.BadLicense.selector);
        reg.publish("n", IH, new string(65), 2);
        vm.stopPrank();
    }

    function test_resolve_unknown_is_zero() public view {
        (bytes20 ih, string memory lic, uint64 seq) = reg.resolve(alice, keccak256("nope"));
        assertEq(ih, bytes20(0));
        assertEq(bytes(lic).length, 0);
        assertEq(seq, 0);
        assertEq(reg.nodesOf(alice).length, 0);
    }

    // ---- nodes ----

    function test_setNodes_roundtrip_replace_clear() public {
        string[] memory n = new string[](2);
        n[0] = "1.2.3.4:6881";
        n[1] = "[2001:db8::1]:6881";
        vm.expectEmit(true, false, false, false);
        emit NodesSet(alice);
        vm.prank(alice);
        reg.setNodes(n);
        string[] memory got = reg.nodesOf(alice);
        assertEq(got.length, 2);
        assertEq(got[0], n[0]);
        assertEq(got[1], n[1]);
        string[] memory one = new string[](1);
        one[0] = "5.6.7.8:1";
        vm.prank(alice);
        reg.setNodes(one);
        got = reg.nodesOf(alice);
        assertEq(got.length, 1);
        assertEq(got[0], "5.6.7.8:1");
        vm.prank(alice);
        reg.setNodes(new string[](0));
        assertEq(reg.nodesOf(alice).length, 0);
        assertEq(reg.nodesOf(bob).length, 0);
    }

    function test_setNodes_bounds_and_rollback() public {
        string[] memory twenty = new string[](20);
        for (uint256 i = 0; i < 20; i++) twenty[i] = "h:1";
        vm.prank(alice);
        reg.setNodes(twenty);
        assertEq(reg.nodesOf(alice).length, 20);
        string[] memory tooMany = new string[](21);
        for (uint256 i = 0; i < 21; i++) tooMany[i] = "h:1";
        vm.prank(alice);
        vm.expectRevert(WebwayRegistry.BadNodes.selector);
        reg.setNodes(tooMany);
        string[] memory mixed = new string[](3);
        mixed[0] = "ok:1";
        mixed[1] = new string(65);
        mixed[2] = "ok:2";
        vm.prank(alice);
        vm.expectRevert(WebwayRegistry.BadNodes.selector);
        reg.setNodes(mixed);
        assertEq(reg.nodesOf(alice).length, 20);
        string[] memory empty = new string[](1);
        empty[0] = "";
        vm.prank(alice);
        vm.expectRevert(WebwayRegistry.BadNodes.selector);
        reg.setNodes(empty);
        assertEq(reg.nodesOf(alice).length, 20);
    }

    function test_setNodes_max_size_replacement_gas() public {
        string[] memory big = new string[](20);
        for (uint256 i = 0; i < 20; i++) big[i] = new string(64);
        vm.prank(alice);
        reg.setNodes(big);
        uint256 g = gasleft();
        vm.prank(alice);
        reg.setNodes(big);
        assertLt(g - gasleft(), 1_500_000);
        assertEq(reg.nodesOf(alice).length, 20);
    }

    // ---- fuzz ----

    function testFuzz_seq_ordering(uint64 a, uint64 b) public {
        vm.assume(a > 0);
        vm.startPrank(alice);
        reg.publish("n", IH, "", a);
        if (b > a) {
            reg.publish("n", IH, "", b);
            (,, uint64 s) = reg.resolve(alice, keccak256("n"));
            assertEq(s, b);
        } else {
            vm.expectRevert(abi.encodeWithSelector(WebwayRegistry.SeqNotIncreasing.selector, a, b));
            reg.publish("n", IH, "", b);
        }
        vm.stopPrank();
    }

    function testFuzz_bind_random_bytes_never_binds(bytes32 pk, bytes memory sig, uint64 epoch, address who) public {
        vm.assume(sig.length == 64);
        vm.prank(who);
        vm.expectRevert(WebwayRegistry.BadSignature.selector);
        reg.bind(pk, sig, epoch);
        (,, bool set) = reg.ownerOf(pk);
        assertFalse(set);
    }
}
