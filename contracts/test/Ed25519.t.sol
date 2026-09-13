// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {Ed25519} from "../src/Ed25519.sol";
import {Sha512} from "../src/Sha512.sol";
import {Ed25519Harness} from "./Ed25519Harness.sol";

// Vectors come from contracts/test/vectors/ed25519.json (node contracts/script/gen-vectors.mjs):
// RFC 8032 section 7.1, 200 random noble-ed25519 signatures, negative cases, and SHA-512 vectors.
// Elements are read with typed cheatcodes (parseJson's type inference would turn a 32-byte
// message into bytes32).
contract Ed25519Test is Test {
    string json;

    function setUp() public {
        json = vm.readFile("test/vectors/ed25519.json");
    }

    function _count(string memory set) internal view returns (uint256) {
        return vm.parseJsonUint(json, string.concat(".counts.", set));
    }

    function _key(string memory set, uint256 i, string memory field) internal pure returns (string memory) {
        return string.concat(".", set, "[", vm.toString(i), "].", field);
    }

    function _vec(string memory set, uint256 i) internal view returns (bytes memory msg_, bytes32 pk, bytes memory sig) {
        msg_ = vm.parseJsonBytes(json, _key(set, i, "msg"));
        pk = vm.parseJsonBytes32(json, _key(set, i, "pk"));
        sig = vm.parseJsonBytes(json, _key(set, i, "sig"));
    }

    // ---- SHA-512 ----

    function test_sha512_vectors() public view {
        uint256 n = _count("sha");
        assertGt(n, 80);
        for (uint256 i = 0; i < n; i++) {
            bytes memory m = vm.parseJsonBytes(json, _key("sha", i, "msg"));
            bytes memory out = vm.parseJsonBytes(json, _key("sha", i, "out"));
            assertEq(Sha512.hash(m), out, string.concat("sha512 vector ", vm.toString(i)));
        }
    }

    function test_sha512_fips() public pure {
        assertEq(
            Sha512.hash("abc"),
            hex"ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        );
        assertEq(
            Sha512.hash(""),
            hex"cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        );
    }

    // ---- Ed25519 positive ----

    function test_rfc8032_vectors() public view {
        uint256 n = _count("rfc");
        assertEq(n, 5);
        for (uint256 i = 0; i < n; i++) {
            (bytes memory m, bytes32 pk, bytes memory sig) = _vec("rfc", i);
            assertTrue(Ed25519.verify(pk, sig, m), string.concat("rfc vector ", vm.toString(i)));
        }
    }

    function test_random_vectors() public view {
        uint256 n = _count("random");
        assertEq(n, 200);
        for (uint256 i = 0; i < n; i++) {
            (bytes memory m, bytes32 pk, bytes memory sig) = _vec("random", i);
            assertTrue(Ed25519.verify(pk, sig, m), string.concat("random vector ", vm.toString(i)));
        }
    }

    // ---- Ed25519 negative ----

    function test_negative_vectors() public view {
        uint256 n = _count("negative");
        assertGt(n, 300);
        for (uint256 i = 0; i < n; i++) {
            (bytes memory m, bytes32 pk, bytes memory sig) = _vec("negative", i);
            string memory why = vm.parseJsonString(json, _key("negative", i, "why"));
            assertFalse(Ed25519.verify(pk, sig, m), string.concat("negative ", vm.toString(i), ": ", why));
        }
    }

    function test_rejects_wrong_sig_length() public view {
        (bytes memory m, bytes32 pk, bytes memory sig) = _vec("rfc", 0);
        bytes memory s63 = new bytes(63);
        bytes memory s65 = new bytes(65);
        for (uint256 i = 0; i < 63; i++) s63[i] = sig[i];
        for (uint256 i = 0; i < 64; i++) s65[i] = sig[i];
        assertFalse(Ed25519.verify(pk, s63, m));
        assertFalse(Ed25519.verify(pk, s65, m));
        assertFalse(Ed25519.verify(pk, "", m));
    }

    function test_rejects_S_ge_L_exactly() public view {
        (bytes memory m, bytes32 pk, bytes memory sig) = _vec("rfc", 0);
        bytes32 r;
        assembly { r := mload(add(sig, 32)) }
        assertFalse(Ed25519.verify(pk, abi.encodePacked(r, _le(Ed25519.L)), m));
        assertFalse(Ed25519.verify(pk, abi.encodePacked(r, bytes32(type(uint256).max)), m));
        assertFalse(Ed25519.verify(pk, abi.encodePacked(r, _le(Ed25519.L - 1)), m));
    }

    function _le(uint256 x) internal pure returns (bytes32 out) {
        for (uint256 i = 0; i < 32; i++) {
            out |= bytes32(bytes1(uint8(x >> (8 * i)))) >> (8 * i);
        }
    }

    // ---- internals ----

    function test_le_roundtrip() public pure {
        assertEq(Ed25519.le(_le(0)), 0);
        assertEq(Ed25519.le(_le(1)), 1);
        assertEq(Ed25519.le(_le(Ed25519.L)), Ed25519.L);
        assertEq(Ed25519.le(_le(type(uint256).max)), type(uint256).max);
        assertEq(Ed25519.le(hex"0100000000000000000000000000000000000000000000000000000000000000"), 1);
        assertEq(Ed25519.le(hex"0000000000000000000000000000000000000000000000000000000000000080"), 1 << 255);
    }

    function test_base_point_and_torsion() public view {
        Ed25519.Pt memory B = Ed25519.Pt(Ed25519.BX, Ed25519.BY, 1, mulmod(Ed25519.BX, Ed25519.BY, Ed25519.P));
        assertFalse(Ed25519.isSmallOrder(B));
        Ed25519.Pt memory zero = Ed25519.Pt(0, 1, 1, 0);
        Ed25519.Pt memory q = Ed25519.shamir(Ed25519.L, B, 0, zero);
        assertTrue(Ed25519.isIdentity(q), "[L]B == identity");
        q = Ed25519.shamir(Ed25519.L - 1, B, 0, zero);
        Ed25519.Pt memory nB = Ed25519.Pt(Ed25519.P - Ed25519.BX, Ed25519.BY, 1, Ed25519.P - mulmod(Ed25519.BX, Ed25519.BY, Ed25519.P));
        assertTrue(Ed25519.eq(q, nB), "[L-1]B == -B");
        (bool ok, Ed25519.Pt memory id) = Ed25519.decompress(hex"0100000000000000000000000000000000000000000000000000000000000000");
        assertTrue(ok);
        assertTrue(Ed25519.isSmallOrder(id), "identity");
        (ok, id) = Ed25519.decompress(hex"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");
        assertTrue(ok);
        assertTrue(Ed25519.isSmallOrder(id), "order 2");
        (ok, id) = Ed25519.decompress(bytes32(0));
        assertTrue(ok);
        assertTrue(Ed25519.isSmallOrder(id), "order 4");
        (ok,) = Ed25519.decompress(hex"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");
        assertFalse(ok, "y = p is non-canonical");
        (ok, id) = Ed25519.decompress(hex"5866666666666666666666666666666666666666666666666666666666666666");
        assertTrue(ok);
        assertTrue(Ed25519.eq(id, B), "decompress(B) == B");
    }

    // ---- hardening ----

    // Foundry cannot etch over 0x05, so the guarded call takes its target as a parameter
    // (production passes address(5)); mocks live at ordinary addresses.
    function test_modexp_real_precompile() public {
        Ed25519Harness h = new Ed25519Harness();
        assertEq(h.modexpAt(address(5), 2, 10), 1024);
        assertEq(h.modexpAt(address(5), Ed25519.I, 2), Ed25519.P - 1, "sqrt(-1)^2 == -1");
    }

    function test_modexp_missing_precompile_reverts() public {
        Ed25519Harness h = new Ed25519Harness();
        address empty = address(0x1234);
        assertEq(empty.code.length, 0);
        // staticcall to an empty account "succeeds" with zero return data → must revert, never mis-verify
        vm.expectRevert(Ed25519.ModexpUnavailable.selector);
        h.modexpAt(empty, 2, 10);
    }

    function test_modexp_short_return_reverts() public {
        Ed25519Harness h = new Ed25519Harness();
        address mock = address(0x1235);
        vm.etch(mock, hex"60106000f3"); // PUSH1 0x10 PUSH1 0 RETURN → returns 16 bytes
        vm.expectRevert(Ed25519.ModexpUnavailable.selector);
        h.modexpAt(mock, 2, 10);
    }

    function test_modexp_unreduced_return_reverts() public {
        Ed25519Harness h = new Ed25519Harness();
        address mock = address(0x1236);
        // PUSH32 0xff..ff PUSH1 0 MSTORE PUSH1 32 PUSH1 0 RETURN → returns 2^256-1 (>= P)
        vm.etch(mock, hex"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff60005260206000f3");
        vm.expectRevert(Ed25519.ModexpUnavailable.selector);
        h.modexpAt(mock, 2, 10);
        address rev = address(0x1237);
        vm.etch(rev, hex"60006000fd"); // PUSH1 0 PUSH1 0 REVERT
        vm.expectRevert(Ed25519.ModexpUnavailable.selector);
        h.modexpAt(rev, 2, 10);
    }

    function test_sha512_dirty_memory() public {
        Ed25519Harness h = new Ed25519Harness();
        uint256 n = _count("sha");
        for (uint256 i = 0; i < n; i++) {
            bytes memory m = vm.parseJsonBytes(json, _key("sha", i, "msg"));
            bytes memory out = vm.parseJsonBytes(json, _key("sha", i, "out"));
            assertEq(h.sha512Dirty(m), out, string.concat("dirty-memory sha512 vector ", vm.toString(i)));
        }
        assertEq(h.sha512Dirty("abc"), hex"ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
    }

    function test_scalar_paths_with_bit_252_set() public {
        // k with bit 252 set is unreachable by search (k = H mod L >= 2^252 has probability ~2^-128),
        // so exercise the scalar multiplication directly: [L-1]A == -A and [L-1]B + [L-1]A == -(B+A).
        Ed25519Harness h = new Ed25519Harness();
        (bytes memory m, bytes32 pk, bytes memory sig) = _vec("rfc", 0);
        assertTrue(h.verify(pk, sig, m));
        bytes32 negPk = pk ^ bytes32(uint256(1) << 7); // flip the sign bit → -A
        assertTrue(h.shamirEq(0, Ed25519.L - 1, pk, negPk), "[L-1]A == -A");
        assertTrue(h.shamirEq(Ed25519.L, Ed25519.L, pk, hex"0100000000000000000000000000000000000000000000000000000000000000"), "[L]B + [L]A == identity");
        uint256 k = (uint256(1) << 252) + 12345; // bit 252 set, < L
        uint256 s = (uint256(1) << 252) + 7;
        assertTrue(k < Ed25519.L && s < Ed25519.L);
        // [k]A + [L-k]A == identity and ([s]B + [k]A) + ([L-s]B + [L-k]A) == identity: bit 252 paths for both scalars
        assertTrue(h.shamirSumIsIdentity(0, k, 0, Ed25519.L - k, pk), "[k]A + [L-k]A");
        assertTrue(h.shamirSumIsIdentity(s, k, Ed25519.L - s, Ed25519.L - k, pk), "[s]B+[k]A + [L-s]B+[L-k]A");
        assertFalse(h.shamirSumIsIdentity(s, k, Ed25519.L - s, Ed25519.L - k - 1, pk), "off by one is not identity");
    }

    // ---- gas ----

    function test_gas_worst_case() public {
        Ed25519Harness h = new Ed25519Harness();
        uint256 n = _count("worst");
        uint256 worstVerify;
        for (uint256 i = 0; i < n; i++) {
            (bytes memory m, bytes32 pk, bytes memory sig) = _vec("worst", i);
            string memory why = vm.parseJsonString(json, _key("worst", i, "why"));
            uint256 g = gasleft();
            bool ok = Ed25519.verify(pk, sig, m);
            uint256 used = g - gasleft();
            assertTrue(ok, why);
            console.log("verify gas, %s: %d", why, used);
            if (used > worstVerify) worstVerify = used;
        }
        // scalar path with every bit of both scalars set (maximum additions in Shamir's loop)
        (, bytes32 pk,) = _vec("rfc", 0);
        (uint256 scalarGas,) = h.shamirGas((uint256(1) << 253) - 1, (uint256(1) << 253) - 1, pk);
        console.log("shamir gas, all-ones scalars: %d", scalarGas);
        // upper bound for a real verification: worst measured verify + (all-ones scalar path - typical scalar path)
        (uint256 typicalScalar,) = h.shamirGas(Ed25519.L - 1, (uint256(1) << 252) + 1, pk);
        uint256 bound = worstVerify + (scalarGas > typicalScalar ? scalarGas - typicalScalar : 0);
        console.log("worst-case verify bound: %d", bound);
        assertLt(bound, 1_200_000);
    }

    function test_gas_verify() public view {
        (bytes memory m, bytes32 pk, bytes memory sig) = _vec("random", 0);
        uint256 g = gasleft();
        bool ok = Ed25519.verify(pk, sig, m);
        uint256 used = g - gasleft();
        assertTrue(ok);
        console.log("Ed25519.verify gas (msg %d bytes): %d", m.length, used);
        g = gasleft();
        Sha512.hash(m);
        console.log("Sha512.hash gas (%d bytes): %d", m.length, g - gasleft());
        assertLt(used, 3_000_000);
    }
}
