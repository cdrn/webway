// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {Ed25519} from "../src/Ed25519.sol";
import {Sha512} from "../src/Sha512.sol";

/// External wrappers so tests can vm.expectRevert around library internals and measure gas per call.
contract Ed25519Harness {
    function verify(bytes32 pk, bytes calldata sig, bytes calldata message) external view returns (bool) {
        return Ed25519.verify(pk, sig, message);
    }

    function decompress(bytes32 b) external view returns (bool ok, uint256 x, uint256 y) {
        (bool o, Ed25519.Pt memory p) = Ed25519.decompress(b);
        return (o, p.x, p.y);
    }

    function shamirGas(uint256 s, uint256 k, bytes32 apk) external view returns (uint256 used, bool okA) {
        (bool o, Ed25519.Pt memory A) = Ed25519.decompress(apk);
        Ed25519.Pt memory nA = Ed25519.Pt(A.x == 0 ? 0 : Ed25519.P - A.x, A.y, A.z, A.t == 0 ? 0 : Ed25519.P - A.t);
        Ed25519.Pt memory B = Ed25519.Pt(Ed25519.BX, Ed25519.BY, 1, mulmod(Ed25519.BX, Ed25519.BY, Ed25519.P));
        uint256 g = gasleft();
        Ed25519.shamir(s, B, k, nA);
        used = g - gasleft();
        okA = o;
    }

    function shamirEq(uint256 s, uint256 k, bytes32 apk, bytes32 expected) external view returns (bool) {
        (, Ed25519.Pt memory A) = Ed25519.decompress(apk);
        Ed25519.Pt memory B = Ed25519.Pt(Ed25519.BX, Ed25519.BY, 1, mulmod(Ed25519.BX, Ed25519.BY, Ed25519.P));
        Ed25519.Pt memory q = Ed25519.shamir(s, B, k, A);
        (, Ed25519.Pt memory e) = Ed25519.decompress(expected);
        return Ed25519.eq(q, e);
    }

    /// ([s1]B + [k1]A) + ([s2]B + [k2]A) == identity ?
    function shamirSumIsIdentity(uint256 s1, uint256 k1, uint256 s2, uint256 k2, bytes32 apk) external view returns (bool) {
        (, Ed25519.Pt memory A) = Ed25519.decompress(apk);
        Ed25519.Pt memory B = Ed25519.Pt(Ed25519.BX, Ed25519.BY, 1, mulmod(Ed25519.BX, Ed25519.BY, Ed25519.P));
        Ed25519.Pt memory q1 = Ed25519.shamir(s1, B, k1, A);
        Ed25519.Pt memory q2 = Ed25519.shamir(s2, B, k2, A);
        Ed25519.add(q1, q2);
        return Ed25519.isIdentity(q1);
    }

    function modexpAt(address precompile, uint256 base, uint256 e) external view returns (uint256) {
        return Ed25519.modexpAt(precompile, base, e);
    }

    function sha512(bytes calldata m) external pure returns (bytes memory) {
        return Sha512.hash(m);
    }

    /// Dirty the free memory (0xff words past the free pointer, pointer untouched) then hash.
    function sha512Dirty(bytes calldata m) external pure returns (bytes memory) {
        assembly {
            let fmp := mload(0x40)
            for { let i := 0 } lt(i, 8192) { i := add(i, 32) } { mstore(add(fmp, i), not(0)) }
        }
        return Sha512.hash(m);
    }
}
