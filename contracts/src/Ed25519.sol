// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {Sha512} from "./Sha512.sol";

/// @title Ed25519
/// @notice RFC 8032 Ed25519 signature verification in pure Solidity.
///
///         Strict: S must be < L; A and R must be canonically encoded (y < p)
///         and on the curve; x = 0 with the sign bit set is rejected; A and R
///         of small order (8·P = identity, which includes the identity itself)
///         are rejected. The group equation is checked without the cofactor:
///         [S]B == R + [k]A.
///
///         Arithmetic is in extended twisted-Edwards coordinates (a = -1) with
///         the HWCD 2008 formulas; the double scalar multiplication uses
///         Shamir's trick. Square roots use the modexp precompile.
library Ed25519 {
    uint256 internal constant P = 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed; // 2^255 - 19
    uint256 internal constant D = 37095705934669439343138083508754565189542113879843219016388785533085940283555; // -121665/121666
    uint256 internal constant D2 = 16295367250680780974490674513165176452449235426866156013048779062215315747161; // 2d
    uint256 internal constant I = 19681161376707505956807079304988542015446066515923890162744021073123829784752; // sqrt(-1)
    uint256 internal constant L = 7237005577332262213973186563042994240857116359379907606001950938285454250989; // group order
    uint256 internal constant TWO256_MOD_L = 7237005577332262213973186563042994240413239274941949949428319933631315875101;
    uint256 internal constant PM5D8 = 7237005577332262213973186563042994240829374041602535252466099000494570602493; // (p-5)/8
    uint256 internal constant BX = 15112221349535400772501151409588531511454012693041857206046113283949847762202;
    uint256 internal constant BY = 46316835694926478169428394003475163141307993866256225615783033603165251855960;

    struct Pt {
        uint256 x;
        uint256 y;
        uint256 z;
        uint256 t;
    }

    /// @notice Verify `sig` (R || S, 64 bytes) over `message` for public key `pk`.
    function verify(bytes32 pk, bytes memory sig, bytes memory message) internal view returns (bool) {
        if (sig.length != 64) return false;
        bytes32 rb;
        bytes32 sb;
        assembly {
            rb := mload(add(sig, 32))
            sb := mload(add(sig, 64))
        }
        uint256 s = le(sb);
        if (s >= L) return false;
        (bool okA, Pt memory A) = decompress(pk);
        if (!okA) return false;
        (bool okR, Pt memory R) = decompress(rb);
        if (!okR) return false;
        if (isSmallOrder(A) || isSmallOrder(R)) return false;

        bytes memory h = Sha512.hash(abi.encodePacked(rb, pk, message));
        bytes32 h0;
        bytes32 h1;
        assembly {
            h0 := mload(add(h, 32))
            h1 := mload(add(h, 64))
        }
        uint256 k = addmod(le(h0), mulmod(le(h1), TWO256_MOD_L, L), L);

        // [s]B + [k](-A) == R
        Pt memory nA = Pt(P - A.x, A.y, A.z, A.t == 0 ? 0 : P - A.t);
        if (A.x == 0) nA.x = 0;
        Pt memory B = Pt(BX, BY, 1, mulmod(BX, BY, P));
        Pt memory Q = shamir(s, B, k, nA);
        return eq(Q, R);
    }

    // ---- encoding ----

    /// @dev little-endian bytes32 → uint256
    function le(bytes32 b) internal pure returns (uint256 r) {
        for (uint256 i = 0; i < 32; i++) {
            r |= uint256(uint8(b[i])) << (8 * i);
        }
    }

    /// @dev RFC 8032 §5.1.3 point decompression. Returns (false, _) for anything non-canonical or off-curve.
    function decompress(bytes32 b) internal view returns (bool, Pt memory) {
        Pt memory pt;
        uint256 y = le(b);
        uint256 sign = y >> 255;
        y &= (1 << 255) - 1;
        if (y >= P) return (false, pt);
        uint256 y2 = mulmod(y, y, P);
        uint256 u = addmod(y2, P - 1, P);
        uint256 v = addmod(mulmod(D, y2, P), 1, P);
        uint256 v3 = mulmod(mulmod(v, v, P), v, P);
        uint256 v7 = mulmod(mulmod(v3, v3, P), v, P);
        uint256 x = mulmod(mulmod(u, v3, P), modexp(mulmod(u, v7, P), PM5D8), P);
        uint256 vx2 = mulmod(v, mulmod(x, x, P), P);
        if (vx2 == u) {
            // ok
        } else if (addmod(vx2, u, P) == 0) {
            x = mulmod(x, I, P);
        } else {
            return (false, pt);
        }
        if (x == 0 && sign == 1) return (false, pt);
        if ((x & 1) != sign) x = P - x;
        pt.x = x;
        pt.y = y;
        pt.z = 1;
        pt.t = mulmod(x, y, P);
        return (true, pt);
    }

    error ModexpUnavailable();

    /// @dev base^e mod P via the EIP-198 precompile. Reverts if the precompile is missing,
    ///      returns the wrong length, or returns an unreduced value (all impossible on mainnet;
    ///      guarded so a broken chain fails closed instead of silently mis-verifying).
    function modexp(uint256 base, uint256 e) private view returns (uint256) {
        return modexpAt(address(5), base, e);
    }

    /// @dev Same as modexp with the precompile address as a parameter (tests point it at mocks; foundry cannot etch 0x05).
    function modexpAt(address precompile, uint256 base, uint256 e) internal view returns (uint256 r) {
        bool ok;
        uint256 size;
        assembly {
            let m := mload(0x40)
            mstore(m, 32)
            mstore(add(m, 32), 32)
            mstore(add(m, 64), 32)
            mstore(add(m, 96), base)
            mstore(add(m, 128), e)
            mstore(add(m, 160), P)
            ok := staticcall(gas(), precompile, m, 192, m, 32)
            size := returndatasize()
            r := mload(m)
        }
        if (!ok || size != 32 || r >= P) revert ModexpUnavailable();
    }

    // ---- group ----

    function isIdentity(Pt memory p) internal pure returns (bool) {
        return p.x == 0 && p.y == p.z;
    }

    /// @dev 8·P == identity ?  (catches the identity and all 2-, 4-, 8-torsion points)
    function isSmallOrder(Pt memory p) internal pure returns (bool) {
        Pt memory q = Pt(p.x, p.y, p.z, p.t);
        dbl(q);
        dbl(q);
        dbl(q);
        return isIdentity(q);
    }

    /// @dev projective equality
    function eq(Pt memory a, Pt memory b) internal pure returns (bool) {
        return mulmod(a.x, b.z, P) == mulmod(b.x, a.z, P) && mulmod(a.y, b.z, P) == mulmod(b.y, a.z, P);
    }

    /// @dev q = 2q  (dbl-2008-hwcd, a = -1), in place
    function dbl(Pt memory q) internal pure {
        uint256 a = mulmod(q.x, q.x, P);
        uint256 b = mulmod(q.y, q.y, P);
        uint256 c = mulmod(2, mulmod(q.z, q.z, P), P);
        uint256 d = a == 0 ? 0 : P - a;
        uint256 xy = addmod(q.x, q.y, P);
        uint256 e = addmod(addmod(mulmod(xy, xy, P), P - a, P), P - b, P);
        uint256 g = addmod(d, b, P);
        uint256 f = addmod(g, P - c, P);
        uint256 h = addmod(d, P - b, P);
        q.x = mulmod(e, f, P);
        q.y = mulmod(g, h, P);
        q.t = mulmod(e, h, P);
        q.z = mulmod(f, g, P);
    }

    /// @dev q = q + p  (add-2008-hwcd-3, unified, a = -1), in place
    function add(Pt memory q, Pt memory p) internal pure {
        uint256 a = mulmod(addmod(q.y, P - q.x, P), addmod(p.y, P - p.x, P), P);
        uint256 b = mulmod(addmod(q.y, q.x, P), addmod(p.y, p.x, P), P);
        uint256 c = mulmod(mulmod(q.t, D2, P), p.t, P);
        uint256 d = mulmod(2, mulmod(q.z, p.z, P), P);
        uint256 e = addmod(b, P - a, P);
        uint256 f = addmod(d, P - c, P);
        uint256 g = addmod(d, c, P);
        uint256 h = addmod(b, a, P);
        q.x = mulmod(e, f, P);
        q.y = mulmod(g, h, P);
        q.t = mulmod(e, h, P);
        q.z = mulmod(f, g, P);
    }

    /// @dev [s]B + [k]A via Shamir's trick (s, k < 2^253)
    function shamir(uint256 s, Pt memory B, uint256 k, Pt memory A) internal pure returns (Pt memory q) {
        Pt memory BA = Pt(B.x, B.y, B.z, B.t);
        add(BA, A);
        q = Pt(0, 1, 1, 0);
        for (uint256 i = 253; i > 0;) {
            unchecked { i--; }
            dbl(q);
            uint256 bs = (s >> i) & 1;
            uint256 bk = (k >> i) & 1;
            if (bs == 1 && bk == 1) add(q, BA);
            else if (bs == 1) add(q, B);
            else if (bk == 1) add(q, A);
        }
    }
}
