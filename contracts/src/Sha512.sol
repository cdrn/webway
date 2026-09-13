// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

/// @title Sha512
/// @notice Pure-Solidity SHA-512 (FIPS 180-4). There is no precompile, so this
///         is what Ed25519 verification costs on the EVM. Constants are the
///         first 64 bits of the fractional parts of the cube roots (K) and
///         square roots (H0) of the first primes, regenerated for this file
///         from first principles rather than copied.
library Sha512 {
    uint256 private constant M64 = 0xffffffffffffffff;

    function K() private pure returns (uint64[80] memory k) {
        k = [
            uint64(0x428a2f98d728ae22), 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
            0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
            0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
            0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
            0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
            0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
            0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
            0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
            0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
            0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
            0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
            0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
            0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
            0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
            0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
            0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
            0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
            0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
            0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
            0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
        ];
    }

    function rotr(uint256 x, uint256 n) private pure returns (uint256) {
        unchecked {
            return ((x >> n) | (x << (64 - n))) & M64;
        }
    }

    function bigS0(uint256 a) private pure returns (uint256) { return rotr(a, 28) ^ rotr(a, 34) ^ rotr(a, 39); }
    function bigS1(uint256 e) private pure returns (uint256) { return rotr(e, 14) ^ rotr(e, 18) ^ rotr(e, 41); }

    /// @notice SHA-512 of `data`, as 64 bytes.
    function hash(bytes memory data) internal pure returns (bytes memory digest) {
        uint256[8] memory H = [
            uint256(0x6a09e667f3bcc908), 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
            0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
        ];
        uint64[80] memory k = K();
        uint256 len = data.length;
        uint256 blocks = (len + 17 + 127) / 128;
        bytes memory p = new bytes(blocks * 128);
        assembly {
            // copy data into p (word by word; trailing garbage is overwritten by padding below)
            let src := add(data, 32)
            let dst := add(p, 32)
            for { let i := 0 } lt(i, len) { i := add(i, 32) } { mstore(add(dst, i), mload(add(src, i))) }
        }
        // padding: 0x80, zeros, then the full 128-bit big-endian bit length (high word = len >> 61)
        for (uint256 i = len; i < p.length; i++) p[i] = 0;
        p[len] = 0x80;
        unchecked {
            uint256 lo = (len << 3) & M64;
            uint256 hi = len >> 61;
            for (uint256 i = 0; i < 8; i++) {
                p[p.length - 1 - i] = bytes1(uint8(lo >> (8 * i)));
                p[p.length - 9 - i] = bytes1(uint8(hi >> (8 * i)));
            }
        }

        uint256[80] memory W;
        for (uint256 b = 0; b < blocks; b++) {
            uint256 off = b * 128;
            for (uint256 t = 0; t < 16; t++) {
                uint256 w;
                assembly { w := shr(192, mload(add(add(p, 32), add(off, mul(t, 8))))) }
                W[t] = w;
            }
            unchecked {
                for (uint256 t = 16; t < 80; t++) {
                    uint256 w15 = W[t - 15];
                    uint256 w2 = W[t - 2];
                    uint256 s0 = rotr(w15, 1) ^ rotr(w15, 8) ^ (w15 >> 7);
                    uint256 s1 = rotr(w2, 19) ^ rotr(w2, 61) ^ (w2 >> 6);
                    W[t] = (W[t - 16] + s0 + W[t - 7] + s1) & M64;
                }
                uint256[8] memory v = [H[0], H[1], H[2], H[3], H[4], H[5], H[6], H[7]];
                for (uint256 t = 0; t < 80; t++) {
                    uint256 T1 = (v[7] + bigS1(v[4]) + ((v[4] & v[5]) ^ ((~v[4]) & v[6] & M64)) + uint256(k[t]) + W[t]) & M64;
                    uint256 T2 = (bigS0(v[0]) + ((v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]))) & M64;
                    v[7] = v[6]; v[6] = v[5]; v[5] = v[4]; v[4] = (v[3] + T1) & M64;
                    v[3] = v[2]; v[2] = v[1]; v[1] = v[0]; v[0] = (T1 + T2) & M64;
                }
                for (uint256 i = 0; i < 8; i++) H[i] = (H[i] + v[i]) & M64;
            }
        }
        digest = new bytes(64);
        uint256 w0 = (H[0] << 192) | (H[1] << 128) | (H[2] << 64) | H[3];
        uint256 w1 = (H[4] << 192) | (H[5] << 128) | (H[6] << 64) | H[7];
        assembly {
            mstore(add(digest, 32), w0)
            mstore(add(digest, 64), w1)
        }
    }
}
