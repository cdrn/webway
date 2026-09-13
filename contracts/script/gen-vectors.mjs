// Generates test vectors for contracts/test/Ed25519.t.sol and Sha512 tests.
// Run from the repo root:  node contracts/script/gen-vectors.mjs
// Output: contracts/test/vectors/ed25519.json (consumed via vm.readFile + vm.parseJson).
import { createHash, randomBytes } from 'node:crypto';
import { writeFileSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import * as ed from '@noble/ed25519';

ed.hashes.sha512 = (m) => new Uint8Array(createHash('sha512').update(m).digest());
const hex = (b) => '0x' + Buffer.from(b).toString('hex');
const H = (s) => Buffer.from(s.replace(/^0x/, ''), 'hex');
const L = (1n << 252n) + 27742317777372353535851937790883648493n;
const P = (1n << 255n) - 19n;
const leBytes = (n, len) => { const b = Buffer.alloc(len); for (let i = 0; i < len; i++) { b[i] = Number(n & 0xffn); n >>= 8n; } return b; };
const leInt = (b) => { let n = 0n; for (let i = b.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(b[i]); return n; };

// RFC 8032 §7.1 vectors: (seed, message). pk and sig are derived (Ed25519 is deterministic) and cross-checked
// against the RFC hex below; a mismatch is a hard error because the RFC values are the reference.
const RFC = [
  { name: 'TEST 1', seed: '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60', msg: '',
    pk: 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a',
    sig: 'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b' },
  { name: 'TEST 2', seed: '4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb', msg: '72',
    pk: '3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c',
    sig: '92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00' },
  { name: 'TEST 3', seed: 'c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7', msg: 'af82',
    pk: 'fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025',
    sig: '6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a' },
  { name: 'TEST SHA(abc)', seed: '833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42',
    msg: 'ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f',
    pk: 'ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf',
    sig: 'dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b58909351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704' },
];
// TEST 1024's 1023-byte message is not reproduced here; its seed/pk are checked and a 1023-byte random message is signed instead.
const RFC1024 = { seed: 'f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5', pk: '278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e' };

const rfc = [];
for (const v of RFC) {
  const pk = ed.getPublicKey(H(v.seed));
  const sig = ed.sign(H(v.msg), H(v.seed));
  if (hex(pk) !== '0x' + v.pk) throw new Error(`${v.name}: pk mismatch vs RFC`);
  if (hex(sig) !== '0x' + v.sig) throw new Error(`${v.name}: sig mismatch vs RFC`);
  if (!ed.verify(sig, H(v.msg), pk)) throw new Error(`${v.name}: noble rejects`);
  rfc.push({ msg: hex(H(v.msg)), pk: hex(pk), sig: hex(sig) });
}
{
  const pk = ed.getPublicKey(H(RFC1024.seed));
  if (hex(pk) !== '0x' + RFC1024.pk) throw new Error('TEST 1024: pk mismatch vs RFC');
  const msg = randomBytes(1023);
  rfc.push({ msg: hex(msg), pk: hex(pk), sig: hex(ed.sign(msg, H(RFC1024.seed))) });
}

// 200 random vectors. Message lengths cover 0..300 with emphasis on the binding-message size (~70 bytes)
// and both sides of SHA-512 block boundaries (R||A||M crosses 128 at M=64, 256 at M=192).
const random = [];
for (let i = 0; i < 200; i++) {
  const seed = randomBytes(32);
  const len = i < 40 ? 60 + (i % 20) : i < 80 ? [0, 1, 63, 64, 65, 127, 128, 129, 191, 192, 193, 255, 256, 257][i % 14] : Math.floor(Math.random() * 300);
  const msg = randomBytes(len);
  random.push({ msg: hex(msg), pk: hex(ed.getPublicKey(seed)), sig: hex(ed.sign(msg, seed)) });
}

// Negative vectors: each must be rejected.
const negative = [];
const flip = (b, bit) => { const c = Buffer.from(b); c[bit >> 3] ^= 1 << (bit & 7); return c; };
for (let i = 0; i < 40; i++) {
  const seed = randomBytes(32); const msg = randomBytes(60 + i); const pk = Buffer.from(ed.getPublicKey(seed)); const sig = Buffer.from(ed.sign(msg, seed));
  const bit = Math.floor(Math.random() * 8 * 32);
  negative.push({ msg: hex(msg), pk: hex(pk), sig: hex(flip(sig, bit)), why: `sig bit ${bit} flipped (R)` });
  negative.push({ msg: hex(msg), pk: hex(pk), sig: hex(flip(sig, 256 + (bit % 252))), why: `sig bit ${256 + (bit % 252)} flipped (S)` });
  negative.push({ msg: hex(flip(msg, bit % (msg.length * 8))), pk: hex(pk), sig: hex(sig), why: 'message bit flipped' });
  negative.push({ msg: hex(msg), pk: hex(flip(pk, bit % 255)), sig: hex(sig), why: 'pk bit flipped' });
  negative.push({ msg: hex(msg), pk: hex(pk), sig: hex(Buffer.concat([sig.subarray(0, 32), leBytes(leInt(sig.subarray(32)) + L, 32)])), why: 'S + L (non-canonical S >= L)' });
  negative.push({ msg: hex(msg), pk: hex(pk), sig: hex(Buffer.concat([sig.subarray(0, 32), leBytes(L, 32)])), why: 'S = L' });
  negative.push({ msg: hex(Buffer.concat([msg, Buffer.from([0])])), pk: hex(pk), sig: hex(sig), why: 'message extended by one byte' });
  negative.push({ msg: hex(msg.subarray(0, msg.length - 1)), pk: hex(pk), sig: hex(sig), why: 'message truncated by one byte' });
}
{
  const seed = randomBytes(32); const msg = randomBytes(64); const pk = Buffer.from(ed.getPublicKey(seed)); const sig = Buffer.from(ed.sign(msg, seed));
  // Non-canonical encodings: y >= p (p+1 and p+2 little-endian), for A and for R
  const yp1 = leBytes(P + 1n, 32); const yp2 = leBytes(P + 2n, 32);
  negative.push({ msg: hex(msg), pk: hex(yp1), sig: hex(sig), why: 'A with y = p+1 (non-canonical)' });
  negative.push({ msg: hex(msg), pk: hex(yp2), sig: hex(sig), why: 'A with y = p+2 (non-canonical)' });
  negative.push({ msg: hex(msg), pk: hex(pk), sig: hex(Buffer.concat([yp1, sig.subarray(32)])), why: 'R with y = p+1 (non-canonical)' });
  // y not on curve (no square root): try y=2 style values found by search
  let y = 2n;
  const onCurve = (yy) => { const u = (yy * yy - 1n + P) % P; const d = 37095705934669439343138083508754565189542113879843219016388785533085940283555n; const v = (d * yy * yy + 1n) % P; const inv = (a) => { let r = 1n, b = a, e = P - 2n; while (e) { if (e & 1n) r = r * b % P; b = b * b % P; e >>= 1n; } return r; }; const x2 = u * inv(v) % P; const s = ((a, e) => { let r = 1n, b = a; while (e) { if (e & 1n) r = r * b % P; b = b * b % P; e >>= 1n; } return r; })(x2, (P - 1n) / 2n); return x2 === 0n || s === 1n; };
  while (onCurve(y)) y++;
  negative.push({ msg: hex(msg), pk: hex(leBytes(y, 32)), sig: hex(sig), why: `A with y=${y} not on curve` });
  negative.push({ msg: hex(msg), pk: hex(pk), sig: hex(Buffer.concat([leBytes(y, 32), sig.subarray(32)])), why: `R with y=${y} not on curve` });
  // Small-order / identity points (RFC 8032 strictness): A = identity (y=1), A = order-2 point (y=-1), order-4 points (y=0), order-8 points
  const small = [
    { y: 1n, s: 0, why: 'A = identity (y=1)' },
    { y: P - 1n, s: 0, why: 'A of order 2 (y=-1)' },
    { y: 0n, s: 0, why: 'A of order 4 (y=0, x=sqrt(-1))' },
    { y: 0n, s: 1, why: 'A of order 4 (y=0, x=-sqrt(-1))' },
  ];
  for (const sp of small) { const b = leBytes(sp.y, 32); b[31] |= sp.s << 7; negative.push({ msg: hex(msg), pk: hex(b), sig: hex(sig), why: sp.why }); }
  // identity as R
  negative.push({ msg: hex(msg), pk: hex(pk), sig: hex(Buffer.concat([leBytes(1n, 32), sig.subarray(32)])), why: 'R = identity' });
  // order-8 torsion points: T = [L]Q for a random on-curve Q outside the prime-order subgroup has order 1, 2, 4 or 8;
  // search until 4T != identity (then T has order 8). Both as A and as R.
  {
    const D = 37095705934669439343138083508754565189542113879843219016388785533085940283555n;
    const mod = (a) => ((a % P) + P) % P;
    const pow = (b, e) => { let r = 1n; b = mod(b); while (e > 0n) { if (e & 1n) r = r * b % P; b = b * b % P; e >>= 1n; } return r; };
    const sqrtRatio = (u, v) => { const x = mod(u * pow(v, 3n) * pow(mod(u * pow(v, 7n)), (P - 5n) / 8n)); const vx2 = mod(v * x * x); if (vx2 === u) return x; if (mod(vx2 + u) === 0n) return mod(x * 19681161376707505956807079304988542015446066515923890162744021073123829784752n); return null; };
    const decompress = (y, sign) => { const u = mod(y * y - 1n); const v = mod(D * y * y + 1n); let x = sqrtRatio(u, v); if (x === null) return null; if (x === 0n && sign) return null; if ((x & 1n) !== BigInt(sign)) x = P - x; return { X: x, Y: y, Z: 1n, T: mod(x * y) }; };
    const dbl = (p) => { const A = mod(p.X * p.X), B = mod(p.Y * p.Y), C = mod(2n * p.Z * p.Z), Dd = mod(-A), E = mod((p.X + p.Y) ** 2n - A - B), G = mod(Dd + B), F = mod(G - C), H = mod(Dd - B); return { X: mod(E * F), Y: mod(G * H), T: mod(E * H), Z: mod(F * G) }; };
    const add = (p, q) => { const A = mod((p.Y - p.X) * (q.Y - q.X)), B = mod((p.Y + p.X) * (q.Y + q.X)), C = mod(p.T * 2n * D * q.T), Dd = mod(2n * p.Z * q.Z), E = mod(B - A), F = mod(Dd - C), G = mod(Dd + C), H = mod(B + A); return { X: mod(E * F), Y: mod(G * H), T: mod(E * H), Z: mod(F * G) }; };
    const mul = (p, k) => { let r = { X: 0n, Y: 1n, Z: 1n, T: 0n }; for (let i = 255; i >= 0; i--) { r = dbl(r); if ((k >> BigInt(i)) & 1n) r = add(r, p); } return r; };
    const isId = (p) => p.X === 0n && p.Y === p.Z;
    const compress = (p) => { const zi = pow(p.Z, P - 2n); const x = mod(p.X * zi), y = mod(p.Y * zi); const b = leBytes(y, 32); if (x & 1n) b[31] |= 0x80; return b; };
    let found = 0;
    for (let tries = 0; tries < 10000 && found < 2; tries++) {
      const y = leInt(randomBytes(32)) & ((1n << 255n) - 1n);
      if (y >= P) continue;
      const Q = decompress(y, 0); if (!Q) continue;
      const T = mul(Q, L);
      if (isId(T) || isId(dbl(T)) || isId(dbl(dbl(T)))) continue; // order 1, 2 or 4
      if (!isId(dbl(dbl(dbl(T))))) throw new Error('8T should be identity');
      const enc = compress(T);
      negative.push({ msg: hex(msg), pk: hex(enc), sig: hex(sig), why: `A of order 8 (#${found})` });
      negative.push({ msg: hex(msg), pk: hex(pk), sig: hex(Buffer.concat([enc, sig.subarray(32)])), why: `R of order 8 (#${found})` });
      found++;
    }
    if (found < 2) throw new Error('could not find order-8 points');
  }
  // x = 0 with sign bit set (RFC 8032 5.1.3 step 4: reject)
  const x0 = leBytes(1n, 32); x0[31] |= 0x80;
  negative.push({ msg: hex(msg), pk: hex(x0), sig: hex(sig), why: 'A: x=0 with sign bit set' });
  // wrong key entirely
  negative.push({ msg: hex(msg), pk: hex(ed.getPublicKey(randomBytes(32))), sig: hex(sig), why: 'signature by a different key' });
  negative.push({ msg: hex(msg), pk: hex(pk), sig: hex(Buffer.alloc(64)), why: 'all-zero signature' });
}
// Sanity: noble rejects every negative vector it can parse (zip215 off = strict); those it cannot parse throw, which is also a rejection.
for (const n of negative) {
  let ok = false;
  try { ok = ed.verify(H(n.sig), H(n.msg), H(n.pk), { zip215: false }); } catch { ok = false; }
  if (ok) throw new Error(`noble accepts negative vector: ${n.why}`);
}

// SHA-512 vectors: FIPS 180-4 examples + random lengths across block boundaries
const sha = [
  { msg: '0x', out: '0x' + createHash('sha512').update('').digest('hex') },
  { msg: hex(Buffer.from('abc')), out: '0x' + createHash('sha512').update('abc').digest('hex') },
  { msg: hex(Buffer.from('abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu')), out: '0x' + createHash('sha512').update('abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu').digest('hex') },
];
if (sha[1].out !== '0xddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f') throw new Error('node sha512("abc") != FIPS value');
for (const len of [1, 55, 56, 57, 63, 64, 65, 111, 112, 113, 119, 120, 127, 128, 129, 130, 200, 239, 240, 241, 255, 256, 257, 300, 383, 384, 385, 500, 1000]) {
  const m = randomBytes(len); sha.push({ msg: hex(m), out: '0x' + createHash('sha512').update(m).digest('hex') });
}
for (let i = 0; i < 60; i++) { const m = randomBytes(Math.floor(Math.random() * 400)); sha.push({ msg: hex(m), out: '0x' + createHash('sha512').update(m).digest('hex') }); }

// Registry binding vectors: "webway-bind:<chainId>:<0x lowercase address>:<epoch>" signed by a publisher key.
// Addresses are anvil/forge's default accounts 0..2 so forge tests can vm.prank them.
const ACCT = ['0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266', '0x70997970C51812dc3A010C7d01b50e0d17dc79C8', '0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC'];
const bindMsg = (chainId, addr, epoch) => Buffer.from(`webway-bind:${chainId}:${addr.toLowerCase()}:${epoch}`, 'utf8');
const seedA = randomBytes(32), seedB = randomBytes(32);
const pkA = ed.getPublicKey(seedA), pkB = ed.getPublicKey(seedB);
const mk = (seed, pk, chainId, addr, epoch) => { const msg = bindMsg(chainId, addr, epoch); return { addr, chainId, epoch, msg: hex(msg), pk: hex(pk), sig: hex(ed.sign(msg, seed)) }; };
const bind = [
  mk(seedA, pkA, 31337, ACCT[0], 0),   // first bind
  mk(seedA, pkA, 31337, ACCT[0], 1),   // same account, higher epoch
  mk(seedA, pkA, 31337, ACCT[1], 2),   // rotation to account 1
  mk(seedA, pkA, 31337, ACCT[1], 1),   // lower epoch (must revert once at 2)
  mk(seedA, pkA, 31337, ACCT[2], 5),   // rotation to account 2
  mk(seedA, pkA, 31338, ACCT[0], 0),   // wrong chain id (must revert)
  mk(seedB, pkB, 31337, ACCT[0], 0),   // a second key, epoch 0
  mk(seedB, pkB, 31337, ACCT[0], 18446744073709551615n), // uint64 max epoch
];
// Worst-case-length binding message for gas measurement: the longest possible chain id and epoch
// (20 decimal digits each) → 12 + 20 + 3 + 40 + 1 + 20 = 96 bytes; plus a padded 154-byte message
// (R||A||M = 218 bytes → 3 SHA-512 blocks) as requested by the review.
const worst = [];
{
  const cid = 18446744073709551615n; const ep = 18446744073709551615n;
  const m1 = bindMsg(cid, ACCT[0], ep);
  worst.push({ msg: hex(m1), pk: hex(pkA), sig: hex(ed.sign(m1, seedA)), why: `${m1.length}-byte binding message (max digits)` });
  const m2 = Buffer.concat([m1, Buffer.alloc(154 - m1.length, 0x7a)]);
  worst.push({ msg: hex(m2), pk: hex(pkA), sig: hex(ed.sign(m2, seedA)), why: '154-byte message (3 SHA-512 blocks)' });
}

const out = join(dirname(fileURLToPath(import.meta.url)), '..', 'test', 'vectors', 'ed25519.json');
mkdirSync(dirname(out), { recursive: true });
const counts = { rfc: rfc.length, random: random.length, negative: negative.length, sha: sha.length, bind: bind.length, worst: worst.length };
writeFileSync(out, JSON.stringify({ counts, rfc, random, negative, sha, bind, worst }, (_, v) => (typeof v === 'bigint' ? v.toString() : v), 1));
console.log(`wrote ${out}: ${rfc.length} rfc, ${random.length} random, ${negative.length} negative, ${sha.length} sha512, ${bind.length} bind, ${worst.length} worst`);
