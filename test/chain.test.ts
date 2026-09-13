import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import { readFileSync, mkdtempSync, mkdirSync, writeFileSync, symlinkSync, existsSync, chmodSync } from 'node:fs';
import { createServer, request as httpRequest, type Server } from 'node:http';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomBytes } from 'node:crypto';
import { createPublicClient, createWalletClient, http, getAddress, toHex, type Address, type Hex } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { generate } from '../src/keys.ts';
import {
  ChainRegistry, RpcDisagreement, AllRpcsFailed, BindingRejected, bindingMessage, signBinding, validChainId, REGISTRY_ABI,
  registryFromEnv, pkHex, nameHash, sanitizeUrl, MAX_U64,
} from '../src/chain.ts';
import { WebwayNode, parseDhtRecord, validPublicNode, MAX_DHT_SEQ } from '../src/node.ts';
import { parse as parseArgv, num, BOOL_FLAGS } from '../src/cliopts.ts';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const CONTRACTS = join(ROOT, 'contracts');
const ARTIFACT = join(CONTRACTS, 'out', 'WebwayRegistry.sol', 'WebwayRegistry.json');
const KEYS: Hex[] = [
  '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80',
  '0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d',
  '0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a',
];
const CHAIN_ID = 31337;
const DEAD = 'http://127.0.0.1:1';
const DEAD2 = 'http://127.0.0.1:2';
const ZERO: Address = '0x0000000000000000000000000000000000000001';

const haveAnvil = spawnSync('anvil', ['--version'], { encoding: 'utf8' }).status === 0;
const haveForge = spawnSync('forge', ['--version'], { encoding: 'utf8' }).status === 0;

// ---- pure unit tests (always run) ----------------------------------------

describe('binding message', () => {
  test('format: decimal chainId, lowercase 0x address, decimal epoch', () => {
    assert.equal(bindingMessage(1, '0xABCDEF0123456789abcdef0123456789ABCDEF01', 0n), 'webway-bind:1:0xabcdef0123456789abcdef0123456789abcdef01:0');
    assert.equal(bindingMessage(8453, ZERO, MAX_U64), 'webway-bind:8453:0x0000000000000000000000000000000000000001:18446744073709551615');
  });
  test('rejects bad chainId / address / epoch (1e21 and 2^53 are integers but not safe → rejected)', () => {
    assert.throws(() => bindingMessage(0, ZERO, 0n));
    assert.throws(() => bindingMessage(1.5, ZERO, 0n));
    assert.throws(() => bindingMessage(1e21, ZERO, 0n), /safe integer/);
    assert.throws(() => bindingMessage(2 ** 53, ZERO, 0n), /safe integer/);
    assert.throws(() => bindingMessage(-1, ZERO, 0n));
    assert.throws(() => bindingMessage(NaN, ZERO, 0n));
    assert.equal(validChainId(2 ** 53 - 1), true); assert.equal(validChainId(2 ** 53), false); assert.equal(validChainId(1e21), false); assert.equal(validChainId('1' as any), false);
    assert.throws(() => bindingMessage(1, 'not-an-address', 0n));
    assert.throws(() => bindingMessage(1, ZERO, -1n));
    assert.throws(() => bindingMessage(1, ZERO, 1n << 64n));
    assert.throws(() => bindingMessage(1, ZERO, 1 as any));
  });
  test('signBinding produces a 64-byte deterministic signature over the message', () => {
    const kp = generate();
    const s1 = signBinding(kp, 1, ZERO, 7n); const s2 = signBinding(kp, 1, ZERO, 7n);
    assert.equal(s1.length, 64); assert.deepEqual(s1, s2);
    assert.notDeepEqual(signBinding(kp, 1, ZERO, 8n), s1);
    assert.notDeepEqual(signBinding(kp, 2, ZERO, 7n), s1);
  });
});

describe('client config', () => {
  test('refuses missing address / empty rpcs / minAgree > endpoints / duplicates; single rpc needs minAgree 1', () => {
    assert.throws(() => new ChainRegistry({ chainId: 1, address: undefined, rpcs: ['http://x'] }), /registry address not set/);
    assert.throws(() => new ChainRegistry({ chainId: 1, address: ZERO, rpcs: [] }), /at least one RPC/);
    assert.throws(() => new ChainRegistry({ chainId: 1, address: ZERO, rpcs: ['http://x'] }), /minAgree=2 but only 1/);
    assert.throws(() => new ChainRegistry({ chainId: 1, address: ZERO, rpcs: ['http://x', 'http://x'] }), /duplicate RPC endpoint/);
    assert.throws(() => new ChainRegistry({ chainId: 1, address: ZERO, rpcs: ['http://x', 'http://x/'] }), /duplicate RPC endpoint/, 'normalised');
    assert.throws(() => new ChainRegistry({ chainId: 1, address: ZERO, rpcs: ['nonsense', 'http://y'] }), /invalid RPC url/);
    assert.throws(() => new ChainRegistry({ chainId: 1, address: ZERO, rpcs: ['http://x'], minAgree: 0 }), /positive integer/);
    assert.equal(new ChainRegistry({ chainId: 1, address: ZERO, rpcs: ['http://x'], minAgree: 1 }).minAgree, 1);
    assert.equal(new ChainRegistry({ chainId: 1, address: ZERO, rpcs: ['http://x/a', 'http://x/b'] }).minAgree, 2);
    assert.throws(() => new ChainRegistry({ chainId: 1e21, address: ZERO, rpcs: ['http://x', 'http://y'] }), /safe integer/);
    assert.throws(() => new ChainRegistry({ chainId: 2 ** 53, address: ZERO, rpcs: ['http://x', 'http://y'] }), /safe integer/);
    assert.throws(() => new ChainRegistry({ chainId: 0, address: ZERO, rpcs: ['http://x', 'http://y'] }), /safe integer/);
  });
  test('registryFromEnv: undefined without address; env parsing; min-agree', () => {
    const saved = { R: process.env.WEBWAY_REGISTRY, U: process.env.WEBWAY_RPC, M: process.env.WEBWAY_MIN_AGREE };
    delete process.env.WEBWAY_REGISTRY; delete process.env.WEBWAY_RPC; delete process.env.WEBWAY_MIN_AGREE;
    try {
      assert.equal(registryFromEnv(), undefined);
      process.env.WEBWAY_REGISTRY = ZERO; process.env.WEBWAY_RPC = 'http://a, http://b';
      const r = registryFromEnv()!;
      assert.deepEqual(r.rpcs, ['http://a/', 'http://b/']); assert.equal(r.chainId, 1); assert.equal(r.minAgree, 2);
      process.env.WEBWAY_RPC = 'http://a';
      assert.throws(() => registryFromEnv(), /--min-agree 1/);
      process.env.WEBWAY_MIN_AGREE = '1';
      assert.equal(registryFromEnv()!.minAgree, 1);
      process.env.WEBWAY_CHAIN_ID = '8453'; assert.equal(registryFromEnv()!.chainId, 8453);
      for (const bad of ['1e21', '9007199254740992', '0', '-1', 'abc', '1.5']) { process.env.WEBWAY_CHAIN_ID = bad; assert.throws(() => registryFromEnv(), /chain id/, `WEBWAY_CHAIN_ID=${bad}`); }
      delete process.env.WEBWAY_CHAIN_ID;
      assert.throws(() => registryFromEnv({ chainId: 1e21 }), /safe integer/);
      assert.throws(() => registryFromEnv({ chainId: 2 ** 53 }), /safe integer/);
    } finally {
      for (const [k, v] of [['WEBWAY_REGISTRY', saved.R], ['WEBWAY_RPC', saved.U], ['WEBWAY_MIN_AGREE', saved.M]] as const) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
    }
  });
  test('sanitizeUrl strips userinfo, path, query', () => {
    assert.equal(sanitizeUrl('https://user:pw@rpc.example.com:8545/v2/SECRET?key=abc#frag'), 'https://rpc.example.com:8545');
    assert.equal(sanitizeUrl('http://127.0.0.1:1'), 'http://127.0.0.1:1');
    assert.equal(sanitizeUrl('nonsense'), '<invalid url>');
  });
  test('nameHash / pkHex helpers', () => {
    assert.equal(nameHash(''), '0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470');
    assert.notEqual(nameHash('acme/tiny'), nameHash('acme/tiny2'));
    assert.equal(pkHex('AB'.repeat(32)), '0x' + 'ab'.repeat(32));
  });
});

describe('DHT payload validation', () => {
  const ih = randomBytes(20); const a = randomBytes(20);
  test('accepts exactly what publishName writes, with and without the a/e cross-check', () => {
    assert.deepEqual(parseDhtRecord({ ih, n: Buffer.from('a/b'), sz: 5 }, 'a/b'), { ih: ih.toString('hex'), size: 5, license: undefined, hint: undefined });
    assert.deepEqual(parseDhtRecord({ ih, n: 'a/b', sz: 0, l: Buffer.from('mit') }, 'a/b'), { ih: ih.toString('hex'), size: 0, license: 'mit', hint: undefined });
    assert.equal(parseDhtRecord({ ih, n: 'a/b', sz: 7, l: '' }, 'a/b')!.license, undefined, 'empty license → undefined');
    const r = parseDhtRecord({ ih, n: 'a/b', sz: 7, a, e: Buffer.from('3') }, 'a/b')!;
    assert.deepEqual(r.hint, { addr: getAddress(`0x${a.toString('hex')}`), epoch: 3n });
    assert.equal(parseDhtRecord({ ih, n: 'a/b', sz: 7, a, e: '18446744073709551615' }, 'a/b')!.hint!.epoch, MAX_U64, 'uint64 max as decimal string');
    assert.equal(parseDhtRecord({ ih, n: 'a/b', sz: 7, a, e: '0' }, 'a/b')!.hint!.epoch, 0n);
  });
  test('rejects malformed / mismatched payloads and bad hints', () => {
    assert.equal(parseDhtRecord(null, 'a/b'), null);
    assert.equal(parseDhtRecord('str', 'a/b'), null);
    assert.equal(parseDhtRecord([ih], 'a/b'), null);
    assert.equal(parseDhtRecord({ n: 'a/b', sz: 1 }, 'a/b'), null, 'missing ih');
    assert.equal(parseDhtRecord({ ih: randomBytes(19), n: 'a/b', sz: 1 }, 'a/b'), null, '19-byte ih');
    assert.equal(parseDhtRecord({ ih: ih.toString('hex'), n: 'a/b', sz: 1 }, 'a/b'), null, 'ih as string');
    assert.equal(parseDhtRecord({ ih, n: 'other/name', sz: 1 }, 'a/b'), null, 'name mismatch');
    assert.equal(parseDhtRecord({ ih, sz: 1 }, 'a/b'), null, 'missing name');
    assert.equal(parseDhtRecord({ ih, n: 'a/b' }, 'a/b'), null, 'missing size');
    assert.equal(parseDhtRecord({ ih, n: 'a/b', sz: -1 }, 'a/b'), null, 'negative size');
    assert.equal(parseDhtRecord({ ih, n: 'a/b', sz: 1.5 }, 'a/b'), null, 'fractional size');
    assert.equal(parseDhtRecord({ ih, n: 'a/b', sz: 2 ** 53 }, 'a/b'), null, 'unsafe size');
    assert.equal(parseDhtRecord({ ih, n: 'a/b', sz: 1, l: 5 }, 'a/b'), null, 'non-string license');
    assert.equal(parseDhtRecord({ ih, n: 'a/b', sz: 1, a: randomBytes(19), e: '0' }, 'a/b'), null, '19-byte address');
    assert.equal(parseDhtRecord({ ih, n: 'a/b', sz: 1, a }, 'a/b'), null, 'address without epoch');
    assert.equal(parseDhtRecord({ ih, n: 'a/b', sz: 1, e: '1' }, 'a/b'), null, 'epoch without address');
    assert.equal(parseDhtRecord({ ih, n: 'a/b', sz: 1, a, e: 1 }, 'a/b'), null, 'numeric epoch (must be a decimal string)');
    assert.equal(parseDhtRecord({ ih, n: 'a/b', sz: 1, a, e: '-1' }, 'a/b'), null, 'negative epoch');
    assert.equal(parseDhtRecord({ ih, n: 'a/b', sz: 1, a, e: '01' }, 'a/b'), null, 'leading zero');
    assert.equal(parseDhtRecord({ ih, n: 'a/b', sz: 1, a, e: '' }, 'a/b'), null, 'empty epoch');
    assert.equal(parseDhtRecord({ ih, n: 'a/b', sz: 1, a, e: '18446744073709551616' }, 'a/b'), null, '2^64');
    assert.equal(parseDhtRecord({ ih, n: 'a/b', sz: 1, a, e: '1x' }, 'a/b'), null, 'junk');
  });
});

describe('bootstrap node validator', () => {
  test('canonical public IPv4 literals only', () => {
    assert.deepEqual(validPublicNode('203.0.113.5:6881'), { host: '203.0.113.5', port: 6881 });
    assert.deepEqual(validPublicNode('8.8.8.8:1'), { host: '8.8.8.8', port: 1 });
    assert.deepEqual(validPublicNode('172.32.0.1:65535'), { host: '172.32.0.1', port: 65535 });
    for (const bad of ['router.bittorrent.com:6881', 'localhost:1', '127.1:6881', '0x7f000001:6881', '2130706433:6881',
      '10.0.0.1:6881', '127.0.0.1:6881', '192.168.1.1:1', '172.16.0.1:1', '172.31.255.255:1', '169.254.1.1:1', '100.64.0.1:1', '0.0.0.0:1', '224.0.0.1:1', '255.255.255.255:1', '192.0.0.1:1',
      '203.0.113.5:0', '203.0.113.5:65536', '203.0.113.5:01', '203.0.113.5', '203.0.113.5:abc', '256.1.1.1:1', '203.0.113.05:1', '[::1]:6881', ' 1.2.3.4:5', '1.2.3:5']) {
      assert.equal(validPublicNode(bad), null, bad);
    }
    assert.deepEqual(validPublicNode('127.0.0.1:6881', true), { host: '127.0.0.1', port: 6881 }, 'allowPrivate');
    assert.equal(validPublicNode('127.1:6881', true), null, 'abbreviated forms never pass');
  });
});

describe('CLI argument parser', () => {
  test('boolean flags do not consume the next argument; value flags do; ordering is free', () => {
    assert.deepEqual(parseArgv(['--no-chain', 'resolve', 'ref']), { args: ['resolve', 'ref'], flags: { 'no-chain': ['true'] } });
    assert.deepEqual(parseArgv(['share', 'DIR', '--chain', '--name', 'org/model']), { args: ['share', 'DIR'], flags: { chain: ['true'], name: ['org/model'] } });
    assert.deepEqual(parseArgv(['--name', 'org/model', '--chain', 'share', 'DIR']), { args: ['share', 'DIR'], flags: { chain: ['true'], name: ['org/model'] } });
    assert.deepEqual(parseArgv(['--registry=0xabc', 'x']).flags, { registry: ['0xabc'] });
    assert.throws(() => parseArgv(['resolve', '--registry']), /missing value/);
    assert.throws(() => parseArgv(['resolve', '--registry', '--chain']), /missing value/);
    for (const b of ['chain', 'no-chain', 'no-dns', 'help']) assert.ok(BOOL_FLAGS.has(b), b);
  });
  test('boolean switches reject =value; numeric options are validated, never silently defaulted', () => {
    assert.throws(() => parseArgv(['--chain=false', 'share']), /takes no value/);
    assert.throws(() => parseArgv(['--no-chain=false', 'resolve', 'x']), /takes no value/);
    const f = parseArgv(['--min-agree', '2', '--dht-port', '0']).flags;
    assert.equal(num(f, 'min-agree', { min: 1 }), 2);
    assert.equal(num(f, 'dht-port', { min: 0, max: 65535 }), 0);
    assert.equal(num(f, 'torrent-port'), undefined);
    assert.throws(() => num(parseArgv(['--min-agree', 'abc']).flags, 'min-agree'), /must be an integer/);
    assert.throws(() => num(parseArgv(['--min-agree', '0']).flags, 'min-agree', { min: 1 }), />= 1/);
    assert.throws(() => num(parseArgv(['--dht-port', '70000']).flags, 'dht-port', { max: 65535 }), /<= 65535/);
    assert.throws(() => num(parseArgv(['--chain-id', '99999999999999999999']).flags, 'chain-id'), /out of range/);
    assert.throws(() => num(parseArgv(['--min-agree', '1', '--min-agree', '2']).flags, 'min-agree'), /more than once/);
  });
});

// ---- anvil-backed tests -------------------------------------------------------

interface Anvil { proc: ChildProcess; url: string; port: number; chainId: number }

async function startAnvil(chainId = CHAIN_ID): Promise<Anvil> {
  const port = 20000 + Math.floor(Math.random() * 20000);
  const proc = spawn('anvil', ['--port', String(port), '--silent', '--chain-id', String(chainId)], { stdio: 'ignore' });
  const url = `http://127.0.0.1:${port}`;
  const client = createPublicClient({ transport: http(url) });
  for (let i = 0; i < 100; i++) {
    try { await client.getChainId(); return { proc, url, port, chainId }; } catch { await new Promise((r) => setTimeout(r, 100)); }
  }
  proc.kill(); throw new Error('anvil did not start');
}

const chainDef = (url: string, id = CHAIN_ID) => ({ id, name: 'anvil', nativeCurrency: { name: 'ETH', symbol: 'ETH', decimals: 18 }, rpcUrls: { default: { http: [url] } } });

async function deploy(url: string, chainId = CHAIN_ID): Promise<Address> {
  const art = JSON.parse(readFileSync(ARTIFACT, 'utf8'));
  const account = privateKeyToAccount(KEYS[0]);
  const chain = chainDef(url, chainId);
  const wallet = createWalletClient({ account, chain, transport: http(url) });
  const pub = createPublicClient({ chain, transport: http(url) });
  const hash = await wallet.deployContract({ abi: art.abi, bytecode: art.bytecode.object as Hex });
  const rc = await pub.waitForTransactionReceipt({ hash });
  return rc.contractAddress!;
}

/** Raw contract write from any account, bypassing the client. */
async function raw(url: string, key: Hex, addr: Address, functionName: string, args: unknown[]) {
  const chain = chainDef(url);
  const wallet = createWalletClient({ account: privateKeyToAccount(key), chain, transport: http(url) });
  const pub = createPublicClient({ chain, transport: http(url) });
  const h = await wallet.writeContract({ address: addr, abi: REGISTRY_ABI, functionName: functionName as any, args: args as any });
  return pub.waitForTransactionReceipt({ hash: h });
}

const rpc = (url: string, method: string, params: unknown[] = []) => createPublicClient({ transport: http(url) }).request({ method: method as any, params: params as any });
const mine = (url: string, n = 3) => rpc(url, 'anvil_mine', [toHex(n)]);
const head = (url: string) => createPublicClient({ transport: http(url) }).getBlockNumber({ cacheTime: 0 });

/** A JSON-RPC proxy that forwards to a target and can rewrite responses (a lying / stale / flaky endpoint). */
interface Proxy { server: Server; url: string; close: () => Promise<void> }
async function proxy(targets: Record<string, string>, rewrite?: (path: string, req: any, res: any) => any, rewriteReq?: (path: string, req: any) => any): Promise<Proxy> {
  const server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      let body = Buffer.concat(chunks).toString('utf8');
      if (rewriteReq) { try { const j = JSON.parse(body); body = JSON.stringify(Array.isArray(j) ? j.map((x) => rewriteReq(req.url ?? '/', x) ?? x) : (rewriteReq(req.url ?? '/', j) ?? j)); } catch {} }
      const target = targets[req.url ?? '/'] ?? targets['/'];
      if (!target) { res.writeHead(502); return res.end(); }
      const t = new URL(target);
      const up = httpRequest({ host: t.hostname, port: t.port, method: 'POST', path: '/', headers: { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body) } }, (upRes) => {
        const out: Buffer[] = [];
        upRes.on('data', (c) => out.push(c));
        upRes.on('end', () => {
          let payload = Buffer.concat(out).toString('utf8');
          if (rewrite) {
            try {
              const reqJson = JSON.parse(body); let resJson = JSON.parse(payload);
              const apply = (rq: any, rs: any) => rewrite(req.url ?? '/', rq, rs) ?? rs;
              resJson = Array.isArray(reqJson) ? resJson.map((rs: any, i: number) => apply(reqJson[i], rs)) : apply(reqJson, resJson);
              payload = JSON.stringify(resJson);
            } catch {}
          }
          res.writeHead(200, { 'content-type': 'application/json' }); res.end(payload);
        });
      });
      up.on('error', () => { res.writeHead(502); res.end(); });
      up.end(body);
    });
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const url = `http://127.0.0.1:${(server.address() as any).port}`;
  return { server, url, close: () => new Promise((r) => server.close(() => r())) };
}

/** Registry + mined blocks: every write in tests is followed by mine() so snapshot reads see it. */
class R extends ChainRegistry {
  urls: string[];
  constructor(urls: string[], addr: Address, minAgree = 1) { super({ chainId: CHAIN_ID, address: addr, rpcs: urls, minAgree }); this.urls = urls; }
  async w<T>(p: Promise<T>): Promise<T> { const v = await p; for (const u of this.urls) await mine(u).catch(() => {}); return v; }
}

describe('on-chain registry (anvil)', { skip: !haveAnvil || !haveForge ? 'anvil/forge not on PATH — install Foundry to run chain tests' : false }, () => {
  let a: Anvil; let addr: Address; let reg: R;
  const acct = KEYS.map((k) => privateKeyToAccount(k));

  before(async () => {
    const b = spawnSync('forge', ['build'], { cwd: CONTRACTS, encoding: 'utf8', env: { ...process.env, FOUNDRY_DISABLE_NIGHTLY_WARNING: '1' } });
    if (b.status !== 0) throw new Error(`forge build failed: ${b.stderr}`);
    a = await startAnvil(); addr = await deploy(a.url); await mine(a.url);
    reg = new R([a.url], addr);
  });
  after(() => { a?.proc.kill(); });

  test('real bind → ownerOf; the contract verified the signature (gas reported)', async () => {
    const kp = generate(); const pk = kp.pk.toString('hex');
    assert.equal(await reg.ownerOf(pk), null);
    assert.equal(await reg.latestOwner(pk), null);
    const tx = await reg.w(reg.bind(KEYS[0], kp, 0n));
    const rc = await createPublicClient({ transport: http(a.url) }).getTransactionReceipt({ hash: tx });
    console.log(`  bind() gas used on anvil: ${rc.gasUsed}`);
    assert.ok(rc.gasUsed < 1_500_000n, `bind gas ${rc.gasUsed}`);
    const o = (await reg.ownerOf(pk))!;
    assert.equal(o.addr, acct[0].address); assert.equal(o.epoch, 0n);
    assert.equal(typeof o.height, 'bigint'); assert.match(o.hash, /^0x[0-9a-f]{64}$/);
    assert.equal(o.height, (await head(a.url)) - 2n, 'snapshot height = head - 2 with one endpoint');
    assert.deepEqual(await reg.latestOwner(pk), { addr: acct[0].address, epoch: 0n });
  });

  test('pre-flight runs the contract verifier: identity pk / identity R are rejected exactly as on-chain', async () => {
    const kp = generate(); const pk = kp.pk.toString('hex');
    assert.equal(await reg.preflightBinding(pk, acct[0].address, 0n, signBinding(kp, CHAIN_ID, acct[0].address, 0n)), true);
    assert.equal(await reg.preflightBinding(pk, acct[1].address, 0n, signBinding(kp, CHAIN_ID, acct[0].address, 0n)), false, 'wrong address');
    assert.equal(await reg.preflightBinding(pk, acct[0].address, 1n, signBinding(kp, CHAIN_ID, acct[0].address, 0n)), false, 'wrong epoch');
    assert.equal(await reg.preflightBinding(pk, acct[0].address, 0n, randomBytes(64)), false);
    assert.equal(await reg.preflightBinding(pk, acct[0].address, 0n, randomBytes(63)), false, 'wrong length');
    const idPk = '01' + '00'.repeat(31);
    const idSig = Buffer.concat([Buffer.from(idPk, 'hex'), Buffer.alloc(32)]);
    assert.equal(await reg.preflightBinding(idPk, acct[0].address, 0n, idSig), false, 'identity key, identity R, S = 0');
    await assert.rejects(raw(a.url, KEYS[0], addr, 'bind', [pkHex(idPk), toHex(idSig), 0n]), /BadSignature/, 'and the chain agrees');
    const badR = Buffer.concat([Buffer.from(idPk, 'hex'), signBinding(kp, CHAIN_ID, acct[0].address, 0n).subarray(32)]);
    assert.equal(await reg.preflightBinding(pk, acct[0].address, 0n, badR), false, 'real key, identity R');
    await assert.rejects(raw(a.url, KEYS[0], addr, 'bind', [pkHex(pk), toHex(badR), 0n]), /BadSignature/);
    const idKp = { pk: Buffer.from(idPk, 'hex'), sk: kp.sk };
    await assert.rejects(reg.bind(KEYS[0], idKp as any, 0n), BindingRejected, 'bind() refuses before sending');
  });

  test('squatter bind reverts: random bytes, another key\'s valid signature, wrong sender, wrong chain id', async () => {
    const kp = generate(); const pk = kp.pk.toString('hex'); const other = generate();
    await assert.rejects(raw(a.url, KEYS[1], addr, 'bind', [pkHex(pk), toHex(randomBytes(64)), 0n]), /BadSignature/);
    await assert.rejects(raw(a.url, KEYS[1], addr, 'bind', [pkHex(pk), toHex(signBinding(other, CHAIN_ID, acct[1].address, 0n)), 0n]), /BadSignature/);
    // a valid signature for account 0 submitted by account 1
    await assert.rejects(raw(a.url, KEYS[1], addr, 'bind', [pkHex(pk), toHex(signBinding(kp, CHAIN_ID, acct[0].address, 0n)), 0n]), /BadSignature/);
    // right account, wrong chain id in the message
    await assert.rejects(raw(a.url, KEYS[0], addr, 'bind', [pkHex(pk), toHex(signBinding(kp, 1, acct[0].address, 0n)), 0n]), /BadSignature/);
    // right message, wrong epoch argument
    await assert.rejects(raw(a.url, KEYS[0], addr, 'bind', [pkHex(pk), toHex(signBinding(kp, CHAIN_ID, acct[0].address, 0n)), 1n]), /BadSignature/);
    await assert.rejects(raw(a.url, KEYS[0], addr, 'bind', [pkHex(pk), '0x', 0n]), /BadSignatureLength/);
    assert.equal(await reg.ownerOf(pk), null, 'nothing bound');
    // and the real key still binds afterwards, unhindered
    await reg.w(reg.bind(KEYS[0], kp, 0n));
    const o = (await reg.ownerOf(pk))!; assert.equal(o.addr, acct[0].address); assert.equal(o.epoch, 0n);
  });

  test('rotation: a higher-epoch bind moves the owner; the old account\'s records (even MAX_U64) stop resolving; lower/equal epoch rejected', async () => {
    const kp = generate(); const pk = kp.pk.toString('hex');
    await reg.w(reg.bind(KEYS[0], kp, 0n));
    await reg.w(reg.publish(KEYS[0], 'n', 'aa'.repeat(20), 'mit', MAX_U64));
    const r0 = (await reg.resolveVerified(pk, 'n'))!;
    assert.deepEqual({ ih: r0.ih, license: r0.license, seq: r0.seq, addr: r0.addr, epoch: r0.epoch }, { ih: 'aa'.repeat(20), license: 'mit', seq: MAX_U64, addr: acct[0].address, epoch: 0n });
    assert.equal(typeof r0.height, 'bigint'); assert.match(r0.hash, /^0x[0-9a-f]{64}$/);
    const v = await reg.verified(pk, 'nothing');
    assert.deepEqual(v.owner, { addr: acct[0].address, epoch: 0n }); assert.equal(v.record, null); assert.equal(typeof v.height, 'bigint');
    await assert.rejects(reg.bind(KEYS[1], kp, 0n), /EpochNotIncreasing/);
    await assert.rejects(reg.bind(KEYS[0], kp, 0n), /EpochNotIncreasing/, 'same account, same epoch');
    await reg.w(reg.bind(KEYS[1], kp, 1n));
    const o1 = (await reg.ownerOf(pk))!; assert.equal(o1.addr, acct[1].address); assert.equal(o1.epoch, 1n);
    assert.equal(await reg.resolveVerified(pk, 'n'), null, 'new owner has not published: null, never the old record');
    await reg.w(reg.publish(KEYS[1], 'n', 'bb'.repeat(20), '', 1n));
    const r1 = (await reg.resolveVerified(pk, 'n'))!;
    assert.deepEqual({ ih: r1.ih, license: r1.license, seq: r1.seq, addr: r1.addr, epoch: r1.epoch }, { ih: 'bb'.repeat(20), license: undefined, seq: 1n, addr: acct[1].address, epoch: 1n });
    // the compromised old account cannot take it back with a lower or equal epoch, even with a valid signature
    await assert.rejects(reg.bind(KEYS[0], kp, 1n), /EpochNotIncreasing/);
    await assert.rejects(reg.bind(KEYS[0], kp, 0n), /EpochNotIncreasing/);
    // ...but the key holder can move on again
    await reg.w(reg.bind(KEYS[2], kp, MAX_U64));
    const o2 = (await reg.ownerOf(pk))!; assert.equal(o2.addr, acct[2].address); assert.equal(o2.epoch, MAX_U64);
    await assert.rejects(reg.bind(KEYS[1], kp, MAX_U64), /EpochNotIncreasing/);
  });

  test('publish/resolve exact; license normalisation; input validation; seq regression; bigint beyond 2^53 exact', async () => {
    const ih = randomBytes(20).toString('hex');
    await reg.w(reg.publish(KEYS[2], 'acme/tiny', ih.toUpperCase(), 'apache-2.0', 42n));
    const rec = (r: any) => r && { ih: r.ih, license: r.license, seq: r.seq };
    assert.deepEqual(rec(await reg.resolve(acct[2].address, 'acme/tiny')), { ih, license: 'apache-2.0', seq: 42n });
    assert.equal(await reg.resolve(acct[2].address, 'acme/other'), null);
    await reg.w(reg.publish(KEYS[2], 'acme/nolic', ih, undefined, 1n));
    assert.deepEqual(rec(await reg.resolve(acct[2].address, 'acme/nolic')), { ih, license: undefined, seq: 1n });
    assert.throws(() => reg.publish(KEYS[2], 'x', 'nothex', undefined, 1n), /40 hex/);
    assert.throws(() => reg.publish(KEYS[2], 'x', ih, undefined, 0n), /1\.\.2\^64-1/);
    assert.throws(() => reg.publish(KEYS[2], 'x', ih, undefined, (1n << 64n)), /1\.\.2\^64-1/);
    assert.throws(() => reg.publish(KEYS[2], 'x', ih, undefined, 5 as any), /bigint/);
    await assert.rejects(reg.publish(KEYS[2], 'acme/tiny', ih, undefined, 42n), /SeqNotIncreasing/);
    await assert.rejects(reg.publish(KEYS[2], 'acme/tiny', ih, undefined, 3n), /SeqNotIncreasing/);
    const big = (1n << 53n) + 1n;
    await reg.w(reg.publish(KEYS[2], 'acme/tiny', ih, '', big));
    assert.equal((await reg.resolve(acct[2].address, 'acme/tiny'))!.seq, big);
    await reg.w(reg.publish(KEYS[2], 'acme/tiny', ih, '', big + 1n));
    assert.equal((await reg.resolve(acct[2].address, 'acme/tiny'))!.seq, big + 1n);
    assert.equal(await reg.latestSeq(acct[2].address, 'acme/tiny'), big + 1n);
  });

  test('nodesOf round trip / replace / bounds; per account', async () => {
    assert.deepEqual(await reg.nodesOf(acct[2].address), []);
    await reg.w(reg.setNodes(KEYS[2], ['1.2.3.4:6881', '[2001:db8::1]:6881']));
    assert.deepEqual(await reg.nodesOf(acct[2].address), ['1.2.3.4:6881', '[2001:db8::1]:6881']);
    await reg.w(reg.setNodes(KEYS[2], ['9.9.9.9:1']));
    assert.deepEqual(await reg.nodesOf(acct[2].address), ['9.9.9.9:1']);
    await assert.rejects(reg.setNodes(KEYS[2], Array(21).fill('h:1')), /BadNodes/);
    assert.deepEqual(await reg.nodesOf(acct[1].address), []);
  });

  describe('quorum and snapshot reads', () => {
    test('minAgree 2 with one live + one dead → insufficient quorum; minAgree 1 → ok; 3 dead + 1 survivor never passes', async () => {
      const kp = generate(); const pk = kp.pk.toString('hex');
      await reg.w(reg.bind(KEYS[0], kp, 0n));
      await reg.w(reg.publish(KEYS[0], 'q', 'dd'.repeat(20), '', 1n));
      const strict = new ChainRegistry({ chainId: CHAIN_ID, address: addr, rpcs: [DEAD, a.url], minAgree: 2 });
      await assert.rejects(strict.resolveVerified(pk, 'q'), (e: any) => e instanceof AllRpcsFailed && /1\/2/.test(e.message));
      const trusting = new ChainRegistry({ chainId: CHAIN_ID, address: addr, rpcs: [DEAD, a.url], minAgree: 1 });
      assert.equal((await trusting.resolveVerified(pk, 'q'))!.ih, 'dd'.repeat(20));
      const r4 = new ChainRegistry({ chainId: CHAIN_ID, address: addr, rpcs: [DEAD, DEAD2, 'http://127.0.0.1:3', a.url] });
      await assert.rejects(r4.snapshot(), AllRpcsFailed);
      await assert.rejects(r4.resolveVerified(pk, 'q'), AllRpcsFailed);
      await assert.rejects(r4.nodesOf(acct[0].address), AllRpcsFailed);
      const wrong = new ChainRegistry({ chainId: CHAIN_ID, address: '0x00000000000000000000000000000000000000aa', rpcs: [a.url], minAgree: 1 });
      await assert.rejects(wrong.resolve(acct[0].address, 'q'), AllRpcsFailed);
    });

    test('two endpoints on one host:port (different paths) that disagree → RpcDisagreement, never a merged answer', async () => {
      const forged = await proxy({ '/a': a.url, '/b': a.url }, (path, rq, rs) => {
        if (path === '/b' && rq.method === 'eth_call' && typeof rs.result === 'string' && rs.result.length >= 2 + 192) {
          const r = rs.result.slice(2);
          return { ...rs, result: '0x' + r.slice(0, 128) + '00'.repeat(31) + '07' + r.slice(192) };
        }
        return rs;
      });
      try {
        const kp = generate(); const pk = kp.pk.toString('hex');
        await reg.w(reg.bind(KEYS[0], kp, 0n));
        await reg.w(reg.publish(KEYS[0], 'same', 'aa'.repeat(20), '', 1n));
        const both = new ChainRegistry({ chainId: CHAIN_ID, address: addr, rpcs: [`${forged.url}/a`, `${forged.url}/b`] });
        assert.equal(sanitizeUrl(`${forged.url}/a`), sanitizeUrl(`${forged.url}/b`), 'identical display labels');
        const err: any = await both.resolve(acct[0].address, 'same').catch((e) => e);
        assert.ok(err instanceof RpcDisagreement, `got ${err?.message}`);
        assert.equal(Object.keys(err.answers).length, 2);
        const honest = new ChainRegistry({ chainId: CHAIN_ID, address: addr, rpcs: [`${forged.url}/a`, a.url] });
        { const r = (await honest.resolve(acct[0].address, 'same'))!; assert.deepEqual({ ih: r.ih, license: r.license, seq: r.seq }, { ih: 'aa'.repeat(20), license: undefined, seq: 1n }); }
      } finally { await forged.close(); }
    });

    test('snapshot: freshest quorum-servable height; lagging/inflated/far-behind endpoints; lying hash; hash-pinned calls; retries', async () => {
      const kp = generate();
      await reg.w(reg.bind(KEYS[0], kp, 0n));
      await reg.w(reg.publish(KEYS[0], 'snap', 'ab'.repeat(20), '', 1n));
      await mine(a.url, 10);
      const h = await head(a.url);
      const rec = (r: any) => r && { ih: r.ih, license: r.license, seq: r.seq };
      // (1) heads h, h, h-64 with minAgree 2 → height h-2 (the 2nd largest head - 2), NOT h-66; the laggard cannot serve it and drops out
      const lag64 = await proxy({ '/': a.url }, (_p, rq, rs) => (rq.method === 'eth_blockNumber' ? { ...rs, result: toHex(h - 64n) } : rs));
      const mirror = await proxy({ '/': a.url });
      try {
        const three = new ChainRegistry({ chainId: CHAIN_ID, address: addr, rpcs: [a.url, mirror.url, lag64.url] });
        const s = await three.snapshot();
        assert.equal(s.height, h - 2n); assert.deepEqual(s.endpoints, [0, 1]);
        assert.match(Object.values(s.excluded)[0], /cannot serve snapshot height/);
        assert.deepEqual(rec(await three.resolve(acct[0].address, 'snap')), { ih: 'ab'.repeat(20), license: undefined, seq: 1n });
        // with the laggard as one of only two endpoints the quorum needs it: height = its head - 2 (it still agrees on the hash)
        const two = new ChainRegistry({ chainId: CHAIN_ID, address: addr, rpcs: [a.url, lag64.url] });
        const s2 = await two.snapshot();
        assert.equal(s2.height, h - 66n); assert.deepEqual(s2.endpoints, [0, 1]);
      } finally { await lag64.close(); await mirror.close(); }
      // (2) one endpoint claiming head + 1000: with two honest endpoints the median is honest → only the liar is excluded
      const high = await proxy({ '/': a.url }, (_p, rq, rs) => (rq.method === 'eth_blockNumber' ? { ...rs, result: toHex(h + 1000n) } : rs));
      const mirror2 = await proxy({ '/': a.url });
      try {
        const three = new ChainRegistry({ chainId: CHAIN_ID, address: addr, rpcs: [a.url, mirror2.url, high.url] });
        const s = await three.snapshot();
        assert.deepEqual(s.endpoints, [0, 1]); assert.match(Object.values(s.excluded)[0], /from the median/);
        assert.equal(s.height, h - 2n);
        assert.deepEqual(rec(await three.resolve(acct[0].address, 'snap')), { ih: 'ab'.repeat(20), license: undefined, seq: 1n });
        const two = new ChainRegistry({ chainId: CHAIN_ID, address: addr, rpcs: [a.url, high.url] });
        await assert.rejects(two.snapshot(), AllRpcsFailed, 'one honest vs one liar: no quorum, never a rollback');
      } finally { await high.close(); await mirror2.close(); }
      // (3) far-behind endpoint is excluded by the median rule
      while ((await head(a.url)) < 130n) await mine(a.url, 30);
      const h2 = await head(a.url);
      const far = await proxy({ '/': a.url }, (_p, rq, rs) => (rq.method === 'eth_blockNumber' ? { ...rs, result: toHex(h2 - 100n) } : rs));
      const mirror3 = await proxy({ '/': a.url });
      try {
        const three = new ChainRegistry({ chainId: CHAIN_ID, address: addr, rpcs: [a.url, mirror3.url, far.url] });
        const s = await three.snapshot();
        assert.deepEqual(s.endpoints, [0, 1]); assert.equal(s.height, h2 - 2n);
      } finally { await far.close(); await mirror3.close(); }
      // (4) same height, different hash → RpcDisagreement on the block hash, before any read
      const liar = await proxy({ '/': a.url }, (_p, rq, rs) => (rq.method === 'eth_getBlockByNumber' && rs.result ? { ...rs, result: { ...rs.result, hash: '0x' + 'de'.repeat(32) } } : rs));
      try {
        const both = new ChainRegistry({ chainId: CHAIN_ID, address: addr, rpcs: [a.url, liar.url] });
        await assert.rejects(both.snapshot(), (e: any) => e instanceof RpcDisagreement && /hash/.test(e.message));
        await assert.rejects(both.resolve(acct[0].address, 'snap'), RpcDisagreement);
      } finally { await liar.close(); }
      // (5) calls are pinned to the block HASH: an endpoint that serves another block's state for a blockHash request
      //     (here: the request is rewritten to block 2, after deployment but before the publish) disagrees with the honest one
      const forkState = await proxy({ '/': a.url }, undefined, (_p, rq) => (rq.method === 'eth_call' && rq.params?.[1]?.blockHash ? { ...rq, params: [rq.params[0], '0x2'] } : rq));
      try {
        const both = new ChainRegistry({ chainId: CHAIN_ID, address: addr, rpcs: [a.url, forkState.url] });
        await assert.rejects(both.resolve(acct[0].address, 'snap'), RpcDisagreement);
        let sawHash = 0;
        const spy = await proxy({ '/': a.url }, undefined, (_p, rq) => { if (rq.method === 'eth_call') { assert.match(rq.params[1].blockHash, /^0x[0-9a-f]{64}$/); assert.equal(rq.params[1].requireCanonical, true); sawHash++; } return rq; });
        try {
          const one = new ChainRegistry({ chainId: CHAIN_ID, address: addr, rpcs: [spy.url], minAgree: 1 });
          assert.deepEqual(rec(await one.resolve(acct[0].address, 'snap')), { ih: 'ab'.repeat(20), license: undefined, seq: 1n });
          assert.ok(sawHash >= 1, 'every read carried the snapshot hash');
        } finally { await spy.close(); }
        // an endpoint that rejects blockHash params drops out of the read: alone it fails closed, next to an honest one it is ignored
        const noPin = await proxy({ '/': a.url }, (_p, rq, rs) => (rq.method === 'eth_call' && rq.params?.[1]?.blockHash ? { jsonrpc: '2.0', id: rs.id, error: { code: -32602, message: 'blockHash unsupported' } } : rs));
        try {
          const alone = new ChainRegistry({ chainId: CHAIN_ID, address: addr, rpcs: [noPin.url], minAgree: 1 });
          await assert.rejects(alone.resolve(acct[0].address, 'snap'), AllRpcsFailed);
          const withHonest = new ChainRegistry({ chainId: CHAIN_ID, address: addr, rpcs: [a.url, noPin.url], minAgree: 1 });
          assert.deepEqual(rec(await withHonest.resolve(acct[0].address, 'snap')), { ih: 'ab'.repeat(20), license: undefined, seq: 1n });
          const strict = new ChainRegistry({ chainId: CHAIN_ID, address: addr, rpcs: [a.url, noPin.url], minAgree: 2 });
          await assert.rejects(strict.resolve(acct[0].address, 'snap'), AllRpcsFailed, 'fails closed below quorum');
        } finally { await noPin.close(); }
      } finally { await forkState.close(); }
      // (6) a wrong hash on the first snapshot (so the pinned call fails) → one retry from a fresh snapshot, then success
      let blockCalls = 0;
      const flaky = await proxy({ '/': a.url }, (_p, rq, rs) => {
        if (rq.method === 'eth_getBlockByNumber' && rs.result) { blockCalls++; if (blockCalls === 1) return { ...rs, result: { ...rs.result, hash: '0x' + 'ee'.repeat(32) } }; }
        return rs;
      });
      try {
        const one = new ChainRegistry({ chainId: CHAIN_ID, address: addr, rpcs: [flaky.url], minAgree: 1 });
        assert.deepEqual(rec(await one.resolve(acct[0].address, 'snap')), { ih: 'ab'.repeat(20), license: undefined, seq: 1n });
        assert.equal(blockCalls, 2, 'failed pinned read, fresh snapshot, success');
      } finally { await flaky.close(); }
      // (7) a read that fails once (RPC error on the first eth_call) is retried from a fresh snapshot and succeeds
      let callsFailed = 0;
      const once = await proxy({ '/': a.url }, (_p, rq, rs) => (rq.method === 'eth_call' && callsFailed++ === 0 ? { jsonrpc: '2.0', id: rs.id, error: { code: -32000, message: 'transient' } } : rs));
      try {
        const one = new ChainRegistry({ chainId: CHAIN_ID, address: addr, rpcs: [once.url], minAgree: 1 });
        assert.deepEqual(rec(await one.resolve(acct[0].address, 'snap')), { ih: 'ab'.repeat(20), license: undefined, seq: 1n });
        assert.ok(callsFailed >= 2, 'the read was retried');
      } finally { await once.close(); }
      // a hash that is always wrong fails after the single retry
      const churn = await proxy({ '/': a.url }, (_p, rq, rs) => (rq.method === 'eth_getBlockByNumber' && rs.result ? { ...rs, result: { ...rs.result, hash: toHex(randomBytes(32)) } } : rs));
      try {
        const c = new ChainRegistry({ chainId: CHAIN_ID, address: addr, rpcs: [churn.url], minAgree: 1 });
        await assert.rejects(c.resolve(acct[0].address, 'snap'), AllRpcsFailed);
      } finally { await churn.close(); }
    });

    test('endpoint on the wrong chain id is excluded from the snapshot', async () => {
      const other = await startAnvil(31338);
      try {
        const kp = generate(); const pk = kp.pk.toString('hex');
        await reg.w(reg.bind(KEYS[0], kp, 0n));
        await reg.w(reg.publish(KEYS[0], 'c', 'cd'.repeat(20), '', 1n));
        const mixed = new ChainRegistry({ chainId: CHAIN_ID, address: addr, rpcs: [other.url, a.url], minAgree: 1 });
        const snap = await mixed.snapshot();
        assert.deepEqual(snap.endpoints, [1]);
        assert.match(Object.values(snap.excluded)[0], /chainId 31338 != 31337/);
        assert.equal((await mixed.resolveVerified(pk, 'c'))!.ih, 'cd'.repeat(20));
        const strict = new ChainRegistry({ chainId: CHAIN_ID, address: addr, rpcs: [other.url, a.url], minAgree: 2 });
        await assert.rejects(strict.resolveVerified(pk, 'c'), (e: any) => e instanceof AllRpcsFailed && /chainId 31338/.test(e.message));
      } finally { other.proc.kill(); }
    });

    test('RPC credentials never appear in errors', async () => {
      const secretUrl = 'http://user:hunter2@127.0.0.1:1/v2/SECRETKEY123?apikey=TOPSECRET';
      const r = new ChainRegistry({ chainId: CHAIN_ID, address: addr, rpcs: [secretUrl, DEAD2] });
      const err: any = await r.resolve(acct[0].address, 'x').catch((e) => e);
      assert.ok(err instanceof AllRpcsFailed);
      for (const s of ['hunter2', 'SECRETKEY123', 'TOPSECRET', 'user:']) assert.equal(err.message.includes(s), false, `leaked ${s}`);
      assert.match(err.message, /http:\/\/127\.0\.0\.1:1/);
      const w = new ChainRegistry({ chainId: CHAIN_ID, address: addr, rpcs: [secretUrl], minAgree: 1 });
      const werr: any = await w.setNodes(KEYS[0], ['x:1']).catch((e) => e);
      for (const s of ['hunter2', 'SECRETKEY123', 'TOPSECRET']) assert.equal(String(werr.message).includes(s), false, `write leaked ${s}`);
    });
  });

  describe('WebwayNode integration', () => {
    let root: string; let router: WebwayNode; let boot: string[]; let pub: WebwayNode; let reader: WebwayNode; let noChain: WebwayNode;
    let dirs = 0;
    const freshDir = (bytes = 40_000) => { const d = join(root, 'src', `d${dirs++}`); mkdirSync(d, { recursive: true }); writeFileSync(join(d, 'w.bin'), randomBytes(bytes)); return d; };
    before(async () => {
      root = mkdtempSync(join(tmpdir(), 'webway-chain-'));
      router = await new WebwayNode({ home: join(root, 'router'), bootstrap: false, nat: false, chain: false }).start();
      boot = [`127.0.0.1:${router.dht.address().port}`];
      pub = await new WebwayNode({ home: join(root, 'pub'), bootstrap: boot, nat: false, chain: reg }).start();
      reader = await new WebwayNode({ home: join(root, 'reader'), bootstrap: boot, nat: false, chain: reg }).start();
      noChain = await new WebwayNode({ home: join(root, 'nochain'), bootstrap: boot, nat: false, chain: false }).start();
      const b = await pub.bindChain(KEYS[0]);
      assert.equal(b.epoch, 0n); assert.equal(b.addr, acct[0].address);
      await mine(a.url);
    });
    after(async () => { await Promise.all([reader.stop(), noChain.stop(), pub.stop(), router.stop()]); });

    test('chain-only name resolves from a fresh node; not without chain', async () => {
      const ihChain = randomBytes(20).toString('hex');
      await reg.w(reg.publish(KEYS[0], 'acme/onchain', ihChain, 'apache-2.0', 100n));
      const r = await reader.resolve(`webway://${pub.pk}/acme/onchain`);
      assert.equal(r.ih, ihChain); assert.equal(r.source, 'chain'); assert.equal(r.license, 'apache-2.0'); assert.equal(r.seq, 100n); assert.equal(r.size, undefined); assert.equal(r.warning, undefined);
      assert.equal(typeof r.snapshot!.height, 'bigint'); assert.match(r.snapshot!.hash, /^0x[0-9a-f]{64}$/);
      assert.equal(r.snapshot!.height, (await head(a.url)) - 2n);
      await assert.rejects(noChain.resolve(`webway://${pub.pk}/acme/onchain`), /no record/);
      const stranger = await new WebwayNode({ home: join(root, 'stranger'), bootstrap: boot, nat: false, chain: reg }).start();
      try { assert.equal((await stranger.resolve(`webway://${pub.pk}/acme/onchain`)).ih, ihChain, 'no hints, no state: still resolves'); } finally { await stranger.stop(); }
    });

    test('DHT records carry a/e as a cross-check: matching → silent; stale after a rotation → dht-hint-mismatch warning, chain authoritative', async () => {
      const share = await pub.share(freshDir(), 'acme/hinted', 'mit');
      const raw0 = await (reader as any).getRaw(pub.pk, 'acme/hinted');
      const rec = parseDhtRecord(raw0.v, 'acme/hinted')!;
      assert.deepEqual(rec.hint, { addr: acct[0].address, epoch: 0n });
      await reg.w(reg.publish(KEYS[0], 'acme/hinted', share.ih, 'mit', share.seq + 1n));
      const r1 = await reader.resolve(`webway://${pub.pk}/acme/hinted`);
      assert.equal(r1.source, 'chain'); assert.equal(r1.ih, share.ih); assert.equal(r1.size, share.size); assert.equal(r1.warning, undefined);
      // rotate the publisher to account 1 (epoch 1); the DHT record still says account 0 / epoch 0
      const b = await pub.bindChain(KEYS[1]); await mine(a.url);
      assert.equal(b.epoch, 1n);
      await reg.w(reg.publish(KEYS[1], 'acme/hinted', 'ab'.repeat(20), 'mit', share.seq + 2n));
      const r2 = await reader.resolve(`webway://${pub.pk}/acme/hinted`);
      assert.equal(r2.ih, 'ab'.repeat(20), 'chain owner (account 1) is authoritative');
      assert.equal(r2.source, 'chain');
      assert.match(r2.warning!, /dht-hint-mismatch/);
      // the old account's record, even with a huge seq, is not consulted
      await reg.w(reg.publish(KEYS[0], 'acme/hinted', 'ee'.repeat(20), 'mit', MAX_U64));
      assert.equal((await reader.resolve(`webway://${pub.pk}/acme/hinted`)).ih, 'ab'.repeat(20));
      // re-sharing writes the new a/e → warning gone
      const share2 = await pub.share(freshDir(), 'acme/hinted', 'mit', { ethKey: KEYS[1] }); await mine(a.url);
      const r3 = await reader.resolve(`webway://${pub.pk}/acme/hinted`);
      assert.equal(r3.ih, share2.ih); assert.equal(r3.warning, undefined);
      assert.deepEqual(parseDhtRecord((await (reader as any).getRaw(pub.pk, 'acme/hinted')).v, 'acme/hinted')!.hint, { addr: acct[1].address, epoch: 1n });
      // move back to account 0 for the remaining tests (epoch 2)
      await pub.bindChain(KEYS[0]); await mine(a.url);
      const ob = (await reg.ownerOf(pub.pk))!; assert.equal(ob.addr, acct[0].address); assert.equal(ob.epoch, 2n);
    });

    test('same infohash on both → newer metadata + DHT size; conflicts by seq; equal seq → chain', async () => {
      const share = await pub.share(freshDir(), 'acme/both', 'mit');
      const r1 = await reader.resolve(`webway://${pub.pk}/acme/both`);
      assert.equal(r1.source, 'dht'); assert.equal(r1.ih, share.ih); assert.equal(r1.size, share.size); assert.equal(r1.warning, undefined);
      assert.ok(r1.snapshot, 'DHT-sourced result still reports the chain snapshot it consulted');
      await reg.w(reg.publish(KEYS[0], 'acme/both', share.ih, 'apache-2.0', r1.seq! + 1n));
      const r2 = await reader.resolve(`webway://${pub.pk}/acme/both`);
      assert.equal(r2.source, 'chain'); assert.equal(r2.license, 'apache-2.0'); assert.equal(r2.size, share.size); assert.equal(r2.warning, undefined);
      const newer = randomBytes(20).toString('hex');
      await reg.w(reg.publish(KEYS[0], 'acme/both', newer, 'mit', r1.seq! + 1000n));
      const r3 = await reader.resolve(`webway://${pub.pk}/acme/both`);
      assert.equal(r3.ih, newer); assert.equal(r3.source, 'chain'); assert.equal(r3.size, undefined); assert.match(r3.warning!, /conflict: DHT \(seq \d+.*older than chain.*using chain/);
      const share2 = await pub.share(freshDir(), 'acme/conf2', 'mit');
      await reg.w(reg.publish(KEYS[0], 'acme/conf2', randomBytes(20).toString('hex'), 'mit', 1n));
      const r4 = await reader.resolve(`webway://${pub.pk}/acme/conf2`);
      assert.equal(r4.ih, share2.ih); assert.equal(r4.source, 'dht'); assert.equal(r4.size, share2.size); assert.match(r4.warning!, /conflict: chain \(seq 1.*older than DHT.*using dht/);
      const share3 = await pub.share(freshDir(), 'acme/conf3', 'mit');
      const eqIh = randomBytes(20).toString('hex');
      await reg.w(reg.publish(KEYS[0], 'acme/conf3', eqIh, 'mit', share3.seq));
      const r5 = await reader.resolve(`webway://${pub.pk}/acme/conf3`);
      assert.equal(r5.ih, eqIh); assert.equal(r5.source, 'chain'); assert.equal(r5.size, undefined); assert.match(r5.warning!, /conflict-equal-seq/);
    });

    test('malformed or name-mismatched DHT record is a failed source; chain still answers', async () => {
      const ihChain = randomBytes(20).toString('hex');
      await reg.w(reg.publish(KEYS[0], 'acme/bad', ihChain, '', 7n));
      await (pub as any).put('acme/bad', { ih: randomBytes(20), n: 'acme/OTHER', sz: 5 }, Math.floor(Date.now() / 1000));
      const r1 = await reader.resolve(`webway://${pub.pk}/acme/bad`);
      assert.equal(r1.ih, ihChain); assert.equal(r1.source, 'chain'); assert.match(r1.warning!, /malformed or for a different name/);
      await (pub as any).put('acme/bad2', { n: 'acme/bad2', sz: 5 }, Math.floor(Date.now() / 1000));
      await reg.w(reg.publish(KEYS[0], 'acme/bad2', ihChain, '', 1n));
      assert.equal((await reader.resolve(`webway://${pub.pk}/acme/bad2`)).source, 'chain');
      await (pub as any).put('acme/bad3', { n: 'acme/bad3' }, Math.floor(Date.now() / 1000));
      await assert.rejects(reader.resolve(`webway://${pub.pk}/acme/bad3`), /DHT: DHT record malformed.*chain: none/);
      await assert.rejects(noChain.resolve(`webway://${pub.pk}/acme/bad`), /malformed/);
      await (pub as any).put('acme/bad4', { ih: randomBytes(20), n: 'acme/bad4', sz: 5, a: randomBytes(19), e: '0' }, Math.floor(Date.now() / 1000));
      await assert.rejects(noChain.resolve(`webway://${pub.pk}/acme/bad4`), /malformed/);
      await (pub as any).put('acme/bad5', { ih: randomBytes(20), n: 'acme/bad5', sz: 5, a: randomBytes(20), e: 7 }, Math.floor(Date.now() / 1000));
      await assert.rejects(noChain.resolve(`webway://${pub.pk}/acme/bad5`), /malformed/, 'numeric epoch is malformed');
    });

    test('fetch() surfaces resolution warnings; re-fetching held content reuses the torrent', async () => {
      const share = await pub.share(freshDir(), 'acme/fetchwarn', 'mit');
      await reg.w(reg.publish(KEYS[0], 'acme/fetchwarn', randomBytes(20).toString('hex'), 'mit', 1n));
      let seen: string | undefined;
      const got = await reader.fetch(`webway://${pub.pk}/acme/fetchwarn`, undefined, (r) => { seen = r.warning; assert.equal(r.ih, share.ih); });
      assert.match(seen!, /conflict: chain \(seq 1/); assert.match(got.warning!, /conflict/); assert.equal(got.ih, share.ih);
      assert.equal(((await reader.shares()).find((s) => s.name === 'acme/fetchwarn') as any).warning, undefined);
      const d = freshDir();
      const clean = await pub.share(d, 'acme/clean', 'mit');
      const got2 = await reader.fetch(`webway://${pub.pk}/acme/clean`);
      assert.equal(got2.warning, undefined); assert.equal(got2.ih, clean.ih);
      const again = await pub.share(d, 'acme/clean-alias', 'mit');
      const got3 = await reader.fetch(`webway://${pub.pk}/acme/clean-alias`);
      assert.equal(got3.ih, again.ih); assert.equal(got3.dir, got2.dir);
    });

    test('one own share per name; share --chain publishes the new content with the same version', async () => {
      const old = await pub.share(freshDir(), 'acme/replace', 'mit');
      const fresh = await pub.share(freshDir(), 'acme/replace', 'mit', { ethKey: KEYS[0] });
      await mine(a.url);
      assert.notEqual(old.ih, fresh.ih);
      const own = (await pub.shares()).filter((s) => s.own && s.name === 'acme/replace');
      assert.equal(own.length, 1); assert.equal(own[0].ih, fresh.ih);
      assert.ok(fresh.chainTx);
      const onChain = await reg.resolve(acct[0].address, 'acme/replace');
      assert.equal(onChain!.ih, fresh.ih); assert.equal(onChain!.seq, fresh.seq);
      const r = await reader.resolve(`webway://${pub.pk}/acme/replace`);
      assert.equal(r.ih, fresh.ih); assert.equal(r.seq, fresh.seq); assert.equal(r.warning, undefined);
      const p = await pub.publishToChain(KEYS[0], 'acme/replace'); await mine(a.url);
      assert.equal(p.share.ih, fresh.ih); assert.ok(p.seq > fresh.seq);
      const heldBefore = (await reader.shares()).filter((s) => !s.own).length;
      await reader.fetch(`webway://${pub.pk}/acme/replace`);
      await reader.fetch(`webway://${pub.pk}/acme/replace`);
      assert.equal((await reader.shares()).filter((s) => !s.own).length, heldBefore + 1);
    });

    test('version allocator: bigint, DHT-safe cap checked before persisting, chain-only names may exceed it', async () => {
      const seqs = await Promise.all([pub.nextSeq('par'), pub.nextSeq('par'), pub.nextSeq('par')]);
      assert.equal(new Set(seqs.map(String)).size, 3);
      assert.ok(seqs[0] < seqs[1] && seqs[1] < seqs[2]);
      const before = JSON.stringify(await (pub as any).readJson('seq.json', {}));
      await assert.rejects(pub.nextSeq('capped', MAX_DHT_SEQ), /DHT-safe maximum/);
      await assert.rejects(pub.nextSeq('capped', MAX_DHT_SEQ + 5n), /DHT-safe maximum/);
      assert.equal(JSON.stringify(await (pub as any).readJson('seq.json', {})), before, 'nothing persisted on rejection');
      assert.equal(await pub.nextSeq('capped', MAX_DHT_SEQ - 1n), MAX_DHT_SEQ);
      await assert.rejects(pub.nextSeq('capped'), /DHT-safe maximum/);
      assert.equal((await (pub as any).readJson('seq.json', {})).capped, MAX_DHT_SEQ.toString());
      assert.equal(await pub.nextChainSeq('big', (1n << 60n)), (1n << 60n) + 1n);
      await assert.rejects(pub.nextChainSeq('big', (1n << 64n) - 1n), /uint64/);
      await assert.rejects(pub.nextSeq('x', -1n), /non-negative bigint/);
      await assert.rejects(pub.nextSeq('x', 5 as any), /bigint/);
    });

    test('reconcile at the latest block: owner\'s record, writer\'s record, own DHT record; a publish seconds ago with no blocks mined; read failure aborts', async () => {
      const name = 'acme/recon';
      const share = await pub.share(freshDir(), name, 'mit');
      const ahead = BigInt(Math.floor(Date.now() / 1000) + 5_000_000);
      // the owner (account 0) publishes and we allocate immediately, no blocks mined
      await raw(a.url, KEYS[0], addr, 'publish', [name, `0x${share.ih}`, 'mit', ahead]);
      assert.equal(await pub.allocateVersion(name), ahead + 1n, 'owner record at latest block');
      // the writer is not the owner: its own record counts too
      await raw(a.url, KEYS[2], addr, 'publish', [name, `0x${share.ih}`, 'mit', ahead + 500n]);
      assert.equal(await pub.allocateVersion(name, KEYS[2]), ahead + 501n);
      assert.equal(await pub.allocateVersion(name), ahead + 502n, 'persisted counter keeps it monotonic');
      const p = await pub.publishToChain(KEYS[0], share); await mine(a.url);
      assert.equal(p.seq, ahead + 503n);
      await (pub as any).writeJson('seq.json', {});
      assert.ok((await pub.allocateVersion(name, KEYS[0])) > ahead + 503n, 'wiped counter still bounded by chain + DHT');
      const broken = new WebwayNode({ home: join(root, 'pub'), bootstrap: boot, nat: false, chain: new ChainRegistry({ chainId: CHAIN_ID, address: addr, rpcs: [DEAD], minAgree: 1 }) });
      (broken as any).key = pub.key; (broken as any).client = pub.client;
      await assert.rejects(broken.allocateVersion(name), /fetch|ECONNREFUSED|HTTP request failed|request/i);
      await reg.w(reg.publish(KEYS[0], 'acme/huge', share.ih, '', (1n << 60n)));
      await pub.share(freshDir(), 'acme/huge', 'mit').then(() => assert.fail('should reject'), (e) => assert.match(String(e.message), /DHT-safe maximum/));
    });

    test('bindChain epochs: default = on-chain epoch + 1, explicit uint64 accepted, persisted as decimal string', async () => {
      const cur = (await reg.ownerOf(pub.pk))!;
      const nxt = await pub.bindChain(KEYS[0]); await mine(a.url);
      assert.equal(nxt.epoch, cur.epoch + 1n);
      const big = MAX_U64 - 1n;
      const b2 = await pub.bindChain(KEYS[0], big); await mine(a.url);
      assert.equal(b2.epoch, big);
      assert.equal((await (pub as any).readJson('chainbind.json', null)).epoch, big.toString());
      const own = await pub.ownBinding();
      assert.equal(own!.epoch, big);
      const s = await pub.share(freshDir(), 'acme/bigepoch', 'mit');
      assert.deepEqual(parseDhtRecord((await (reader as any).getRaw(pub.pk, 'acme/bigepoch')).v, 'acme/bigepoch')!.hint, { addr: acct[0].address, epoch: big });
      assert.equal((await reader.resolve(`webway://${pub.pk}/acme/bigepoch`)).warning, undefined);
      assert.equal(s.ih.length, 40);
      await assert.rejects(pub.bindChain(KEYS[0], 5n), /EpochNotIncreasing/);
      await assert.rejects(pub.bindChain(KEYS[0], 1n << 64n), /epoch out of range/);
    });

    test('on-chain bootstrap: async at start, marks done only after a successful read, on follow(), on resolve(); dedupe; budget', async () => {
      const routerAddr = `127.0.0.1:${router.dht.address().port}`;
      await reg.w(reg.setNodes(KEYS[0], [routerAddr, '10.0.0.1:6881', 'garbage', routerAddr, '203.0.113.9:6881', 'router.bittorrent.com:6881']));
      const fresh = await new WebwayNode({ home: join(root, 'fresh'), bootstrap: false, nat: false, chain: reg, allowPrivate: true }).start();
      try {
        assert.deepEqual(await fresh.chainBootstrapReady, [], 'follows nobody yet');
        assert.equal(fresh.dht.nodes.count(), 0);
        const added = await fresh.bootstrapFromChain([pub.pk]);
        assert.deepEqual(added, [routerAddr, '10.0.0.1:6881', '203.0.113.9:6881'], 'deduped; hostnames and garbage dropped');
        assert.deepEqual(await fresh.bootstrapFromChain([pub.pk]), [], 'once per pk per session after success');
        for (let i = 0; i < 50 && fresh.dht.nodes.count() === 0; i++) await new Promise((r) => setTimeout(r, 100));
        assert.ok(fresh.dht.nodes.count() >= 1, 'router learned via the chain');
      } finally { await fresh.stop(); }
      // a failed read does not mark the publisher done: it is retried
      const flakyReg = { failNext: true } as { failNext: boolean };
      const flaky = await proxy({ '/': a.url }, (_p, rq, rs) => { if (rq.method === 'eth_call' && flakyReg.failNext) { flakyReg.failNext = false; return { jsonrpc: '2.0', id: rs.id, error: { code: -32000, message: 'transient' } }; } return rs; });
      try {
        const rr = new ChainRegistry({ chainId: CHAIN_ID, address: addr, rpcs: [flaky.url], minAgree: 1 });
        // make BOTH the read and its retry fail by failing the first two calls
        flakyReg.failNext = true;
        let fails = 2;
        await flaky.close();
        const flaky2 = await proxy({ '/': a.url }, (_p, rq, rs) => (rq.method === 'eth_call' && fails-- > 0 ? { jsonrpc: '2.0', id: rs.id, error: { code: -32000, message: 'transient' } } : rs));
        try {
          const rr2 = new ChainRegistry({ chainId: CHAIN_ID, address: addr, rpcs: [flaky2.url], minAgree: 1 });
          const n = await new WebwayNode({ home: join(root, 'retry'), bootstrap: false, nat: false, chain: rr2, allowPrivate: true }).start();
          try {
            assert.deepEqual(await n.bootstrapFromChain([pub.pk]), [], 'first attempt fails');
            assert.equal(fails <= 0, true);
            assert.deepEqual(await n.bootstrapFromChain([pub.pk]), [routerAddr, '10.0.0.1:6881', '203.0.113.9:6881'], 'not marked done → retried and succeeds');
          } finally { await n.stop(); }
        } finally { await flaky2.close(); }
        void rr;
      } finally { /* closed above */ }
      // budget: 20 distinct destinations
      await reg.w(reg.setNodes(KEYS[0], Array.from({ length: 20 }, (_, i) => `203.0.113.${i + 1}:6881`)));
      const budget = await new WebwayNode({ home: join(root, 'budget'), bootstrap: false, nat: false, chain: reg }).start();
      try { assert.equal((await budget.bootstrapFromChain([pub.pk])).length, 20); } finally { await budget.stop(); }
      // follow() and resolve() trigger it without blocking
      await reg.w(reg.setNodes(KEYS[0], [routerAddr]));
      const f = await new WebwayNode({ home: join(root, 'follower'), bootstrap: false, nat: false, chain: reg, allowPrivate: true }).start();
      try {
        await f.follow(pub.pk);
        for (let i = 0; i < 50 && f.dht.nodes.count() === 0; i++) await new Promise((r) => setTimeout(r, 100));
        assert.ok(f.dht.nodes.count() >= 1, 'follow() bootstrapped');
      } finally { await f.stop(); }
      const g = await new WebwayNode({ home: join(root, 'getter'), bootstrap: false, nat: false, chain: reg, allowPrivate: true }).start();
      try {
        await reg.w(reg.publish(KEYS[0], 'acme/boot', 'ab'.repeat(20), '', 1n));
        assert.equal((await g.resolve(`webway://${pub.pk}/acme/boot`)).ih, 'ab'.repeat(20));
        for (let i = 0; i < 50 && g.dht.nodes.count() === 0; i++) await new Promise((r) => setTimeout(r, 100));
        assert.ok(g.dht.nodes.count() >= 1, 'resolve() of an unfollowed pk bootstrapped');
      } finally { await g.stop(); }
      const s = await new WebwayNode({ home: join(root, 'follower'), bootstrap: false, nat: false, chain: reg, allowPrivate: true }).start();
      try { assert.deepEqual(await s.chainBootstrapReady, [routerAddr]); } finally { await s.stop(); }
      const dead = await new WebwayNode({ home: join(root, 'follower'), bootstrap: false, nat: false, chain: new ChainRegistry({ chainId: CHAIN_ID, address: addr, rpcs: [DEAD], minAgree: 1 }) }).start();
      try { assert.deepEqual(await dead.chainBootstrapReady, []); } finally { await dead.stop(); }
    });
  });

  describe('installed CLI', () => {
    test('the built entry point runs when invoked through a symlink named `webway`', { timeout: 120_000 }, async () => {
      const b = spawnSync('npx', ['tsc'], { cwd: ROOT, encoding: 'utf8' });
      assert.equal(b.status, 0, b.stdout + b.stderr);
      chmodSync(join(ROOT, 'dist', 'cli.js'), 0o755);
      const bin = mkdtempSync(join(tmpdir(), 'webway-bin-'));
      const link = join(bin, 'webway');
      symlinkSync(join(ROOT, 'dist', 'cli.js'), link);
      assert.ok(existsSync(link));
      const home = mkdtempSync(join(tmpdir(), 'webway-home-'));
      const help = spawnSync(link, ['help'], { encoding: 'utf8', env: { ...process.env, WEBWAY_HOME: home } });
      assert.equal(help.status, 0, help.stderr);
      assert.match(help.stdout, /webway — Napster for model weights/);
      const id = spawnSync(link, ['id', '--no-chain'], { encoding: 'utf8', env: { ...process.env, WEBWAY_HOME: home } });
      assert.equal(id.status, 0, id.stderr);
      assert.match(id.stdout.trim(), /^[0-9a-f]{64}$/);
      const bad = spawnSync(link, ['id', '--min-agree', 'abc'], { encoding: 'utf8', env: { ...process.env, WEBWAY_HOME: home } });
      assert.equal(bad.status, 1); assert.match(bad.stderr, /must be an integer/);
      const badSwitch = spawnSync(link, ['--chain=false', 'id'], { encoding: 'utf8', env: { ...process.env, WEBWAY_HOME: home } });
      assert.equal(badSwitch.status, 1); assert.match(badSwitch.stderr, /takes no value/);
    });
  });
});
