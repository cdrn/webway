import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, mkdir, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { ADOPT, WebwayNode } from '../src/node.ts';
import { LIMITS } from '../src/bootstrap.ts';

const knows = (n: WebwayNode, port: number) => n.dht.toJSON().nodes.some((x: any) => x.port === port);
const waitFor = async (f: () => boolean, ms = 5000) => { for (let i = 0; i < ms / 100 && !f(); i++) await new Promise((r) => setTimeout(r, 100)); return f(); };
const local = (opts: object) => new WebwayNode({ nat: false, dns: false, ...opts }).start();
const PK = 'a'.repeat(64);

/** A UDP port that is free right now (bind 0, read, close). */
async function freeUdpPort(): Promise<number> {
  const { createSocket } = await import('node:dgram');
  const s = createSocket('udp4');
  await new Promise<void>((r) => s.bind(0, '127.0.0.1', r));
  const port = s.address().port;
  await new Promise<void>((r) => s.close(r));
  return port;
}

/** Replace the DHT's addNode with a recorder so adoption sends no packets. */
function recordAdds(n: WebwayNode): string[] {
  const seen: string[] = [];
  n.dht.addNode = (a: { host: string; port: number }) => { seen.push(`${a.host}:${a.port}`); };
  return seen;
}

test('reading a catalog admits a node the reader could not otherwise learn (#4, #9)', async () => {
  const root = await mkdtemp(join(tmpdir(), 'webway-cat-'));
  const modelDir = join(root, 'src', 'm');
  await mkdir(modelDir, { recursive: true });
  await writeFile(join(modelDir, 'w.bin'), randomBytes(256 * 1024));

  const router = await local({ home: join(root, 'r'), bootstrap: false });
  const boot = [`127.0.0.1:${router.dht.address().port}`];
  const pub = await local({ home: join(root, 'pub'), bootstrap: boot, allowPrivate: true });
  const reader = await local({ home: join(root, 'reader'), bootstrap: boot, allowPrivate: true });
  // A hermit nobody's routing table contains: it can only reach the reader through the catalog.
  const hermit = await local({ home: join(root, 'hermit'), bootstrap: false });
  const hermitPort = hermit.dht.address().port;
  try {
    // Advertise the hermit without it ever entering pub's routing table.
    const realToJSON = pub.dht.toJSON.bind(pub.dht);
    pub.dht.toJSON = () => { const j = realToJSON(); return { ...j, nodes: [...j.nodes, { host: '127.0.0.1', port: hermitPort }] }; };
    await pub.share(modelDir, 'acme/m');
    const cat = JSON.parse(await readFile(join(pub.home, 'catalog', 'catalog.json'), 'utf8'));
    assert.ok(cat.nodes.includes(`127.0.0.1:${hermitPort}`), JSON.stringify(cat.nodes));
    assert.ok(cat.nodes.length <= LIMITS.advertise);
    assert.deepEqual(cat.entries.map((e: any) => e.name), ['acme/m']);
    assert.equal(cat.pk, pub.pk);

    assert.equal(knows(reader, hermitPort), false, 'reader is ignorant of the hermit');
    const entries = await reader.catalog(pub.pk);
    assert.equal(entries.length, 1);
    assert.equal(await waitFor(() => knows(reader, hermitPort)), true, 'hermit admitted via catalog adoption');
    const st = (await reader.adoptState())[pub.pk];
    assert.ok(st.seen.includes(`127.0.0.1:${hermitPort}`));
    assert.ok(!st.seen.includes(boot[0]), 'a node already in the table costs no budget and is not marked adopted');

    // Provenance: the reader will not re-advertise the freshly adopted hermit in its own catalog...
    await writeFile(join(modelDir, 'w2.bin'), randomBytes(1024));
    await reader.share(modelDir, 'reader/m');
    let mine = JSON.parse(await readFile(join(reader.home, 'catalog', 'catalog.json'), 'utf8'));
    assert.ok(!mine.nodes.includes(`127.0.0.1:${hermitPort}`), `fresh adoption not re-advertised: ${JSON.stringify(mine.nodes)}`);
    assert.ok(mine.nodes.includes(boot[0]), 'independently learned router still advertised');
    // ...until it has been in the table for an hour.
    (reader as any).adopted.set(`127.0.0.1:${hermitPort}`, Date.now() - ADOPT.reAdvertiseAfterMs - 1);
    await reader.publishCatalog();
    mine = JSON.parse(await readFile(join(reader.home, 'catalog', 'catalog.json'), 'utf8'));
    assert.ok(mine.nodes.includes(`127.0.0.1:${hermitPort}`), 'aged adoption re-advertised');
  } finally {
    for (const n of [reader, pub, hermit, router]) await n.stop().catch(() => {});
  }
});

test('adoptNodes: validate before cap; >20, duplicates, 20 invalid before a valid one', async () => {
  const root = await mkdtemp(join(tmpdir(), 'webway-adopt-'));
  const n = await local({ home: join(root, 'n'), bootstrap: false });
  const adds = recordAdds(n);
  try {
    const invalid20 = Array.from({ length: 20 }, (_, i) => `junk${i}`);
    assert.deepEqual(await n.adoptNodes([...invalid20, '8.8.8.8:8'], PK), ['8.8.8.8:8']);
    assert.deepEqual(adds, ['8.8.8.8:8']);
    // duplicates within a read collapse; across reads they are skipped (persisted)
    assert.deepEqual(await n.adoptNodes(['9.9.9.9:9', '9.9.9.9:9', '8.8.8.8:8'], PK), ['9.9.9.9:9']);
    // >20 entries: only 20 per read, and only 20 per publisher lifetime
    const many = Array.from({ length: 30 }, (_, i) => `1.${i}.0.1:1`);
    const got = await n.adoptNodes(many, 'b'.repeat(64));
    assert.equal(got.length, 20);
    assert.deepEqual(await n.adoptNodes(many.slice(20), 'b'.repeat(64)), [], 'publisher budget exhausted');
    assert.equal((await n.adoptState())['b'.repeat(64)].n, ADOPT.perPublisher);
  } finally { await n.stop(); }
});

test('adoptNodes: rotating catalogs cannot exceed the per-publisher budget; persisted across restarts', async () => {
  const root = await mkdtemp(join(tmpdir(), 'webway-adopt2-'));
  let n = await local({ home: join(root, 'n'), bootstrap: false });
  let adds = recordAdds(n);
  try {
    for (let round = 0; round < 5; round++) {
      const batch = Array.from({ length: 20 }, (_, i) => `2.${round}.${i}.1:1`); // distinct /24 each
      await n.adoptNodes(batch, PK);
    }
    assert.equal(adds.length, ADOPT.perPublisher);
    await n.stop();
    n = await local({ home: join(root, 'n'), bootstrap: false });
    adds = recordAdds(n);
    assert.deepEqual(await n.adoptNodes(['3.3.3.3:3'], PK), [], 'budget survives restart');
    assert.equal(adds.length, 0);
    // a different publisher has its own budget
    assert.deepEqual(await n.adoptNodes(['3.3.3.3:3'], 'c'.repeat(64)), ['3.3.3.3:3']);
  } finally { await n.stop(); }
});

test('adoptNodes: at most 4 per /24 per publisher', async () => {
  const root = await mkdtemp(join(tmpdir(), 'webway-adopt3-'));
  const n = await local({ home: join(root, 'n'), bootstrap: false });
  const adds = recordAdds(n);
  try {
    const sameSubnet = Array.from({ length: 10 }, (_, i) => `4.4.4.${i + 1}:1`);
    const got = await n.adoptNodes([...sameSubnet, '5.5.5.5:5'], PK);
    assert.deepEqual(got, ['4.4.4.1:1', '4.4.4.2:1', '4.4.4.3:1', '4.4.4.4:1', '5.5.5.5:5']);
    assert.deepEqual(await n.adoptNodes(['4.4.4.200:1'], PK), [], 'subnet cap persists');
    assert.equal(adds.length, 5);
  } finally { await n.stop(); }
});

test('adoptNodes: global per-session cap of 100', async () => {
  const root = await mkdtemp(join(tmpdir(), 'webway-adopt4-'));
  const n = await local({ home: join(root, 'n'), bootstrap: false });
  const adds = recordAdds(n);
  try {
    for (let p = 0; p < 8; p++) {
      const pk = String.fromCharCode(97 + p).repeat(64);
      await n.adoptNodes(Array.from({ length: 20 }, (_, i) => `6.${p}.${i}.1:1`), pk);
    }
    assert.equal(adds.length, ADOPT.perSession);
  } finally { await n.stop(); }
});

test('adoptNodes: only public IPv4 literals unless allowPrivate; hostnames and IPv6 never', async () => {
  const root = await mkdtemp(join(tmpdir(), 'webway-adopt5-'));
  const n = await local({ home: join(root, 'n'), bootstrap: false });
  const adds = recordAdds(n);
  const p = await local({ home: join(root, 'p'), bootstrap: false, allowPrivate: true });
  const padds = recordAdds(p);
  try {
    const list = ['127.0.0.1:53', '192.168.1.1:6881', '10.0.0.1:1', '100.64.0.1:1', '169.254.1.1:1', '::ffff:127.0.0.1:1', '[::ffff:127.0.0.1]:1',
      'router.bittorrent.com:6881', 'localhost:1', '[2606:4700::1]:1', '999.1.1.1:1', '8.8.8.8:0', '8.8.8.8:8'];
    assert.deepEqual(await n.adoptNodes(list, PK), ['8.8.8.8:8']);
    assert.deepEqual(adds, ['8.8.8.8:8']);
    assert.deepEqual(await p.adoptNodes(list, PK), ['127.0.0.1:53', '192.168.1.1:6881', '10.0.0.1:1', '100.64.0.1:1', '169.254.1.1:1', '8.8.8.8:8']);
    assert.equal(padds.length, 6);
  } finally { await n.stop(); await p.stop(); }
});

test('adoptNodes: full routing table -> only never-seen addresses considered', async () => {
  const root = await mkdtemp(join(tmpdir(), 'webway-adopt6-'));
  const n = await local({ home: join(root, 'n'), bootstrap: false });
  const adds = recordAdds(n);
  try {
    assert.deepEqual(await n.adoptNodes(['7.7.7.7:7'], PK), ['7.7.7.7:7']);
    n.dht.nodes.count = () => ADOPT.tableFull;
    // already adopted this session (in-memory provenance) from a different publisher -> skipped when full
    assert.deepEqual(await n.adoptNodes(['7.7.7.7:7', '7.7.8.8:8'], 'd'.repeat(64)), ['7.7.8.8:8']);
    assert.equal(adds.length, 2);
  } finally { await n.stop(); }
});

test('adoptNodes: junk shapes are harmless and write nothing', async () => {
  const root = await mkdtemp(join(tmpdir(), 'webway-adopt7-'));
  const n = await local({ home: join(root, 'n'), bootstrap: false });
  const adds = recordAdds(n);
  try {
    for (const junk of [undefined, 'nope', 42, [null, 42, 'garbage', '1.2.3.4:0', { host: 'x', port: 1 }], []])
      assert.deepEqual(await n.adoptNodes(junk, PK), []);
    assert.deepEqual(await n.adoptNodes(['8.8.8.8:8'], 42 as any), []);
    assert.equal(adds.length, 0);
    assert.deepEqual(await n.adoptState(), {});
  } finally { await n.stop(); }
});

test('private nodes are not advertised unless allowPrivate', async () => {
  const root = await mkdtemp(join(tmpdir(), 'webway-cat3-'));
  const modelDir = join(root, 'src', 'm');
  await mkdir(modelDir, { recursive: true });
  await writeFile(join(modelDir, 'w.bin'), randomBytes(64 * 1024));
  const router = await local({ home: join(root, 'r'), bootstrap: false });
  const pub = await local({ home: join(root, 'pub'), bootstrap: [`127.0.0.1:${router.dht.address().port}`] });
  try {
    await pub.share(modelDir, 'acme/m');
    const cat = JSON.parse(await readFile(join(pub.home, 'catalog', 'catalog.json'), 'utf8'));
    assert.deepEqual(cat.nodes, []);
  } finally { await pub.stop(); await router.stop(); }
});

test('--peer (with junk and IPv6 mixed in) and remembered dht.json feed the routing table; corrupt dht.json tolerated', async () => {
  const root = await mkdtemp(join(tmpdir(), 'webway-cat4-'));
  const router = await local({ home: join(root, 'r'), bootstrap: false });
  const port = router.dht.address().port;
  const a = await local({ home: join(root, 'a'), bootstrap: [], peers: [`127.0.0.1:${port}`, 'junk', '1.2.3.4:0', '[::1]:6881', '999.9.9.9:1'] });
  try {
    assert.equal(await waitFor(() => knows(a, port)), true, 'peer adopted');
    await a.stop(); // persists dht.json
    // corrupt the cache with entries the review flagged, keep the good one
    const saved = JSON.parse(await readFile(join(root, 'a', 'dht.json'), 'utf8'));
    saved.nodes = [{ host: '127.0.0.1:0', port: 6881 }, { host: '', port: 1 }, { host: '999.1.1.1', port: 1 }, null, 'str', ...saved.nodes];
    await writeFile(join(root, 'a', 'dht.json'), JSON.stringify(saved));
    const a2 = await local({ home: join(root, 'a'), bootstrap: [] });
    try {
      assert.equal(await waitFor(() => knows(a2, port)), true, 'remembered node reused');
    } finally { await a2.stop(); }
    await writeFile(join(root, 'a', 'dht.json'), '{not json');
    const a3 = await local({ home: join(root, 'a'), bootstrap: [] });
    await a3.stop();
  } finally { await a.stop().catch(() => {}); await router.stop(); }
});

test('startup does not wait on DNS: hanging resolver + live explicit peer starts promptly; seeds added when they arrive', async () => {
  const root = await mkdtemp(join(tmpdir(), 'webway-dns-'));
  const router = await local({ home: join(root, 'r'), bootstrap: false });
  const port = router.dht.address().port;
  const hermit = await local({ home: join(root, 'h'), bootstrap: false });
  const hermitPort = hermit.dht.address().port;
  let cancelled = 0;
  let release!: (v: string[][]) => void;
  const resolver = {
    resolveTxt: (h: string) => new Promise<string[][]>((res) => { if (h === '_webway-seeds.hang.org') return; release = res; }),
    cancel: () => { cancelled++; },
  };
  const t0 = Date.now();
  const n = await new WebwayNode({ home: join(root, 'n'), bootstrap: [], peers: [`127.0.0.1:${port}`], nat: false, allowPrivate: true,
    dns: ['hang.org', 'slow.org'], dnsResolver: resolver, dnsTimeoutMs: 1500 }).start();
  try {
    assert.ok(Date.now() - t0 < 1400, `start() returned in ${Date.now() - t0}ms, before the DNS timeout`);
    assert.equal(await waitFor(() => knows(n, port)), true, 'explicit peer live before DNS resolves');
    assert.equal(knows(n, hermitPort), false);
    release([[`127.0.0.1:${hermitPort}`]]); // slow.org answers now
    const seeds = await n.dnsReady;
    assert.deepEqual(seeds, [`127.0.0.1:${hermitPort}`]);
    assert.equal(await waitFor(() => knows(n, hermitPort)), true, 'DNS seed added on arrival');
    assert.ok(cancelled >= 1, 'hung query was cancelled');
  } finally { await n.stop(); await hermit.stop(); await router.stop(); }
});

test('stop() cancels an in-flight DNS query and settles dnsReady promptly (timers cleared), even if the resolver ignores cancel', async () => {
  const root = await mkdtemp(join(tmpdir(), 'webway-dns2-'));
  let cancelled = 0;
  const resolver = { resolveTxt: () => new Promise<string[][]>(() => {}), cancel: () => { cancelled++; } };
  const n = await new WebwayNode({ home: join(root, 'n'), bootstrap: [], nat: false, dns: ['x.org'], dnsResolver: resolver, dnsTimeoutMs: 60_000 }).start();
  const t0 = Date.now();
  await n.stop();
  assert.ok(cancelled >= 1);
  assert.deepEqual(await n.dnsReady, []);
  assert.ok(Date.now() - t0 < 1000, 'settled on abort, not on the 60s timer');
  // the same with the DEFAULT (owned) resolver: stop() must reach it. Use an unresolvable name so the
  // query is genuinely in flight; cancel() rejects it with ECANCELLED and the wrapper settles.
  const m = await new WebwayNode({ home: join(root, 'm'), bootstrap: [], nat: false, dns: ['hang.invalid'], dnsTimeoutMs: 60_000 }).start();
  const t1 = Date.now();
  await m.stop();
  assert.deepEqual(await m.dnsReady, []);
  assert.ok(Date.now() - t1 < 2000, 'owned resolver query cancelled by stop()');
  const timeouts = (process as any).getActiveResourcesInfo().filter((r: string) => r === 'Timeout');
  assert.ok(timeouts.length <= 2, `no lingering DNS timers: ${timeouts.length}`); // test runner's own timers at most
});

test('no DNS seeds are admitted once stop() has begun', async () => {
  const root = await mkdtemp(join(tmpdir(), 'webway-dns3-'));
  let release!: (v: string[][]) => void;
  const resolver = { resolveTxt: () => new Promise<string[][]>((res) => { release = res; }), cancel() {} };
  const n = await new WebwayNode({ home: join(root, 'n'), bootstrap: [], nat: false, dns: ['x.org'], dnsResolver: resolver, dnsTimeoutMs: 60_000 }).start();
  const adds = recordAdds(n);
  const stopping = n.stop();
  release([['8.8.8.8:8']]);
  await stopping;
  assert.deepEqual(await n.dnsReady, []);
  assert.deepEqual(adds, []);
  assert.equal(n.dnsCandidates.size, 0);
});

test('DNS seeds are retryable: a seed that fails its first ping is re-pinged and then populates the table', async () => {
  const root = await mkdtemp(join(tmpdir(), 'webway-dns4-'));
  const port = await freeUdpPort();
  const resolver = { resolveTxt: async () => [[`127.0.0.1:${port}`]], cancel() {} };
  const n = await new WebwayNode({ home: join(root, 'n'), bootstrap: [], nat: false, allowPrivate: true, dns: ['x.org'], dnsResolver: resolver, dnsRetryMs: 400 }).start();
  let seed: WebwayNode | undefined;
  try {
    await n.dnsReady;
    assert.ok(n.dnsCandidates.has(`127.0.0.1:${port}`), 'seed retained as candidate');
    await new Promise((r) => setTimeout(r, 300));
    assert.equal(n.dht.nodes.count(), 0, 'first ping failed: nothing listening');
    seed = await local({ home: join(root, 'seed'), bootstrap: false, dhtPort: port });
    assert.equal(await waitFor(() => knows(n, port), 4000), true, 'retry ping succeeded');
    assert.ok(n.dnsRetries >= 1 && n.dnsRetries <= 5, `retries bounded: ${n.dnsRetries}`);
    const before = n.dnsRetries;
    await new Promise((r) => setTimeout(r, 900));
    assert.equal(n.dnsRetries, before, 'retrying stops once the table is populated');
  } finally { await n.stop(); await seed?.stop(); }
});

test('startup pings only the capped bootstrap list: 130 --peer values -> at most 128 pinged', async () => {
  const root = await mkdtemp(join(tmpdir(), 'webway-peers-'));
  const peers = Array.from({ length: 130 }, (_, i) => `127.0.0.1:${40000 + i}`); // closed loopback ports: harmless
  const n = await new WebwayNode({ home: join(root, 'n'), bootstrap: [], peers, nat: false, dns: false }).start();
  try {
    assert.equal(n.startupPeers.length, 128);
    assert.deepEqual(n.startupPeers, peers.slice(0, 128));
  } finally { await n.stop(); }
});

test('delayed TXT arrival still starts the retry loop', async () => {
  const root = await mkdtemp(join(tmpdir(), 'webway-dns6-'));
  const port = await freeUdpPort();
  let release!: (v: string[][]) => void;
  const resolver = { resolveTxt: () => new Promise<string[][]>((res) => { release = res; }), cancel() {} };
  const n = await new WebwayNode({ home: join(root, 'n'), bootstrap: [], nat: false, allowPrivate: true, dns: ['x.org'], dnsResolver: resolver, dnsRetryMs: 200, dnsTimeoutMs: 10_000 }).start();
  try {
    assert.equal(n.dnsCandidates.size, 0, 'nothing has arrived yet');
    await new Promise((r) => setTimeout(r, 300));
    assert.equal(n.dnsRetries, 0, 'no loop without candidates');
    release([[`127.0.0.1:${port}`]]);
    await n.dnsReady;
    assert.equal(n.dnsCandidates.size, 1);
    await new Promise((r) => setTimeout(r, 700));
    assert.ok(n.dnsRetries >= 1, `retries started after late arrival: ${n.dnsRetries}`);
  } finally { await n.stop(); }
});

test('an initially successful seed ping triggers exactly one first-contact lookup', async () => {
  const root = await mkdtemp(join(tmpdir(), 'webway-dns7-'));
  const seed = await local({ home: join(root, 'seed'), bootstrap: false });
  const port = seed.dht.address().port;
  const resolver = { resolveTxt: async () => [[`127.0.0.1:${port}`]], cancel() {} };
  const n = await new WebwayNode({ home: join(root, 'n'), bootstrap: [], nat: false, allowPrivate: true, dns: ['x.org'], dnsResolver: resolver, dnsRetryMs: 200 }).start();
  try {
    assert.equal(await waitFor(() => knows(n, port)), true);
    assert.equal(await waitFor(() => n.dnsLookups === 1), true, 'lookup ran on first contact');
    await new Promise((r) => setTimeout(r, 700));
    assert.equal(n.dnsLookups, 1, 'exactly one');
    assert.equal(n.dnsRetries, 0, 'no retries when the first ping succeeded');
    // isolation later: drop every contact, notice it, and a new retry episode begins with a fresh lookup arm
    n.checkIsolation(); // (normally on the 60s persist tick) while populated: records "was populated", resets retry budget
    for (const x of n.dht.nodes.toArray()) n.dht.removeNode(x.id);
    assert.equal(n.dht.nodes.count(), 0);
    n.checkIsolation(); // now empty-after-populated -> new episode
    assert.equal(await waitFor(() => n.dnsRetries >= 1, 3000), true, 'retry episode restarted after isolation');
    assert.equal(await waitFor(() => n.dnsLookups === 2, 3000), true, 'seed answered again -> second lookup');
  } finally { await n.stop(); await seed.stop(); }
});

test('DNS retry is bounded at 5 when seeds never answer', async () => {
  const root = await mkdtemp(join(tmpdir(), 'webway-dns5-'));
  const port = await freeUdpPort();
  const resolver = { resolveTxt: async () => [[`127.0.0.1:${port}`]], cancel() {} };
  const n = await new WebwayNode({ home: join(root, 'n'), bootstrap: [], nat: false, allowPrivate: true, dns: ['x.org'], dnsResolver: resolver, dnsRetryMs: 100 }).start();
  try {
    await n.dnsReady;
    await new Promise((r) => setTimeout(r, 1200));
    assert.equal(n.dnsRetries, 5);
    assert.equal(n.dht.nodes.count(), 0);
  } finally { await n.stop(); }
});

test('adoptNodes: 200k-entry catalog returns within a few ms and admits <= 20', async () => {
  const root = await mkdtemp(join(tmpdir(), 'webway-perf-'));
  const n = await local({ home: join(root, 'n'), bootstrap: false });
  const adds = recordAdds(n);
  try {
    const huge = Array.from({ length: 200_000 }, (_, i) => `${1 + (i % 200)}.${(i >> 8) & 255}.${i & 255}.1:1`);
    const time = async (f: () => Promise<unknown>) => { const t = process.hrtime.bigint(); await f(); return Number(process.hrtime.bigint() - t) / 1e6; };
    await n.adoptNodes(['9.9.9.9:9'], 'f'.repeat(64)); // warm up fs/JIT
    // Baseline: a 20-entry read (one disk write). The 200k read must cost about the same:
    // the work is bounded by ADOPT.inspect, not by the array length (200k parses would be ~100x).
    const small = await time(() => n.adoptNodes(Array.from({ length: 20 }, (_, i) => `2.${i}.0.1:1`), '1'.repeat(64)));
    let got: string[] = [];
    const big = await time(async () => { got = await n.adoptNodes(huge, PK); });
    assert.ok(got.length <= ADOPT.perRead && got.length > 0);
    assert.equal(adds.length, got.length + 21);
    assert.ok(big < Math.max(3 * small, 30) + 30, `200k read ${big.toFixed(1)}ms vs 20-entry ${small.toFixed(1)}ms`);
    assert.ok(big < 500, `absolute bound: ${big.toFixed(1)}ms`);
    // budget exhausted publisher: still bounded, still nothing (no disk write on this path)
    const again = await time(async () => assert.deepEqual(await n.adoptNodes(huge, PK), []));
    assert.ok(again < 100, `exhausted read ${again.toFixed(1)}ms`);
    // inspection bound: a valid entry beyond the first 200 raw entries is never looked at
    const late = [...Array.from({ length: ADOPT.inspect }, () => 'junk'), '8.8.8.8:8'];
    assert.deepEqual(await n.adoptNodes(late, 'e'.repeat(64)), []);
  } finally { await n.stop(); }
});

test('adoptNodes: concurrent batches for one publisher are serialised — 20 pings, 20 persisted', async () => {
  const root = await mkdtemp(join(tmpdir(), 'webway-conc-'));
  const n = await local({ home: join(root, 'n'), bootstrap: false });
  const adds = recordAdds(n);
  try {
    const a = Array.from({ length: 20 }, (_, i) => `11.${i}.0.1:1`);
    const b = Array.from({ length: 20 }, (_, i) => `12.${i}.0.1:1`);
    const [ra, rb] = await Promise.all([n.adoptNodes(a, PK), n.adoptNodes(b, PK)]);
    assert.equal(ra.length + rb.length, 20);
    assert.equal(adds.length, 20);
    const st = (await n.adoptState())[PK];
    assert.equal(st.n, 20);
    assert.equal(st.seen.length, 20);
    // different publishers concurrently: neither erases the other's record
    const [rc, rd] = await Promise.all([n.adoptNodes(['13.0.0.1:1'], 'c'.repeat(64)), n.adoptNodes(['14.0.0.1:1'], 'd'.repeat(64))]);
    assert.deepEqual([rc, rd], [['13.0.0.1:1'], ['14.0.0.1:1']]);
    const all = await n.adoptState();
    assert.ok(all['c'.repeat(64)] && all['d'.repeat(64)] && all[PK]);
    // atomic write: no temp files left behind, file parses
    const files = (await import('node:fs/promises')).readdir(join(root, 'n'));
    assert.ok(!(await files).some((f) => f.endsWith('.tmp')));
  } finally { await n.stop(); }
});

test('adoptNodes: publisher key case variants share one budget; invalid keys are ignored', async () => {
  const root = await mkdtemp(join(tmpdir(), 'webway-case-'));
  const n = await local({ home: join(root, 'n'), bootstrap: false });
  const adds = recordAdds(n);
  try {
    const lo = 'ab'.repeat(32), up = 'AB'.repeat(32);
    assert.equal((await n.adoptNodes(Array.from({ length: 20 }, (_, i) => `21.${i}.0.1:1`), lo)).length, 20);
    assert.deepEqual(await n.adoptNodes(Array.from({ length: 20 }, (_, i) => `22.${i}.0.1:1`), up), []);
    assert.equal(adds.length, 20);
    assert.deepEqual(Object.keys(await n.adoptState()), [lo]);
    assert.deepEqual(await n.adoptNodes(['8.8.8.8:8'], 'not-a-key'), []);
    await assert.rejects(n.follow('ZZ'.repeat(32)));
    await assert.rejects(n.catalog('short'));
    await n.follow(up);
    assert.deepEqual(await n.follows(), [lo]);
    // pre-existing case-variant accounting on disk is merged on load
    await writeFile(join(root, 'n', 'dht-adopt.json'), JSON.stringify({ publishers: { [up]: { n: 19, seen: [], subnets: {} }, [lo]: { n: 1, seen: ['1.1.1.1:1'], subnets: { '1.1.1': 1 } } }, adopted: {} }));
    assert.deepEqual(await n.adoptNodes(['23.0.0.1:1'], lo), []);
  } finally { await n.stop(); }
});

test('adoption provenance survives restart: adopted node is not re-advertised after stop/start', async () => {
  const root = await mkdtemp(join(tmpdir(), 'webway-prov-'));
  const modelDir = join(root, 'src', 'm');
  await mkdir(modelDir, { recursive: true });
  await writeFile(join(modelDir, 'w.bin'), randomBytes(64 * 1024));
  const hermit = await local({ home: join(root, 'h'), bootstrap: false });
  const hPort = hermit.dht.address().port;
  const router = await local({ home: join(root, 'r'), bootstrap: false });
  const rPort = router.dht.address().port;
  let n = await local({ home: join(root, 'n'), bootstrap: [`127.0.0.1:${rPort}`], allowPrivate: true });
  try {
    assert.deepEqual(await n.adoptNodes([`127.0.0.1:${hPort}`], PK), [`127.0.0.1:${hPort}`]); // real ping
    assert.equal(await waitFor(() => knows(n, hPort)), true);
    await n.stop();
    n = await local({ home: join(root, 'n'), bootstrap: [], allowPrivate: true }); // remembered dht.json brings both back
    assert.equal(await waitFor(() => knows(n, hPort) && knows(n, rPort)), true, 'both contacts remembered');
    await n.share(modelDir, 'n/m');
    const cat = JSON.parse(await readFile(join(n.home, 'catalog', 'catalog.json'), 'utf8'));
    assert.ok(!cat.nodes.includes(`127.0.0.1:${hPort}`), `adopted node not re-advertised after restart: ${JSON.stringify(cat.nodes)}`);
    assert.ok(cat.nodes.includes(`127.0.0.1:${rPort}`), 'independently learned router still advertised');
    // age the provenance on disk -> re-advertised after the next restart
    const f = JSON.parse(await readFile(join(root, 'n', 'dht-adopt.json'), 'utf8'));
    f.adopted[`127.0.0.1:${hPort}`] = Date.now() - ADOPT.reAdvertiseAfterMs - 1000;
    await writeFile(join(root, 'n', 'dht-adopt.json'), JSON.stringify(f));
    await n.stop();
    n = await local({ home: join(root, 'n'), bootstrap: [], allowPrivate: true });
    assert.equal(await waitFor(() => knows(n, hPort)), true);
    await n.publishCatalog();
    const cat2 = JSON.parse(await readFile(join(n.home, 'catalog', 'catalog.json'), 'utf8'));
    assert.ok(cat2.nodes.includes(`127.0.0.1:${hPort}`), 'aged adoption re-advertised');
  } finally { await n.stop().catch(() => {}); await hermit.stop(); await router.stop(); }
});
