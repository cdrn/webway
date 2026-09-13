import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, mkdir, readdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { WebwayNode, parseCatalog, checkInt, type NodeOpts } from '../src/node.ts';
import { parseSearchOpts } from '../src/args.ts';

const PK = (c: string) => c.repeat(64);
const IH = (c: string) => c.repeat(40);
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function tinyModel(root: string, name: string) {
  const dir = join(root, 'src', name);
  await mkdir(dir, { recursive: true });
  await writeFile(join(dir, 'model.safetensors'), randomBytes(2048));
  return dir;
}

/** Infohash of a node's currently seeded catalog torrent (publishCatalog keeps exactly one). */
const catalogIh = (p: WebwayNode) => (p.client.torrents as { name: string; infoHash: string }[]).find((t) => t.name === 'catalog')!.infoHash;

/** Publish an arbitrary set of files as `p`'s catalog torrent and point p's signed catalog record at it. */
async function publishRaw(p: WebwayNode, files: Record<string, string | Buffer>): Promise<string> {
  const dir = join(p.home, 'raw-' + randomBytes(4).toString('hex'));
  await mkdir(dir, { recursive: true });
  for (const [f, body] of Object.entries(files)) await writeFile(join(dir, f), body);
  const t = await (p as any).seed(dir, 'catalog');
  const seq = await (p as any).nextSeq('catalog');
  await (p as any).put('catalog', { ih: Buffer.from(t.infoHash, 'hex') }, seq);
  return t.infoHash;
}

async function cluster(names: string[], extra: NodeOpts = {}) {
  const root = await mkdtemp(join(tmpdir(), 'webway-hard-'));
  const router = await new WebwayNode({ home: join(root, 'router'), bootstrap: false, nat: false }).start();
  const boot = [`127.0.0.1:${router.dht.address().port}`];
  const nodes = await Promise.all(names.map((n) => new WebwayNode({ home: join(root, n), bootstrap: boot, nat: false, ...extra }).start()));
  const fresh = (n: string, o: NodeOpts = {}) => new WebwayNode({ home: join(root, n), bootstrap: boot, nat: false, ...extra, ...o }).start();
  const stopAll = async (more: WebwayNode[] = []) => Promise.all([router, ...nodes, ...more].map((n) => n.stop().catch(() => {})));
  return { root, router, nodes, fresh, stopAll };
}

// ---- 1. deadlines -----------------------------------------------------------

test('a catalog with a record but no seeders costs one bounded timeout, not the whole search', async () => {
  // 5 s per-catalog budget: under full-suite load a live catalog fetch (DHT get + metadata + download)
  // can exceed 2 s; the property is that the dead one costs ONE budget, not the 120 s search default.
  const { root, router, nodes: [p, q], fresh, stopAll } = await cluster(['p', 'q'], { catalogTimeoutMs: 5000 });
  const extra: WebwayNode[] = [];
  try {
    const ps = await p.share(await tinyModel(root, 'pm'), 'p/model');
    await q.share(await tinyModel(root, 'qm'), 'q/model');
    const pCatalogIh = catalogIh(p);
    // the only seeder of p's catalog goes away; p's DHT node and the signed record stay
    const seed = await (p.client as any).get(pCatalogIh);
    await new Promise<void>((r) => seed.destroy({}, () => r()));
    assert.ok(router.dht._values.get(WebwayNode.targetFor(p.pk, 'catalog').toString('hex')), 'record still present');

    const alice = await fresh('alice'); extra.push(alice); // cold reader: nothing cached
    await alice.follow(p.pk); await alice.follow(q.pk);
    const t0 = Date.now();
    const hits = await alice.search('model');
    const elapsed = Date.now() - t0;
    assert.deepEqual(hits.map((h) => h.name), ['q/model']);
    assert.ok(elapsed < 15000, `search took ${elapsed}ms`);
    assert.equal(hits.find((h) => h.name === 'p/model'), undefined);
    assert.ok(ps.ih);
    // the timed-out download was cleaned up: no torrent left behind for it
    await sleep(300);
    assert.equal(await (alice.client as any).get(pCatalogIh), null);
    // catalogFull on the dead publisher returns empty within the bound
    const t1 = Date.now();
    assert.deepEqual(await alice.catalogFull(p.pk, 800), { entries: [], endorse: [] });
    assert.ok(Date.now() - t1 < 2500);
  } finally { await stopAll(extra); }
});

test('overall search deadline stops the walk', async () => {
  const { root, nodes: [p], fresh, stopAll } = await cluster(['p']);
  const extra: WebwayNode[] = [];
  try {
    await p.share(await tinyModel(root, 'pm'), 'p/model');
    const alice = await fresh('alice', { searchTimeoutMs: 0 }); extra.push(alice);
    await alice.follow(p.pk);
    assert.deepEqual(await alice.search('model'), []);
    assert.equal(alice.catalogFetches, 0);
  } finally { await stopAll(extra); }
});

// ---- 2. validation ----------------------------------------------------------

test('parseCatalog keeps good entries and drops every malformed shape', () => {
  const pk = PK('a');
  const good = { name: 'org/good', ih: IH('b'), size: 5 };
  const j = {
    entries: [
      null, 42, 'str', [], { name: 42 }, { name: 'no-ih', size: 1 }, { name: 'bad-ih', ih: 'zz', size: 1 },
      { name: '', ih: IH('c'), size: 1 }, { name: 'neg', ih: IH('c'), size: -1 }, { name: 'nan', ih: IH('c'), size: NaN },
      { name: 'inf', ih: IH('c'), size: Infinity }, { name: 'strsize', ih: IH('c'), size: '5' }, { name: 'lic', ih: IH('c'), size: 1, license: 7 },
      good, { name: 'upper', ih: IH('B'), size: 0, license: 'mit' }, { name: 'x'.repeat(513), ih: IH('d'), size: 1 },
    ],
    endorse: [null, 1, 'short', pk, PK('e'), PK('E'), PK('f')],
  };
  const c = parseCatalog(JSON.stringify(j), pk);
  assert.deepEqual(c.entries, [good, { name: 'upper', ih: IH('b'), size: 0, license: 'mit' }]);
  assert.deepEqual(c.endorse, [PK('e'), PK('f')]);
  for (const bad of ['not json', '[1,2]', 'null', '"s"', '{}', '{"entries":null,"endorse":"x"}', '{"entries":{}}']) {
    assert.deepEqual(parseCatalog(bad, pk), { entries: [], endorse: [] }, bad);
  }
});

test('parseCatalog caps entries and endorsements', () => {
  const entries = Array.from({ length: WebwayNode.CATALOG_MAX_ENTRIES + 50 }, (_, i) => ({ name: `m${i}`, ih: IH('a'), size: i }));
  const endorse = Array.from({ length: WebwayNode.CATALOG_MAX_ENDORSE + 50 }, (_, i) => i.toString(16).padStart(64, '0'));
  const c = parseCatalog(JSON.stringify({ entries, endorse }), PK('f'));
  assert.equal(c.entries.length, WebwayNode.CATALOG_MAX_ENTRIES);
  assert.equal(c.endorse.length, WebwayNode.CATALOG_MAX_ENDORSE);
});

test('malformed entries mixed with valid ones do not abort a live search', async () => {
  const { root, nodes: [p, q], fresh, stopAll } = await cluster(['p', 'q']);
  const extra: WebwayNode[] = [];
  try {
    const qs = await q.share(await tinyModel(root, 'qm'), 'q/model');
    await publishRaw(p, { 'catalog.json': JSON.stringify({ entries: [null, { name: 42 }, { name: 'p/missing-ih', size: 1 }, { name: 'p/model', ih: IH('9'), size: 3 }], endorse: [q.pk, 'junk'] }) });
    const alice = await fresh('alice'); extra.push(alice);
    await alice.follow(p.pk);
    const hits = await alice.search('model');
    assert.deepEqual(hits.map((h) => [h.name, h.hops]), [['p/model', 0], ['q/model', 1]]);
    assert.equal(hits[1].ih, qs.ih);
  } finally { await stopAll(extra); }
});

// ---- 3. resource bounds -----------------------------------------------------

test('oversized catalog torrents are refused before download and not retained', async () => {
  const { nodes: [p], fresh, stopAll } = await cluster(['p']);
  const extra: WebwayNode[] = [];
  try {
    const ih = await publishRaw(p, { 'catalog.json': JSON.stringify({ entries: [{ name: 'p/m', ih: IH('1'), size: 1 }] }), 'blob.bin': randomBytes(WebwayNode.CATALOG_MAX_BYTES + 4096) });
    const alice = await fresh('alice'); extra.push(alice);
    assert.deepEqual(await alice.catalogFull(p.pk), { entries: [], endorse: [] });
    assert.equal(alice.catalogRefused, 1);
    await sleep(300);
    assert.equal(await (alice.client as any).get(ih), null, 'refused torrent destroyed');
    assert.deepEqual(await alice.search('m'), []);
  } finally { await stopAll(extra); }
});

test('fan-out is bounded by maxPublishers and the queue is deduplicated', async () => {
  const { root, nodes: [p1, p2, x1, x2, x3], fresh, stopAll } = await cluster(['p1', 'p2', 'x1', 'x2', 'x3']);
  const extra: WebwayNode[] = [];
  try {
    const xs = [x1, x2, x3];
    for (const [i, x] of xs.entries()) await x.share(await tinyModel(root, `x${i}`), `x${i}/model`);
    // both p1 and p2 endorse the same three real publishers plus a large tail of unreachable keys
    const tail = Array.from({ length: 2000 }, (_, i) => (i + 1).toString(16).padStart(64, '0'));
    for (const p of [p1, p2]) await publishRaw(p, { 'catalog.json': JSON.stringify({ entries: [], endorse: [...xs.map((x) => x.pk), ...tail] }) });

    const alice = await fresh('alice', { catalogTimeoutMs: 5000 }); extra.push(alice);
    let calls = 0;
    const real = alice.catalogFull.bind(alice);
    alice.catalogFull = (pk, d) => { calls++; return real(pk, d); };
    await alice.follow(p1.pk); await alice.follow(p2.pk);

    // depth 0 / max 1: exactly one publisher visited, endorsements never expanded
    calls = 0; assert.deepEqual(await alice.search('model', { depth: 0, maxPublishers: 1 }), []); assert.equal(calls, 1);
    // depth 0: both followed, no expansion
    calls = 0; assert.deepEqual(await alice.search('model', { depth: 0 }), []); assert.equal(calls, 2);
    // overlapping fan-out at depth 1: x1..x3 visited once each despite being endorsed twice; endorse list capped at 100
    calls = 0;
    const hits = await alice.search('model', { depth: 1, maxPublishers: 5 });
    assert.deepEqual(hits.map((h) => h.name).sort(), ['x0/model', 'x1/model', 'x2/model']);
    assert.equal(calls, 5); // p1, p2, x1, x2, x3 -- budget of 5 spent, tail never queued
    assert.equal(alice.catalogFetches, 5);
    // budget larger than reachable graph: still each publisher at most once, capped by endorse cap (100 per catalog)
    calls = 0;
    await alice.search('model', { depth: 1, maxPublishers: 20 });
    assert.ok(calls <= 20, `visited ${calls}`);
    assert.equal(alice.catalogFetches, 5, 'unreachable keys cost DHT lookups, never downloads');
  } finally { await stopAll(extra); }
});

test('results are capped at SEARCH_MAX_RESULTS', async () => {
  const { nodes: [p], fresh, stopAll } = await cluster(['p']);
  const extra: WebwayNode[] = [];
  try {
    const entries = Array.from({ length: WebwayNode.SEARCH_MAX_RESULTS + 200 }, (_, i) => ({ name: `p/m${i}`, ih: i.toString(16).padStart(40, '0'), size: 1 }));
    await publishRaw(p, { 'catalog.json': JSON.stringify({ entries }) });
    const alice = await fresh('alice'); extra.push(alice);
    await alice.follow(p.pk);
    assert.equal((await alice.search('m')).length, WebwayNode.SEARCH_MAX_RESULTS);
  } finally { await stopAll(extra); }
});

// ---- 4. isolation by pk + infohash -----------------------------------------

test('a replacement catalog torrent without catalog.json yields no stale entries', async () => {
  const { root, nodes: [p], fresh, stopAll } = await cluster(['p']);
  const extra: WebwayNode[] = [];
  try {
    await p.follow(PK('c'));
    await p.share(await tinyModel(root, 'pm'), 'p/model');
    const alice = await fresh('alice'); extra.push(alice);
    const a = await alice.catalogFull(p.pk);
    assert.equal(a.entries.length, 1); assert.deepEqual(a.endorse, [PK('c')]);
    await publishRaw(p, { 'other.txt': 'nothing to see' });
    assert.deepEqual(await alice.catalogFull(p.pk), { entries: [], endorse: [] });
    assert.deepEqual(await alice.search('model'), []);
    // downloads live under catalogs/<pk>/<ih>; the superseded one was retired (off the critical path)
    await alice.lifecycleIdle();
    const dirs = await readdir(join(alice.home, 'catalogs', p.pk));
    assert.equal(dirs.length, 1);
    assert.match(dirs[0], /^[0-9a-f]{40}$/);
  } finally { await stopAll(extra); }
});

// ---- 5. option validation ---------------------------------------------------

test('search rejects invalid numeric options at the API boundary', async () => {
  const { nodes: [n], stopAll } = await cluster(['n']);
  try {
    for (const bad of [-1, 1.5, NaN, Infinity, -Infinity, WebwayNode.SEARCH_MAX_DEPTH + 1, '2', null, 2 ** 53]) {
      await assert.rejects(n.search('x', { depth: bad as any }), RangeError, `depth ${String(bad)}`);
    }
    for (const bad of [-1, 0.5, NaN, Infinity, WebwayNode.SEARCH_MAX_PUBLISHERS + 1, '5', true]) {
      await assert.rejects(n.search('x', { maxPublishers: bad as any }), RangeError, `maxPublishers ${String(bad)}`);
    }
    assert.deepEqual(await n.search('x', { depth: 0, maxPublishers: 0 }), []);
    assert.deepEqual(await n.search('x', { depth: WebwayNode.SEARCH_MAX_DEPTH, maxPublishers: WebwayNode.SEARCH_MAX_PUBLISHERS }), []);
    assert.equal(checkInt('k', 3, 5), 3);
    assert.throws(() => checkInt('k', 6, 5), RangeError);
  } finally { await stopAll(); }
});

test('CLI search flags are validated before a node starts', () => {
  assert.deepEqual(parseSearchOpts({}), {});
  assert.deepEqual(parseSearchOpts({ depth: ['3'], max: ['10'] }), { depth: 3, maxPublishers: 10 });
  assert.deepEqual(parseSearchOpts({ depth: ['0'] }), { depth: 0 });
  for (const bad of ['true' /* missing value */, 'garbage', '1.5', 'Infinity', '-1', 'NaN', '', ' 2', '2 ', '0x2', '1e2', '99999999999']) {
    assert.throws(() => parseSearchOpts({ depth: [bad] }), RangeError, `depth ${JSON.stringify(bad)}`);
    assert.throws(() => parseSearchOpts({ max: [bad] }), RangeError, `max ${JSON.stringify(bad)}`);
  }
  assert.throws(() => parseSearchOpts({ depth: [String(WebwayNode.SEARCH_MAX_DEPTH + 1)] }), RangeError);
  assert.throws(() => parseSearchOpts({ max: [String(WebwayNode.SEARCH_MAX_PUBLISHERS + 1)] }), RangeError);
});

// ---- 6. torrent reuse -------------------------------------------------------

test('catalog loads reuse existing torrents and coalesce concurrent calls', async () => {
  const { root, nodes: [p, q], fresh, stopAll } = await cluster(['p', 'q']);
  const extra: WebwayNode[] = [];
  try {
    const ps = await p.share(await tinyModel(root, 'pm'), 'p/model');
    const ih = catalogIh(p);
    // q's record points at p's catalog torrent
    const seq = await (q as any).nextSeq('catalog');
    await (q as any).put('catalog', { ih: Buffer.from(ih, 'hex') }, seq);

    // pre-seeded locally: p reading its own catalog must not destroy its own seed
    const own = await p.catalogFull(p.pk);
    assert.equal(own.entries[0].ih, ps.ih);
    assert.equal(p.catalogFetches, 0);
    assert.ok(await (p.client as any).get(ih), 'own catalog torrent still seeded');

    const alice = await fresh('alice'); extra.push(alice);
    const a1 = await alice.catalogFull(p.pk);
    assert.equal(a1.entries[0].ih, ps.ih);
    assert.equal(alice.catalogFetches, 1);
    const a2 = await alice.catalogFull(q.pk); // same infohash: reused, not re-downloaded, not destroyed
    assert.deepEqual(a2.entries, a1.entries);
    assert.equal(alice.catalogFetches, 1);
    assert.ok(await (alice.client as any).get(ih), 'shared torrent still present');

    const bob = await fresh('bob'); extra.push(bob);
    const rs = await Promise.all([bob.catalogFull(p.pk), bob.catalogFull(p.pk), bob.catalogFull(q.pk)]);
    for (const r of rs) assert.equal(r.entries[0].ih, ps.ih);
    assert.equal(bob.catalogFetches, 1);
    assert.equal(bob.client.torrents.filter((t) => t.infoHash === ih).length, 1);
  } finally { await stopAll(extra); }
});

// ---- 7. retention -----------------------------------------------------------

test('superseded catalog torrents are retired and the cache is bounded', async () => {
  const { root, nodes: [p], fresh, stopAll } = await cluster(['p']);
  const extra: WebwayNode[] = [];
  try {
    const alice = await fresh('alice', { catalogCacheMax: 3 }); extra.push(alice);
    const ihs: string[] = [];
    for (let i = 0; i < 6; i++) {
      await p.share(await tinyModel(root, `v${i}`), `p/v${i}`);
      const c = await alice.catalogFull(p.pk);
      assert.equal(c.entries.length, i + 1);
      ihs.push(catalogIh(p));
      await alice.lifecycleIdle();
      assert.ok(alice.catalogCacheSize <= 3, `cache ${alice.catalogCacheSize}`);
      assert.equal(alice.client.torrents.filter((t) => ihs.includes(t.infoHash)).length, 1, 'only the current catalog torrent is kept');
    }
    assert.equal(alice.catalogFetches, 6);
    assert.equal(new Set(ihs).size, 6);
    assert.deepEqual(await readdir(join(alice.home, 'catalogs', p.pk)), [ihs[5]]);
    // LRU: touching the current one keeps it; the eldest go first
    assert.equal(alice.catalogCacheSize, 3);
  } finally { await stopAll(extra); }
});
