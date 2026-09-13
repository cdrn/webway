import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, mkdir, readdir, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { WebwayNode, parseCatalog, type NodeOpts } from '../src/node.ts';
import { generate, sign, type Keypair } from '../src/keys.ts';

const IH = (c: string) => c.repeat(40);
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const stalled = () => randomBytes(20).toString('hex'); // an infohash nobody seeds
async function waitUntil(cond: () => boolean, what: string, ms = 3000) {
  const t0 = Date.now();
  while (!cond()) { if (Date.now() - t0 > ms) throw new Error(`timed out waiting for ${what}`); await sleep(10); }
}

async function tinyModel(root: string, name: string) {
  const dir = join(root, 'src', name);
  await mkdir(dir, { recursive: true });
  await writeFile(join(dir, 'model.safetensors'), randomBytes(2048));
  return dir;
}

const catalogIh = (p: WebwayNode) => (p.client.torrents as { name: string; infoHash: string }[]).find((t) => t.name === 'catalog')!.infoHash;

/** Seed `files` as a catalog torrent from node `p`; return its infohash (no record is written). */
async function seedRaw(p: WebwayNode, files: Record<string, string | Buffer>): Promise<string> {
  const dir = join(p.home, 'raw-' + randomBytes(4).toString('hex'));
  await mkdir(dir, { recursive: true });
  for (const [f, body] of Object.entries(files)) await writeFile(join(dir, f), body);
  return (await (p as any).seed(dir, 'catalog')).infoHash;
}

/** Point `p`'s own signed catalog record at `ih`. */
async function pointOwn(p: WebwayNode, ih: string) {
  await (p as any).put('catalog', { ih: Buffer.from(ih, 'hex') }, await (p as any).nextSeq('catalog'));
}

/** Point a catalog record signed by an arbitrary keypair at `ih`, using `p`'s DHT node. */
function pointAs(p: WebwayNode, kp: Keypair, ih: string, seq = Math.floor(Date.now() / 1000)): Promise<string> {
  return new Promise((resolve, reject) => {
    p.dht.put({ k: kp.pk, salt: Buffer.from('catalog'), seq, v: { ih: Buffer.from(ih, 'hex') }, sign: (b: Buffer) => sign(kp, b) },
      (err: Error | null) => (err ? reject(err) : resolve(kp.pk.toString('hex'))));
  });
}

async function cluster(names: string[], extra: NodeOpts = {}) {
  const root = await mkdtemp(join(tmpdir(), 'webway-life-'));
  const router = await new WebwayNode({ home: join(root, 'router'), bootstrap: false, nat: false }).start();
  const boot = [`127.0.0.1:${router.dht.address().port}`];
  const nodes = await Promise.all(names.map((n) => new WebwayNode({ home: join(root, n), bootstrap: boot, nat: false, ...extra }).start()));
  const fresh = (n: string, o: NodeOpts = {}) => new WebwayNode({ home: join(root, n), bootstrap: boot, nat: false, ...extra, ...o }).start();
  const extras: WebwayNode[] = [];
  const stopAll = async () => Promise.all([router, ...nodes, ...extras].map((n) => n.stop().catch(() => {})));
  return { root, router, nodes, fresh: async (n: string, o: NodeOpts = {}) => { const x = await fresh(n, o); extras.push(x); return x; }, stopAll };
}

const alive = async (n: WebwayNode, ih: string) => !!(await (n.client as any).get(ih));
const exists = (p: string) => stat(p).then(() => true, () => false);
const refs = (n: WebwayNode) => (n as any).refs as Map<string, { owned: boolean; readers: number; retainedBy: Set<string>; torrent: any; dir?: string }>;

// ---- A. one ownership record per infohash ----------------------------------

test('A1: two publishers sharing one catalog torrent; one updates, the other keeps it alive', async () => {
  const { root, nodes: [p, q], fresh, stopAll } = await cluster(['p', 'q']);
  try {
    await p.share(await tinyModel(root, 'pm'), 'p/model');
    const X = catalogIh(p);
    await pointOwn(q, X);
    const alice = await fresh('alice');
    assert.equal((await alice.catalogFull(p.pk)).entries.length, 1);
    assert.equal((await alice.catalogFull(q.pk)).entries.length, 1);
    assert.equal(alice.catalogFetches, 1);
    assert.deepEqual([...refs(alice).get(X)!.retainedBy].sort(), [p.pk, q.pk].sort());

    // q moves to Y: X is still p's current catalog and must survive
    const Y = await seedRaw(q, { 'catalog.json': JSON.stringify({ entries: [{ name: 'q/other', ih: IH('7'), size: 1 }] }) });
    await pointOwn(q, Y);
    assert.equal((await alice.catalogFull(q.pk)).entries[0].name, 'q/other');
    await alice.lifecycleIdle();
    assert.ok(await alive(alice, X), 'X still alive for p');
    assert.ok(await alive(alice, Y));
    assert.deepEqual([...refs(alice).get(X)!.retainedBy], [p.pk]);
    assert.equal(alice.catalogTorrentCount, 2);

    // p moves too: now nobody retains X and it goes, with its directory
    const xDir = refs(alice).get(X)!.dir!;
    await p.share(await tinyModel(root, 'pm2'), 'p/model-2');
    assert.equal((await alice.catalogFull(p.pk)).entries.length, 2);
    await alice.lifecycleIdle();
    assert.equal(await alive(alice, X), false, 'X destroyed once unreferenced');
    assert.equal(await exists(xDir), false, 'X dir removed');
    assert.equal(refs(alice).has(X), false);
    assert.equal(alice.catalogTorrentCount, 2);
    assert.deepEqual(alice.lifecycleErrors, []);
  } finally { await stopAll(); }
});

test('A2: two publishers sharing one stalled torrent; the short-deadline caller leaving does not kill the other load', async () => {
  const { nodes: [p, q], fresh, stopAll } = await cluster(['p', 'q']);
  try {
    const S = stalled();
    await pointOwn(p, S); await pointOwn(q, S);
    const alice = await fresh('alice');
    const long = alice.catalogFull(p.pk, 2500);
    await waitUntil(() => refs(alice).get(S)?.readers === 1, 'p acquires S'); // DHT lookup + acquire, timing varies under load
    const t0 = Date.now();
    assert.deepEqual(await alice.catalogFull(q.pk, 300), { entries: [], endorse: [] });
    // 300 ms deadline; a caller wrongly joined to p's 2500 ms load would take ~2500 ms. 2000 still distinguishes under load.
    assert.ok(Date.now() - t0 < 2000, `short caller took ${Date.now() - t0}ms`);
    await alice.lifecycleIdle();
    assert.ok(await alive(alice, S), 'S still alive: p is still waiting on it');
    assert.equal(refs(alice).get(S)?.readers, 1);
    assert.equal(refs(alice).get(S)?.owned, true);
    assert.deepEqual(await long, { entries: [], endorse: [] });
    await alice.lifecycleIdle();
    assert.equal(await alive(alice, S), false, 'S destroyed once its last reader timed out');
    assert.equal(await exists(join(alice.home, 'catalogs', p.pk, S)), false);
    assert.equal(refs(alice).has(S), false);
    assert.deepEqual(alice.lifecycleErrors, []);
  } finally { await stopAll(); }
});

test('A3: retirement destroys the stored object only; an external reseed of the same hash survives', async () => {
  const { root, nodes: [p], fresh, stopAll } = await cluster(['p']);
  try {
    await p.share(await tinyModel(root, 'pm'), 'p/model');
    const X = catalogIh(p);
    const alice = await fresh('alice');
    await alice.catalogFull(p.pk);
    const ref = refs(alice).get(X)!;
    assert.equal(ref.owned, true);
    // something else tears our torrent down and re-adds the same hash elsewhere (e.g. a model download)
    await new Promise<void>((r) => ref.torrent.destroy({}, () => r()));
    const otherDir = join(root, 'elsewhere'); await mkdir(otherDir, { recursive: true });
    const replacement = alice.client.add(X, { path: otherDir, announce: [] } as any);
    await new Promise<void>((r) => replacement.once('done', () => r()));
    // p updates -> X is retired: the replacement must not be touched
    await p.share(await tinyModel(root, 'pm2'), 'p/model-2');
    assert.equal((await alice.catalogFull(p.pk)).entries.length, 2);
    await alice.lifecycleIdle();
    const now = await (alice.client as any).get(X);
    assert.ok(now, 'replacement still present');
    assert.equal(now, replacement);
    assert.equal(now.destroyed, false);
    assert.ok(await exists(join(otherDir, 'catalog', 'catalog.json')), 'replacement files intact');
    assert.deepEqual(alice.lifecycleErrors, []);
  } finally { await stopAll(); }
});

// ---- B. per-caller deadlines ----------------------------------------------

test('B: a short-deadline caller joining a long in-flight load leaves at its own deadline', async () => {
  const { nodes: [p], fresh, stopAll } = await cluster(['p']);
  try {
    const S = stalled();
    await pointOwn(p, S);
    const alice = await fresh('alice');
    const long = alice.catalogFull(p.pk, 2000); // 2s budget, will stall on metadata
    await waitUntil(() => refs(alice).get(S)?.readers === 1, 'p acquires S');
    const t0 = Date.now();
    assert.deepEqual(await alice.catalogFull(p.pk, 30), { entries: [], endorse: [] }); // same pk/ih key: coalesced
    const elapsed = Date.now() - t0;
    // 30 ms deadline vs a 2000 ms shared load: anything under ~600 ms proves it left on its own deadline.
    assert.ok(elapsed < 600, `short caller took ${elapsed}ms`);
    // the shared load is still running for the long caller
    assert.equal(refs(alice).get(S)?.readers, 1);
    assert.ok(await alive(alice, S));
    const t1 = Date.now();
    await long;
    assert.ok(Date.now() - t1 >= 1500, 'long caller waited for its own deadline');
    await alice.lifecycleIdle();
    assert.equal(await alive(alice, S), false);
  } finally { await stopAll(); }
});

test('B: search deadline shorter than an in-flight load completes quickly', async () => {
  const { nodes: [p], fresh, stopAll } = await cluster(['p']);
  try {
    const S = stalled();
    await pointOwn(p, S);
    const alice = await fresh('alice', { searchTimeoutMs: 10 });
    await alice.follow(p.pk);
    const long = alice.catalogFull(p.pk, 1000);
    await sleep(20);
    const t0 = Date.now();
    assert.deepEqual(await alice.search('x'), []);
    // 10 ms search deadline vs a 1000 ms in-flight load: < 400 ms proves the search did not wait for the load.
    assert.ok(Date.now() - t0 < 400, `search took ${Date.now() - t0}ms, not bounded by its own deadline`);
    await long;
    await alice.lifecycleIdle();
  } finally { await stopAll(); }
});

// ---- C. abortable waits ---------------------------------------------------

test('C: repeated timeouts on a borrowed stalled torrent do not grow its listener count', async () => {
  const { root, nodes: [p], fresh, stopAll } = await cluster(['p']);
  try {
    const S = stalled();
    await pointOwn(p, S);
    const alice = await fresh('alice');
    const mine = alice.client.add(S, { path: join(root, 'mine'), announce: [] } as any); // borrowed, stalled
    await sleep(50);
    const counts = () => ['metadata', 'done', 'error', 'close'].map((e) => (mine as any).listenerCount(e));
    const base = counts();
    for (let i = 0; i < 6; i++) {
      assert.deepEqual(await alice.catalogFull(p.pk, 40), { entries: [], endorse: [] });
      await alice.lifecycleIdle();
      assert.deepEqual(counts(), base, `listener counts after timeout ${i + 1}`);
    }
    assert.equal(alice.catalogFetches, 0, 'never started a download of our own');
    assert.equal((mine as any).destroyed, false, 'borrowed torrent never destroyed');
    assert.equal(refs(alice).has(S), false, 'borrowed ref forgotten once idle');
  } finally { await stopAll(); }
});

// ---- D. ownership independent of the parsed cache -------------------------

test('D: parsed-cache eviction never relabels an owned torrent; superseded A is retired', async () => {
  const { root, nodes: [p, q], fresh, stopAll } = await cluster(['p', 'q']);
  try {
    await p.share(await tinyModel(root, 'pa'), 'p/a');
    const A = catalogIh(p);
    await q.share(await tinyModel(root, 'qb'), 'q/b');
    const B = catalogIh(q);
    const alice = await fresh('alice', { catalogCacheMax: 1 });

    await alice.catalogFull(p.pk); // P/A
    assert.equal(refs(alice).get(A)!.owned, true);
    await alice.catalogFull(q.pk); // Q/B evicts P/A from the parsed cache -> P's retention of A dropped, A retired
    await alice.lifecycleIdle();
    assert.equal(alice.catalogCacheSize, 1);
    assert.equal(await alive(alice, A), false);
    await alice.catalogFull(p.pk); // revisit P/A: fresh owned download
    assert.equal(refs(alice).get(A)!.owned, true);
    assert.equal(alice.catalogFetches, 3);

    // pure parsed-cache loss (no retirement): revisiting must keep A owned, not relabel it borrowed
    (alice as any).catalogCache.clear();
    await alice.catalogFull(p.pk);
    assert.equal(alice.catalogFetches, 3, 'reused the retained torrent');
    assert.equal(refs(alice).get(A)!.owned, true);

    // P -> C: A must be retired (destroyed + dir removed)
    const aDir = refs(alice).get(A)!.dir!;
    await p.share(await tinyModel(root, 'pc'), 'p/c');
    const C = catalogIh(p);
    assert.equal((await alice.catalogFull(p.pk)).entries.length, 2);
    await alice.lifecycleIdle();
    assert.equal(await alive(alice, A), false, 'A retired');
    assert.equal(await exists(aDir), false, 'A dir removed');
    assert.ok(await alive(alice, C));
    assert.deepEqual(alice.lifecycleErrors, []);
  } finally { await stopAll(); }
});

// ---- E. option validation -------------------------------------------------

test('E: lifecycle options are validated; catalogCacheMax 0 means no cache', async () => {
  for (const [k, max] of [['catalogTimeoutMs', WebwayNode.CATALOG_TIMEOUT_MAX_MS], ['searchTimeoutMs', WebwayNode.SEARCH_TIMEOUT_MAX_MS], ['catalogCacheMax', WebwayNode.CATALOG_CACHE_MAX_MAX], ['catalogTorrentsMax', WebwayNode.CATALOG_TORRENTS_MAX_MAX]] as const) {
    for (const bad of [NaN, Infinity, -Infinity, -1, 1.5, max + 1, '5', null, 2 ** 53]) {
      assert.throws(() => new WebwayNode({ [k]: bad } as any), RangeError, `${k}=${String(bad)}`);
    }
    new WebwayNode({ [k]: 0 } as any); new WebwayNode({ [k]: max } as any); // boundaries accepted
  }
  const { root, nodes: [p], fresh, stopAll } = await cluster(['p']);
  try {
    await p.share(await tinyModel(root, 'pm'), 'p/model');
    const alice = await fresh('alice', { catalogCacheMax: 0 });
    for (let i = 0; i < 3; i++) {
      assert.equal((await alice.catalogFull(p.pk)).entries.length, 1);
      assert.equal(alice.catalogCacheSize, 0, 'nothing cached');
    }
    assert.equal(alice.catalogFetches, 1, 'torrent retained and reused even without a parsed cache');
    assert.equal(alice.catalogTorrentCount, 1);
  } finally { await stopAll(); }
});

// ---- F. parseCatalog scans past invalid entries ----------------------------

test('F: 5000 invalid entries do not consume the allowance for valid ones', () => {
  const j = { entries: [...Array(WebwayNode.CATALOG_MAX_ENTRIES).fill(null), { name: 'p/last', ih: IH('a'), size: 1 }] };
  assert.deepEqual(parseCatalog(JSON.stringify(j), 'b'.repeat(64)).entries, [{ name: 'p/last', ih: IH('a'), size: 1 }]);
  const many = { entries: Array.from({ length: WebwayNode.CATALOG_MAX_ENTRIES + 10 }, (_, i) => (i % 2 ? null : { name: `m${i}`, ih: IH('c'), size: i })) };
  const c = parseCatalog(JSON.stringify(many), 'b'.repeat(64));
  assert.equal(c.entries.length, (WebwayNode.CATALOG_MAX_ENTRIES + 10) / 2);
  const over = { entries: Array.from({ length: WebwayNode.CATALOG_MAX_ENTRIES + 10 }, (_, i) => ({ name: `m${i}`, ih: IH('c'), size: i })) };
  assert.equal(parseCatalog(JSON.stringify(over), 'b'.repeat(64)).entries.length, WebwayNode.CATALOG_MAX_ENTRIES);
});

// ---- 7. bounded torrent retention across many publishers -------------------

test('discovering many distinct publishers keeps at most catalogTorrentsMax catalog torrents and dirs', async () => {
  const { nodes: [p], fresh, stopAll } = await cluster(['p']);
  try {
    const N = 9, MAX = 3;
    const pubs: { pk: string; ih: string }[] = [];
    for (let i = 0; i < N; i++) {
      const ih = await seedRaw(p, { 'catalog.json': JSON.stringify({ entries: [{ name: `pub${i}/model`, ih: i.toString(16).padStart(40, '0'), size: i }] }) });
      pubs.push({ pk: await pointAs(p, generate(), ih), ih });
    }
    const alice = await fresh('alice', { catalogTorrentsMax: MAX, catalogCacheMax: 100 });
    for (const [i, { pk }] of pubs.entries()) {
      assert.equal((await alice.catalogFull(pk)).entries[0].name, `pub${i}/model`);
      await alice.lifecycleIdle();
      assert.ok(alice.catalogTorrentCount <= MAX, `torrents ${alice.catalogTorrentCount} after ${i + 1}`);
    }
    assert.equal(alice.catalogFetches, N);
    assert.equal(alice.catalogCacheSize, N, 'parsed cache is separate from torrent retention');
    let dirs = 0;
    for (const pk of await readdir(join(alice.home, 'catalogs'))) dirs += (await readdir(join(alice.home, 'catalogs', pk))).length;
    assert.ok(dirs <= MAX, `${dirs} catalog dirs on disk`);
    // the most recently used survive
    const kept = [...refs(alice).keys()];
    assert.deepEqual(kept.sort(), pubs.slice(-MAX).map((x) => x.ih).sort());
    assert.deepEqual(alice.lifecycleErrors, []);
  } finally { await stopAll(); }
});

// ---- final round: generation dirs, cap after release, aborted loads --------

test('G1: reloading a pk/ih after its retained torrent closed never lets old cleanup touch the new files', async () => {
  const { root, nodes: [p], fresh, stopAll } = await cluster(['p']);
  try {
    await p.share(await tinyModel(root, 'pm'), 'p/model');
    const X = catalogIh(p);
    const alice = await fresh('alice', { catalogCacheMax: 0 }); // no parsed cache: every call reloads
    assert.equal((await alice.catalogFull(p.pk)).entries.length, 1);
    const old = refs(alice).get(X)!;
    assert.equal(old.owned, true);
    // the retained torrent closes underneath us (what publishCatalog's re-seed does to a catalog torrent)
    await new Promise<void>((r) => old.torrent.destroy({}, () => r()));
    assert.equal(old.torrent.destroyed, true);
    // same pk/ih reloads: a new generation, old cleanup runs, new files must survive
    assert.equal((await alice.catalogFull(p.pk)).entries.length, 1);
    const fresh_ = refs(alice).get(X)!;
    assert.notEqual(fresh_, old);
    assert.notEqual(fresh_.dir, old.dir, 'generation-specific directories');
    assert.equal(fresh_.owned, true);
    await alice.lifecycleIdle();
    assert.equal(await exists(old.dir!), false, 'old generation dir removed');
    assert.ok(await exists(join(fresh_.dir!, 'catalog', 'catalog.json')), 'new generation files intact');
    assert.equal(fresh_.torrent.destroyed, false);
    assert.equal((await alice.catalogFull(p.pk)).entries.length, 1, 'still readable after old cleanup');
    assert.equal(alice.catalogFetches, 2);
    assert.deepEqual(alice.lifecycleErrors, []);
  } finally { await stopAll(); }
});

test('G2: torrent cap is enforced after release, under concurrent completion, and respects cache-hit recency', async () => {
  const { root, nodes: [p, q, r], fresh, stopAll } = await cluster(['p', 'q', 'r']);
  try {
    await p.share(await tinyModel(root, 'pm'), 'p/model');
    await q.share(await tinyModel(root, 'qm'), 'q/model');
    await r.share(await tinyModel(root, 'rm'), 'r/model');
    const [P, Q, R] = [catalogIh(p), catalogIh(q), catalogIh(r)];

    // cap 0: nothing idle survives, results still returned
    const zero = await fresh('zero', { catalogTorrentsMax: 0 });
    assert.equal((await zero.catalogFull(p.pk)).entries.length, 1);
    await zero.lifecycleIdle();
    assert.equal(zero.catalogTorrentCount, 0);
    assert.equal(await alive(zero, P), false);
    assert.equal(await exists(join(zero.home, 'catalogs', p.pk)), false, 'no dirs left');

    // cap 1 with two loads completing concurrently
    const one = await fresh('one', { catalogTorrentsMax: 1 });
    const both = await Promise.all([one.catalogFull(p.pk), one.catalogFull(q.pk)]);
    assert.equal(both[0].entries.length + both[1].entries.length, 2);
    await one.lifecycleIdle();
    assert.equal(one.catalogTorrentCount, 1);

    // cap 2, LRU by use: p is hit repeatedly from the parsed cache, q goes cold, r arrives -> q evicted, p kept
    const two = await fresh('two', { catalogTorrentsMax: 2 });
    await two.catalogFull(p.pk);
    await sleep(5);
    await two.catalogFull(q.pk);
    await sleep(5);
    for (let i = 0; i < 3; i++) { await two.catalogFull(p.pk); await sleep(2); } // cache hits
    assert.equal(two.catalogFetches, 2);
    await two.catalogFull(r.pk);
    await two.lifecycleIdle();
    assert.equal(two.catalogTorrentCount, 2);
    assert.ok(await alive(two, P), 'hot publisher kept');
    assert.ok(await alive(two, R));
    assert.equal(await alive(two, Q), false, 'cold publisher evicted');
    assert.deepEqual([...refs(two).keys()].sort(), [P, R].sort());
    for (const n of [zero, one, two]) assert.deepEqual(n.lifecycleErrors, []);
  } finally { await stopAll(); }
});

test('G3: a retry right after a timed-out load starts a fresh load instead of joining the aborted one', async () => {
  const { root, nodes: [p], fresh, stopAll } = await cluster(['p']);
  try {
    await p.share(await tinyModel(root, 'pm'), 'p/model');
    const alice = await fresh('alice');
    // make the first acquisition slow (pending I/O) so the 60ms caller times out mid-load
    const real = (alice as any).acquire.bind(alice);
    let slowOnce = true;
    (alice as any).acquire = async (...a: unknown[]) => { if (slowOnce) { slowOnce = false; await sleep(250); } return real(...a); };
    assert.deepEqual(await alice.catalogFull(p.pk, 60), { entries: [], endorse: [] });
    const t0 = Date.now();
    const retry = await alice.catalogFull(p.pk, 3000); // immediately: the aborted load is still settling
    assert.equal(retry.entries.length, 1, 'retry must not inherit the aborted load');
    assert.ok(Date.now() - t0 < 2500);
    await alice.lifecycleIdle();
    assert.equal(alice.catalogTorrentCount, 1);
    assert.equal((alice as any).catalogInflight.size, 0);
    assert.deepEqual(alice.lifecycleErrors, []);
  } finally { await stopAll(); }
});
