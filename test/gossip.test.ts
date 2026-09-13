import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, mkdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { WebwayNode } from '../src/node.ts';

async function tinyModel(root: string, name: string) {
  const dir = join(root, 'src', name);
  await mkdir(dir, { recursive: true });
  await writeFile(join(dir, 'model.safetensors'), randomBytes(4096));
  await writeFile(join(dir, 'config.json'), JSON.stringify({ name }));
  return dir;
}

test('search walks the web of publishers: depth, hops, cycles, dedupe, caps, dark nodes, cache', async () => {
  const root = await mkdtemp(join(tmpdir(), 'webway-gossip-'));
  const router = await new WebwayNode({ home: join(root, 'router'), bootstrap: false, nat: false }).start();
  const boot = [`127.0.0.1:${router.dht.address().port}`];
  const mk = (n: string) => new WebwayNode({ home: join(root, n), bootstrap: boot, nat: false }).start();
  const [p1, p2, p3, p4, alice] = await Promise.all(['p1', 'p2', 'p3', 'p4', 'alice'].map(mk));
  const all = [router, p1, p2, p3, p4, alice];
  try {
    // Topology (→ = endorses):  p1 → p2, p3;  p2 → p3;  p3 → p1 (cycle), p4;  p4 → nobody.
    await p1.follow(p2.pk); await p1.follow(p3.pk);
    await p2.follow(p3.pk);
    await p3.follow(p1.pk); await p3.follow(p4.pk);
    // p3 also "follows" itself and something malformed: writer must drop self, reader must drop junk.
    const realFollows = p3.follows.bind(p3);
    p3.follows = async () => [...(await realFollows()), p3.pk, 'not-a-key'];

    const shares = await Promise.all([
      p1.share(await tinyModel(root, 'm1'), 'p1/model-one'),
      p2.share(await tinyModel(root, 'm2'), 'p2/model-two'),
      p3.share(await tinyModel(root, 'm3'), 'p3/model-three'),
      p4.share(await tinyModel(root, 'm4'), 'p4/model-four'),
    ]);
    const ih = Object.fromEntries(shares.map((s) => [s.name, s.ih]));

    // catalog.json carries endorse (self stripped by writer; junk stripped by reader)
    const c3 = await alice.catalogFull(p3.pk);
    assert.deepEqual(new Set(c3.endorse), new Set([p1.pk, p4.pk]));
    assert.equal(c3.endorse.includes(p3.pk), false);
    const c4 = await alice.catalogFull(p4.pk);
    assert.deepEqual(c4.endorse, []);
    assert.equal(c4.entries[0].ih, ih['p4/model-four']);
    // backwards-compatible catalog() still returns entries
    assert.deepEqual(await alice.catalog(p4.pk), c4.entries);

    await alice.follow(p1.pk);
    const names = (hits: { name: string; hops: number }[]) => hits.map((h) => `${h.name}@${h.hops}`);

    // depth 0: only directly followed
    assert.deepEqual(names(await alice.search('model', { depth: 0 })), ['p1/model-one@0']);
    // depth 1: p1 plus what p1 endorses
    assert.deepEqual(names(await alice.search('model', { depth: 1 })), ['p1/model-one@0', 'p2/model-two@1', 'p3/model-three@1']);
    // depth 2: everything, p4 at 2 hops; cycle p3→p1 terminates; p3 reached via p1 and p2 appears once
    const d2 = await alice.search('model', { depth: 2 });
    assert.deepEqual(names(d2), ['p1/model-one@0', 'p2/model-two@1', 'p3/model-three@1', 'p4/model-four@2']);
    assert.equal(d2.filter((h) => h.pk === p3.pk).length, 1);
    for (const h of d2) assert.equal(h.ih, ih[h.name]);
    // default depth is 2
    assert.deepEqual(names(await alice.search('model')), names(d2));
    // deeper than the graph: same answer, still terminates
    assert.deepEqual(names(await alice.search('model', { depth: 5 })), names(d2));
    // query filters by substring, case-insensitive
    assert.deepEqual(names(await alice.search('FOUR')), ['p4/model-four@2']);
    assert.deepEqual(await alice.search('nope'), []);
    // maxPublishers caps the walk
    assert.deepEqual(names(await alice.search('model', { maxPublishers: 1 })), ['p1/model-one@0']);
    assert.deepEqual(names(await alice.search('model', { maxPublishers: 2 })), ['p1/model-one@0', 'p2/model-two@1']);
    assert.deepEqual(await alice.search('model', { maxPublishers: 0 }), []);
    // self is never visited even if followed
    await alice.follow(alice.pk);
    assert.deepEqual(names(await alice.search('model', { depth: 0 })), ['p1/model-one@0']);

    // cache: the four catalogs were fetched once; repeated searches fetch nothing new
    assert.equal(alice.catalogFetches, 4);
    await alice.search('model'); await alice.search('model', { depth: 1 });
    assert.equal(alice.catalogFetches, 4);
    // a republished catalog (new infohash) is a cache miss
    await p4.share(await tinyModel(root, 'm4b'), 'p4/model-five');
    assert.deepEqual(names(await alice.search('five')), ['p4/model-five@2']);
    assert.equal(alice.catalogFetches, 5);

    // p4 goes dark and its catalog record is gone from every node: search still works, p4 just drops out
    await p4.stop();
    const key = WebwayNode.targetFor(p4.pk, 'catalog').toString('hex');
    for (const n of [router, p1, p2, p3, alice]) n.dht._values.remove(key);
    alice.catalogFetches = 0;
    const dark = await alice.search('model');
    assert.deepEqual(names(dark), ['p1/model-one@0', 'p2/model-two@1', 'p3/model-three@1']);
    assert.equal(alice.catalogFetches, 0);
  } finally {
    await Promise.all(all.map((n) => n.stop().catch(() => {})));
  }
});

test('search with nobody followed is empty and never throws', async () => {
  const root = await mkdtemp(join(tmpdir(), 'webway-gossip-'));
  const n = await new WebwayNode({ home: join(root, 'solo'), bootstrap: false, nat: false }).start();
  try {
    assert.deepEqual(await n.search('anything'), []);
    // following a publisher that has never published anything
    await n.follow('a'.repeat(64));
    assert.deepEqual(await n.search('anything', { depth: 3 }), []);
    await assert.rejects(n.follow('short'), /64 hex/);
  } finally { await n.stop(); }
});
