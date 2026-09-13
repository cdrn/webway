import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, mkdir, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { WebwayNode } from '../src/node.ts';

const t0 = Date.now(); const lap = (m: string) => console.log(`  [${((Date.now() - t0) / 1000).toFixed(1)}s] ${m}`);

test('publisher signs a name, stranger resolves it via DHT, downloads verified, then reseeds', async () => {
  const root = await mkdtemp(join(tmpdir(), 'webway-'));
  const modelDir = join(root, 'src', 'tiny-llm');
  await mkdir(modelDir, { recursive: true });
  const w1 = randomBytes(3 * 1024 * 1024), w2 = randomBytes(700 * 1024);
  await writeFile(join(modelDir, 'model.safetensors'), w1);
  await writeFile(join(modelDir, 'config.json'), w2);

  // Isolated DHT: one router node that knows nothing; everyone else bootstraps off it.
  const router = await new WebwayNode({ home: join(root, 'router'), bootstrap: false, nat: false }).start();
  const boot = [`127.0.0.1:${router.dht.address().port}`];
  const pub = await new WebwayNode({ home: join(root, 'pub'), bootstrap: boot, nat: false }).start();
  const alice = await new WebwayNode({ home: join(root, 'alice'), bootstrap: boot, nat: false }).start();
  try {
    lap('nodes up');
    const share = await pub.share(modelDir, 'acme/tiny-llm', 'apache-2.0');
    const ref = `webway://${pub.pk}/acme/tiny-llm`;

    lap('shared');
    const r = await alice.resolve(ref);
    assert.equal(r.ih, share.ih);
    assert.equal(r.license, 'apache-2.0');

    lap('resolved');
    const got = await alice.fetch(ref);
    assert.equal(await readFile(join(got.dir, 'model.safetensors')).then((b) => b.equals(w1)), true);
    assert.equal(await readFile(join(got.dir, 'config.json')).then((b) => b.equals(w2)), true);

    // Catalog discovery: follow the publisher, search.
    lap('fetched');
    await alice.follow(pub.pk);
    const hits = await alice.search('tiny');
    assert.equal(hits.length, 1);
    assert.equal(hits[0].ih, share.ih);

    // Publisher goes dark. Bob can still get it from Alice (the Napster property).
    lap('searched');
    await pub.stop();
    // ...and the *name* survives too: wipe every DHT node's value store, let Alice
    // re-put the signed records she holds, and a newcomer can still resolve (#2).
    router.dht._values.clear(); alice.dht._values.clear();
    assert.equal(await alice.republish(), 2); // name record + catalog record
    lap('alice re-put');
    const bob = await new WebwayNode({ home: join(root, 'bob'), bootstrap: boot, nat: false }).start();
    try {
      const viaName = await bob.resolve(ref);
      assert.equal(viaName.ih, share.ih);
      const got2 = await bob.fetch(share.ih);
      assert.equal(await readFile(join(got2.dir, 'model.safetensors')).then((b) => b.equals(w1)), true);
      lap('bob fetched from alice');
    } finally { await bob.stop(); }
  } finally {
    await alice.stop();
    await pub.stop().catch(() => {});
    await router.stop();
  }
});
