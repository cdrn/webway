import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, readdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { atomicWriteJson, type AtomicFs } from '../src/atomic.ts';

/** In-memory fs with real 'wx' semantics and a rename that fails with ENOENT if the source is gone. */
function memFs() {
  const files = new Map<string, string>();
  let renames = 0;
  const err = (code: string) => Object.assign(new Error(code), { code });
  const fs: AtomicFs = {
    async mkdir() {},
    async writeFile(p, d, o) { if (o.flag === 'wx' && files.has(p)) throw err('EEXIST'); files.set(p, d); },
    async rename(a, b) { renames++; if (!files.has(a)) throw err('ENOENT'); files.set(b, files.get(a)!); files.delete(a); },
    async unlink(p) { if (!files.has(p)) throw err('ENOENT'); files.delete(p); },
  };
  return { fs, files, renames: () => renames };
}

test('concurrent writes to one file: no ENOENT/EEXIST, final content is the last write, no temp files left', async () => {
  const realNow = Date.now; Date.now = () => 1_700_000_000_000; // fixed clock: names must not depend on time
  try {
    const { fs, files } = memFs();
    const N = 200;
    await Promise.all(Array.from({ length: N }, (_, i) => atomicWriteJson('/home', 'state.json', { i }, fs)));
    assert.equal(JSON.parse(files.get('/home/state.json')!).i, N - 1);
    assert.deepEqual([...files.keys()], ['/home/state.json'], 'no temp files remain');
  } finally { Date.now = realNow; }
});

test('temp names are unique and exclusively created: <file>.<pid>.<counter>.<random6>.tmp', async () => {
  const { fs } = memFs();
  const seen: string[] = [];
  const spy: AtomicFs = { ...fs, writeFile: async (p, d, o) => { assert.equal(o.flag, 'wx'); seen.push(p); return fs.writeFile(p, d, o); } };
  await Promise.all([atomicWriteJson('/h', 'a.json', 1, spy), atomicWriteJson('/h', 'a.json', 2, spy), atomicWriteJson('/h', 'b.json', 3, spy)]);
  assert.equal(new Set(seen).size, 3);
  for (const p of seen) assert.match(p, new RegExp(`^/h/[ab]\\.json\\.${process.pid}\\.\\d+\\.[0-9a-f]{6}\\.tmp$`));
});

test('a failed rename removes its temp file and does not block later writes', async () => {
  const { fs, files } = memFs();
  let fail = true;
  const flaky: AtomicFs = { ...fs, rename: async (a, b) => { if (fail) { fail = false; throw Object.assign(new Error('EIO'), { code: 'EIO' }); } return fs.rename(a, b); } };
  await assert.rejects(atomicWriteJson('/h', 'x.json', 1, flaky));
  await atomicWriteJson('/h', 'x.json', 2, flaky);
  assert.deepEqual([...files.keys()], ['/h/x.json']);
  assert.equal(JSON.parse(files.get('/h/x.json')!), 2);
});

test('real fs: concurrent writes converge and leave no .tmp', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'webway-atomic-'));
  await Promise.all(Array.from({ length: 50 }, (_, i) => atomicWriteJson(dir, 'f.json', { i })));
  assert.equal(JSON.parse(await readFile(join(dir, 'f.json'), 'utf8')).i, 49);
  assert.deepEqual(await readdir(dir), ['f.json']);
});
