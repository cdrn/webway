import { test, describe, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { createServer, type Server, type IncomingMessage, type ServerResponse } from 'node:http';
import { createHash, randomBytes } from 'node:crypto';
import { mkdtemp, readFile, writeFile, mkdir, stat, lstat, symlink, readdir, rm, readlink, rename } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { dirname, join, resolve as resolvePath } from 'node:path';
import { WebwayNode, assertPublishable, type Share } from '../src/node.ts';
import { importHf, parseHfRef, licenseOf, downloadFile, validateManifest, validatePath, containedPath, redact, blobSha1, HF_ORIGIN, versionIdFor } from '../src/hf.ts';
import { parse, esc, formatShared, formatImportProgress, checkArgs } from '../src/cli.ts';
import { Lock, lockPath, modelLink, pendingPath, pointerPath, readPointer, recordPath, recoverVersions, versionDir, withRepoLock } from '../src/versions.ts';
import { utimes } from 'node:fs/promises';

const sha = (b: Buffer) => createHash('sha256').update(b).digest('hex');
const SHA_A = 'a'.repeat(40), SHA_B = 'b'.repeat(40), SHA_C = 'c'.repeat(40);

type Mode = 'ignoreRange' | 'badStart' | 'badTotal' | 'badEnd' | 'shortBody' | 'noContentRange' | '416' | 'unsolicited206' | 'stall' | 'oversize' | 'endless' | 'status500';
interface MockFile { data: Buffer; size?: number | 'omit'; sha256?: string; lfs?: boolean; mode?: Mode }
type Files = Record<string, MockFile>;
interface MockRepo { head: string; commits: Record<string, Files>; cardData?: any; tags?: string[]; status?: number; gated?: boolean; raw?: unknown; apiStall?: boolean }

/** Minimal HuggingFace: /api/models/:repo[/revision/:rev]?blobs=true and /:repo/resolve/:rev-or-sha/:path */
class MockHf {
  server!: Server; base = ''; repos = new Map<string, MockRepo>();
  requests: { url: string; headers: IncomingMessage['headers'] }[] = [];
  open: ServerResponse[] = [];
  async start() {
    this.server = createServer((req, res) => {
      const url = req.url ?? '/';
      this.requests.push({ url, headers: req.headers });
      const auth = req.headers.authorization;
      let m = /^\/api\/models\/([^/]+\/[^/?]+)(?:\/revision\/([^/?]+))?\?blobs=true$/.exec(url);
      if (m) {
        const repo = this.repos.get(m[1]);
        if (!repo || repo.status === 404) { res.writeHead(404); return res.end('{}'); }
        if (repo.gated && auth !== 'Bearer good-token') { res.writeHead(401); return res.end('{}'); }
        if (repo.status) { res.writeHead(repo.status); return res.end('{}'); }
        res.writeHead(200, { 'content-type': 'application/json' });
        if (repo.apiStall) { res.write('{"sha":"' + repo.head + '","siblings":[{"rfil'); this.open.push(res); return; }
        if (repo.raw !== undefined) return res.end(typeof repo.raw === 'string' ? repo.raw : JSON.stringify(repo.raw));
        const siblings = Object.entries(repo.commits[repo.head]).map(([rfilename, f]) => ({
          rfilename,
          ...(f.size === 'omit' ? {} : { size: f.size ?? f.data.length }),
          ...(f.lfs ? { lfs: { sha256: f.sha256 ?? sha(f.data), size: f.size === 'omit' || f.size === undefined ? f.data.length : f.size } } : {}),
        }));
        return res.end(JSON.stringify({ id: m[1], sha: repo.head, siblings, cardData: repo.cardData, tags: repo.tags ?? [] }));
      }
      m = /^\/([^/]+\/[^/]+)\/resolve\/([^/]+)\/(.+)$/.exec(url);
      if (m) {
        const repo = this.repos.get(m[1]);
        const rev = m[2] === 'main' ? repo?.head : m[2];
        const f = rev ? repo?.commits[rev]?.[decodeURIComponent(m[3])] : undefined;
        if (!repo || !f) { res.writeHead(404); return res.end(); }
        if (repo.gated && auth !== 'Bearer good-token') { res.writeHead(403); return res.end(); }
        if (f.mode === 'status500') { res.writeHead(500); return res.end(); }
        const range = /^bytes=(\d+)-$/.exec(req.headers.range ?? '');
        const len = f.data.length;
        if (f.mode === 'unsolicited206' && !range) { res.writeHead(206, { 'content-range': `bytes 0-${len - 1}/${len}` }); return res.end(f.data); }
        if (range && f.mode !== 'ignoreRange') {
          const start = Number(range[1]);
          if (f.mode === '416') { res.writeHead(416, { 'content-range': `bytes */${len}` }); return res.end(); }
          const cr = f.mode === 'badStart' ? `bytes 0-${len - 1}/${len}` : f.mode === 'badTotal' ? `bytes ${start}-${len - 1}/${len + 5}` : f.mode === 'badEnd' ? `bytes ${start}-${start}/${len}` : `bytes ${start}-${len - 1}/${len}`;
          res.writeHead(206, f.mode === 'noContentRange' ? {} : { 'content-range': cr });
          if (f.mode === 'shortBody') return res.end(f.data.subarray(start, start + 3));
          return res.end(f.mode === 'badStart' ? f.data : f.data.subarray(start));
        }
        if (f.mode === 'stall') { res.writeHead(200); res.write(f.data.subarray(0, 10)); this.open.push(res); return; }
        if (f.mode === 'oversize') { res.writeHead(200); return res.end(Buffer.concat([f.data, randomBytes(100_000)])); }
        if (f.mode === 'endless') {
          res.writeHead(200); this.open.push(res);
          const tick = () => { if (res.destroyed || res.writableEnded) return; res.write(randomBytes(8192), () => setImmediate(tick)); };
          return tick();
        }
        res.writeHead(200, { 'content-length': len });
        return res.end(f.data);
      }
      res.writeHead(404); res.end();
    });
    await new Promise<void>((r) => this.server.listen(0, '127.0.0.1', r));
    this.base = `http://127.0.0.1:${(this.server.address() as any).port}`;
  }
  async stop() { for (const r of this.open) r.destroy(); await new Promise<void>((r) => this.server.close(() => r())); }
  resolves(repo: string) { return this.requests.filter((r) => r.url.startsWith(`/${repo}/resolve/`)); }
  set(name: string, files: Files, extra: Partial<MockRepo> = {}) { this.repos.set(name, { head: SHA_A, commits: { [SHA_A]: files }, ...extra }); }
}

describe('hf import', () => {
  const hf = new MockHf();
  let root: string; let node: WebwayNode; let router: WebwayNode;
  let shareCalls = 0; let savedToken: string | undefined;
  before(async () => {
    savedToken = process.env.HF_TOKEN; delete process.env.HF_TOKEN;
    await hf.start();
    root = await mkdtemp(join(tmpdir(), 'webway-hf-'));
    // share() signs the name into the DHT, which needs at least one other node: an isolated router.
    router = await new WebwayNode({ home: join(root, 'router'), bootstrap: false, nat: false }).start();
    node = await new WebwayNode({ home: join(root, 'home'), bootstrap: [`127.0.0.1:${router.dht.address().port}`], nat: false }).start();
    const realPrepare = node.prepareShare.bind(node);
    node.prepareShare = async (...a) => { shareCalls++; return realPrepare(...a); };
  });
  after(async () => {
    await node.stop(); await router.stop(); await hf.stop();
    if (savedToken === undefined) delete process.env.HF_TOKEN; else process.env.HF_TOKEN = savedToken;
  });
  beforeEach(() => { hf.requests.length = 0; shareCalls = 0; });

  const H = () => node.home;
  const VID = (commit: string) => versionIdFor(commit, hf.base);
  const ver = (repo: string, commit = SHA_A) => versionDir(H(), repo, VID(commit));
  const rec = (repo: string, commit = SHA_A) => recordPath(H(), repo, VID(commit));
  const lockDir = (repo: string, opts: any = {}) => mkdir(lockPath(H(), repo), { recursive: true }).then(() => writeFile(join(lockPath(H(), repo), 'owner.json'), JSON.stringify(opts)));
  const link = (repo: string) => modelLink(H(), repo);
  const linkTarget = async (repo: string) => resolvePath(dirname(link(repo)), await readlink(link(repo)));
  const exists = async (p: string) => { try { await lstat(p); return true; } catch { return false; } };
  const ownShare = async (repo: string) => (await node.shares()).find((x) => x.own && x.name === repo);
  /** A failed import must never reach prepareShare() (the seed + publish step behind share()). */
  const fails = async (p: Promise<unknown>, re: RegExp) => { const before = shareCalls; await assert.rejects(p, re); assert.equal(shareCalls, before, 'share() must not be called on failure'); };
  const seededFiles = async (ih: string): Promise<string[] | undefined> => { const t = await (node.client as any).get(ih); return t ? t.files.map((f: any) => f.path).sort() : undefined; };
  const stageRecord = async (repo: string, files: Record<string, any>, commit = SHA_A, origin = hf.base) => {
    await mkdir(ver(repo, commit), { recursive: true });
    await writeFile(rec(repo, commit), JSON.stringify({ commit, origin, files }));
  };

  // ---- parsing / helpers ---------------------------------------------------

  test('parseHfRef accepts hf://, https://huggingface.co/, and bare; rejects junk', () => {
    assert.equal(parseHfRef('hf://org/model'), 'org/model');
    assert.equal(parseHfRef('https://huggingface.co/org/model/'), 'org/model');
    assert.equal(parseHfRef('org/my.model-v1_2'), 'org/my.model-v1_2');
    for (const bad of ['model', 'a/b/c', '../x/y', 'org/..', 'org/mod el']) assert.throws(() => parseHfRef(bad), /not a HuggingFace/);
  });

  test('licenseOf: cardData string, cardData array, license: tag, none, non-string junk', () => {
    assert.equal(licenseOf({ cardData: { license: 'mit' } }), 'mit');
    assert.equal(licenseOf({ cardData: { license: ['apache-2.0', 'mit'] } }), 'apache-2.0');
    assert.equal(licenseOf({ tags: ['x', 'license:llama3'] }), 'llama3');
    assert.equal(licenseOf({ cardData: {}, tags: [] }), undefined);
    assert.equal(licenseOf({ cardData: { license: [42] as any } }), undefined);
  });

  test('redact strips userinfo, query strings/fragments and escapes control characters (J)', () => {
    assert.equal(redact('https://h/x/file.bin?token=secret&x=1#frag'), 'https://h/x/file.bin');
    assert.equal(redact('https://user:secret@host/file'), 'https://host/file');
    assert.equal(redact('http://tok@host:8080/a?b=c'), 'http://host:8080/a');
    assert.equal(redact('a\x1b[2Jb'), 'a\\x1b[2Jb');
  });

  // ---- 1/B. path containment --------------------------------------------------

  test('validatePath rejects backslashes, drive/UNC forms, control chars, dot segments, depth, device names, Windows-invalid chars (F)', () => {
    for (const bad of ['..\\..\\escape.bin', 'a\\b', 'C:/x', 'C:\\x', '//srv/share/x', '/etc/passwd', 'a/../b', './a', 'a//b', 'a/', 'x\x1b[2J', 'a\nb', 'a\x00b', 'nul.txt', 'con', 'a/COM1',
      'a?b', 'a<b', 'a>b', 'a"b', 'a|b', 'a*b', 'a:b', 'trailing.', 'trailing ', 'd./f'])
      assert.throws(() => validatePath(bad), Error, `should reject ${JSON.stringify(bad)}`);
    assert.throws(() => validatePath(Array(17).fill('d').join('/')), /deeper than 16/);
    assert.equal(validatePath(Array(16).fill('d').join('/')), Array(16).fill('d').join('/'));
    assert.equal(validatePath('onnx/model.onnx'), 'onnx/model.onnx');
    assert.equal(validatePath('weird name (1).bin'), 'weird name (1).bin');
  });

  test('backslash traversal in the manifest is rejected before any download and nothing is written', async () => {
    hf.set('acme/bs', { '..\\..\\escape.bin': { data: randomBytes(10) }, 'ok.bin': { data: randomBytes(10) } });
    await fails(importHf(node, 'acme/bs', { baseUrl: hf.base }), /backslash/);
    assert.equal(hf.resolves('acme/bs').length, 0);
    assert.equal(await exists(ver('acme/bs')), false);
    assert.equal(await exists(join(H(), 'escape.bin')), false);
  });

  test('symlink ancestor inside the version dir is refused; nothing lands outside', async () => {
    const outside = join(root, 'outside-symlink'); await mkdir(outside, { recursive: true });
    hf.set('acme/sym', { 'sub/file.bin': { data: randomBytes(10) } });
    await mkdir(ver('acme/sym'), { recursive: true });
    await symlink(outside, join(ver('acme/sym'), 'sub'));
    await fails(importHf(node, 'acme/sym', { baseUrl: hf.base }), /symlink/);
    assert.equal(hf.resolves('acme/sym').length, 0);
    assert.deepEqual(await readdir(outside), []);
  });

  test('B: version dir itself symlinked to a populated external dir -> refused, nothing outside deleted', async () => {
    const outside = join(root, 'outside-populated'); await mkdir(join(outside, 'deep'), { recursive: true });
    await writeFile(join(outside, 'keep.txt'), 'precious'); await writeFile(join(outside, 'deep', 'also.txt'), 'precious');
    hf.set('acme/symroot', { 'w.bin': { data: randomBytes(10) } });
    await mkdir(dirname(ver('acme/symroot')), { recursive: true });
    await symlink(outside, ver('acme/symroot'));
    await fails(importHf(node, 'acme/symroot', { baseUrl: hf.base }), /symlink/);
    assert.equal(hf.resolves('acme/symroot').length, 0);
    assert.deepEqual((await readdir(outside)).sort(), ['deep', 'keep.txt']);
    assert.equal((await readFile(join(outside, 'keep.txt'))).toString(), 'precious');
    assert.equal(await exists(join(outside, 'w.bin')), false);
    await rm(ver('acme/symroot'));
  });

  test('B: versions/<org>/<model> root symlinked to an external dir -> refused, external untouched', async () => {
    const outside = join(root, 'outside-root'); await mkdir(outside, { recursive: true });
    await writeFile(join(outside, 'x.txt'), 'x');
    hf.set('acme/symroot2', { 'w.bin': { data: randomBytes(10) } });
    await mkdir(join(H(), 'versions', 'acme'), { recursive: true });
    await symlink(outside, join(H(), 'versions', 'acme', 'symroot2'));
    await fails(importHf(node, 'acme/symroot2', { baseUrl: hf.base }), /symlink/);
    assert.equal(hf.resolves('acme/symroot2').length, 0);
    assert.deepEqual(await readdir(outside), ['x.txt']);
    await rm(join(H(), 'versions', 'acme', 'symroot2'));
  });

  test('containedPath: escapes and symlinked final components are refused; missing paths are fine', async () => {
    const r = join(root, 'contain'); await mkdir(join(r, 'd'), { recursive: true });
    await writeFile(join(r, 'target'), 'x');
    await symlink(join(r, 'target'), join(r, 'd', 'link'));
    await assert.rejects(containedPath(r, 'd/link'), /symlink/);
    await assert.rejects(containedPath(r, '../x'), /outside/);
    await assert.rejects(containedPath(r, 'd'), /not a regular file/);
    assert.equal(await containedPath(r, 'd/new/file'), join(r, 'd', 'new', 'file'));
  });

  // ---- 7/F. manifest schema validation ---------------------------------------

  test('validateManifest rejects every malformed shape, folded prefixes, and size limits (never touches the filesystem)', () => {
    const ok = (siblings: unknown, extra: any = {}) => validateManifest({ sha: SHA_A, siblings, ...extra });
    assert.throws(() => validateManifest(null), /not an object/);
    assert.throws(() => validateManifest([]), /not an object/);
    assert.throws(() => validateManifest({ siblings: [] }), /commit sha/);
    assert.throws(() => validateManifest({ sha: 'xyz', siblings: [] }), /commit sha/);
    assert.throws(() => ok({}), /siblings must be an array/);
    assert.throws(() => ok([null]), /not an object/);
    assert.throws(() => ok([{ rfilename: 42 }]), /rfilename/);
    assert.throws(() => ok([{ rfilename: 'a', size: -1 }]), /bad size/);
    assert.throws(() => ok([{ rfilename: 'a', size: '10' }]), /bad size/);
    assert.throws(() => ok([{ rfilename: 'a', size: 1.5 }]), /bad size/);
    assert.throws(() => ok([{ rfilename: 'a', size: 2 ** 53 }]), /bad size/);
    assert.throws(() => ok([{ rfilename: 'a', lfs: { sha256: '' } }]), /malformed sha256/);
    assert.throws(() => ok([{ rfilename: 'a', lfs: { sha256: 'abc' } }]), /malformed sha256/);
    assert.throws(() => ok([{ rfilename: 'a', lfs: { sha256: 'A'.repeat(64) } }]), /malformed sha256/);
    assert.throws(() => ok([{ rfilename: 'a', lfs: 'x' }]), /bad lfs/);
    assert.throws(() => ok([{ rfilename: 'a', lfs: { size: -3 } }]), /bad lfs.size/);
    assert.throws(() => ok([{ rfilename: 'a', size: 5, lfs: { size: 6 } }]), /disagree/);
    assert.throws(() => ok([{ rfilename: 'a' }, { rfilename: 'a' }]), /duplicate/);
    assert.throws(() => ok([{ rfilename: 'a' }, { rfilename: 'a/b' }]), /both a file and a directory/);
    assert.throws(() => ok([{ rfilename: 'a/b' }, { rfilename: 'a' }]), /both a file and a directory/);
    assert.throws(() => ok([{ rfilename: 'A.bin' }, { rfilename: 'a.bin' }]), /case-insensitive/);
    assert.throws(() => ok([{ rfilename: 'x/A' }, { rfilename: 'X/a' }]), /case-insensitive/);
    assert.throws(() => ok([{ rfilename: 'A/x' }, { rfilename: 'a/y' }]), /case-insensitive/); // F: directory alias
    assert.throws(() => ok([{ rfilename: 'Dir/Sub/x' }, { rfilename: 'dir/other' }]), /case-insensitive/);
    assert.throws(() => ok([{ rfilename: 'a' }, { rfilename: 'A/b' }]), /case-insensitive/);
    assert.doesNotThrow(() => ok([{ rfilename: 'a/x' }, { rfilename: 'a/y' }]));
    assert.throws(() => ok([{ rfilename: '.gitattributes' }]), /no files/);
    assert.throws(() => ok([]), /no files/);
    assert.throws(() => ok(Array.from({ length: 10_001 }, (_, i) => ({ rfilename: `f${i}` }))), /exceeds limit/);
    assert.throws(() => validateManifest({ sha: SHA_A, siblings: [{ rfilename: 'a', size: 11 }] }, { maxFiles: 10, maxDepth: 16, maxMetadataBytes: 1e6, maxFileBytes: 10, maxTotalBytes: 1e9 }), /per-file limit/);
    assert.throws(() => validateManifest({ sha: SHA_A, siblings: [{ rfilename: 'a', size: 6 }, { rfilename: 'b', size: 6 }] }, { maxFiles: 10, maxDepth: 16, maxMetadataBytes: 1e6, maxFileBytes: 10, maxTotalBytes: 10 }), /total size/);
    const m = ok([{ rfilename: '.gitattributes' }, { rfilename: 'w.bin', size: 3, lfs: { sha256: 'f'.repeat(64), size: 3 } }, { rfilename: 'c.json' }]);
    assert.deepEqual(m, { commit: SHA_A, files: [{ path: 'w.bin', size: 3, sha256: 'f'.repeat(64) }, { path: 'c.json', size: undefined, sha256: undefined }] });
    assert.equal(ok([{ rfilename: 'w', lfs: { size: 7 } }]).files[0].size, 7, 'lfs.size fills in size');
  });

  test('malformed API bodies fail before any resolve request: non-object, invalid JSON, empty sha256, huge manifest', async () => {
    for (const [name, raw, re] of [
      ['acme/m1', '[]', /not an object/],
      ['acme/m2', '{not json', /invalid JSON/],
      ['acme/m3', { sha: SHA_A, siblings: [{ rfilename: 'w', lfs: { sha256: '' } }] }, /malformed sha256/],
      ['acme/m4', { sha: SHA_A, siblings: Array.from({ length: 10_001 }, (_, i) => ({ rfilename: `f${i}` })) }, /exceeds limit/],
      ['acme/m5', { sha: SHA_A, siblings: [{ rfilename: 'a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/p/q' }] }, /deeper/],
      ['acme/m6', { siblings: [{ rfilename: 'w' }] }, /commit sha/],
      ['acme/m7', { sha: SHA_A, siblings: [{ rfilename: 'A/x' }, { rfilename: 'a/y' }] }, /case-insensitive/],
    ] as const) {
      hf.set(name, {}, { raw });
      await fails(importHf(node, name, { baseUrl: hf.base }), re);
      assert.equal(hf.resolves(name).length, 0, name);
      assert.equal(await exists(ver(name)), false, `${name} version dir must not exist`);
    }
  });

  test('metadata body larger than the limit is refused; metadata that stops mid-JSON is aborted by the stall timer (E)', async () => {
    hf.set('acme/meta', {}, { raw: { sha: SHA_A, siblings: [{ rfilename: 'w' }], pad: 'x'.repeat(5000) } });
    await fails(importHf(node, 'acme/meta', { baseUrl: hf.base, limits: { maxMetadataBytes: 1000 } }), /larger than 1000 bytes/);
    hf.set('acme/metastall', { 'w.bin': { data: randomBytes(5) } }, { apiStall: true });
    const t0 = Date.now();
    await fails(importHf(node, 'acme/metastall', { baseUrl: hf.base, stallMs: 300 }), /stalled/);
    assert.ok(Date.now() - t0 < 5000);
  });

  // ---- happy path ---------------------------------------------------------------

  test('full import: license from cardData, .gitattributes skipped, nested path, bytes exact, pinned to commit, versioned layout', async () => {
    const f: Files = { 'config.json': { data: Buffer.from('{"a":1}') }, 'model.safetensors': { data: randomBytes(300_000), lfs: true }, '.gitattributes': { data: Buffer.from('x') }, 'onnx/model.onnx': { data: randomBytes(50_000) } };
    hf.set('acme/a', f, { cardData: { license: 'apache-2.0' } });
    const progress: number[] = [];
    const s = await importHf(node, 'hf://acme/a', { baseUrl: hf.base, onProgress: (p) => progress.push(p.bytes) });
    assert.equal(shareCalls, 1);
    assert.equal(s.name, 'acme/a'); assert.equal(s.license, 'apache-2.0'); assert.equal(s.own, true);
    assert.equal(s.dir, link('acme/a'), 'share dir is the models/ symlink');
    assert.equal(await linkTarget('acme/a'), resolvePath(ver('acme/a')));
    assert.equal((await readPointer(H(), 'acme/a'))?.commit, SHA_A);
    for (const [name, mf] of Object.entries(f)) {
      if (name === '.gitattributes') { assert.equal(await exists(join(s.dir, name)), false); continue; }
      assert.ok((await readFile(join(s.dir, name))).equals(mf.data), `${name} bytes`);
    }
    assert.equal(s.size, 7 + 300_000 + 50_000);
    assert.deepEqual(await seededFiles(s.ih), ['a/config.json', 'a/model.safetensors', 'a/onnx/model.onnx'], 'torrent named after the model, not the commit');
    const rs = hf.resolves('acme/a');
    assert.equal(rs.some((r) => r.url.includes('.gitattributes')), false);
    assert.ok(rs.every((r) => r.url.includes(`/resolve/${SHA_A}/`)), 'every resolve is pinned to the commit sha, not the branch');
    assert.ok(rs.some((r) => r.url.endsWith(`/resolve/${SHA_A}/onnx/model.onnx`)));
    for (let i = 1; i < progress.length; i++) assert.ok(progress[i] >= progress[i - 1], 'progress monotonic');
    assert.equal(progress.at(-1), 7 + 300_000 + 50_000);
    assert.ok(hf.requests.every((r) => r.headers.authorization === undefined), 'no Authorization without a token');
    assert.ok(hf.requests[0].url.startsWith('/api/models/acme/a?blobs=true'));
    assert.equal(await exists(rec('acme/a')), false, 'in-progress record removed after promotion');
    assert.equal(await exists(lockPath(H(), 'acme/a')), false, 'lock released');
  });

  test('re-importing the already-current commit downloads nothing and keeps the share', async () => {
    hf.set('acme/same', { 'w.bin': { data: randomBytes(10) } });
    const s1 = await importHf(node, 'acme/same', { baseUrl: hf.base });
    hf.requests.length = 0;
    const s2 = await importHf(node, 'acme/same', { baseUrl: hf.base });
    assert.equal(s2.ih, s1.ih);
    assert.equal(hf.resolves('acme/same').length, 0);
    assert.deepEqual(await seededFiles(s1.ih), ['same/w.bin']);
  });

  test('license from tag when cardData has none; --license override wins; none -> undefined; size omitted still verified', async () => {
    hf.set('acme/b', { 'w.bin': { data: randomBytes(10) } }, { tags: ['license:llama3.1'] });
    assert.equal((await importHf(node, 'acme/b', { baseUrl: hf.base })).license, 'llama3.1');
    hf.set('acme/b2', { 'w.bin': { data: randomBytes(10) } }, { tags: ['license:llama3.1'] });
    assert.equal((await importHf(node, 'acme/b2', { baseUrl: hf.base, license: 'mit' })).license, 'mit');
    hf.set('acme/c', { 'w.bin': { data: randomBytes(10) } });
    assert.equal((await importHf(node, 'acme/c', { baseUrl: hf.base })).license, undefined);
    const data = randomBytes(3000);
    hf.set('acme/g', { 'w.bin': { data, size: 'omit' } });
    const s = await importHf(node, 'acme/g', { baseUrl: hf.base });
    assert.ok((await readFile(join(s.dir, 'w.bin'))).equals(data));
  });

  // ---- 2/G. commit pinning + cache identity -------------------------------------------

  test('same-size revision change is re-downloaded and promoted; old version dir removed', async () => {
    hf.set('acme/rev', { 'config.json': { data: Buffer.from('{"v":1}') } });
    const s1 = await importHf(node, 'acme/rev', { baseUrl: hf.base });
    assert.equal((await readFile(join(s1.dir, 'config.json'))).toString(), '{"v":1}');
    const repo = hf.repos.get('acme/rev')!;
    repo.commits[SHA_B] = { 'config.json': { data: Buffer.from('{"v":2}') } }; repo.head = SHA_B;
    hf.requests.length = 0;
    const s2 = await importHf(node, 'acme/rev', { baseUrl: hf.base });
    assert.equal((await readFile(join(s2.dir, 'config.json'))).toString(), '{"v":2}');
    assert.notEqual(s2.ih, s1.ih);
    assert.equal(hf.resolves('acme/rev').length, 1);
    assert.ok(hf.resolves('acme/rev')[0].url.includes(`/resolve/${SHA_B}/`));
    assert.deepEqual(await seededFiles(s2.ih), ['rev/config.json']);
    assert.equal(await seededFiles(s1.ih), undefined, 'old torrent torn down');
    assert.equal(await exists(ver('acme/rev', SHA_A)), false, 'old version dir removed');
    assert.equal(await linkTarget('acme/rev'), resolvePath(ver('acme/rev', SHA_B)));
  });

  test('branch moves mid-import: every file comes from the pinned commit, never mixed', async () => {
    const v1: Files = { 'a.bin': { data: randomBytes(500) }, 'b.bin': { data: randomBytes(500) } };
    const v2: Files = { 'a.bin': { data: randomBytes(500) }, 'b.bin': { data: randomBytes(500) } };
    hf.set('acme/move', v1);
    const repo = hf.repos.get('acme/move')!; repo.commits[SHA_B] = v2;
    const f = async (url: any, init?: any) => { const r = await fetch(url, init); if (String(url).includes('/api/models/')) repo.head = SHA_B; return r; };
    const s = await importHf(node, 'acme/move', { baseUrl: hf.base, fetch: f as typeof fetch });
    assert.ok((await readFile(join(s.dir, 'a.bin'))).equals(v1['a.bin'].data));
    assert.ok((await readFile(join(s.dir, 'b.bin'))).equals(v1['b.bin'].data));
    assert.ok(hf.resolves('acme/move').every((r) => r.url.includes(`/resolve/${SHA_A}/`)));
  });

  test('staging record: origin + identity + blob id; identity change forces re-download; matching identity is reused', async () => {
    const data = randomBytes(2000); const plain = Buffer.from('plain-content');
    hf.set('acme/rec', { 'w.bin': { data, lfs: true }, 'p.txt': { data: plain }, 'boom.bin': { data: randomBytes(10), mode: 'status500' } });
    await fails(importHf(node, 'acme/rec', { baseUrl: hf.base }), /download failed \(500\)/);
    const r = JSON.parse(await readFile(rec('acme/rec'), 'utf8'));
    assert.equal(r.commit, SHA_A); assert.equal(r.origin, hf.base);
    assert.deepEqual(r.files['w.bin'], { size: 2000, sha256: sha(data) });
    assert.equal(r.files['p.txt'].blob, createHash('sha1').update(`blob ${plain.length}\0`).update(plain).digest('hex'), 'git blob id recorded for non-LFS files');
    assert.ok((await readFile(join(ver('acme/rec'), 'w.bin'))).equals(data), 'staged file kept for resume');
    // Same commit, fixed third file: w.bin + p.txt are reused, only boom.bin fetched.
    hf.repos.get('acme/rec')!.commits[SHA_A]['boom.bin'].mode = undefined;
    hf.requests.length = 0;
    await importHf(node, 'acme/rec', { baseUrl: hf.base });
    assert.deepEqual(hf.resolves('acme/rec').map((x) => x.url.split('/').pop()), ['boom.bin']);
    // Poisoned record: same commit but recorded identity differs -> re-download.
    hf.set('acme/rec2', { 'w.bin': { data: randomBytes(2000) }, 'boom.bin': { data: randomBytes(10), mode: 'status500' } });
    await fails(importHf(node, 'acme/rec2', { baseUrl: hf.base }), /500/);
    const r2 = JSON.parse(await readFile(rec('acme/rec2'), 'utf8')); r2.files['w.bin'].size = 1999; await writeFile(rec('acme/rec2'), JSON.stringify(r2));
    hf.repos.get('acme/rec2')!.commits[SHA_A]['boom.bin'].mode = undefined;
    hf.requests.length = 0;
    await importHf(node, 'acme/rec2', { baseUrl: hf.base });
    assert.deepEqual(hf.resolves('acme/rec2').map((x) => x.url.split('/').pop()).sort(), ['boom.bin', 'w.bin']);
  });

  test('G: a staged non-LFS file whose bytes no longer match its recorded blob id is re-downloaded', async () => {
    const plain = randomBytes(300);
    hf.set('acme/blob', { 'p.bin': { data: plain }, 'boom.bin': { data: randomBytes(10), mode: 'status500' } });
    await fails(importHf(node, 'acme/blob', { baseUrl: hf.base }), /500/);
    await writeFile(join(ver('acme/blob'), 'p.bin'), randomBytes(300)); // same size, different bytes
    hf.repos.get('acme/blob')!.commits[SHA_A]['boom.bin'].mode = undefined;
    hf.requests.length = 0;
    const s = await importHf(node, 'acme/blob', { baseUrl: hf.base });
    assert.deepEqual(hf.resolves('acme/blob').map((x) => x.url.split('/').pop()).sort(), ['boom.bin', 'p.bin']);
    assert.ok((await readFile(join(s.dir, 'p.bin'))).equals(plain));
  });

  test('G: a mirror-poisoned cache is not reused when importing from the real origin', async () => {
    const good = Buffer.from('GOOD-bytes'); const bad = Buffer.from('BAD!-bytes');
    // Mirror serves BAD for p.txt and fails on the second file, leaving a staged BAD p.txt with origin=mirror.
    hf.set('acme/mirror', { 'p.txt': { data: bad }, 'boom.bin': { data: randomBytes(10), mode: 'status500' } });
    await fails(importHf(node, 'acme/mirror', { baseUrl: hf.base }), /500/);
    assert.ok((await readFile(join(ver('acme/mirror'), 'p.txt'))).equals(bad));
    // "Real origin": same commit, same size, GOOD bytes. Route https://huggingface.co to a second mock repo.
    hf.set('acme/mirror-real', { 'p.txt': { data: good }, 'boom.bin': { data: randomBytes(10) } });
    const seen: string[] = [];
    const real = async (url: any, init?: any) => { const u = String(url).replace(HF_ORIGIN, hf.base).replace('acme/mirror', 'acme/mirror-real'); seen.push(u); return fetch(u, init); };
    const s = await importHf(node, 'acme/mirror', { fetch: real as typeof fetch });
    assert.ok(seen.some((u) => u.endsWith('/p.txt')), 'p.txt was re-fetched from the real origin');
    assert.ok((await readFile(join(s.dir, 'p.txt'))).equals(good), 'published bytes come from the real origin');
  });

  test('byte-identical LFS file already published is reused instead of re-downloaded', async () => {
    const big = randomBytes(100_000);
    hf.set('acme/reuse', { 'big.bin': { data: big, lfs: true }, 'c.json': { data: Buffer.from('1') } });
    await importHf(node, 'acme/reuse', { baseUrl: hf.base });
    const repo = hf.repos.get('acme/reuse')!;
    repo.commits[SHA_B] = { 'big.bin': { data: big, lfs: true }, 'c.json': { data: Buffer.from('2') } }; repo.head = SHA_B;
    hf.requests.length = 0;
    const s = await importHf(node, 'acme/reuse', { baseUrl: hf.base });
    assert.deepEqual(hf.resolves('acme/reuse').map((r) => r.url.split('/').pop()), ['c.json']);
    assert.ok((await readFile(join(s.dir, 'big.bin'))).equals(big));
    assert.equal((await readFile(join(s.dir, 'c.json'))).toString(), '2');
  });

  // ---- 3/A. versioned immutable publish -----------------------------------------------

  test('file deleted in the new revision is neither published nor seeded', async () => {
    hf.set('acme/del', { 'old.bin': { data: randomBytes(10) }, 'keep.bin': { data: randomBytes(10) } });
    const s1 = await importHf(node, 'acme/del', { baseUrl: hf.base });
    assert.deepEqual(await seededFiles(s1.ih), ['del/keep.bin', 'del/old.bin']);
    const repo = hf.repos.get('acme/del')!;
    repo.commits[SHA_B] = { 'keep.bin': repo.commits[SHA_A]['keep.bin'] }; repo.head = SHA_B;
    const s2 = await importHf(node, 'acme/del', { baseUrl: hf.base });
    assert.deepEqual((await readdir(s2.dir)).sort(), ['keep.bin']);
    assert.deepEqual(await seededFiles(s2.ih), ['del/keep.bin']);
  });

  test('unrelated local file in the in-progress version dir is pruned and not seeded; a real dir at models/ path is refused', async () => {
    hf.set('acme/unrel', { 'w.bin': { data: randomBytes(10) } });
    await stageRecord('acme/unrel', {});
    await writeFile(join(ver('acme/unrel'), 'notes.txt'), 'mine');
    const s = await importHf(node, 'acme/unrel', { baseUrl: hf.base });
    assert.deepEqual(await readdir(s.dir), ['w.bin']);
    assert.deepEqual(await seededFiles(s.ih), ['unrel/w.bin']);
    hf.set('acme/realdir', { 'w.bin': { data: randomBytes(10) } });
    await mkdir(link('acme/realdir'), { recursive: true });
    await writeFile(join(link('acme/realdir'), 'user.bin'), 'user data');
    await fails(importHf(node, 'acme/realdir', { baseUrl: hf.base }), /already exists as a real directory/);
    assert.equal((await readFile(join(link('acme/realdir'), 'user.bin'))).toString(), 'user data');
  });

  test('mid-import failure leaves the previous share fully intact and never calls share()', async () => {
    const v1 = randomBytes(1000);
    hf.set('acme/fail', { 'w.bin': { data: v1 } });
    const s1 = await importHf(node, 'acme/fail', { baseUrl: hf.base });
    const repo = hf.repos.get('acme/fail')!;
    repo.commits[SHA_B] = { 'w.bin': { data: randomBytes(1000) }, 'x.bin': { data: randomBytes(10), mode: 'status500' } }; repo.head = SHA_B;
    shareCalls = 0;
    await fails(importHf(node, 'acme/fail', { baseUrl: hf.base }), /500/);
    assert.ok((await readFile(join(s1.dir, 'w.bin'))).equals(v1), 'published bytes untouched');
    assert.deepEqual(await readdir(s1.dir), ['w.bin']);
    assert.equal((await ownShare('acme/fail'))?.ih, s1.ih, 'shares.json still points at v1');
    assert.deepEqual(await seededFiles(s1.ih), ['fail/w.bin'], 'v1 still seeding');
    assert.equal((await router.resolve(`webway://${node.pk}/acme/fail`)).ih, s1.ih, 'name still resolves to v1');
    assert.equal((await readPointer(H(), 'acme/fail'))?.commit, SHA_A);
  });

  test('A: DHT publish failure after a complete download -> old share intact, old bytes seeded, new version dir removed', async () => {
    const v1 = randomBytes(500);
    hf.set('acme/dhtfail', { 'w.bin': { data: v1 } });
    const s1 = await importHf(node, 'acme/dhtfail', { baseUrl: hf.base });
    const repo = hf.repos.get('acme/dhtfail')!;
    repo.commits[SHA_B] = { 'w.bin': { data: randomBytes(500) } }; repo.head = SHA_B;
    const real = node.publishName.bind(node);
    node.publishName = async () => { throw new Error('dht down'); };
    try { await assert.rejects(importHf(node, 'acme/dhtfail', { baseUrl: hf.base }), /dht down/); } finally { node.publishName = real; }
    assert.equal((await ownShare('acme/dhtfail'))?.ih, s1.ih);
    assert.deepEqual(await seededFiles(s1.ih), ['dhtfail/w.bin'], 'old torrent still seeding');
    assert.ok((await readFile(join(s1.dir, 'w.bin'))).equals(v1));
    assert.equal(await linkTarget('acme/dhtfail'), resolvePath(ver('acme/dhtfail', SHA_A)));
    assert.equal((await readPointer(H(), 'acme/dhtfail'))?.commit, SHA_A);
    assert.equal(await exists(ver('acme/dhtfail', SHA_B)), false, 'new version dir removed');
    assert.equal(await exists(rec('acme/dhtfail', SHA_B)), false);
    assert.equal(node.client.torrents.filter((t: any) => t.name === 'dhtfail').length, 1, 'no orphan torrent for the failed version');
  });

  test('A: crash after share (before pointer) -> recover restores old as truth; re-import completes with no downloads', async () => {
    hf.set('acme/crash1', { 'w.bin': { data: randomBytes(100) } });
    const s1 = await importHf(node, 'acme/crash1', { baseUrl: hf.base });
    const repo = hf.repos.get('acme/crash1')!;
    const v2 = randomBytes(100);
    repo.commits[SHA_B] = { 'w.bin': { data: v2 } }; repo.head = SHA_B;
    await assert.rejects(importHf(node, 'acme/crash1', { baseUrl: hf.base, crashAt: 'afterShare' }), /simulated crash after share/);
    assert.equal(await exists(lockPath(H(), 'acme/crash1')), false, 'lock released even on crash');
    await node.recoverImports();
    assert.equal((await ownShare('acme/crash1'))?.ih, s1.ih, 'old share is the truth again');
    assert.equal(await linkTarget('acme/crash1'), resolvePath(ver('acme/crash1', SHA_A)));
    assert.equal((await readPointer(H(), 'acme/crash1'))?.commit, SHA_A);
    assert.equal(await exists(ver('acme/crash1', SHA_B)), true, 'staged new version kept (in progress)');
    hf.requests.length = 0;
    const s2 = await importHf(node, 'acme/crash1', { baseUrl: hf.base });
    assert.equal(hf.resolves('acme/crash1').length, 0, 'everything reused');
    assert.ok((await readFile(join(s2.dir, 'w.bin'))).equals(v2));
    assert.equal((await readPointer(H(), 'acme/crash1'))?.commit, SHA_B);
    assert.equal(await exists(ver('acme/crash1', SHA_A)), false);
  });

  test('A: crash after pointer (before link) and after link -> recover completes the promotion', async () => {
    for (const [name, crashAt] of [['acme/crash2', 'afterPointer'], ['acme/crash3', 'afterLink']] as const) {
      hf.set(name, { 'w.bin': { data: randomBytes(100) } });
      await importHf(node, name, { baseUrl: hf.base });
      const repo = hf.repos.get(name)!;
      const v2 = randomBytes(100);
      repo.commits[SHA_B] = { 'w.bin': { data: v2 } }; repo.head = SHA_B;
      await assert.rejects(importHf(node, name, { baseUrl: hf.base, crashAt }), /simulated crash/);
      const restored = (await node.recoverImports()).restore;
      const mine = restored.find((s) => s.name === name)!;
      assert.equal(mine.dir, link(name));
      assert.equal((await readPointer(H(), name))?.commit, SHA_B);
      assert.equal(await linkTarget(name), resolvePath(ver(name, SHA_B)), `${crashAt}: link repaired`);
      assert.equal(await exists(rec(name, SHA_B)), false, `${crashAt}: record cleared`);
      assert.equal(await exists(ver(name, SHA_A)), false, `${crashAt}: old version pruned`);
      assert.equal((await ownShare(name))?.ih, mine.ih);
      assert.ok((await readFile(join(link(name), 'w.bin'))).equals(v2));
    }
  });

  test('update while seeding: old torrent torn down, new one seeded, name repointed, exactly one own share', async () => {
    hf.set('acme/upd', { 'w.bin': { data: randomBytes(1000) } });
    const s1 = await importHf(node, 'acme/upd', { baseUrl: hf.base });
    const repo = hf.repos.get('acme/upd')!;
    const v2 = randomBytes(2000);
    repo.commits[SHA_B] = { 'w.bin': { data: v2 } }; repo.head = SHA_B;
    const s2 = await importHf(node, 'acme/upd', { baseUrl: hf.base });
    assert.notEqual(s1.ih, s2.ih);
    assert.equal(await seededFiles(s1.ih), undefined);
    assert.deepEqual(await seededFiles(s2.ih), ['upd/w.bin']);
    assert.ok((await readFile(join(s2.dir, 'w.bin'))).equals(v2));
    assert.equal((await node.shares()).filter((x) => x.name === 'acme/upd').length, 1);
    assert.equal((await router.resolve(`webway://${node.pk}/acme/upd`)).ih, s2.ih);
    assert.deepEqual((await readdir(dirname(ver('acme/upd')))).sort(), [VID(SHA_B), 'current.json'], 'only the current version remains');
  });

  test('F: a manifest file that vanishes after download is caught by the completeness check before promotion', async () => {
    hf.set('acme/vanish', { 'a.bin': { data: randomBytes(100) }, 'b.bin': { data: randomBytes(100) } });
    let done = 0;
    await fails(importHf(node, 'acme/vanish', { baseUrl: hf.base, onProgress: async (p) => {
      if (p.fileIndex === 1 && p.fileBytes === 100 && done++ === 0) await rm(join(ver('acme/vanish'), 'a.bin'));
    } }), /incomplete import: a\.bin missing/);
    assert.equal(await exists(pointerPath(H(), 'acme/vanish')), false);
  });

  // ---- C. per-repo lock -----------------------------------------------------------------

  test('C: two concurrent imports of the same repo -> one succeeds, the other refuses fast; published bytes are the winner\'s', async () => {
    const a = randomBytes(300);
    hf.set('acme/lock', { 'w.bin': { data: a } });
    let release!: () => void; const gate = new Promise<void>((r) => (release = r));
    let parked!: () => void; const reached = new Promise<void>((r) => (parked = r));
    let gated = false;
    const slow = async (url: any, init?: any) => { if (String(url).includes('/resolve/') && !gated) { gated = true; parked(); await gate; } return fetch(url, init); };
    const first = importHf(node, 'acme/lock', { baseUrl: hf.base, fetch: slow as typeof fetch });
    await reached; // first is now inside the lock, parked on the gate
    const t0 = Date.now();
    await assert.rejects(importHf(node, 'acme/lock', { baseUrl: hf.base, license: 'mit' }), /already in progress \(pid \d+\)/);
    assert.ok(Date.now() - t0 < 2000, 'refusal is fast');
    release();
    const s = await first;
    assert.equal(s.license, undefined, 'the winner\'s metadata, not the loser\'s');
    assert.ok((await readFile(join(s.dir, 'w.bin'))).equals(a));
    assert.equal(await exists(lockPath(H(), 'acme/lock')), false);
  });

  test('C: a stale lock (dead pid, old mtime) is broken; a fresh lock is honoured even with a dead pid', async () => {
    hf.set('acme/stale', { 'w.bin': { data: randomBytes(10) } });
    await lockDir('acme/stale', { pid: 999_999_999, startedAt: 'x', hostname: (await import('node:os')).hostname() });
    const old = new Date(Date.now() - 10 * 60_000); await utimes(lockPath(H(), 'acme/stale'), old, old);
    await importHf(node, 'acme/stale', { baseUrl: hf.base });
    await lockDir('acme/stale', { pid: 999_999_999, startedAt: 'x' }); // fresh mtime: heartbeat rule says live
    await fails(importHf(node, 'acme/stale', { baseUrl: hf.base }), /already in progress/);
    await lockDir('acme/stale', { pid: process.pid, startedAt: 'x' });
    await utimes(lockPath(H(), 'acme/stale'), old, old); // old mtime but our own live pid... start time mismatch -> stale
    await importHf(node, 'acme/stale', { baseUrl: hf.base });
    await rm(lockPath(H(), 'acme/stale'), { recursive: true, force: true });
  });

  // ---- 4/D. Range validation ------------------------------------------------------------

  const partialThen = async (name: string, mode: Mode | undefined, size = 6000, cut = 2500) => {
    const data = randomBytes(size);
    hf.set(name, { 'w.bin': { data, mode } });
    await stageRecord(name, { 'w.bin': { size } });
    await writeFile(join(ver(name), 'w.bin'), data.subarray(0, cut));
    hf.requests.length = 0;
    const fb: number[] = [];
    const s = await importHf(node, name, { baseUrl: hf.base, onProgress: (p) => fb.push(p.fileBytes) });
    assert.ok((await readFile(join(s.dir, 'w.bin'))).equals(data), 'final bytes correct');
    return { rs: hf.resolves(name), fb, data };
  };

  test('valid 206 with matching Content-Range resumes; only the tail is fetched; fileBytes starts at the offset', async () => {
    const { rs, fb } = await partialThen('acme/r-ok', undefined);
    assert.equal(rs.length, 1); assert.equal(rs[0].headers.range, 'bytes=2500-');
    assert.equal(fb[0], 2500); assert.equal(fb.at(-1), 6000);
    for (let i = 1; i < fb.length; i++) assert.ok(fb[i] >= fb[i - 1] && fb[i] <= 6000, 'fileBytes monotonic within bounds');
  });

  test('206 whose Content-Range start does not match the partial file -> restart from zero', async () => {
    const { rs, fb } = await partialThen('acme/r-start', 'badStart');
    assert.equal(rs.length, 2); assert.equal(rs[0].headers.range, 'bytes=2500-'); assert.equal(rs[1].headers.range, undefined);
    assert.equal(fb[0], 0, 'effective offset reported as 0 after restart'); assert.equal(fb.at(-1), 6000);
    assert.ok(fb.every((n) => n <= 6000));
  });

  test('206 whose total disagrees / without Content-Range / 416 -> restart from zero', async () => {
    for (const [n, m] of [['acme/r-total', 'badTotal'], ['acme/r-nocr', 'noContentRange'], ['acme/r-416', '416']] as const) {
      const { rs } = await partialThen(n, m);
      assert.equal(rs.length, 2, n); assert.equal(rs[1].headers.range, undefined, n);
    }
  });

  test('D: 206 "bytes 2-2/6" with a 4-byte body (end != total-1) -> rejected at the header, restart from zero', async () => {
    const { rs } = await partialThen('acme/r-end', 'badEnd', 6, 2);
    assert.equal(rs.length, 2); assert.equal(rs[0].headers.range, 'bytes=2-'); assert.equal(rs[1].headers.range, undefined);
  });

  test('D: valid Content-Range but body shorter than end-start+1 -> error, partial removed, nothing promoted', async () => {
    const data = randomBytes(6000);
    hf.set('acme/r-short', { 'w.bin': { data, mode: 'shortBody' } });
    await stageRecord('acme/r-short', { 'w.bin': { size: 6000 } });
    await writeFile(join(ver('acme/r-short'), 'w.bin'), data.subarray(0, 2500));
    await fails(importHf(node, 'acme/r-short', { baseUrl: hf.base }), /range body length 3 != 3500/);
    assert.equal(await exists(join(ver('acme/r-short'), 'w.bin')), false);
  });

  test('server ignores Range (200) -> single request, fileBytes 0 -> 6000, never above total', async () => {
    const { rs, fb } = await partialThen('acme/r-ign', 'ignoreRange');
    assert.equal(rs.length, 1);
    assert.equal(fb[0], 0); assert.equal(fb.at(-1), 6000); assert.ok(fb.every((n) => n <= 6000));
  });

  test('unsolicited 206 on a fresh download is an error', async () => {
    hf.set('acme/r-uns', { 'w.bin': { data: randomBytes(100), mode: 'unsolicited206' } });
    await fails(importHf(node, 'acme/r-uns', { baseUrl: hf.base }), /unsolicited partial/);
  });

  test('existing file larger than expected is restarted; complete-size staged file with wrong sha256 is re-downloaded', async () => {
    const data = randomBytes(5000);
    hf.set('acme/d3', { 'w.bin': { data } });
    await stageRecord('acme/d3', { 'w.bin': { size: 5000 } });
    await writeFile(join(ver('acme/d3'), 'w.bin'), randomBytes(9000));
    hf.requests.length = 0;
    const s = await importHf(node, 'acme/d3', { baseUrl: hf.base });
    assert.equal(hf.resolves('acme/d3')[0].headers.range, undefined);
    assert.ok((await readFile(join(s.dir, 'w.bin'))).equals(data));
    const d4 = randomBytes(4000);
    hf.set('acme/d4', { 'w.bin': { data: d4, lfs: true } });
    await stageRecord('acme/d4', { 'w.bin': { size: 4000, sha256: sha(d4) } });
    await writeFile(join(ver('acme/d4'), 'w.bin'), randomBytes(4000));
    hf.requests.length = 0;
    const s4 = await importHf(node, 'acme/d4', { baseUrl: hf.base });
    assert.equal(hf.resolves('acme/d4').length, 1);
    assert.ok((await readFile(join(s4.dir, 'w.bin'))).equals(d4));
  });

  test('size mismatch raises and removes the bad file; sha256 mismatch likewise; nothing promoted', async () => {
    hf.set('acme/e', { 'w.bin': { data: randomBytes(100), size: 999 } });
    await fails(importHf(node, 'acme/e', { baseUrl: hf.base }), /size mismatch/);
    assert.equal(await exists(join(ver('acme/e'), 'w.bin')), false);
    hf.set('acme/f', { 'w.bin': { data: randomBytes(100), lfs: true, sha256: 'ab'.repeat(32) } });
    await fails(importHf(node, 'acme/f', { baseUrl: hf.base }), /sha256 mismatch/);
    assert.equal(await exists(join(ver('acme/f'), 'w.bin')), false);
    assert.equal(await exists(link('acme/f')), false, 'nothing published');
  });

  test('downloadFile with no size and a partial file restarts cleanly', async () => {
    const data = randomBytes(2000);
    hf.set('acme/dl', { 'w.bin': { data } });
    const dest = join(root, 'dl', 'w.bin');
    await mkdir(join(root, 'dl'), { recursive: true });
    await writeFile(dest, data.subarray(0, 100));
    const got = await downloadFile(`${hf.base}/acme/dl/resolve/main/w.bin`, dest, { fetch });
    assert.equal(got, 2000);
    assert.ok((await readFile(dest)).equals(data));
  });

  // ---- 5. zero-byte files -------------------------------------------------------------

  test('zero-byte files are created without a request (no sha, correct sha) and rejected with a wrong sha', async () => {
    const EMPTY = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
    hf.set('acme/z1', { 'empty.txt': { data: Buffer.alloc(0) }, 'w.bin': { data: randomBytes(5) } });
    const s = await importHf(node, 'acme/z1', { baseUrl: hf.base });
    assert.equal((await stat(join(s.dir, 'empty.txt'))).size, 0);
    assert.deepEqual(hf.resolves('acme/z1').map((r) => r.url.split('/').pop()), ['w.bin']);
    assert.deepEqual(await seededFiles(s.ih), ['z1/empty.txt', 'z1/w.bin']);
    hf.set('acme/z2', { 'empty.txt': { data: Buffer.alloc(0), lfs: true, sha256: EMPTY } });
    const s2 = await importHf(node, 'acme/z2', { baseUrl: hf.base });
    assert.equal((await stat(join(s2.dir, 'empty.txt'))).size, 0);
    hf.set('acme/z3', { 'empty.txt': { data: Buffer.alloc(0), lfs: true, sha256: 'ab'.repeat(32) } });
    await fails(importHf(node, 'acme/z3', { baseUrl: hf.base }), /sha256 mismatch/);
    assert.equal(await exists(join(ver('acme/z3'), 'empty.txt')), false);
  });

  test('a non-ENOENT filesystem error is surfaced, not swallowed', async () => {
    hf.set('acme/z4', { 'd/w.bin': { data: randomBytes(5) } });
    await mkdir(ver('acme/z4'), { recursive: true });
    await writeFile(join(ver('acme/z4'), 'd'), 'i am a file, not a dir');
    await fails(importHf(node, 'acme/z4', { baseUrl: hf.base }), /not a directory/);
  });

  // ---- 6/E. bounds --------------------------------------------------------------------

  test('stream longer than the advertised size is aborted immediately and the file removed', async () => {
    hf.set('acme/over', { 'w.bin': { data: randomBytes(100), mode: 'oversize' } });
    await fails(importHf(node, 'acme/over', { baseUrl: hf.base }), /exceeds expected size/);
    assert.equal(await exists(join(ver('acme/over'), 'w.bin')), false);
  });

  test('E: endless unknown-size body is aborted at the per-file cap; a known size over the cap is refused before download', async () => {
    hf.set('acme/endless', { 'w.bin': { data: randomBytes(10), size: 'omit', mode: 'endless' } });
    await fails(importHf(node, 'acme/endless', { baseUrl: hf.base, limits: { maxFileBytes: 50_000 } }), /size limit \(50000 bytes\)/);
    assert.equal(await exists(join(ver('acme/endless'), 'w.bin')), false);
    hf.set('acme/toobig', { 'w.bin': { data: randomBytes(10), size: 60_000 } });
    await fails(importHf(node, 'acme/toobig', { baseUrl: hf.base, limits: { maxFileBytes: 50_000 } }), /per-file limit/);
    assert.equal(hf.resolves('acme/toobig').length, 0);
    hf.set('acme/total', { 'a.bin': { data: randomBytes(10), size: 'omit' }, 'b.bin': { data: randomBytes(10), size: 'omit' } });
    await fails(importHf(node, 'acme/total', { baseUrl: hf.base, limits: { maxTotalBytes: 15 } }), /size limit/);
  });

  test('stalled stream is aborted after stallMs', async () => {
    hf.set('acme/stall', { 'w.bin': { data: randomBytes(1000), mode: 'stall' } });
    const t0 = Date.now();
    await fails(importHf(node, 'acme/stall', { baseUrl: hf.base, stallMs: 300 }), /stalled/);
    assert.ok(Date.now() - t0 < 5000);
  });

  test('AbortSignal cancels: pre-aborted before API; aborted mid-download', async () => {
    hf.set('acme/ab', { 'w.bin': { data: randomBytes(50_000) } });
    await fails(importHf(node, 'acme/ab', { baseUrl: hf.base, signal: AbortSignal.abort(new Error('user cancelled')) }), /cancelled|abort/i);
    assert.equal(hf.requests.length, 0);
    const ctrl = new AbortController();
    await fails(importHf(node, 'acme/ab', { baseUrl: hf.base, signal: ctrl.signal, onProgress: (p) => { if (p.bytes > 0) ctrl.abort(new Error('stop now')); } }), /stop now|abort/i);
  });

  // ---- H. cancellation at the promotion boundary -----------------------------------------

  test('H: abort from the final progress callback -> nothing promoted (fresh import, and a zero-byte single-file import)', async () => {
    hf.set('acme/h1', { 'w.bin': { data: randomBytes(100) } });
    const c1 = new AbortController();
    await fails(importHf(node, 'acme/h1', { baseUrl: hf.base, signal: c1.signal, onProgress: (p) => { if (p.fileBytes === 100) c1.abort(new Error('late abort')); } }), /late abort/);
    assert.equal(await exists(pointerPath(H(), 'acme/h1')), false);
    assert.equal(await exists(link('acme/h1')), false);
    assert.equal(await ownShare('acme/h1'), undefined);
    hf.set('acme/h2', { 'empty.txt': { data: Buffer.alloc(0) } });
    const c2 = new AbortController();
    await fails(importHf(node, 'acme/h2', { baseUrl: hf.base, signal: c2.signal, onProgress: () => c2.abort(new Error('late abort')) }), /late abort/);
    assert.equal(await exists(pointerPath(H(), 'acme/h2')), false);
    assert.equal(await ownShare('acme/h2'), undefined);
  });

  test('H: abort from the final progress callback while updating -> old version stays current and seeded', async () => {
    const v1 = randomBytes(100);
    hf.set('acme/h3', { 'w.bin': { data: v1 } });
    const s1 = await importHf(node, 'acme/h3', { baseUrl: hf.base });
    const repo = hf.repos.get('acme/h3')!;
    repo.commits[SHA_B] = { 'w.bin': { data: randomBytes(100) } }; repo.head = SHA_B;
    const c = new AbortController();
    await fails(importHf(node, 'acme/h3', { baseUrl: hf.base, signal: c.signal, onProgress: (p) => { if (p.fileBytes === 100) c.abort(new Error('late abort')); } }), /late abort/);
    assert.equal((await readPointer(H(), 'acme/h3'))?.commit, SHA_A);
    assert.equal((await ownShare('acme/h3'))?.ih, s1.ih);
    assert.deepEqual(await seededFiles(s1.ih), ['h3/w.bin']);
    assert.ok((await readFile(join(link('acme/h3'), 'w.bin'))).equals(v1));
  });

  // ---- 8/I. publish constraints + node.share() safety -----------------------------------

  test('62-char model name fails before any request; 64-byte total name is accepted', async () => {
    const long = `org/${'m'.repeat(62)}`;
    await fails(importHf(node, long, { baseUrl: hf.base }), /64 bytes/);
    assert.equal(hf.requests.length, 0, 'no network traffic');
    const exact = `org/${'m'.repeat(60)}`; // 4 + 60 = 64 bytes
    hf.set(exact, { 'w.bin': { data: randomBytes(5) } });
    const s = await importHf(node, exact, { baseUrl: hf.base });
    assert.equal(s.name, exact);
  });

  test('oversized card license fails after metadata but before any download; explicit oversized --license fails before any request', async () => {
    hf.set('acme/lic', { 'w.bin': { data: randomBytes(5) } }, { cardData: { license: 'x'.repeat(65) } });
    await fails(importHf(node, 'acme/lic', { baseUrl: hf.base }), /license must be at most 64/);
    assert.equal(hf.resolves('acme/lic').length, 0);
    hf.requests.length = 0;
    await fails(importHf(node, 'acme/lic', { baseUrl: hf.base, license: 'y'.repeat(65) }), /license/);
    assert.equal(hf.requests.length, 0);
  });

  test('assertPublishable: name/license byte limits and control characters', () => {
    assertPublishable('a'.repeat(64), 'b'.repeat(64));
    assert.throws(() => assertPublishable('a'.repeat(65)), /64 bytes/);
    assert.throws(() => assertPublishable('é'.repeat(33)), /64 bytes/); // 66 bytes utf-8
    assert.throws(() => assertPublishable(''), /1\.\.64/);
    assert.throws(() => assertPublishable('a\x1bb'), /control/);
    assert.throws(() => assertPublishable('ok', 'x\ny'), /control/);
  });

  test('node.share: a name the DHT cannot carry is rejected with no share state written', async () => {
    const d = join(root, 'share-long'); await mkdir(d, { recursive: true }); await writeFile(join(d, 'w'), 'w');
    await assert.rejects(node.share(d, 'org/' + 'n'.repeat(70)), /64 bytes/);
    assert.equal((await node.shares()).some((s) => s.name.startsWith('org/nnn')), false);
  });

  test('I: node.share persists before publishing, rolls back on publish failure, and keeps the previous torrent seeding', async () => {
    const d1 = join(root, 'share-i-1'); await mkdir(d1, { recursive: true }); await writeFile(join(d1, 'w'), randomBytes(10));
    const d2 = join(root, 'share-i-2'); await mkdir(d2, { recursive: true }); await writeFile(join(d2, 'w'), randomBytes(10));
    const s1 = await node.share(d1, 'org/i-replace');
    const real = node.publishName.bind(node);
    let duringPublish: Share[] = [];
    node.publishName = async () => { duringPublish = await node.shares(); throw new Error('dht down'); };
    try { await assert.rejects(node.share(d2, 'org/i-replace'), /dht down/); } finally { node.publishName = real; }
    assert.ok(duringPublish.some((s) => s.own && s.name === 'org/i-replace' && s.dir === d2), 'new record was persisted before publishName ran');
    assert.equal((await ownShare('org/i-replace'))?.ih, s1.ih, 'rolled back to the previous record');
    assert.ok(await (node.client as any).get(s1.ih), 'previous torrent still seeding');
    assert.equal(node.client.torrents.some((t: any) => t.path === d2 || t.name === 'share-i-2'), false, 'new torrent destroyed');
  });

  test('I: seed() returning an already-existing torrent is never destroyed on publish failure', async () => {
    const d = join(root, 'share-i-alias'); await mkdir(d, { recursive: true }); await writeFile(join(d, 'w'), randomBytes(10));
    const s1 = await node.share(d, 'org/i-alias-1');
    const real = node.publishName.bind(node);
    node.publishName = async () => { throw new Error('dht down'); };
    try { await assert.rejects(node.share(d, 'org/i-alias-2'), /dht down/); } finally { node.publishName = real; }
    assert.ok(await (node.client as any).get(s1.ih), 'the shared torrent behind org/i-alias-1 survives');
    assert.equal(await ownShare('org/i-alias-2'), undefined);
    assert.equal((await ownShare('org/i-alias-1'))?.ih, s1.ih);
  });

  test('I: own shares are keyed by name; held shares with the same name are untouched by upsert and stopSharing', async () => {
    const d = join(root, 'share-i-held'); await mkdir(d, { recursive: true }); await writeFile(join(d, 'w'), randomBytes(10));
    const held: Share = { name: 'org/i-held', ih: 'f'.repeat(40), dir: join(root, 'nowhere'), size: 1, own: false };
    await writeFile(join(H(), 'shares.json'), JSON.stringify([...(await node.shares()), held]));
    const s = await node.share(d, 'org/i-held');
    const all = (await node.shares()).filter((x) => x.name === 'org/i-held');
    assert.equal(all.length, 2);
    assert.ok(all.some((x) => !x.own && x.ih === held.ih), 'held share preserved');
    assert.ok(all.some((x) => x.own && x.ih === s.ih));
    await node.stopSharing('org/i-held');
    assert.equal(await (node.client as any).get(s.ih), null, 'own torrent stopped');
    await node.share(d, 'org/i-held'); // re-share; the held record must still be there
    assert.equal((await node.shares()).filter((x) => x.name === 'org/i-held' && !x.own).length, 1);
  });

  // ---- 9. credentials -------------------------------------------------------------------

  test('gated repo: 401 without token gives HF_TOKEN guidance; explicit token sends Authorization on every request', async () => {
    const data = randomBytes(1000);
    hf.set('acme/gated', { 'w.bin': { data } }, { gated: true, cardData: { license: 'llama3' } });
    await fails(importHf(node, 'acme/gated', { baseUrl: hf.base }), /HF_TOKEN/);
    await fails(importHf(node, 'acme/gated', { baseUrl: hf.base, token: 'bad' }), /HF_TOKEN/);
    hf.requests.length = 0;
    const s = await importHf(node, 'acme/gated', { baseUrl: hf.base, token: 'good-token' });
    assert.ok(hf.requests.every((r) => r.headers.authorization === 'Bearer good-token'));
    assert.ok((await readFile(join(s.dir, 'w.bin'))).equals(data));
  });

  test('HF_TOKEN from the environment is NOT sent to a custom baseUrl, but IS used for the real origin', async () => {
    hf.set('acme/tok', { 'w.bin': { data: randomBytes(10) } });
    process.env.HF_TOKEN = 'ambient-secret';
    try {
      await importHf(node, 'acme/tok', { baseUrl: hf.base });
      assert.ok(hf.requests.length > 0);
      assert.ok(hf.requests.every((r) => r.headers.authorization === undefined), 'ambient token must not leak to a mirror');
      let seen: string | undefined;
      const f = async (url: any, init?: any) => { seen = init?.headers?.authorization; return new Response('{}', { status: 404 }); };
      await fails(importHf(node, 'acme/real', { fetch: f as typeof fetch }), /not found/);
      assert.equal(seen, 'Bearer ambient-secret');
    } finally { delete process.env.HF_TOKEN; }
  });

  test('403 on a file resolve (gated at download time) gives HF_TOKEN guidance', async () => {
    const repo: MockRepo = { head: SHA_A, commits: { [SHA_A]: { 'w.bin': { data: randomBytes(10) } } } };
    hf.repos.set('acme/h', repo);
    const f = async (url: any, init?: any) => { const r = await fetch(url, init); repo.gated = true; return r; };
    await fails(importHf(node, 'acme/h', { baseUrl: hf.base, fetch: f as typeof fetch }), /HF_TOKEN/);
  });

  test('error messages never include query strings or userinfo from URLs', async () => {
    const dest = join(root, 'q', 'w.bin'); await mkdir(join(root, 'q'), { recursive: true });
    const clean = (e: Error) => { assert.ok(!/SECRET|sig=abc|user:pw/.test(e.message), e.message); return true; };
    await assert.rejects(downloadFile(`${hf.base}/nope/nope/resolve/main/w.bin?token=SECRET&sig=abc`, dest, { fetch }), (e: Error) => clean(e) && /download failed \(404\)/.test(e.message));
    // fetch itself refuses credentialed URLs, and its own error text echoes the URL: that must be redacted too.
    await assert.rejects(downloadFile(`${hf.base.replace('//', '//user:pw@')}/nope/nope/resolve/main/w.bin`, dest, { fetch }), clean);
  });

  test('a connection-level failure (stale keep-alive socket, ECONNRESET) is retried once; persistent failure surfaces', async () => {
    hf.set('acme/reset', { 'w.bin': { data: randomBytes(10) } });
    let calls = 0; let failed = false;
    const flaky = async (url: any, init?: any) => {
      calls++;
      if (!failed) { failed = true; throw new TypeError('fetch failed', { cause: Object.assign(new Error('read ECONNRESET'), { code: 'ECONNRESET' }) }); }
      return fetch(url, init);
    };
    await importHf(node, 'acme/reset', { baseUrl: hf.base, fetch: flaky as typeof fetch });
    assert.equal(calls, 3, 'api (failed + retried) + one resolve');
    const dead = async () => { throw new TypeError('fetch failed', { cause: Object.assign(new Error('read ECONNRESET'), { code: 'ECONNRESET' }) }); };
    await fails(importHf(node, 'acme/reset', { baseUrl: hf.base, fetch: dead as typeof fetch }), /fetch failed/);
    let n = 0; const counted = async () => { n++; throw new TypeError('fetch failed', { cause: Object.assign(new Error('bad cert'), { code: 'CERT_HAS_EXPIRED' }) }); };
    await fails(importHf(node, 'acme/reset', { baseUrl: hf.base, fetch: counted as typeof fetch }), /fetch failed/);
    assert.equal(n, 1, 'non-transient failures are not retried');
  });

  test('404 model gives a clear error; other API errors surface status; revision appears in message and API path', async () => {
    await fails(importHf(node, 'acme/nope', { baseUrl: hf.base }), /not found: acme\/nope/);
    hf.set('acme/broken', {}, { status: 500 });
    await fails(importHf(node, 'acme/broken', { baseUrl: hf.base }), /API 500/);
    await fails(importHf(node, 'acme/nope', { baseUrl: hf.base, revision: 'v9' }), /acme\/nope @ v9/);
    hf.set('acme/r', { 'w.bin': { data: randomBytes(10) } }, { head: SHA_C, commits: { [SHA_C]: { 'w.bin': { data: randomBytes(10) } } } });
    hf.requests.length = 0;
    await importHf(node, 'acme/r', { baseUrl: hf.base, revision: 'v2' });
    assert.ok(hf.requests[0].url.startsWith('/api/models/acme/r/revision/v2?blobs=true'), hf.requests[0].url);
    assert.ok(hf.resolves('acme/r')[0].url.endsWith(`/resolve/${SHA_C}/w.bin`));
  });

  // ---- 10. terminal safety ---------------------------------------------------------------

  test('filenames with control characters are rejected at validation, before any download', async () => {
    hf.set('acme/ctl', { 'w\x1b[2J.bin': { data: randomBytes(5) } });
    await fails(importHf(node, 'acme/ctl', { baseUrl: hf.base }), /control characters/);
    assert.equal(hf.resolves('acme/ctl').length, 0);
    hf.set('acme/ctl2', { 'w\r.bin': { data: randomBytes(5) } });
    await fails(importHf(node, 'acme/ctl2', { baseUrl: hf.base }), /control characters/);
  });

  test('CLI formatters escape untrusted strings (captured output)', () => {
    assert.equal(esc('a\x1b[2Jb\r\nc'), 'a\\x1b[2Jb\\x0d\\x0ac');
    const out = formatShared('pk', { name: 'org/model', size: 1000, license: 'mit\x1b[2J', ih: 'ih' });
    assert.ok(!out.includes('\x1b')); assert.ok(out.includes('[mit\\x1b[2J]'));
    const line = formatImportProgress({ fileIndex: 0, fileCount: 2, file: 'w\x07.bin', fileBytes: 10, fileTotal: 20 });
    assert.equal(line, '  [1/2] w\\x07.bin 0 kB/0 kB');
    assert.ok(!line.includes('\x07'));
  });

  // ---- 12/J. CLI argument parsing ---------------------------------------------------------

  test('parse: flags require values; a following --flag is not a value', () => {
    assert.throws(() => parse(['import', 'org/model', '--license']), /missing value for --license/);
    assert.throws(() => parse(['import', 'org/model', '--revision', '--license', 'mit']), /missing value for --revision/);
    assert.deepEqual(parse(['import', 'org/model', '--revision', 'v2', '--license', 'mit']), { args: ['import', 'org/model'], flags: { revision: ['v2'], license: ['mit'] } });
    assert.deepEqual(parse(['serve', '--peer', 'a:1', '--peer', 'b:2']).flags, { peer: ['a:1', 'b:2'] });
  });

  test('J: checkArgs rejects extra positionals for every command and unknown commands', () => {
    for (const [cmd, ok, extra] of [['id', [], ['x']], ['share', ['d'], ['d', 'x']], ['import', ['o/m'], ['o/m', 'x']], ['get', ['r'], ['r', 'x']], ['serve', [], ['x']], ['resolve', ['r'], ['r', 'x']], ['follow', ['pk'], ['pk', 'x']], ['ls', [], ['x']]] as const) {
      assert.doesNotThrow(() => checkArgs(cmd, [...ok]), cmd);
      assert.throws(() => checkArgs(cmd, [...extra]), /unexpected argument: x/, cmd);
    }
    assert.doesNotThrow(() => checkArgs('search', ['a', 'b', 'c']));
    assert.throws(() => checkArgs('search', []), /usage: webway search/);
    assert.throws(() => checkArgs('import', []), /usage: webway import/);
    assert.throws(() => checkArgs('bogus', []), /unknown command: bogus/);
  });

  test('CLI process: bad arguments exit 1 with the message, before the node starts', () => {
    const run = (...a: string[]) => spawnSync(process.execPath, ['--experimental-strip-types', join(process.cwd(), 'src', 'cli.ts'), ...a], { encoding: 'utf8', env: { ...process.env, WEBWAY_HOME: join(root, 'cli-home') }, timeout: 20_000 });
    const cases: [string[], RegExp][] = [
      [['import', 'org/model', '--license'], /missing value for --license/],
      [['import', 'org/model', '--revision', '--license', 'mit'], /missing value for --revision/],
      [['import'], /usage: webway import/],
      [['import', 'org/model', 'unexpected'], /unexpected argument: unexpected/],
      [['share', '/tmp/x'], /usage: webway share/],
      [['get', 'x', '--dht-port', 'abc'], /--dht-port must be a port number/],
      [['import', 'org/' + 'n'.repeat(70)], /64 bytes/],
      [['ls', 'extra'], /unexpected argument/],
      [['frobnicate'], /unknown command: frobnicate/],
    ];
    for (const [args, re] of cases) { const r = run(...args); assert.equal(r.status, 1, args.join(' ')); assert.match(r.stderr, re); }
  });


  // ---- round 3: retention, journal, locks, transactions --------------------------------

  test('R1: catalog failure after the name is published -> committed: new version stays, share intact, warning returned', async () => {
    hf.set('acme/cat', { 'w.bin': { data: randomBytes(100) } });
    const s1 = await importHf(node, 'acme/cat', { baseUrl: hf.base });
    const repo = hf.repos.get('acme/cat')!;
    const v2 = randomBytes(100);
    repo.commits[SHA_B] = { 'w.bin': { data: v2 } }; repo.head = SHA_B;
    const real = node.publishCatalog.bind(node);
    node.publishCatalog = async () => { throw new Error('catalog put failed'); };
    let s2;
    try { s2 = await importHf(node, 'acme/cat', { baseUrl: hf.base }); } finally { node.publishCatalog = real; }
    assert.match(s2.warning ?? '', /catalog publish failed.*catalog put failed/);
    assert.notEqual(s2.ih, s1.ih);
    assert.equal((await ownShare('acme/cat'))?.ih, s2.ih);
    assert.equal((await readPointer(H(), 'acme/cat'))?.commit, SHA_B);
    assert.equal(await exists(ver('acme/cat', SHA_B)), true, 'new version dir kept');
    assert.ok((await readFile(join(link('acme/cat'), 'w.bin'))).equals(v2));
    assert.deepEqual(await seededFiles(s2.ih), ['cat/w.bin']);
    assert.equal((await router.resolve(`webway://${node.pk}/acme/cat`)).ih, s2.ih);
    // node.share() directly: same contract.
    const d = join(root, 'share-cat'); await mkdir(d, { recursive: true }); await writeFile(join(d, 'w'), randomBytes(10));
    node.publishCatalog = async () => { throw new Error('catalog put failed'); };
    let s3;
    try { s3 = await node.share(d, 'org/cat-direct'); } finally { node.publishCatalog = real; }
    assert.match(s3.warning ?? '', /catalog/);
    assert.equal((await ownShare('org/cat-direct'))?.ih, s3.ih);
    assert.ok(!('warning' in ((await ownShare('org/cat-direct')) as any)), 'warning is not persisted');
  });

  test('R2: a .gitattributes-only update yields the same infohash -> current untouched, seeding intact, duplicate dir dropped', async () => {
    hf.set('acme/ga', { 'w.bin': { data: randomBytes(100) }, '.gitattributes': { data: Buffer.from('a') } });
    const s1 = await importHf(node, 'acme/ga', { baseUrl: hf.base });
    const repo = hf.repos.get('acme/ga')!;
    repo.commits[SHA_B] = { 'w.bin': repo.commits[SHA_A]['w.bin'], '.gitattributes': { data: Buffer.from('b') } }; repo.head = SHA_B;
    const s2 = await importHf(node, 'acme/ga', { baseUrl: hf.base });
    assert.equal(s2.ih, s1.ih);
    assert.equal((await readPointer(H(), 'acme/ga'))?.commit, SHA_A, 'current stays on the version that backs the live torrent');
    assert.equal(await linkTarget('acme/ga'), resolvePath(ver('acme/ga', SHA_A)));
    assert.equal(await exists(ver('acme/ga', SHA_A)), true);
    assert.equal(await exists(ver('acme/ga', SHA_B)), false, 'duplicate content dropped');
    assert.deepEqual(await seededFiles(s1.ih), ['ga/w.bin'], 'still seeding from the old dir');
    assert.ok(node.isBacking(ver('acme/ga', SHA_A)));
    assert.ok((await readFile(join(link('acme/ga'), 'w.bin'))).equals(repo.commits[SHA_A]['w.bin'].data));
  });

  test('R2: an alias share that keeps the old torrent alive keeps its backing dir through an update', async () => {
    hf.set('acme/alias', { 'w.bin': { data: randomBytes(100) } });
    const s1 = await importHf(node, 'acme/alias', { baseUrl: hf.base });
    await node.share(ver('acme/alias', SHA_A), 'acme/alias-v1', undefined, { torrentName: 'alias' }); // second own name on the same torrent + dir
    const repo = hf.repos.get('acme/alias')!;
    repo.commits[SHA_B] = { 'w.bin': { data: randomBytes(100) } }; repo.head = SHA_B;
    const s2 = await importHf(node, 'acme/alias', { baseUrl: hf.base });
    assert.notEqual(s2.ih, s1.ih);
    assert.ok(await (node.client as any).get(s1.ih), 'old torrent still alive for the alias');
    assert.equal(await exists(ver('acme/alias', SHA_A)), true, 'its backing dir was retained');
    assert.equal((await readPointer(H(), 'acme/alias'))?.commit, SHA_B);
    assert.deepEqual(await seededFiles(s2.ih), ['alias/w.bin']);
  });

  test('R3: recovery running while another importer holds the lock skips that repo; a committed new current survives', async () => {
    hf.set('acme/race', { 'w.bin': { data: randomBytes(100) } });
    await importHf(node, 'acme/race', { baseUrl: hf.base });
    const repo = hf.repos.get('acme/race')!;
    repo.commits[SHA_B] = { 'w.bin': { data: randomBytes(100) } }; repo.head = SHA_B;
    let release!: () => void; const gate = new Promise<void>((r) => (release = r));
    let parked!: () => void; const reached = new Promise<void>((r) => (parked = r));
    let gated = false;
    const slow = async (url: any, init?: any) => { if (String(url).includes('/resolve/') && !gated) { gated = true; parked(); await gate; } return fetch(url, init); };
    const importing = importHf(node, 'acme/race', { baseUrl: hf.base, fetch: slow as typeof fetch });
    await reached;
    const rec1 = await node.recoverImports();
    assert.ok(rec1.skipped.includes('acme/race'), 'locked repo skipped');
    release();
    const s2 = await importing;
    const rec2 = await node.recoverImports();
    assert.ok(!rec2.skipped.includes('acme/race'));
    assert.equal((await readPointer(H(), 'acme/race'))?.commit, SHA_B);
    assert.equal(await exists(ver('acme/race', SHA_B)), true, 'new current survives recovery');
    assert.equal((await ownShare('acme/race'))?.ih, s2.ih);
  });

  test('R4: lock protocol: a live holder with heartbeat is not reclaimed past the stale window; a dead holder is; two reclaimers -> one winner', async () => {
    const dir = join(H(), 'locks', 'proto.lock');
    // Live holder with a fast heartbeat and a tiny stale window: contender never wins.
    const holder = (await Lock.tryAcquire(dir, { heartbeatMs: 20, staleMs: 120 }))!;
    assert.ok(holder);
    await new Promise((r) => setTimeout(r, 400)); // > staleMs, but the heartbeat keeps mtime fresh
    assert.equal(await Lock.tryAcquire(dir, { staleMs: 120 }), undefined, 'live holder honoured');
    await holder.release();
    // Dead holder: old mtime + dead pid -> reclaimed.
    await mkdir(dir); await writeFile(join(dir, 'owner.json'), JSON.stringify({ pid: 999_999_999, startedAt: 'gone', hostname: (await import('node:os')).hostname() }));
    const old = new Date(Date.now() - 1000); await utimes(dir, old, old);
    const [a, b] = await Promise.all([Lock.tryAcquire(dir, { staleMs: 100 }), Lock.tryAcquire(dir, { staleMs: 100 })]);
    assert.equal([a, b].filter(Boolean).length, 1, 'exactly one reclaimer wins');
    await (a ?? b)!.release();
    assert.equal(await exists(dir), false);
    assert.deepEqual((await readdir(join(H(), 'locks'))).filter((n) => n.startsWith('proto.lock')), [], 'stale-aside dirs cleaned up');
  });

  test('R7: incomplete owner.json falls back to the mtime rule: old -> reclaimed, fresh -> live', async () => {
    const dir = join(H(), 'locks', 'partial.lock');
    await mkdir(dir); await writeFile(join(dir, 'owner.json'), '');
    assert.equal(await Lock.tryAcquire(dir, { staleMs: 100 }), undefined, 'fresh mtime: treated as live');
    const old = new Date(Date.now() - 1000); await utimes(dir, old, old);
    const l = await Lock.tryAcquire(dir, { staleMs: 100 });
    assert.ok(l, 'old mtime: reclaimed');
    await l!.release();
    await mkdir(dir); // no owner.json at all, old mtime
    await utimes(dir, old, old);
    const l2 = await Lock.tryAcquire(dir, { staleMs: 100 });
    assert.ok(l2); await l2!.release();
  });

  test('R5: pending journal with no pointer: completed when the share record + content exist', async () => {
    hf.set('acme/pend1', { 'w.bin': { data: randomBytes(100) } });
    await assert.rejects(importHf(node, 'acme/pend1', { baseUrl: hf.base, crashAt: 'afterShare' }), /simulated/);
    assert.equal(await readPointer(H(), 'acme/pend1'), undefined);
    assert.equal(await exists(pendingPath(H(), 'acme/pend1', VID(SHA_A))), true, 'journal present');
    const r = await node.recoverImports();
    const mine = r.restore.find((s) => s.name === 'acme/pend1')!;
    assert.ok(mine, 'promotion completed by recovery');
    assert.equal((await readPointer(H(), 'acme/pend1'))?.commit, SHA_A);
    assert.equal(await linkTarget('acme/pend1'), resolvePath(ver('acme/pend1')));
    assert.equal(await exists(pendingPath(H(), 'acme/pend1', VID(SHA_A))), false);
    assert.equal((await ownShare('acme/pend1'))?.ih, mine.ih);
  });

  test('R5: pending journal with no pointer and no share record: record dropped, content not promoted', async () => {
    hf.set('acme/pend2', { 'w.bin': { data: randomBytes(100) } });
    await assert.rejects(importHf(node, 'acme/pend2', { baseUrl: hf.base, crashAt: 'afterShare' }), /simulated/);
    // Simulate the share record having been lost (e.g. persisted on a different disk state).
    await writeFile(join(H(), 'shares.json'), JSON.stringify((await node.shares()).filter((s) => s.name !== 'acme/pend2')));
    const r = await node.recoverImports();
    assert.equal(r.restore.some((s) => s.name === 'acme/pend2'), false);
    assert.equal(await readPointer(H(), 'acme/pend2'), undefined);
    assert.equal(await exists(link('acme/pend2')), false);
    assert.equal(await exists(pendingPath(H(), 'acme/pend2', VID(SHA_A))), false, 'journal cleared');
    assert.equal(await ownShare('acme/pend2'), undefined);
  });

  test('R5: cancellation during share drops the name from our re-put set', async () => {
    hf.set('acme/canc', { 'w.bin': { data: randomBytes(100) } });
    const c = new AbortController();
    const real = node.publishName.bind(node);
    node.publishName = async (s) => { await real(s); c.abort(new Error('cancel during share')); };
    try { await assert.rejects(importHf(node, 'acme/canc', { baseUrl: hf.base, signal: c.signal }), /cancel during share/); } finally { node.publishName = real; }
    assert.equal(await ownShare('acme/canc'), undefined);
    assert.equal((await node.held())[`${node.pk}/acme/canc`], undefined);
    assert.equal(await readPointer(H(), 'acme/canc'), undefined);
    assert.equal(await exists(pendingPath(H(), 'acme/canc', VID(SHA_A))), false);
    assert.equal(node.client.torrents.some((t: any) => t.name === 'canc'), false, 'torrent dropped');
  });

  test('R5: link repair failure aborts that repo\'s recovery before any pruning', async () => {
    hf.set('acme/linkfail', { 'w.bin': { data: randomBytes(100) } });
    await importHf(node, 'acme/linkfail', { baseUrl: hf.base });
    const repo = hf.repos.get('acme/linkfail')!;
    repo.commits[SHA_B] = { 'w.bin': { data: randomBytes(100) } }; repo.head = SHA_B;
    await assert.rejects(importHf(node, 'acme/linkfail', { baseUrl: hf.base, crashAt: 'afterPointer' }), /simulated/);
    // Make link repair impossible: a real directory where the symlink should go.
    await rm(link('acme/linkfail'), { force: true }); await mkdir(link('acme/linkfail'));
    const r = await node.recoverImports();
    assert.ok(r.errors.some((e) => e.repo === 'acme/linkfail' && /real directory/.test(e.error)));
    assert.equal(await exists(ver('acme/linkfail', SHA_A)), true, 'old version NOT pruned');
    assert.equal(await exists(ver('acme/linkfail', SHA_B)), true);
    await rm(link('acme/linkfail'), { recursive: true, force: true });
    await node.recoverImports();
    assert.equal(await linkTarget('acme/linkfail'), resolvePath(ver('acme/linkfail', SHA_B)));
  });

  test('R6: a share that succeeds while another share\'s DHT publish fails keeps both records correct', async () => {
    const d1 = join(root, 'txn-1'); await mkdir(d1, { recursive: true }); await writeFile(join(d1, 'w'), randomBytes(10));
    const d2 = join(root, 'txn-2'); await mkdir(d2, { recursive: true }); await writeFile(join(d2, 'w'), randomBytes(10));
    const real = node.publishName.bind(node);
    let release!: () => void; const gate = new Promise<void>((r) => (release = r));
    node.publishName = async (s) => { if (s.name === 'org/txn-fail') { await gate; throw new Error('dht down'); } return real(s); };
    try {
      const failing = node.share(d1, 'org/txn-fail');
      await new Promise((r) => setTimeout(r, 50));
      const ok = await node.share(d2, 'org/txn-ok'); // completes while the other is stuck in publishName
      release();
      await assert.rejects(failing, /dht down/);
      assert.equal((await ownShare('org/txn-ok'))?.ih, ok.ih, 'unrelated successful share survived the rollback');
      assert.equal(await ownShare('org/txn-fail'), undefined);
    } finally { node.publishName = real; }
  });

  test('O1/N2: the version dir swapped underneath the import (parent replaced) is detected before the write', async () => {
    hf.set('acme/swap', { 'a.bin': { data: randomBytes(100) }, 'b.bin': { data: randomBytes(100) } });
    await fails(importHf(node, 'acme/swap', { baseUrl: hf.base, beforeWrite: async (f) => {
      if (f === 'b.bin') { await rename(ver('acme/swap'), ver('acme/swap') + '.moved'); await mkdir(ver('acme/swap')); }
    } }), /version dir changed underneath/);
    assert.equal(await exists(join(ver('acme/swap'), 'b.bin')), false, 'nothing written into the impostor dir');
    await rm(ver('acme/swap') + '.moved', { recursive: true, force: true });
  });

  test('imported model is resolvable by signed name from another node and is being seeded', async () => {
    const data = randomBytes(64 * 1024);
    hf.set('acme/live', { 'w.bin': { data, lfs: true } }, { cardData: { license: 'mit' } });
    const s = await importHf(node, 'acme/live', { baseUrl: hf.base });
    const mine = await ownShare('acme/live');
    assert.ok(mine && mine.ih === s.ih);
    assert.deepEqual(await seededFiles(s.ih), ['live/w.bin']);
    const r = await router.resolve(`webway://${node.pk}/acme/live`);
    assert.equal(r.ih, s.ih); assert.equal(r.license, 'mit');
  });

  test('blobSha1 matches git', async () => {
    const p = join(root, 'blob.txt'); await writeFile(p, 'hello\n');
    assert.equal(await blobSha1(p, 6), 'ce013625030ba8dba906f756967f9e9ca394464a');
  });
});

test('live: hf-internal-testing/tiny-random-gpt2', { skip: !process.env.WEBWAY_LIVE }, async () => {
  const root = await mkdtemp(join(tmpdir(), 'webway-hf-live-'));
  const router = await new WebwayNode({ home: join(root, 'router'), bootstrap: false, nat: false }).start();
  const node = await new WebwayNode({ home: join(root, 'home'), bootstrap: [`127.0.0.1:${router.dht.address().port}`], nat: false }).start();
  try {
    const s = await importHf(node, 'hf://hf-internal-testing/tiny-random-gpt2', {});
    assert.equal(s.name, 'hf-internal-testing/tiny-random-gpt2');
    assert.ok(s.size > 0);
    assert.ok((await stat(join(s.dir, 'config.json'))).size > 0);
    assert.ok((await stat(join(s.dir, 'model.safetensors'))).size > 0);
    console.log(`  live import ok: ${s.size} bytes, license=${s.license}, ih=${s.ih}`);
  } finally { await node.stop(); await router.stop(); }
});
