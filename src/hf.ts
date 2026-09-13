import { createHash } from 'node:crypto';
import { constants as FS, createReadStream } from 'node:fs';
import { copyFile, lstat, mkdir, open, readdir, rm, stat } from 'node:fs/promises';
import { createHash as _h } from 'node:crypto';
import { dirname, join, resolve as resolvePath, sep } from 'node:path';
import { pipeline } from 'node:stream/promises';
import { Readable } from 'node:stream';
import { assertPublishable, type WebwayNode, type Share } from './node.ts';
import {
  assertNoSymlinkBelow, ensureRealDir, modelLink, pendingPath, pruneVersions, readJsonOr, readPointer, recordPath, setModelLink,
  versionDir, withRepoLock, writeJsonAtomic, writePointer, type VersionPointer,
} from './versions.ts';

export interface HfSibling { rfilename: string; size?: number; lfs?: { sha256?: string; size?: number } }
export interface HfModelInfo { id?: string; sha?: string; siblings?: HfSibling[]; cardData?: { license?: string | string[] }; tags?: string[] }

/** One validated manifest entry. */
export interface ManifestFile { path: string; size?: number; sha256?: string }
export interface Manifest { commit: string; files: ManifestFile[] }

export interface ImportProgress {
  file: string;
  fileBytes: number;      // bytes on disk for this file so far (effective offset after resume/restart decisions)
  fileTotal?: number;     // expected size if known
  bytes: number;          // total bytes downloaded this run (monotonic)
  fileIndex: number;
  fileCount: number;
}

export interface Limits {
  maxFiles: number;          // manifest entries
  maxDepth: number;          // path components
  maxMetadataBytes: number;  // API JSON body
  maxFileBytes: number;      // any single file (known or unknown size)
  maxTotalBytes: number;     // whole import
}
export const DEFAULT_LIMITS: Limits = { maxFiles: 10_000, maxDepth: 16, maxMetadataBytes: 32 * 1024 * 1024, maxFileBytes: 200 * 1024 ** 3, maxTotalBytes: 2 * 1024 ** 4 };

export interface ImportOpts {
  revision?: string;
  /** Sent as a bearer token. Defaults to HF_TOKEN only when baseUrl is the real HuggingFace origin. */
  token?: string;
  baseUrl?: string;
  license?: string; // override the model card
  onProgress?: (p: ImportProgress) => void;
  fetch?: typeof fetch;
  signal?: AbortSignal;
  stallMs?: number;  // abort any response that delivers no bytes for this long (default 60s)
  limits?: Partial<Limits>;
  /** Test hook: throw at a promotion step boundary to simulate a crash. */
  crashAt?: 'afterShare' | 'afterPointer' | 'afterLink';
  /** Test hook: runs right before each file is written (after containment checks). */
  beforeWrite?: (file: string) => Promise<void> | void;
}

/** Version id: the commit, plus an origin tag when the bytes did not come from huggingface.co. */
export function versionIdFor(commit: string, origin: string): string {
  return origin === HF_ORIGIN ? commit : `${commit}-${_h('sha1').update(origin).digest('hex').slice(0, 8)}`;
}

export const HF_ORIGIN = 'https://huggingface.co';
export const SKIP = new Set(['.gitattributes']);
const DEFAULT_STALL_MS = 60_000;

/** Accepts `hf://org/model`, `https://huggingface.co/org/model`, or bare `org/model`. */
export function parseHfRef(ref: string): string {
  const r = ref.trim().replace(/^hf:\/\//i, '').replace(/^https?:\/\/(www\.)?huggingface\.co\//i, '').replace(/\/+$/, '');
  const m = /^([A-Za-z0-9][\w.-]*)\/([A-Za-z0-9][\w.-]*)$/.exec(r);
  if (!m) throw new Error(`not a HuggingFace model ref: ${redact(ref)} (want hf://org/model)`);
  return `${m[1]}/${m[2]}`;
}

export function licenseOf(info: HfModelInfo): string | undefined {
  const c = info.cardData?.license;
  if (Array.isArray(c) && c.length && typeof c[0] === 'string') return c[0];
  if (typeof c === 'string' && c) return c;
  const t = info.tags?.find((x) => typeof x === 'string' && x.startsWith('license:'));
  return t ? t.slice('license:'.length) : undefined;
}

/** Strip userinfo, query strings and fragments so signed URLs / tokens never land in error text. */
export function redact(s: string): string {
  return s.replace(/\/\/[^/@\s]*@/g, '//').replace(/[?#][^\s]*/g, '').replace(/[\x00-\x1f\x7f-\x9f]/g, (c) => `\\x${c.charCodeAt(0).toString(16).padStart(2, '0')}`);
}

// ---- manifest validation ---------------------------------------------------

const CONTROL = /[\x00-\x1f\x7f-\x9f]/;
const WIN_INVALID = /[<>:"|?*]/;
const HEX64 = /^[0-9a-f]{64}$/;
const HEX40 = /^[0-9a-f]{40}$/;
const fold = (s: string) => s.normalize('NFKC').toLowerCase();

function isSafeSize(n: unknown): n is number { return typeof n === 'number' && Number.isSafeInteger(n) && n >= 0; }

/** Validate one relative path from the API. Returns the normalised posix path. */
export function validatePath(p: unknown, limits: Limits = DEFAULT_LIMITS): string {
  if (typeof p !== 'string' || !p.length) throw new Error('manifest: rfilename must be a non-empty string');
  const shown = redact(p);
  if (CONTROL.test(p)) throw new Error(`manifest: control characters in path: ${shown}`);
  if (p.includes('\\')) throw new Error(`manifest: backslash in path: ${shown}`);
  if (p.startsWith('/')) throw new Error(`manifest: absolute path: ${shown}`);
  if (/^[A-Za-z]:/.test(p) || p.includes(':')) throw new Error(`manifest: drive or UNC form in path: ${shown}`);
  if (WIN_INVALID.test(p)) throw new Error(`manifest: character not allowed in a filename: ${shown}`);
  const parts = p.split('/');
  if (parts.length > limits.maxDepth) throw new Error(`manifest: path deeper than ${limits.maxDepth}: ${shown}`);
  if (parts.some((x) => x === '' || x === '.' || x === '..')) throw new Error(`manifest: unsafe path component: ${shown}`);
  if (parts.some((x) => /^(con|prn|aux|nul|com\d|lpt\d)(\..*)?$/i.test(x))) throw new Error(`manifest: reserved device name in path: ${shown}`);
  if (parts.some((x) => x.endsWith(' ') || x.endsWith('.'))) throw new Error(`manifest: path component ends with space or dot: ${shown}`);
  return parts.join('/');
}

/**
 * Runtime schema validation of the API JSON. Nothing touches the filesystem until this passes.
 * Returns the pinned commit and the files to fetch (with .gitattributes dropped).
 */
export function validateManifest(info: unknown, limits: Limits = DEFAULT_LIMITS): Manifest {
  if (!info || typeof info !== 'object' || Array.isArray(info)) throw new Error('manifest: API response is not an object');
  const i = info as Record<string, unknown>;
  if (typeof i.sha !== 'string' || !HEX40.test(i.sha)) throw new Error('manifest: API did not return a commit sha');
  if (!Array.isArray(i.siblings)) throw new Error('manifest: siblings must be an array');
  if (i.siblings.length > limits.maxFiles) throw new Error(`manifest: ${i.siblings.length} files exceeds limit of ${limits.maxFiles}`);
  const files: ManifestFile[] = [];
  const seen = new Set<string>();
  const spelling = new Map<string, string>(); // folded prefix/path -> the one exact spelling allowed
  const dirs = new Set<string>();             // folded directory prefixes
  let total = 0;
  for (const s of i.siblings as unknown[]) {
    if (!s || typeof s !== 'object' || Array.isArray(s)) throw new Error('manifest: sibling is not an object');
    const sib = s as Record<string, unknown>;
    const path = validatePath(sib.rfilename, limits);
    if (sib.size !== undefined && !isSafeSize(sib.size)) throw new Error(`manifest: bad size for ${redact(path)}`);
    let sha256: string | undefined;
    let lfsSize: number | undefined;
    if (sib.lfs !== undefined) {
      if (!sib.lfs || typeof sib.lfs !== 'object' || Array.isArray(sib.lfs)) throw new Error(`manifest: bad lfs entry for ${redact(path)}`);
      const l = sib.lfs as Record<string, unknown>;
      if (l.sha256 !== undefined) {
        if (typeof l.sha256 !== 'string' || !HEX64.test(l.sha256)) throw new Error(`manifest: malformed sha256 for ${redact(path)}`);
        sha256 = l.sha256;
      }
      if (l.size !== undefined) {
        if (!isSafeSize(l.size)) throw new Error(`manifest: bad lfs.size for ${redact(path)}`);
        lfsSize = l.size;
      }
      if (sib.size !== undefined && lfsSize !== undefined && sib.size !== lfsSize) throw new Error(`manifest: size/lfs.size disagree for ${redact(path)}`);
    }
    if (seen.has(path)) throw new Error(`manifest: duplicate path ${redact(path)}`);
    seen.add(path);
    // Every prefix and the full path must have exactly one spelling once case/unicode-folded,
    // or a case-insensitive filesystem would alias two manifest entries onto one directory.
    const parts = path.split('/');
    for (let k = 1; k <= parts.length; k++) {
      const exact = parts.slice(0, k).join('/');
      const f = fold(exact);
      const prior = spelling.get(f);
      if (prior !== undefined && prior !== exact) throw new Error(`manifest: paths collide on a case-insensitive filesystem: ${redact(exact)} vs ${redact(prior)}`);
      spelling.set(f, exact);
      if (k < parts.length) dirs.add(f);
    }
    if (SKIP.has(path)) continue;
    const size = (sib.size as number | undefined) ?? lfsSize;
    if (size !== undefined) {
      if (size > limits.maxFileBytes) throw new Error(`manifest: ${redact(path)} is ${size} bytes, over the per-file limit of ${limits.maxFileBytes}`);
      total += size;
      if (total > limits.maxTotalBytes) throw new Error(`manifest: total size exceeds the limit of ${limits.maxTotalBytes} bytes`);
    }
    files.push({ path, size, sha256 });
  }
  for (const f of files) if (dirs.has(fold(f.path))) throw new Error(`manifest: ${redact(f.path)} is both a file and a directory`);
  if (!files.length) throw new Error('manifest: no files to import');
  return { commit: i.sha, files };
}

// ---- containment -------------------------------------------------------------

/**
 * Ensure `root/rel` resolves inside `root` and that no existing component below root is a
 * symlink. Returns the absolute destination. Called at validation time and again right
 * before each open, copy and the promotion.
 */
export async function containedPath(root: string, rel: string): Promise<string> {
  const absRoot = resolvePath(root);
  const dest = resolvePath(absRoot, ...rel.split('/'));
  if (dest !== absRoot && !dest.startsWith(absRoot + sep)) throw new Error(`refusing path outside model dir: ${redact(rel)}`);
  const parts = rel.split('/');
  let cur = absRoot;
  for (let k = 0; k < parts.length; k++) {
    cur = join(cur, parts[k]);
    let st;
    try { st = await lstat(cur); } catch (e: any) { if (e.code === 'ENOENT') return dest; throw e; }
    if (st.isSymbolicLink()) throw new Error(`refusing symlink in model dir: ${redact(parts.slice(0, k + 1).join('/'))}`);
    if (k < parts.length - 1 && !st.isDirectory()) throw new Error(`refusing: ${redact(parts.slice(0, k + 1).join('/'))} is not a directory`);
    if (k === parts.length - 1 && !st.isFile()) throw new Error(`refusing: ${redact(rel)} exists and is not a regular file`);
  }
  return dest;
}

// ---- HTTP ---------------------------------------------------------------------

function authHeaders(token?: string): Record<string, string> {
  return token ? { authorization: `Bearer ${token}` } : {};
}

function gatedError(what: string): Error {
  return new Error(`HuggingFace refused access to ${redact(what)}. If the repo is gated: accept its license on the HuggingFace model page and set HF_TOKEN to a token that has access.`);
}

type Resolved = { baseUrl: string; revision: string; token?: string; fetch: typeof fetch; signal?: AbortSignal; stallMs: number; limits: Limits };

const TRANSIENT = new Set(['ECONNRESET', 'EPIPE', 'ECONNREFUSED', 'ETIMEDOUT', 'UND_ERR_SOCKET', 'UND_ERR_CONNECT_TIMEOUT', 'ECONNABORTED']);
function isTransient(e: unknown): boolean {
  const cause = (e as any)?.cause ?? e;
  return TRANSIENT.has(String(cause?.code ?? '')) || TRANSIENT.has(String((e as any)?.code ?? ''));
}

/**
 * fetch with one retry for connection-level failures on requests that have not yet
 * delivered a response (a keep-alive socket closed by the far end, a reset, …).
 * Never retries after a response has been received.
 */
export async function fetchOnce(f: typeof fetch, url: string, init: RequestInit): Promise<Response> {
  try {
    try { return await f(url, init); }
    catch (e) {
      if (init.signal?.aborted || !isTransient(e)) throw e;
      return await f(url, init);
    }
  } catch (e: any) {
    if (init.signal?.aborted) throw e;
    // Never let a raw fetch error (which can echo the full URL) out with secrets in it.
    const code = e?.cause?.code ?? e?.code;
    throw Object.assign(new Error(`${redact(String(e?.message ?? e))}${code ? ` (${code})` : ''}`), { code });
  }
}

/** A stall watchdog: aborts `ctrl` if `arm()` is not called again within `ms`. */
function watchdog(ctrl: AbortController, ms: number, what: string) {
  let timer: NodeJS.Timeout | undefined;
  const arm = () => { clearTimeout(timer); timer = setTimeout(() => ctrl.abort(new Error(`download stalled: no data for ${ms}ms: ${what}`)), ms); };
  const stop = () => clearTimeout(timer);
  return { arm, stop };
}

function combine(a?: AbortSignal, b?: AbortSignal): AbortSignal | undefined {
  if (a && b) return AbortSignal.any([a, b]);
  return a ?? b;
}

/** Read a whole body under a byte cap and a stall timer. */
async function readBounded(r: Response, ctrl: AbortController, max: number, stallMs: number, what: string): Promise<Buffer> {
  if (!r.body) return Buffer.alloc(0);
  const chunks: Buffer[] = []; let n = 0;
  const wd = watchdog(ctrl, stallMs, what);
  wd.arm();
  try {
    for await (const c of Readable.fromWeb(r.body as any)) {
      n += c.length;
      if (n > max) { const err = new Error(`${what}: response larger than ${max} bytes`); ctrl.abort(err); throw err; }
      chunks.push(c as Buffer);
      wd.arm();
    }
  } catch (e) {
    if (ctrl.signal.aborted && ctrl.signal.reason instanceof Error) throw ctrl.signal.reason;
    throw e;
  } finally { wd.stop(); }
  return Buffer.concat(chunks);
}

export async function fetchModelInfo(repo: string, o: Resolved): Promise<unknown> {
  const url = `${o.baseUrl}/api/models/${repo}${o.revision === 'main' ? '' : `/revision/${encodeURIComponent(o.revision)}`}?blobs=true`;
  const ctrl = new AbortController();
  const wd = watchdog(ctrl, o.stallMs, 'HuggingFace API'); wd.arm();
  let r: Response;
  try { r = await fetchOnce(o.fetch, url, { headers: authHeaders(o.token), signal: combine(o.signal, ctrl.signal) }); }
  catch (e) { if (ctrl.signal.aborted && ctrl.signal.reason instanceof Error) throw ctrl.signal.reason; throw e; }
  finally { wd.stop(); }
  if (r.status === 401 || r.status === 403) throw gatedError(repo);
  if (r.status === 404) throw new Error(`HuggingFace model not found: ${repo}${o.revision === 'main' ? '' : ` @ ${redact(o.revision)}`}`);
  if (!r.ok) throw new Error(`HuggingFace API ${r.status} for ${repo}`);
  const body = await readBounded(r, ctrl, o.limits.maxMetadataBytes, o.stallMs, 'HuggingFace API');
  try { return JSON.parse(body.toString('utf8')); } catch { throw new Error('HuggingFace API returned invalid JSON'); }
}

async function hashFile(p: string, algo: string, prefix = ''): Promise<string> {
  const h = createHash(algo);
  if (prefix) h.update(prefix);
  await pipeline(createReadStream(p), async function* (src) { for await (const c of src) h.update(c as Buffer); });
  return h.digest('hex');
}
const sha256File = (p: string) => hashFile(p, 'sha256');
/** Git blob id: sha1("blob <size>\0" + bytes). Our own content identity for non-LFS files. */
export const blobSha1 = async (p: string, size: number) => hashFile(p, 'sha1', `blob ${size}\0`);

async function sizeOf(p: string): Promise<number | undefined> {
  try { const st = await lstat(p); if (!st.isFile()) throw new Error(`refusing: ${redact(p)} is not a regular file`); return st.size; }
  catch (e: any) { if (e.code === 'ENOENT') return undefined; throw e; }
}

function parseContentRange(h: string | null): { start: number; end: number; total: number } | undefined {
  const m = /^bytes (\d+)-(\d+)\/(\d+)$/.exec(h ?? '');
  if (!m) return undefined;
  const [start, end, total] = [Number(m[1]), Number(m[2]), Number(m[3])];
  if (!Number.isSafeInteger(start) || !Number.isSafeInteger(end) || !Number.isSafeInteger(total) || start > end || end >= total) return undefined;
  return { start, end, total };
}

/** Open for writing without following a symlink at the destination (O_NOFOLLOW where the platform has it). */
async function openNoFollow(dest: string, append: boolean) {
  const nofollow = (FS as any).O_NOFOLLOW ?? 0;
  const flags = (append ? FS.O_WRONLY | FS.O_APPEND : FS.O_WRONLY | FS.O_CREAT | FS.O_TRUNC) | nofollow;
  return open(dest, flags, 0o644);
}

export interface DownloadOpts {
  size?: number; sha256?: string; token?: string; fetch: typeof fetch;
  onBytes?: (n: number) => void;
  /** Called once the resume/restart decision is made, with the byte offset the download begins at. */
  onStart?: (offset: number) => void;
  signal?: AbortSignal; stallMs?: number;
  /** Hard cap for a file of unknown size (and a sanity cap for known ones). */
  maxBytes?: number;
}

/**
 * Download one file to `dest`. A complete file (size matches, sha256 matches if known) is
 * kept; a partial one is resumed via a validated Range response when the size is known;
 * anything else is restarted from zero. Returns bytes downloaded by this call.
 */
export async function downloadFile(url: string, dest: string, o: DownloadOpts): Promise<number> {
  await mkdir(dirname(dest), { recursive: true });
  const existing = await sizeOf(dest);
  const cap = o.size ?? o.maxBytes ?? DEFAULT_LIMITS.maxFileBytes;
  if (o.size !== undefined && o.maxBytes !== undefined && o.size > o.maxBytes) throw new Error(`refusing ${redact(dest)}: ${o.size} bytes is over the per-file limit`);

  if (o.size !== undefined && existing === o.size) {
    if (!o.sha256 || (await sha256File(dest)) === o.sha256) { o.onStart?.(o.size); return 0; }
    await rm(dest);
  } else if (o.size === 0 && existing === undefined) {
    const fh = await openNoFollow(dest, false); await fh.close();
    if (o.sha256 && (await sha256File(dest)) !== o.sha256) { await rm(dest, { force: true }); throw new Error(`sha256 mismatch for ${redact(dest)}: expected ${o.sha256} for an empty file`); }
    o.onStart?.(0);
    return 0;
  }

  let start = 0;
  if (o.size !== undefined && existing !== undefined && existing > 0 && existing < o.size) start = existing;
  else if (existing !== undefined && existing !== o.size) await rm(dest, { force: true });

  const stallMs = o.stallMs ?? DEFAULT_STALL_MS;
  let got = 0;
  for (let attempt = 0; attempt < 2; attempt++) {
    const ctrl = new AbortController();
    const signal = combine(o.signal, ctrl.signal)!;
    const headers: Record<string, string> = { ...authHeaders(o.token) };
    if (start > 0) headers.range = `bytes=${start}-`;
    const wd = watchdog(ctrl, stallMs, redact(url));
    wd.arm();
    let r: Response;
    try { r = await fetchOnce(o.fetch, url, { headers, redirect: 'follow', signal }); }
    catch (e) { wd.stop(); if (ctrl.signal.aborted && ctrl.signal.reason instanceof Error) throw ctrl.signal.reason; throw e; }
    if (r.status === 401 || r.status === 403) { wd.stop(); throw gatedError(url); }

    let expectBody: number | undefined;
    if (start > 0) {
      // Resuming: accept only a 206 whose Content-Range starts exactly where our file ends,
      // ends at the last byte, and whose total is what we expect.
      const cr = r.status === 206 ? parseContentRange(r.headers.get('content-range')) : undefined;
      const ok = r.status === 206 && cr && cr.start === start && cr.total === o.size && cr.end === o.size! - 1;
      if (!ok) {
        if (r.status !== 200 && r.status !== 206 && r.status !== 416) { wd.stop(); await r.body?.cancel().catch(() => {}); throw new Error(`download failed (${r.status}): ${redact(url)}`); }
        await rm(dest, { force: true });
        start = 0;
        if (r.status !== 200) { wd.stop(); await r.body?.cancel().catch(() => {}); continue; } // 206 mismatch / 416: one clean retry from zero
        // 200: the server ignored Range and sent the whole representation; use it from zero.
      } else expectBody = cr!.end - cr!.start + 1;
    } else {
      if (r.status === 206) { wd.stop(); await r.body?.cancel().catch(() => {}); throw new Error(`unsolicited partial response for ${redact(url)}`); }
      if (!r.ok) { wd.stop(); throw new Error(`download failed (${r.status}): ${redact(url)}`); }
    }
    if (!r.body) { wd.stop(); throw new Error(`empty body: ${redact(url)}`); }
    o.onStart?.(start);

    let received = start;
    const counter = async function* (src: AsyncIterable<Uint8Array>) {
      for await (const c of src) {
        received += c.length;
        if (received > cap) {
          const err = new Error(o.size !== undefined ? `download exceeds expected size (${o.size}) for ${redact(url)}` : `download exceeds the size limit (${cap} bytes) for ${redact(url)}`);
          ctrl.abort(err); throw err;
        }
        got += c.length; o.onBytes?.(c.length); wd.arm();
        yield c;
      }
    };
    wd.arm();
    const fh = await openNoFollow(dest, start > 0);
    try {
      await pipeline(Readable.fromWeb(r.body as any), counter, fh.createWriteStream(), { signal });
    } catch (e: any) {
      wd.stop();
      const reason = ctrl.signal.aborted ? ctrl.signal.reason : o.signal?.aborted ? (o.signal.reason ?? e) : e;
      if (received > cap) await rm(dest, { force: true }); // poisoned; do not resume from it
      throw reason instanceof Error ? reason : new Error(String(reason));
    }
    wd.stop();
    if (expectBody !== undefined && got !== expectBody) { await rm(dest, { force: true }); throw new Error(`range body length ${got} != ${expectBody} for ${redact(url)}`); }
    break;
  }

  const final = (await stat(dest)).size;
  if (o.size !== undefined && final !== o.size) { await rm(dest, { force: true }); throw new Error(`size mismatch for ${redact(dest)}: got ${final}, expected ${o.size}`); }
  if (o.sha256) {
    const h = await sha256File(dest);
    if (h !== o.sha256) { await rm(dest, { force: true }); throw new Error(`sha256 mismatch for ${redact(dest)}: got ${h}, expected ${o.sha256}`); }
  }
  return got;
}

// ---- staging record ---------------------------------------------------------------

interface FileIdentity { size?: number; sha256?: string; blob?: string }
interface StagingRecord { commit: string; origin: string; files: Record<string, FileIdentity> }

async function readRecord(p: string): Promise<StagingRecord | undefined> {
  const j = await readJsonOr<any>(p, undefined);
  return j && typeof j === 'object' && typeof j.commit === 'string' && typeof j.origin === 'string' && j.files && typeof j.files === 'object' ? j : undefined;
}

/** Walk a directory tree without ever following a symlink; any symlink is an error. */
async function* walk(root: string, rel = ''): AsyncGenerator<string> {
  for (const e of await readdir(join(root, rel), { withFileTypes: true })) {
    const p = rel ? `${rel}/${e.name}` : e.name;
    if (e.isSymbolicLink()) throw new Error(`refusing symlink in staging dir: ${redact(p)}`);
    if (e.isDirectory()) yield* walk(root, p);
    else if (e.isFile()) yield p;
    else throw new Error(`refusing special file in staging dir: ${redact(p)}`);
  }
}

/** Remove anything in `dir` that is not in `keep`, then prune empty directories. Never crosses a symlink. */
async function pruneTo(dir: string, keep: Set<string>): Promise<void> {
  const files: string[] = [];
  for await (const p of walk(dir)) files.push(p);
  for (const p of files) if (!keep.has(p)) await rm(join(dir, ...p.split('/')), { force: true });
  const pruneEmpty = async (d: string): Promise<boolean> => {
    let empty = true;
    for (const e of await readdir(d, { withFileTypes: true })) {
      if (e.isSymbolicLink()) throw new Error(`refusing symlink in staging dir: ${e.name}`);
      if (e.isDirectory()) { if (await pruneEmpty(join(d, e.name))) await rm(join(d, e.name), { recursive: true, force: true }); else empty = false; }
      else empty = false;
    }
    return empty;
  };
  await pruneEmpty(dir);
}

/** Every manifest file present as a regular file with the expected size. */
async function verifyComplete(dir: string, manifest: Manifest): Promise<void> {
  for (const f of manifest.files) {
    const dest = await containedPath(dir, f.path);
    const size = await sizeOf(dest);
    if (size === undefined) throw new Error(`incomplete import: ${redact(f.path)} missing`);
    if (f.size !== undefined && size !== f.size) throw new Error(`incomplete import: ${redact(f.path)} is ${size} bytes, expected ${f.size}`);
  }
}

// ---- import ------------------------------------------------------------------------

/**
 * Download a HuggingFace model repo, pinned to the commit the API reports, into an
 * immutable version dir; verify every file; then promote it: seed + sign the name,
 * write the `current` pointer (the commit point), repoint models/<org>/<model>, and
 * only then retire the previous version. A failure before the commit point leaves the
 * previously published share, torrent and DHT name untouched.
 */
export function importHf(node: WebwayNode, ref: string, opts: ImportOpts = {}): Promise<Share & { warning?: string }> {
  const repo = parseHfRef(ref);
  return withRepoLock(node.home, repo, () => importLocked(node, repo, opts));
}

async function importLocked(node: WebwayNode, repo: string, opts: ImportOpts): Promise<Share & { warning?: string }> {
  const baseUrl = (opts.baseUrl ?? HF_ORIGIN).replace(/\/$/, '');
  // Ambient credentials only ever go to the real HuggingFace origin.
  const token = opts.token ?? (baseUrl === HF_ORIGIN ? process.env.HF_TOKEN : undefined);
  const limits: Limits = { ...DEFAULT_LIMITS, ...opts.limits };
  const stallMs = opts.stallMs ?? DEFAULT_STALL_MS;
  const o: Resolved = { baseUrl, revision: opts.revision ?? 'main', token, fetch: opts.fetch ?? fetch, signal: opts.signal, stallMs, limits };
  const home = node.home;
  const model = repo.split('/')[1];
  assertPublishable(repo, opts.license);
  o.signal?.throwIfAborted();

  const info = await fetchModelInfo(repo, o);
  const manifest = validateManifest(info, limits);
  const license = opts.license ?? licenseOf(info as HfModelInfo);
  assertPublishable(repo, license);

  const version = versionIdFor(manifest.commit, baseUrl);
  const dir = versionDir(home, repo, version);
  const recPath = recordPath(home, repo, version);
  const link = modelLink(home, repo);
  // The whole ancestry (versions root, this version dir, its record) must be real directories/files.
  await ensureRealDir(home, dir);
  await assertNoSymlinkBelow(home, recPath);
  for (const f of manifest.files) await containedPath(dir, f.path);
  // Pin the version dir's identity: a swapped parent between validation and a write is detected and aborted.
  const dirFlags = FS.O_RDONLY | ((FS as any).O_DIRECTORY ?? 0) | ((FS as any).O_NOFOLLOW ?? 0);
  const dirHandle = await open(dir, dirFlags);
  const ident = await dirHandle.stat();
  const assertSameDir = async (what: string) => {
    const now = await lstat(dir).catch(() => undefined);
    if (!now || !now.isDirectory() || now.ino !== ident.ino || now.dev !== ident.dev) throw new Error(`version dir changed underneath the import (${what}); aborting`);
  };
  try {
    // A pre-existing real directory at the model path would be shadowed by the symlink; refuse early.
    let linkSt; try { linkSt = await lstat(link); } catch (e: any) { if (e.code !== 'ENOENT') throw e; }
    if (linkSt && !linkSt.isSymbolicLink()) throw new Error(`models/${repo} already exists as a real directory (from \`webway get\`?); remove it before importing`);

    const current = await readPointer(home, repo);
    if (current?.version === version) {
      // Already promoted this exact commit from this origin; make sure it is shared and return.
      await verifyComplete(dir, manifest);
      return node.share(dir, repo, license, { torrentName: model, dir: link, keepPrevious: false });
    }

    // Staging record: a staged file is reusable only if it was fetched for this commit, from this
    // origin, with this identity (size + LFS sha256, or our own computed git blob id for non-LFS).
    const prev = await readRecord(recPath);
    const record: StagingRecord = { commit: manifest.commit, origin: baseUrl, files: {} };
    const keep = new Set(manifest.files.map((f) => f.path));
    const pending = pendingPath(home, repo, version);
    await assertSameDir('prune');
    await pruneTo(dir, keep);
    await rm(pending, { force: true });
    for (const f of manifest.files) {
      const dest = await containedPath(dir, f.path);
      const old = prev && prev.commit === manifest.commit && prev.origin === baseUrl ? prev.files[f.path] : undefined;
      let reusable = !!old && old.size === f.size && old.sha256 === f.sha256;
      if (reusable && !f.sha256) {
        // Non-LFS: only a complete file with a recorded blob id that still matches is trusted.
        const sz = await sizeOf(dest);
        reusable = sz !== undefined && sz === f.size && !!old!.blob && (await blobSha1(dest, sz)) === old!.blob;
        if (!reusable && sz !== undefined && f.size !== undefined && sz < f.size && !!old) reusable = true; // partial: resumable, verified by size at the end
      }
      if (!reusable) await rm(dest, { force: true });
      record.files[f.path] = { size: f.size, sha256: f.sha256, blob: reusable ? old?.blob : undefined };
    }
    await writeJsonAtomic(recPath, record);

    let bytes = 0; let total = 0;
    for (let i = 0; i < manifest.files.length; i++) {
      o.signal?.throwIfAborted();
      const f = manifest.files[i];
      const dest = await containedPath(dir, f.path);
      // Reuse a byte-identical LFS file from the currently published version instead of re-downloading.
      if (f.sha256 && current && (await sizeOf(dest)) === undefined) {
        try {
          const pub = await containedPath(versionDir(home, repo, current.version), f.path);
          if ((await sizeOf(pub)) === f.size && (await sha256File(pub)) === f.sha256) { await mkdir(dirname(dest), { recursive: true }); await copyFile(pub, dest, FS.COPYFILE_EXCL); }
        } catch { /* not reusable */ }
      }
      let fileBytes = 0;
      const report = () => opts.onProgress?.({ file: f.path, fileBytes, fileTotal: f.size, bytes, fileIndex: i, fileCount: manifest.files.length });
      const url = `${o.baseUrl}/${repo}/resolve/${manifest.commit}/${f.path.split('/').map(encodeURIComponent).join('/')}`;
      const budget = limits.maxTotalBytes - total;
      if (f.size !== undefined && f.size > budget) throw new Error(`import exceeds the total size limit of ${limits.maxTotalBytes} bytes`);
      await opts.beforeWrite?.(f.path);
      await assertSameDir(f.path);
      await containedPath(dir, f.path); // re-check right before opening
      await downloadFile(url, dest, {
        size: f.size, sha256: f.sha256, token: o.token, fetch: o.fetch, signal: o.signal, stallMs, maxBytes: Math.min(limits.maxFileBytes, budget),
        onStart: (offset) => { fileBytes = offset; report(); },
        onBytes: (n) => { bytes += n; fileBytes += n; report(); },
      });
      const finalSize = (await stat(dest)).size;
      total += finalSize;
      if (total > limits.maxTotalBytes) { await rm(dest, { force: true }); throw new Error(`import exceeds the total size limit of ${limits.maxTotalBytes} bytes`); }
      if (!f.sha256) { record.files[f.path].blob = await blobSha1(dest, finalSize); await writeJsonAtomic(recPath, record); }
      fileBytes = finalSize;
      report();
    }

    // ---- promotion ---------------------------------------------------------------------
    o.signal?.throwIfAborted();
    await assertSameDir('final prune');
    await pruneTo(dir, keep);
    await verifyComplete(dir, manifest);
    await assertNoSymlinkBelow(home, dir);
    o.signal?.throwIfAborted();

    const prevOwn = (await node.shares()).find((s) => s.own && s.name === repo);
    // Journal the promotion before the name is published, so recovery can finish or abandon it.
    await writeJsonAtomic(pending, { commit: manifest.commit, version, name: repo });
    let share: Share & { warning?: string };
    try {
      share = await node.prepareShare(dir, repo, license, { torrentName: model, dir: link, keepPrevious: true });
    } catch (e) {
      // Nothing was committed: the old version is untouched. Drop the new one.
      await rm(dir, { recursive: true, force: true }); await rm(recPath, { force: true });
      throw e;
    }
    // From here the name is published: the new content is referenced and must never be deleted.
    if (opts.crashAt === 'afterShare') throw new Error('simulated crash after share');
    if (o.signal?.aborted) {
      // Cancelled between publishing and the commit point: roll the local share back (the DHT
      // record expires on its own) and keep the new dir only as staged content.
      await node.unshare(share, prevOwn);
      await rm(pending, { force: true });
      o.signal.throwIfAborted();
    }
    if (current && share.ih === current.share.ih) {
      // Identical content (e.g. only .gitattributes changed): the live torrent is backed by the
      // current version dir, so leave current as it is and drop the duplicate.
      await rm(pending, { force: true });
      await rm(recPath, { force: true });
      if (!node.isBacking(dir)) await rm(dir, { recursive: true, force: true });
      return node.share(versionDir(home, repo, current.version), repo, license, { torrentName: model, dir: link, keepPrevious: false });
    }
    // Commit point. From here the transaction completes regardless of cancellation.
    const ptr: VersionPointer = { commit: manifest.commit, version, origin: baseUrl, dir, share: { name: share.name, ih: share.ih, dir: share.dir, size: share.size, license: share.license, own: true } };
    await writePointer(home, repo, ptr);
    if (opts.crashAt === 'afterPointer') throw new Error('simulated crash after pointer');
    await setModelLink(home, repo, dir);
    if (opts.crashAt === 'afterLink') throw new Error('simulated crash after link');
    await rm(pending, { force: true });
    await rm(recPath, { force: true });
    if (prevOwn && prevOwn.ih !== share.ih) await node.stopTorrent(prevOwn.ih, repo);
    await pruneVersions(home, repo, { keep: new Set([version]), isLive: (d) => node.isBacking(d) });
    let warning: string | undefined;
    try { await node.publishCatalog(); } catch (e: any) { warning = `catalog publish failed (will retry on serve): ${e?.message ?? e}`; }
    return warning ? { ...share, warning } : share;
  } finally {
    await dirHandle.close().catch(() => {});
  }
}
