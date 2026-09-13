import { execFile } from 'node:child_process';
import { hostname } from 'node:os';
import { lstat, mkdir, open, readdir, readFile, readlink, rename, rm, symlink, unlink, utimes } from 'node:fs/promises';
import { basename, dirname, join, relative, resolve as resolvePath, sep } from 'node:path';
import { atomicWriteJson } from './atomic.ts';
import { promisify } from 'node:util';
import type { Share } from './node.ts';

/**
 * Versioned, immutable publish layout for imported models.
 *
 *   <home>/versions/<org>/<model>/<version>/      immutable content for one commit (+origin)
 *   <home>/versions/<org>/<model>/<version>.json  in-progress record (exists while a download is staged)
 *   <home>/versions/<org>/<model>/<version>.pending.json
 *                                                 promotion journal, written before the name is published
 *   <home>/versions/<org>/<model>/current.json    pointer to the promoted version (the commit point)
 *   <home>/models/<org>/<model>                   symlink -> ../../versions/<org>/<model>/<version>
 *   <home>/locks/<org>__<model>.lock/             per-repo import lock (a directory; see withRepoLock)
 *
 * Nothing is ever renamed over the published path. Promotion writes `current.json`
 * (tmp + rename); a crash at any point leaves the old or the new version fully
 * consistent, and recoverVersions() reconciles the rest on the next start.
 */

export interface VersionPointer { commit: string; version: string; origin?: string; dir: string; share: Share }
export interface Pending { commit: string; version: string; name: string; ih?: string }

const VERSION_RE = /^[0-9a-f]{40}(-[0-9a-f]{8})?$/;

export function versionsRoot(home: string, repo: string) { return join(home, 'versions', ...repo.split('/')); }
export function versionDir(home: string, repo: string, version: string) { return join(versionsRoot(home, repo), version); }
export function recordPath(home: string, repo: string, version: string) { return join(versionsRoot(home, repo), `${version}.json`); }
export function pendingPath(home: string, repo: string, version: string) { return join(versionsRoot(home, repo), `${version}.pending.json`); }
export function pointerPath(home: string, repo: string) { return join(versionsRoot(home, repo), 'current.json'); }
export function modelLink(home: string, repo: string) { return join(home, 'models', ...repo.split('/')); }
export function lockPath(home: string, repo: string) { return join(home, 'locks', `${repo.replace('/', '__')}.lock`); }

/**
 * Every path component strictly below `home` must exist as a real directory/file or not
 * exist at all: a symlink anywhere in the chain is refused. (`home` itself may be a
 * symlink; macOS temp dirs are.)
 */
export async function assertNoSymlinkBelow(home: string, target: string): Promise<void> {
  const root = resolvePath(home);
  const abs = resolvePath(target);
  if (abs !== root && !abs.startsWith(root + sep)) throw new Error(`refusing path outside home: ${target}`);
  const parts = relative(root, abs).split(sep).filter(Boolean);
  let cur = root;
  for (const p of parts) {
    cur = join(cur, p);
    let st;
    try { st = await lstat(cur); } catch (e: any) { if (e.code === 'ENOENT') return; throw e; }
    if (st.isSymbolicLink()) throw new Error(`refusing symlink inside webway home: ${relative(root, cur)}`);
  }
}

/** Write JSON atomically (exclusive temp file + rename; writes to one path are serialised in-process). */
export async function writeJsonAtomic(path: string, v: unknown): Promise<void> {
  await atomicWriteJson(dirname(path), basename(path), v);
}

export async function readJsonOr<T>(path: string, dflt: T): Promise<T> {
  try { return JSON.parse(await readFile(path, 'utf8')); } catch { return dflt; }
}

export async function readPointer(home: string, repo: string): Promise<VersionPointer | undefined> {
  const p = await readJsonOr<any>(pointerPath(home, repo), undefined);
  return p && typeof p.commit === 'string' && typeof p.version === 'string' && VERSION_RE.test(p.version) && p.share && typeof p.share.ih === 'string' ? p : undefined;
}

export async function writePointer(home: string, repo: string, ptr: VersionPointer): Promise<void> {
  await assertNoSymlinkBelow(home, pointerPath(home, repo));
  await writeJsonAtomic(pointerPath(home, repo), ptr);
}

export async function readPending(home: string, repo: string, version: string): Promise<Pending | undefined> {
  const p = await readJsonOr<any>(pendingPath(home, repo, version), undefined);
  return p && typeof p.commit === 'string' && typeof p.version === 'string' && typeof p.name === 'string' ? p : undefined;
}

/**
 * Point <home>/models/<org>/<model> at a version dir. Atomic: a fresh symlink is created
 * beside the target and renamed over it. A real directory at the link path (e.g. an
 * earlier `webway get`) is never touched: the caller gets an error instead.
 */
export async function setModelLink(home: string, repo: string, dir: string): Promise<void> {
  const link = modelLink(home, repo);
  await assertNoSymlinkBelow(home, dirname(link));
  await mkdir(dirname(link), { recursive: true });
  let st;
  try { st = await lstat(link); } catch (e: any) { if (e.code !== 'ENOENT') throw e; }
  if (st && !st.isSymbolicLink()) throw new Error(`${relative(home, link)} already exists as a real directory (from \`webway get\`?); remove it before importing ${repo}`);
  const target = relative(dirname(link), dir);
  const tmp = `${link}.tmp-${process.pid}-${Date.now()}`;
  await symlink(target, tmp);
  try { await rename(tmp, link); } catch (e) { await unlink(tmp).catch(() => {}); throw e; }
}

export async function readModelLink(home: string, repo: string): Promise<string | undefined> {
  try { return resolvePath(dirname(modelLink(home, repo)), await readlink(modelLink(home, repo))); } catch { return undefined; }
}

export interface RetainOpts { keep?: Set<string>; isLive?: (dir: string) => boolean }

/**
 * Delete version dirs of `repo` that are not in `keep`, not staged-in-progress (record
 * present), not journaled as pending, and not backing a live torrent (`isLive`).
 */
export async function pruneVersions(home: string, repo: string, o: RetainOpts = {}): Promise<string[]> {
  const root = versionsRoot(home, repo);
  await assertNoSymlinkBelow(home, root);
  let ents;
  try { ents = await readdir(root, { withFileTypes: true }); } catch (e: any) { if (e.code === 'ENOENT') return []; throw e; }
  const removed: string[] = [];
  for (const e of ents) {
    if (e.isSymbolicLink()) throw new Error(`refusing symlink inside versions dir: ${e.name}`);
    if (!e.isDirectory() || !VERSION_RE.test(e.name) || o.keep?.has(e.name)) continue;
    const dir = join(root, e.name);
    if (o.isLive?.(dir)) continue;
    let inProgress = false;
    try { await lstat(recordPath(home, repo, e.name)); inProgress = true; } catch {}
    if (inProgress) continue;
    if (await readPending(home, repo, e.name)) continue;
    await rm(dir, { recursive: true, force: true });
    removed.push(e.name);
  }
  return removed;
}

export interface RecoverOpts {
  isLive?: (dir: string) => boolean;
  /** Own shares as persisted; used to decide whether a pending promotion can be completed. */
  shares?: Share[];
  /** Test hook: acquire the lock this way (default withRepoLock). */
  lock?: <T>(home: string, repo: string, fn: () => Promise<T>) => Promise<T>;
}
export interface Recovery {
  restore: Share[];                 // own shares that are the truth (current pointers, completed pendings)
  remove: string[];                 // own share names whose promotion could not be completed
  skipped: string[];                // repos whose lock is held by a live importer
  errors: { repo: string; error: string }[];
}

/**
 * Reconcile on start, per repo and under that repo's lock: `current.json` is the truth; a
 * journaled pending promotion with no pointer is completed when its share record and
 * content exist, otherwise the share record is dropped (the DHT record expires on its own,
 * ~2h; nothing unpublishes it). The model link is repaired before anything is pruned and a
 * repair failure aborts that repo's recovery. Version dirs that are neither current, in
 * progress, pending, nor backing a live torrent are removed.
 */
export async function recoverVersions(home: string, o: RecoverOpts = {}): Promise<Recovery> {
  const out: Recovery = { restore: [], remove: [], skipped: [], errors: [] };
  const lock = o.lock ?? withRepoLock;
  const root = join(home, 'versions');
  let orgs: string[] = [];
  try { orgs = (await readdir(root, { withFileTypes: true })).filter((d) => d.isDirectory()).map((d) => d.name); } catch (e: any) { if (e.code === 'ENOENT') return out; throw e; }
  for (const org of orgs) {
    let models: string[] = [];
    try { models = (await readdir(join(root, org), { withFileTypes: true })).filter((d) => d.isDirectory()).map((d) => d.name); } catch { continue; }
    for (const model of models) {
      const repo = `${org}/${model}`;
      try {
        await lock(home, repo, async () => {
          let ptr = await readPointer(home, repo);
          // Journaled promotions: complete or abandon.
          let ents: string[] = [];
          try { ents = (await readdir(versionsRoot(home, repo), { withFileTypes: true })).filter((d) => d.isDirectory() && VERSION_RE.test(d.name)).map((d) => d.name); } catch {}
          for (const v of ents) {
            const dir = versionDir(home, repo, v);
            const pending = await readPending(home, repo, v);
            if (!pending || pending.name !== repo) continue;
            if (ptr?.version === v) { await rm(pendingPath(home, repo, v), { force: true }); continue; } // already committed
            const rec = o.shares?.find((s) => s.own && s.name === repo && s.dir === modelLink(home, repo) && (!pending.ih || s.ih === pending.ih));
            if (rec && !ptr) {
              // Published, persisted, content present, but the pointer was never written: finish it.
              await writePointer(home, repo, { commit: pending.commit, version: v, dir, share: rec });
              ptr = await readPointer(home, repo);
              await rm(pendingPath(home, repo, v), { force: true });
            } else {
              // Cannot prove the publish completed: drop the local record; the dir stays only if in progress.
              if (rec && ptr && rec.ih !== ptr.share.ih) out.remove.push(repo);
              await rm(pendingPath(home, repo, v), { force: true });
            }
          }
          if (!ptr) { await pruneVersions(home, repo, { isLive: o.isLive }); return; }
          const dir = versionDir(home, repo, ptr.version);
          let ok = false;
          try { ok = (await lstat(dir)).isDirectory(); } catch {}
          if (!ok) { await rm(pointerPath(home, repo), { force: true }); out.remove.push(repo); await pruneVersions(home, repo, { isLive: o.isLive }); return; }
          if ((await readModelLink(home, repo)) !== resolvePath(dir)) await setModelLink(home, repo, dir); // throws -> abort before pruning
          await rm(recordPath(home, repo, ptr.version), { force: true });
          out.restore.push({ ...ptr.share, dir: modelLink(home, repo), own: true });
          await pruneVersions(home, repo, { keep: new Set([ptr.version]), isLive: o.isLive });
        });
      } catch (e: any) {
        if (e?.code === 'ELOCKED') out.skipped.push(repo);
        else out.errors.push({ repo, error: String(e?.message ?? e) });
      }
    }
  }
  return out;
}

// ---- per-repo lock ------------------------------------------------------------
//
// The lock is a directory (mkdir is atomic everywhere) holding owner.json {pid, startedAt,
// hostname}. The holder touches the directory's mtime every HEARTBEAT ms. A lock is stale
// only when its mtime is older than STALE ms AND its owner is provably gone (pid dead, or the
// pid's process start time no longer matches). Reclaiming renames the stale dir aside first,
// so two reclaimers cannot both win. A lock whose owner.json is missing/unparseable (crash
// during creation) falls back to the mtime rule alone.

export interface LockOpts { heartbeatMs?: number; staleMs?: number }
const HEARTBEAT_MS = 15_000;
const STALE_MS = 90_000;
const execFileP = promisify(execFile);

function pidAlive(pid: number): boolean {
  try { process.kill(pid, 0); return true; } catch (e: any) { return e.code === 'EPERM'; }
}

/** Process start time as reported by `ps` (empty when unavailable). */
export async function processStart(pid: number): Promise<string> {
  try { const { stdout } = await execFileP('ps', ['-o', 'lstart=', '-p', String(pid)]); return stdout.trim(); } catch { return ''; }
}

async function isStale(dir: string, staleMs: number): Promise<boolean> {
  let st;
  try { st = await lstat(dir); } catch (e: any) { return e.code === 'ENOENT'; }
  if (Date.now() - st.mtimeMs <= staleMs) return false;
  let owner: any;
  try { owner = JSON.parse(await readFile(join(dir, 'owner.json'), 'utf8')); } catch { return true; } // incomplete owner: mtime rule only
  if (typeof owner?.pid !== 'number') return true;
  if (owner.hostname && owner.hostname !== hostname()) return false; // cannot inspect a foreign host's pids; trust the heartbeat rule
  if (!pidAlive(owner.pid)) return true;
  if (typeof owner.startedAt === 'string' && owner.startedAt) {
    const now = await processStart(owner.pid);
    if (now && now !== owner.startedAt) return true; // pid reused by a different process
  }
  return false;
}

export class Lock {
  private hb?: NodeJS.Timeout;
  readonly dir: string;
  constructor(dir: string) { this.dir = dir; }
  static async tryAcquire(dir: string, o: LockOpts = {}): Promise<Lock | undefined> {
    await mkdir(dirname(dir), { recursive: true });
    const make = async (): Promise<boolean> => {
      try { await mkdir(dir); } catch (e: any) { if (e.code === 'EEXIST') return false; throw e; }
      const owner = { pid: process.pid, startedAt: await processStart(process.pid), hostname: hostname(), at: Date.now() };
      await writeJsonAtomic(join(dir, 'owner.json'), owner);
      return true;
    };
    if (!(await make())) {
      if (!(await isStale(dir, o.staleMs ?? STALE_MS))) return undefined;
      // Reclaim: move the stale dir aside (only one reclaimer's rename succeeds), then create ours.
      const aside = `${dir}.stale.${Math.random().toString(36).slice(2)}`;
      try { await rename(dir, aside); } catch (e: any) { if (e.code !== 'ENOENT') throw e; }
      rm(aside, { recursive: true, force: true }).catch(() => {});
      if (!(await make())) return undefined;
    }
    const lock = new Lock(dir);
    const hbMs = o.heartbeatMs ?? HEARTBEAT_MS;
    lock.hb = setInterval(() => { const now = new Date(); utimes(dir, now, now).catch(() => {}); }, hbMs);
    lock.hb.unref();
    return lock;
  }
  async release(): Promise<void> {
    clearInterval(this.hb);
    await rm(this.dir, { recursive: true, force: true });
  }
}

/** Run `fn` holding the repo's import lock; a concurrent import of the same repo fails fast (error code ELOCKED). */
export async function withRepoLock<T>(home: string, repo: string, fn: () => Promise<T>, o: LockOpts = {}): Promise<T> {
  const path = lockPath(home, repo);
  await assertNoSymlinkBelow(home, path);
  const lock = await Lock.tryAcquire(path, o);
  if (!lock) {
    const owner = await readJsonOr<any>(join(path, 'owner.json'), {});
    throw Object.assign(new Error(`an import of ${repo} is already in progress (pid ${owner.pid ?? '?'}); wait for it or remove ${path}`), { code: 'ELOCKED' });
  }
  try { return await fn(); } finally { await lock.release(); }
}

/** Ensure a directory exists and is a real directory (created fresh if missing). */
export async function ensureRealDir(home: string, dir: string): Promise<void> {
  await assertNoSymlinkBelow(home, dir);
  await mkdir(dir, { recursive: true });
  const st = await lstat(dir);
  if (!st.isDirectory()) throw new Error(`not a directory: ${dir}`);
}
