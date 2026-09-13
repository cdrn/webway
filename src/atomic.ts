import { promises as fsp } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { join } from 'node:path';

/** The slice of fs we need, so tests can substitute an in-memory one. */
export interface AtomicFs {
  mkdir(path: string, opts: { recursive: true }): Promise<unknown>;
  writeFile(path: string, data: string, opts: { flag: 'wx' }): Promise<void>;
  rename(from: string, to: string): Promise<void>;
  unlink(path: string): Promise<void>;
}

const defaultFs: AtomicFs = {
  mkdir: (p, o) => fsp.mkdir(p, o),
  writeFile: (p, d, o) => fsp.writeFile(p, d, o),
  rename: (a, b) => fsp.rename(a, b),
  unlink: (p) => fsp.unlink(p),
};

let counter = 0;
const chains = new Map<string, Promise<unknown>>();

/**
 * Atomic JSON write: exclusively create a unique sibling temp file
 * (`<file>.<pid>.<counter>.<random6>.tmp`, flag 'wx'), then rename it over the
 * target. Writes to the same path are serialised in-process, so the last call
 * to resolve is the content on disk. Cross-process coordination is not provided
 * (see issue #10).
 */
export function atomicWriteJson(dir: string, file: string, value: unknown, fs: AtomicFs = defaultFs): Promise<void> {
  const target = join(dir, file);
  const prev = chains.get(target) ?? Promise.resolve();
  const run = prev.then(async () => {
    await fs.mkdir(dir, { recursive: true });
    const tmp = join(dir, `${file}.${process.pid}.${++counter}.${randomBytes(3).toString('hex')}.tmp`);
    await fs.writeFile(tmp, JSON.stringify(value, null, 2), { flag: 'wx' });
    try { await fs.rename(tmp, target); }
    catch (e) { await fs.unlink(tmp).catch(() => {}); throw e; }
  }, async () => { /* previous failure does not block this write */ }).then(() => undefined);
  const settled = run.catch(() => {});
  chains.set(target, settled);
  void settled.then(() => { if (chains.get(target) === settled) chains.delete(target); });
  return run;
}
