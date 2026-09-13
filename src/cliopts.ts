import { DNS_SEED_DOMAINS, dedupe } from './bootstrap.ts';
import type { NodeOpts } from './node.ts';

/** Flags that take no value. Everything else that starts with -- consumes the next argument (or `=value`). */
export const BOOLEAN_FLAGS = new Set(['no-dns', 'chain', 'no-chain', 'help', 'no-seed']);
/** @deprecated alias */
export const BOOL_FLAGS = BOOLEAN_FLAGS;

export function parse(argv: string[], bools = BOOLEAN_FLAGS) {
  const args: string[] = []; const flags: Record<string, string[]> = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--') { args.push(...argv.slice(i + 1)); break; }
    if (a.startsWith('--')) {
      const eq = a.indexOf('=');
      const k = eq > 0 ? a.slice(2, eq) : a.slice(2);
      if (!k) throw new Error(`bad flag: ${a}`);
      if (bools.has(k)) {
        if (eq > 0) throw new Error(`--${k} is a switch and takes no value`);
        (flags[k] ??= []).push('true'); continue;
      }
      if (eq > 0) { (flags[k] ??= []).push(a.slice(eq + 1)); continue; }
      const v = argv[i + 1];
      if (v === undefined || v.startsWith('--')) throw new Error(`missing value for --${k}`);
      (flags[k] ??= []).push(v); i++;
    } else args.push(a);
  }
  return { args, flags };
}

/** A numeric option: absent → undefined; otherwise must be a finite safe integer within [min, max]. Never a silent default. */
export function num(flags: Record<string, string[]>, key: string, opts: { min?: number; max?: number } = {}): number | undefined {
  const vals = flags[key];
  if (!vals?.length) return undefined;
  if (vals.length > 1) throw new Error(`--${key} given more than once`);
  const raw = vals[0];
  if (!/^-?\d+$/.test(raw)) throw new Error(`--${key} must be an integer, got ${JSON.stringify(raw)}`);
  const n = Number(raw);
  if (!Number.isSafeInteger(n)) throw new Error(`--${key} out of range`);
  if (opts.min !== undefined && n < opts.min) throw new Error(`--${key} must be >= ${opts.min}`);
  if (opts.max !== undefined && n > opts.max) throw new Error(`--${key} must be <= ${opts.max}`);
  return n;
}

export const bool = (flags: Record<string, string[]>, key: string): boolean => !!flags[key]?.length;

/** NodeOpts from parsed flags. `--dns-domain` adds to the default seed domains; `--no-dns` wins. */
export function optsFromFlags(flags: Record<string, string[]>): NodeOpts {
  return {
    peers: flags.peer,
    torrentPort: Number(flags['torrent-port']?.[0]) || undefined,
    dhtPort: Number(flags['dht-port']?.[0]) || undefined,
    dns: flags['no-dns'] ? false : flags['dns-domain'] ? dedupe([...DNS_SEED_DOMAINS, ...flags['dns-domain'].map((d) => d.toLowerCase())]) : true,
  };
}
