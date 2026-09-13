import { DNS_SEED_DOMAINS, dedupe } from './bootstrap.ts';
import type { NodeOpts } from './node.ts';

export const BOOLEAN_FLAGS = new Set(['no-dns']);

export function parse(argv: string[]) {
  const args: string[] = []; const flags: Record<string, string[]> = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith('--')) {
      const k = a.slice(2);
      if (!k) throw new Error(`bad flag: ${a}`);
      if (BOOLEAN_FLAGS.has(k)) { (flags[k] ??= []).push('true'); continue; }
      const v = argv[i + 1];
      if (v === undefined || v.startsWith('--')) throw new Error(`missing value for --${k}`);
      (flags[k] ??= []).push(v); i++;
    } else args.push(a);
  }
  return { args, flags };
}

/** NodeOpts from parsed flags. `--dns-domain` adds to the default seed domains; `--no-dns` wins. */
export function optsFromFlags(flags: Record<string, string[]>): NodeOpts {
  return {
    peers: flags.peer,
    torrentPort: Number(flags['torrent-port']?.[0]) || undefined,
    dhtPort: Number(flags['dht-port']?.[0]) || undefined,
    dns: flags['no-dns'] ? false : flags['dns-domain'] ? dedupe([...DNS_SEED_DOMAINS, ...flags['dns-domain'].map((d) => d.toLowerCase())]) : true,
  };
}
