import { DNS_SEED_DOMAINS, dedupe } from './bootstrap.ts';
import type { NodeOpts } from './node.ts';

export const BOOLEAN_FLAGS = new Set(['no-dns']);

export function parse(argv: string[]) {
  const args: string[] = []; const flags: Record<string, string[]> = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith('--')) {
      const k = a.slice(2);
      (flags[k] ??= []).push(BOOLEAN_FLAGS.has(k) ? 'true' : argv[++i] ?? 'true');
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
