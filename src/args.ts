import { WebwayNode, type SearchOpts } from './node.ts';

/**
 * Parse `--depth` / `--max` from the CLI flag map into validated SearchOpts.
 * Rejects missing values (the parser stores "true"), NaN, fractions, negatives,
 * Infinity and anything above the documented maxima, before a node is started.
 */
export function parseSearchOpts(flags: Record<string, string[] | undefined>): SearchOpts {
  const opts: SearchOpts = {};
  const read = (flag: string, max: number): number | undefined => {
    const raw = flags[flag]?.[0];
    if (raw === undefined) return undefined;
    if (!/^\d{1,9}$/.test(raw)) throw new RangeError(`--${flag} must be an integer in [0, ${max}], got ${JSON.stringify(raw)}`);
    const n = Number(raw);
    if (n > max) throw new RangeError(`--${flag} must be an integer in [0, ${max}], got ${raw}`);
    return n;
  };
  const depth = read('depth', WebwayNode.SEARCH_MAX_DEPTH);
  const max = read('max', WebwayNode.SEARCH_MAX_PUBLISHERS);
  if (depth !== undefined) opts.depth = depth;
  if (max !== undefined) opts.maxPublishers = max;
  return opts;
}
