import { promises as dns } from 'node:dns';
import { isIP } from 'node:net';

/**
 * Bootstrap paths. Losing any one of them must not strand a node:
 *   1. builtin public DHT routers (easy to block, but there are several)
 *   2. nodes remembered from the last session (dht.json)
 *   3. DNS TXT seeds at _webway-seeds.<domain> (any domain; operators can add their own)
 *   4. --peer host:port given by hand
 * Plus, once online: nodes carried inside publishers' catalogs, and LSD on the LAN.
 *
 * All sources are merged into one bounded list; the DHT queries them concurrently.
 * Every source is untrusted input and every list is bounded. The installed DHT
 * stack (k-rpc) splits `host:port` on ':' over a udp4 socket, so IPv6 endpoints
 * are recognised but never used.
 */

// Operators can opt into DNS seeds with --dns-domain. No project seed is deployed.
export const DNS_SEED_DOMAINS: string[] = [];
export const DNS_SEED_LABEL = '_webway-seeds';

export const LIMITS = {
  rememberedCap: 50,
  dnsDomains: 8,
  dnsBytesPerDomain: 4096,
  dnsEndpointsPerDomain: 32,
  dnsEndpointsTotal: 64,
  bootstrapTotal: 128, // hard: builtin + --peer are prioritised, but 128 means 128
  advertise: 20,
} as const;

export type Family = 4 | 6 | 'name';
export interface Endpoint { host: string; port: number; family: Family }

export type TxtResolver = (hostname: string) => Promise<string[][]>;
export interface CancellableResolver { resolveTxt: TxtResolver; cancel(): void }

// ---- address classification -------------------------------------------------

/** One trailing dot is the DNS root and carries no identity: `a.org.` === `a.org`. */
export function stripDot(h: string): string {
  return h.endsWith('.') && h.length > 1 ? h.slice(0, -1) : h;
}

/** RFC 1123 hostname: labels 1-63 chars, alnum + hyphen, no leading/trailing hyphen, total <= 253. */
export function isHostname(h: string): boolean {
  if (typeof h !== 'string') return false;
  const s = stripDot(h);
  if (s.length === 0 || s.length > 253) return false;
  return s.split('.').every((l) => /^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/.test(l));
}

function v4Bytes(h: string): number[] | undefined {
  if (isIP(h) !== 4) return undefined;
  return h.split('.').map(Number);
}

/** Expand an IPv6 literal to 8 16-bit groups. Handles `::` and a trailing dotted IPv4. Returns undefined for junk. */
export function v6Groups(h: string): number[] | undefined {
  if (isIP(h) !== 6) return undefined;
  let s = h.toLowerCase();
  const zone = s.indexOf('%'); if (zone >= 0) s = s.slice(0, zone);
  const m = /^(.*:)(\d+\.\d+\.\d+\.\d+)$/.exec(s);
  if (m) {
    const b = v4Bytes(m[2]); if (!b) return undefined;
    s = m[1] + ((b[0] << 8) | b[1]).toString(16) + ':' + ((b[2] << 8) | b[3]).toString(16);
  }
  const halves = s.split('::');
  if (halves.length > 2) return undefined;
  const head = halves[0] ? halves[0].split(':') : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const fill = halves.length === 2 ? 8 - head.length - tail.length : 0;
  if (fill < 0 || head.length + tail.length + fill !== 8) return undefined;
  const groups = [...head, ...Array(fill).fill('0'), ...tail].map((g) => parseInt(g, 16));
  return groups.every((g) => Number.isInteger(g) && g >= 0 && g <= 0xffff) ? groups : undefined;
}

/** Canonical textual form: lowercase hostnames without trailing dot, dotted IPv4, fully expanded lowercase IPv6. */
export function normalizeHost(h: string): string {
  const g = v6Groups(h);
  if (g) return g.map((x) => x.toString(16).padStart(4, '0')).join(':');
  return stripDot(h.toLowerCase());
}

function inV4(b: number[], net: number[], bits: number): boolean {
  const ip = ((b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]) >>> 0;
  const n = ((net[0] << 24) | (net[1] << 16) | (net[2] << 8) | net[3]) >>> 0;
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return (ip & mask) === (n & mask);
}

const V4_NONPUBLIC: [number[], number][] = [
  [[0, 0, 0, 0], 8], [[10, 0, 0, 0], 8], [[100, 64, 0, 0], 10], [[127, 0, 0, 0], 8], [[169, 254, 0, 0], 16],
  [[172, 16, 0, 0], 12], [[192, 0, 0, 0], 24], [[192, 0, 2, 0], 24], [[192, 168, 0, 0], 16], [[198, 18, 0, 0], 15],
  [[198, 51, 100, 0], 24], [[203, 0, 113, 0], 24], [[224, 0, 0, 0], 4], [[240, 0, 0, 0], 4],
];

/** True for anything that is not public unicast: private, loopback, link-local, CGNAT, mapped, multicast, reserved, docs. */
export function isPrivateHost(host: string): boolean {
  if (typeof host !== 'string') return true;
  const b4 = v4Bytes(host);
  if (b4) return V4_NONPUBLIC.some(([net, bits]) => inV4(b4, net, bits));
  const g = v6Groups(host);
  if (g) {
    const [g0, g1, g2, g3, g4, g5, g6, g7] = g;
    if (g.every((x) => x === 0)) return true; // ::
    if (g0 === 0 && g1 === 0 && g2 === 0 && g3 === 0 && g4 === 0 && g5 === 0 && g6 === 0 && g7 === 1) return true; // ::1
    if (g0 === 0 && g1 === 0 && g2 === 0 && g3 === 0 && g4 === 0 && (g5 === 0xffff || g5 === 0)) // ::ffff:a.b.c.d and ::a.b.c.d
      return isPrivateHost(`${g6 >> 8}.${g6 & 0xff}.${g7 >> 8}.${g7 & 0xff}`);
    if ((g0 & 0xffc0) === 0xfe80) return true; // fe80::/10 link-local
    if ((g0 & 0xfe00) === 0xfc00) return true; // fc00::/7 ULA
    if ((g0 & 0xff00) === 0xff00) return true; // ff00::/8 multicast
    if (g0 === 0x2001 && g1 === 0x0db8) return true; // documentation
    if (g0 === 0x0064 && g1 === 0xff9b) return true; // 64:ff9b::/96 NAT64
    return false;
  }
  const h = stripDot(host.toLowerCase());
  return h === 'localhost' || h.endsWith('.localhost');
}

/** A public unicast IP literal (IPv4 or IPv6). Hostnames are never "public literals". */
export function isPublicIpLiteral(host: string): boolean {
  return isIP(host) !== 0 && !isPrivateHost(host);
}

// ---- endpoint parsing -----------------------------------------------------------

/** Parse one `host:port` (IPv6 as `[::1]:6881`). Strict: valid IPv4, valid IPv6, or RFC 1123 hostname. */
export function parseHostPort(s: string): Endpoint | undefined {
  if (typeof s !== 'string') return undefined;
  const t = s.trim();
  const m6 = /^\[([^\]]+)\]:(\d{1,5})$/.exec(t);
  const m4 = /^([^\s:\[\]/]+):(\d{1,5})$/.exec(t);
  const m = m6 ?? m4;
  if (!m) return undefined;
  const port = Number(m[2]);
  if (!Number.isInteger(port) || port < 1 || port > 65535) return undefined;
  const host = m[1];
  if (m6) return isIP(host) === 6 ? { host: normalizeHost(host), port, family: 6 } : undefined;
  if (isIP(host) === 4) return { host, port, family: 4 };
  if (isIP(host) === 6) return undefined; // bare v6 without brackets is ambiguous
  if (/^[\d.]+$/.test(host)) return undefined; // numeric-looking but not a valid IPv4 (999.999.999.999)
  return isHostname(host) ? { host: normalizeHost(host), port, family: 'name' } : undefined;
}

/** Validate a structured {host, port} (e.g. from dht.json) with the same rules as the string form. */
export function parseNode(n: unknown): Endpoint | undefined {
  if (!n || typeof n !== 'object') return undefined;
  const { host, port } = n as { host?: unknown; port?: unknown };
  if (typeof host !== 'string' || !Number.isInteger(port)) return undefined;
  if (host.includes(':')) return isIP(host) === 6 ? parseHostPort(`[${host}]:${port}`) : undefined;
  return parseHostPort(`${host}:${port}`);
}

export function formatHostPort(n: { host: string; port: number }): string {
  return isIP(n.host) === 6 ? `[${n.host}]:${n.port}` : `${n.host}:${n.port}`;
}

/** Can the installed DHT transport actually reach this endpoint? (udp4 socket, ':'-split parsing.) */
export function usable(e: Endpoint): boolean {
  return e.family !== 6;
}

/** Split a TXT record into canonical `host:port` strings, dropping junk (IPv6 included: see usable()). */
export function parseSeedRecord(record: string): string[] {
  return canonicalEndpoints(String(record ?? '').split(/[\s,]+/));
}

export function dedupe(list: readonly string[]): string[] {
  return [...new Set(list)];
}

/** Normalise + validate a list of endpoint strings, keeping only transport-usable ones, deduped. */
export function canonicalEndpoints(list: readonly string[]): string[] {
  const out = new Set<string>();
  for (const s of list) {
    const e = parseHostPort(s);
    if (e && usable(e)) out.add(formatHostPort(e));
  }
  return [...out];
}

// ---- DNS seeds ----------------------------------------------------------------------

/** A resolver we own, so a hung query can be cancelled (pending promises reject with ECANCELLED). */
export function ownedResolver(): CancellableResolver {
  const r = new dns.Resolver();
  return { resolveTxt: (h) => r.resolveTxt(h), cancel: () => r.cancel() };
}

export interface DnsSeedOpts {
  /** Fires as each domain completes, with that domain's endpoints not already emitted by another domain. */
  onDomain?: (seeds: string[], domain: string) => void;
  /** Abort everything: settles the returned promise promptly and clears every timer. */
  signal?: AbortSignal;
}

/**
 * Query TXT at _webway-seeds.<domain> for every domain (max 8). Never throws.
 * Domains resolve independently (Promise.allSettled): a fast domain's seeds are
 * emitted through `onDomain` while a slow one is still pending. A domain that fails,
 * hangs past `timeoutMs` (its query is cancelled), or returns junk contributes nothing.
 * Per-domain: 4 KiB of TXT (over-budget records are dropped whole, never cut), 32
 * usable endpoints after IPv6/hostname filtering and dedupe. Total: 64.
 * An abort (opts.signal) cancels the resolver and settles promptly.
 */
export async function dnsSeeds(
  domains: readonly string[],
  resolver?: TxtResolver | CancellableResolver,
  timeoutMs = 3000,
  opts: DnsSeedOpts = {},
): Promise<string[]> {
  const r: CancellableResolver = !resolver ? ownedResolver() : typeof resolver === 'function' ? { resolveTxt: resolver, cancel() {} } : resolver;
  const list = dedupe(domains.filter((d) => typeof d === 'string' && isHostname(d)).map((d) => normalizeHost(d))).slice(0, LIMITS.dnsDomains);
  const emitted = new Set<string>();
  const order: string[] = [];
  if (opts.signal?.aborted) return [];
  let abortResolve: (() => void) | undefined;
  const aborted = new Promise<void>((res) => { abortResolve = res; });
  const onAbort = () => { abortResolve?.(); try { r.cancel(); } catch {} };
  opts.signal?.addEventListener('abort', onAbort, { once: true });
  try {
    await Promise.allSettled(list.map(async (d) => {
      let timer: NodeJS.Timeout | undefined;
      const timeout = new Promise<'timeout'>((res) => { timer = setTimeout(() => res('timeout'), timeoutMs); });
      try {
        const query = Promise.resolve().then(() => r.resolveTxt(`${DNS_SEED_LABEL}.${d}`)).catch(() => [] as string[][]);
        const records = await Promise.race([query, timeout, aborted.then(() => 'aborted' as const)]);
        if (records === 'timeout') { r.cancel(); return; }
        if (records === 'aborted' || !Array.isArray(records)) return;
        let budget = LIMITS.dnsBytesPerDomain;
        const tokens: string[] = [];
        for (const chunks of records) {
          if (!Array.isArray(chunks)) continue;
          const text = chunks.filter((c) => typeof c === 'string').join('');
          const bytes = Buffer.byteLength(text, 'utf8');
          if (bytes > budget) break; // never parse a record we would have to cut
          budget -= bytes;
          tokens.push(...text.split(/[\s,]+/));
          if (budget <= 0) break;
        }
        const fresh: string[] = [];
        // IP literals only: a hostname here would be resolved later by k-rpc-socket's own
        // dns.lookup, outside our deadline and beyond our cancel(). Operators publish IPs.
        for (const ep of canonicalEndpoints(tokens).filter((s) => parseHostPort(s)?.family === 4)) {
          if (fresh.length >= LIMITS.dnsEndpointsPerDomain) break;
          if (emitted.size >= LIMITS.dnsEndpointsTotal) break;
          if (emitted.has(ep)) continue;
          emitted.add(ep); order.push(ep); fresh.push(ep);
        }
        if (fresh.length && !opts.signal?.aborted) opts.onDomain?.(fresh, d);
      } finally { if (timer) clearTimeout(timer); }
    }));
  } finally {
    opts.signal?.removeEventListener('abort', onAbort);
  }
  return order;
}

// ---- merge ------------------------------------------------------------------------------

let warnedOverflow = false;

/**
 * Pure merge of every bootstrap source, first occurrence wins in README order
 * (builtin, remembered, dns, peers), canonicalised, deduped, IPv6 dropped.
 * Builtin and --peer entries are prioritised: remembered (<=50) and DNS (<=64)
 * only fill the room they leave. 128 is a hard cap: if the prioritised entries
 * alone exceed it, the first 128 are kept and a warning is logged once.
 */
export function mergeBootstrap(src: {
  builtin: readonly string[];
  remembered?: readonly string[];
  dns?: readonly string[] | false;
  peers?: readonly string[];
  onOverflow?: (dropped: number) => void;
}): string[] {
  const builtin = canonicalEndpoints(src.builtin);
  const peers = canonicalEndpoints(src.peers ?? []);
  const reserved = new Set([...builtin, ...peers]);
  const remembered = canonicalEndpoints(src.remembered ?? []).slice(0, LIMITS.rememberedCap);
  const dns = src.dns === false ? [] : canonicalEndpoints(src.dns ?? []).slice(0, LIMITS.dnsEndpointsTotal);
  let room = Math.max(0, LIMITS.bootstrapTotal - reserved.size);
  const out: string[] = [];
  const seen = new Set<string>();
  for (const e of [...builtin, ...remembered, ...dns, ...peers]) {
    if (seen.has(e)) continue;
    if (reserved.has(e)) { seen.add(e); out.push(e); continue; }
    if (room > 0) { seen.add(e); out.push(e); room--; }
  }
  if (out.length > LIMITS.bootstrapTotal) {
    const dropped = out.length - LIMITS.bootstrapTotal;
    (src.onOverflow ?? ((n: number) => { if (!warnedOverflow) { warnedOverflow = true; console.error(`webway: ${n} bootstrap entries beyond the ${LIMITS.bootstrapTotal} cap were dropped (too many builtin/--peer)`); } }))(dropped);
    return out.slice(0, LIMITS.bootstrapTotal);
  }
  return out;
}

/**
 * Which explicit --peer values get an immediate ping at startup: only those that
 * survived the merged, capped bootstrap list (never the raw --peer array).
 * With bootstrap disabled, the canonical peers themselves, capped.
 */
export function startupPeerPings(bootstrap: readonly string[] | false, peers: readonly string[]): string[] {
  const canon = canonicalEndpoints(peers);
  if (bootstrap === false) return canon.slice(0, LIMITS.bootstrapTotal);
  const inList = new Set(bootstrap);
  return canon.filter((p) => inList.has(p));
}

// ---- advertising ------------------------------------------------------------------------

/**
 * Pick up to `max` routing-table nodes fit to advertise in a catalog (or reuse from dht.json):
 * structurally valid, IPv4 only, public unless allowPrivate, deduped. `exclude` drops
 * addresses we should not vouch for (e.g. ones we only recently adopted from someone else's catalog).
 */
export function advertisableNodes(
  nodes: readonly unknown[],
  max: number = LIMITS.advertise,
  allowPrivate = false,
  exclude: (addr: string) => boolean = () => false,
): string[] {
  const out: string[] = [];
  if (!Array.isArray(nodes)) return out;
  const seen = new Set<string>();
  for (const n of nodes) {
    const e = parseNode(n);
    if (!e || e.family !== 4) continue;
    if (!allowPrivate && isPrivateHost(e.host)) continue;
    const s = formatHostPort(e);
    if (exclude(s) || seen.has(s)) continue;
    seen.add(s); out.push(s);
    if (out.length >= max) break;
  }
  return out;
}

/** /24 key for IPv4 concentration limits. */
export function subnetKey(host: string): string {
  const b = v4Bytes(host);
  return b ? `${b[0]}.${b[1]}.${b[2]}` : host;
}
