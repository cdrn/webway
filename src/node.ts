import WebTorrent, { type Torrent } from 'webtorrent';
import bencode from 'bencode';
import { createHash } from 'node:crypto';
import { mkdir, readFile, writeFile, rm, rmdir } from 'node:fs/promises';
import { atomicWriteJson } from './atomic.ts';
import { join, basename, dirname } from 'node:path';
import { homedir } from 'node:os';
import { loadOrCreate, sign, verify, type Keypair } from './keys.ts';
import { DNS_SEED_DOMAINS, LIMITS, advertisableNodes, canonicalEndpoints, dnsSeeds, formatHostPort, isPrivateHost, mergeBootstrap, ownedResolver, parseHostPort, startupPeerPings, subnetKey, usable, type CancellableResolver, type TxtResolver } from './bootstrap.ts';
import { pruneVersions, readPointer, recoverVersions, versionsRoot, withRepoLock, type Recovery } from './versions.ts';
import { resolve as resolvePath, sep } from 'node:path';

/**
 * A webway node = a BitTorrent client + a Mainline DHT node + a publisher key.
 *
 * Resilience properties, and where each comes from:
 *  - no central index:        Mainline DHT (BEP5) for peers, BEP44 for names
 *  - unforgeable content:     infohash is the content
 *  - unforgeable names:       webway://<ed25519 pk>/<name> is a BEP44 mutable
 *                             item signed by the publisher; DHT nodes reject bad sigs
 *  - no single bootstrap:     builtin routers + persisted routing table + DNS TXT
 *                             seeds + --peer + nodes carried in catalogs + LSD
 *  - NAT traversal:           uTP + UPnP/NAT-PMP via webtorrent; PEX (BEP11)
 *  - dies only with Mainline: ~10M nodes, nobody owns it
 */

export const EXTRA_BOOTSTRAP = [
  'router.bittorrent.com:6881',
  'router.utorrent.com:6881',
  'dht.transmissionbt.com:6881',
  'dht.libtorrent.org:25401',
  'dht.aelitis.com:6881',
];

export interface Record_ { ih: string; name: string; size: number; license?: string; seq: number }
/** A signed BEP44 item we hold and will keep alive on behalf of its publisher. */
export interface HeldRecord { k: string; salt: string; v: string; sig: string; seq: number }
export interface CatalogEntry { name: string; ih: string; size: number; license?: string }
/** nodes: raw `host:port` strings the publisher advertises (#4), present only when non-empty; validated and rationed by adoptNodes(), not here. */
export interface Catalog { entries: CatalogEntry[]; endorse: string[]; nodes?: string[] }
const emptyCatalog = (): Catalog => ({ entries: [], endorse: [] });
export interface SearchHit extends CatalogEntry { pk: string; hops: number }
export interface SearchOpts { depth?: number; maxPublishers?: number }
/** Lifecycle record for one catalog torrent (one per infohash). */
interface TorrentRef { ih: string; torrent: Torrent; owned: boolean; dir?: string; readers: number; retainedBy: Set<string>; lastUse: number }
export interface Share { name: string; ih: string; dir: string; size: number; license?: string; own: boolean }
export interface ShareOpts {
  torrentName?: string;   // torrent name (default: basename(dir))
  dir?: string;           // what to persist as the share's dir (default: dir); serve() re-adds from dirname(dir)
  keepPrevious?: boolean; // leave the torrent that previously backed this name running (caller retires it)
}

export interface NodeOpts {
  home?: string;
  bootstrap?: string[] | false;
  torrentPort?: number;
  dhtPort?: number;
  peers?: string[]; // extra DHT nodes host:port
  nat?: boolean; // UPnP/NAT-PMP port mapping (default on)
  catalogTimeoutMs?: number; // per-publisher catalog fetch deadline (default 20s)
  searchTimeoutMs?: number; // overall search deadline (default 120s)
  catalogCacheMax?: number; // in-memory parsed-catalog cache entries (default 200; 0 = no cache)
  catalogTorrentsMax?: number; // owned catalog torrents kept alive (default 200, LRU)
  dns?: boolean | string[]; // DNS TXT seeds: true = DNS_SEED_DOMAINS, false = skip, array = those domains
  allowPrivate?: boolean; // advertise/adopt private/loopback nodes (tests only)
  dnsResolver?: TxtResolver | CancellableResolver; // test hook
  dnsTimeoutMs?: number;
  dnsRetryMs?: number; // test hook: interval between DNS-seed bootstrap retries (default 30s)
}

/** Catalog-node adoption limits (#4 review). Publishers recommend nodes; we ration how far we trust that. */
export const ADOPT = {
  perPublisher: 20, // lifetime, persisted in dht-adopt.json
  perSession: 100,
  perSubnetPerPublisher: 4, // /24
  perRead: 20,
  inspect: 200, // raw catalog entries looked at per read, valid or not
  tableFull: 200, // routing-table size beyond which only never-seen addresses are considered
  reAdvertiseAfterMs: 60 * 60_000, // adopted nodes are not vouched for in our own catalog until this old
  provenanceTtlMs: 24 * 60 * 60_000, // forget adoption timestamps older than this
} as const;

/** DNS seeds stay retryable: if the table is still empty after bootstrap, re-ping them a bounded number of times. */
export const DNS_RETRY = { intervalMs: 30_000, max: 5 } as const;

interface AdoptState { n: number; seen: string[]; subnets: Record<string, number> }
interface AdoptFile { publishers: Record<string, AdoptState>; adopted: Record<string, number> }

/** Publisher keys are 32-byte ed25519 keys in hex; hex case carries no identity. */
export function canonPk(pk: unknown): string | undefined {
  return typeof pk === 'string' && /^[0-9a-fA-F]{64}$/.test(pk) ? pk.toLowerCase() : undefined;
}

/** Validate dht-adopt.json, resetting only the corrupt parts and merging case-variant publisher keys. */
export function sanitizeAdoptFile(raw: unknown): AdoptFile {
  const out: AdoptFile = { publishers: {}, adopted: {} };
  const r = (raw && typeof raw === 'object' ? raw : {}) as Record<string, unknown>;
  const pubs = (r.publishers && typeof r.publishers === 'object' ? r.publishers : {}) as Record<string, unknown>;
  for (const [k, v] of Object.entries(pubs)) {
    const pk = canonPk(k);
    if (!pk || !v || typeof v !== 'object') continue;
    const s = v as Record<string, unknown>;
    const seen = Array.isArray(s.seen) ? s.seen.filter((x): x is string => typeof x === 'string' && !!parseHostPort(x)) : [];
    const subnets: Record<string, number> = {};
    if (s.subnets && typeof s.subnets === 'object') for (const [sub, n] of Object.entries(s.subnets as Record<string, unknown>)) if (Number.isInteger(n) && (n as number) > 0) subnets[sub] = n as number;
    const n = Number.isInteger(s.n) && (s.n as number) >= 0 ? (s.n as number) : seen.length;
    const cur = out.publishers[pk];
    if (!cur) out.publishers[pk] = { n, seen, subnets };
    else { // case variant of a key we already have: budgets are one budget
      cur.n += n; cur.seen = [...new Set([...cur.seen, ...seen])];
      for (const [sub, c] of Object.entries(subnets)) cur.subnets[sub] = (cur.subnets[sub] ?? 0) + c;
    }
  }
  const ad = (r.adopted && typeof r.adopted === 'object' ? r.adopted : {}) as Record<string, unknown>;
  const now = Date.now();
  for (const [addr, t] of Object.entries(ad)) if (parseHostPort(addr) && Number.isFinite(t) && (t as number) <= now && now - (t as number) < ADOPT.provenanceTtlMs) out.adopted[addr] = t as number;
  return out;
}

/** DHT salt limit (BEP44) bounds the name; the record itself must stay well under 1000 bytes. */
export const MAX_NAME_BYTES = 64;
export const MAX_LICENSE_BYTES = 64;

/** Fail fast on anything the DHT record could not carry. Safe to call before any download. */
export function assertPublishable(name: string, license?: string): void {
  if (!name || Buffer.byteLength(name) > MAX_NAME_BYTES) throw new Error(`name must be 1..${MAX_NAME_BYTES} bytes (DHT salt limit): ${name.length > 80 ? name.slice(0, 80) + '…' : name}`);
  if (/[\x00-\x1f\x7f-\x9f]/.test(name)) throw new Error('name contains control characters');
  if (license !== undefined) {
    if (Buffer.byteLength(license) > MAX_LICENSE_BYTES) throw new Error(`license must be at most ${MAX_LICENSE_BYTES} bytes`);
    if (/[\x00-\x1f\x7f-\x9f]/.test(license)) throw new Error('license contains control characters');
  }
}

/** Where a torrent's files landed: multi-file torrents nest under t.name, single-file ones don't. */
function torrentRoot(t: Torrent, path: string): string {
  return t.files.every((f: { path: string }) => f.path.startsWith(t.name + '/')) ? join(path, t.name) : path;
}

export class WebwayNode {
  readonly home: string;
  client!: WebTorrent;
  key!: Keypair;
  private timers: NodeJS.Timeout[] = [];
  private opts: NodeOpts;
  /** Resolves with the DNS seed endpoints once they arrive (never blocks start()). */
  dnsReady: Promise<string[]> = Promise.resolve([]);
  private dnsResolverHandle: CancellableResolver | undefined;
  private dnsAbort = new AbortController();
  /** DNS seeds we have heard of this session, kept as retryable bootstrap candidates (bounded). */
  readonly dnsCandidates = new Set<string>();
  private dnsRetryTimer: NodeJS.Timeout | undefined;
  dnsRetries = 0;
  /** How many first-contact self-lookups we have run (one per isolation episode at most). */
  dnsLookups = 0;
  private discoveryListener: (() => void) | undefined;
  private wasPopulated = false;
  /** The --peer values actually pinged at startup (subset of the capped bootstrap list). */
  startupPeers: string[] = [];
  private stopping = false;
  /** addr -> when we adopted it from someone's catalog (provenance; not re-advertised while fresh). Persisted. */
  private adopted = new Map<string, number>();
  private adoptedThisSession = 0;
  private adoptChain: Promise<unknown> = Promise.resolve();
  /** infohash -> directories currently backing a live torrent for it (seed/serve/fetch/import). */
  private backing = new Map<string, Set<string>>();
  private sharesTxn: Promise<unknown> = Promise.resolve();

  constructor(opts: NodeOpts = {}) {
    if (opts.catalogTimeoutMs !== undefined) checkInt('catalogTimeoutMs', opts.catalogTimeoutMs, WebwayNode.CATALOG_TIMEOUT_MAX_MS);
    if (opts.searchTimeoutMs !== undefined) checkInt('searchTimeoutMs', opts.searchTimeoutMs, WebwayNode.SEARCH_TIMEOUT_MAX_MS);
    if (opts.catalogCacheMax !== undefined) checkInt('catalogCacheMax', opts.catalogCacheMax, WebwayNode.CATALOG_CACHE_MAX_MAX);
    if (opts.catalogTorrentsMax !== undefined) checkInt('catalogTorrentsMax', opts.catalogTorrentsMax, WebwayNode.CATALOG_TORRENTS_MAX_MAX);
    this.opts = opts;
    this.home = opts.home ?? process.env.WEBWAY_HOME ?? join(homedir(), '.webway');
  }

  get pk() { return this.key.pk.toString('hex'); }
  get dht(): any { return (this.client as any).dht; }
  modelsDir() { return join(this.home, 'models'); }

  async start(): Promise<this> {
    await mkdir(this.modelsDir(), { recursive: true });
    this.key = await loadOrCreate(join(this.home, 'key.json'));
    await this.recoverImports();
    const saved = await this.readJson<{ nodes?: any[] }>('dht.json', {});
    // Bootstrap set = builtin routers + nodes we knew last session + DNS TXT seeds + anything passed on the CLI.
    // (k-rpc treats a non-empty `nodes` as a replacement for `bootstrap`, so we merge by hand.)
    const remembered = advertisableNodes(saved.nodes ?? [], LIMITS.rememberedCap, true);
    // Validate --peer values: a junk entry must not crash the DHT socket; IPv6 is unusable (udp4 transport).
    const peers = canonicalEndpoints(this.opts.peers ?? []);
    // DNS never delays startup: the DHT starts on builtin + remembered + peers and DNS seeds are
    // added as they arrive (their query is cancelled on timeout or stop()).
    const bootstrap = this.opts.bootstrap === false ? false
      : mergeBootstrap({ builtin: this.opts.bootstrap ?? EXTRA_BOOTSTRAP, remembered, dns: false, peers });
    const dnsDomains = this.opts.dns === false ? false : Array.isArray(this.opts.dns) ? this.opts.dns : DNS_SEED_DOMAINS;
    // Restore adoption provenance before anything can publish a catalog.
    const adoptFile = sanitizeAdoptFile(await this.readJson<unknown>('dht-adopt.json', {}));
    for (const [addr, t] of Object.entries(adoptFile.adopted)) this.adopted.set(addr, t);
    const clientOpts = {
      torrentPort: this.opts.torrentPort ?? 0,
      dhtPort: this.opts.dhtPort ?? 0,
      dht: { verify, bootstrap },
      natUpnp: this.opts.nat ?? true,
      natPmp: this.opts.nat ?? true,
      tracker: false, // DHT + PEX only; nothing to subpoena
      lsd: true, // BEP14: find peers on the LAN with no DHT at all
    };
    // webtorrent binds uTP (UDP) on whatever port the kernel gave its TCP server; when that UDP
    // port is already taken the client dies with EADDRINUSE. Bounded retry with a fresh client
    // (only when the ports were kernel-assigned; an explicit port collision is the user's to fix).
    for (let attempt = 1; ; attempt++) {
      this.client = new WebTorrent(clientOpts as any);
      try { await this.waitListening(); break; }
      catch (e: any) {
        await new Promise<void>((r) => this.client.destroy(() => r()));
        if (e?.code !== 'EADDRINUSE' || attempt >= 5 || this.opts.torrentPort || this.opts.dhtPort) throw e;
      }
    }
    // Immediate pings only for --peer values that survived the merged, capped list (never the raw array).
    this.startupPeers = startupPeerPings(bootstrap, peers);
    for (const p of this.startupPeers) { const a = parseHostPort(p); if (a) this.dht.addNode({ host: a.host, port: a.port }); }
    if (bootstrap !== false && dnsDomains !== false) {
      // We own the resolver: stop() cancels it (pending queries reject) and aborts the wrapper
      // (settles the promise, clears its timers) whatever the resolver does.
      const given = this.opts.dnsResolver;
      this.dnsResolverHandle = !given ? ownedResolver() : typeof given === 'function' ? { resolveTxt: given, cancel() {} } : given;
      const admitted: string[] = [];
      // Only what mergeBootstrap would have admitted: cap total against the reserved list.
      let room = Math.max(0, LIMITS.bootstrapTotal - bootstrap.length);
      const admit = (seeds: string[]) => {
        if (this.stopping || !this.dht || this.dht.destroyed) return;
        const fresh: string[] = [];
        for (const s of seeds) {
          if (room <= 0 || this.dnsCandidates.size >= LIMITS.dnsEndpointsTotal) break;
          if (bootstrap.includes(s) || this.dnsCandidates.has(s)) continue;
          this.dnsCandidates.add(s); room--; admitted.push(s); fresh.push(s);
        }
        if (!fresh.length) return;
        // First-contact discovery is armed BEFORE the seed pings so an immediately successful ping
        // counts; only now, when DNS seeds exist (the ordinary bootstrap list populates the table itself).
        this.armDiscovery();
        for (const s of fresh) { const a = parseHostPort(s); if (a) this.dht.addNode({ host: a.host, port: a.port }); }
        this.scheduleDnsRetry(); // candidates arriving late must still get the retry loop
      };
      // Per-domain emission: a fast domain's seeds go in before a hanging one times out.
      this.dnsReady = dnsSeeds(dnsDomains, this.dnsResolverHandle, this.opts.dnsTimeoutMs, { signal: this.dnsAbort.signal, onDomain: admit })
        .then(() => admitted).catch(() => admitted);
    }
    // Wait (bounded) for the routing table to populate so puts/gets have somewhere to go.
    // (An empty list can never populate anything: don't sit through the 15 s for it.)
    if (bootstrap !== false && bootstrap.length > 0) await Promise.race([new Promise<void>((r) => this.dht.once('ready', r)), new Promise<void>((r) => setTimeout(r, 15_000).unref())]);
    if (bootstrap !== false && dnsDomains !== false) this.scheduleDnsRetry();
    // Persist the routing table so we can rejoin even if every bootstrap router is gone,
    // and notice if we have become isolated (retry DNS seeds again).
    const persist = () => { this.checkIsolation(); this.writeJson('dht.json', { nodes: this.dht.toJSON().nodes }).catch(() => {}); };
    this.timers.push(setInterval(persist, 60_000));
    this.timers[0].unref();
    return this;
  }

  /**
   * Arm one-shot first-contact discovery: when the routing table is empty and a node
   * answers, look up our own id through it to populate the table. Armed only while the
   * table is empty; re-armed by checkIsolation() if we later lose every contact.
   */
  private armDiscovery(): void {
    if (this.discoveryListener || this.stopping || !this.dht || this.dht.destroyed) return;
    if (this.dht.nodes.count() > 0) return; // bootstrap population already handles a non-empty table
    const onNode = () => {
      this.disarmDiscovery();
      if (this.stopping || this.dht.destroyed) return;
      this.dnsLookups++;
      this.dht.lookup(this.dht.nodeId, () => {});
    };
    this.discoveryListener = onNode;
    this.dht.on('node', onNode);
  }

  private disarmDiscovery(): void {
    if (!this.discoveryListener) return;
    this.dht?.removeListener('node', this.discoveryListener);
    this.discoveryListener = undefined;
  }

  /**
   * DNS seeds are not one-shot pings: while the routing table is empty, re-ping the
   * candidates every DNS_RETRY.intervalMs, at most DNS_RETRY.max times (per isolation
   * episode). Scheduled after bootstrap, whenever candidates arrive, and whenever
   * checkIsolation() finds the table empty again.
   */
  private scheduleDnsRetry(): void {
    if (this.stopping || this.dnsRetryTimer || !this.dht || this.dht.destroyed) return;
    if (this.dnsCandidates.size === 0) return;
    const interval = this.opts.dnsRetryMs ?? DNS_RETRY.intervalMs;
    const tick = () => {
      this.dnsRetryTimer = undefined;
      if (this.stopping || !this.dht || this.dht.destroyed) return;
      if (this.dht.nodes.count() > 0 || this.dnsRetries >= DNS_RETRY.max) return;
      this.dnsRetries++;
      this.armDiscovery();
      for (const s of this.dnsCandidates) { const a = parseHostPort(s); if (a) this.dht.addNode({ host: a.host, port: a.port }); }
      this.dnsRetryTimer = setTimeout(tick, interval);
      this.dnsRetryTimer.unref();
    };
    // First tick waits one interval: the seeds were pinged on admission; only retry if that failed.
    this.dnsRetryTimer = setTimeout(tick, interval);
    this.dnsRetryTimer.unref();
  }

  /** Populated -> reset the retry budget; populated-then-empty -> start a new retry episode. */
  checkIsolation(): void {
    if (this.stopping || !this.dht || this.dht.destroyed) return;
    if (this.dht.nodes.count() > 0) { this.dnsRetries = 0; this.wasPopulated = true; return; }
    if (this.wasPopulated) { this.wasPopulated = false; this.armDiscovery(); this.scheduleDnsRetry(); }
  }

  /** Resolve once both the DHT socket and the torrent (TCP + uTP) server are listening; reject on a startup error. */
  private waitListening(): Promise<void> {
    const c: any = this.client;
    return new Promise<void>((resolve, reject) => {
      let dhtUp = false, torrentUp = false;
      const done = () => { if (dhtUp && torrentUp) { c.removeListener('error', onErr); resolve(); } };
      const onErr = (e: any) => reject(e);
      c.once('error', onErr);
      c.dht.once('listening', () => { dhtUp = true; done(); });
      if (c.listening) { torrentUp = true; done(); } else c.once('listening', () => { torrentUp = true; done(); });
    });
  }

  async stop(): Promise<void> {
    this.stopping = true; // set before any await: nothing is admitted while we wind down
    for (const t of this.timers) clearInterval(t);
    if (this.dnsRetryTimer) { clearTimeout(this.dnsRetryTimer); this.dnsRetryTimer = undefined; }
    this.disarmDiscovery();
    this.dnsAbort.abort();
    try { this.dnsResolverHandle?.cancel(); } catch {}
    try { await this.writeJson('dht.json', { nodes: this.dht?.toJSON().nodes ?? [] }); } catch {}
    await new Promise<void>((r) => this.client.destroy(() => r()));
  }

  // ---- persistence -------------------------------------------------------

  private async readJson<T>(f: string, dflt: T): Promise<T> {
    try { return JSON.parse(await readFile(join(this.home, f), 'utf8')); } catch { return dflt; }
  }
  /** Atomic + serialised per path (see atomic.ts); a crash never leaves truncated JSON. */
  private writeJson(f: string, v: unknown) { return atomicWriteJson(this.home, f, v); }
  shares() { return this.readJson<Share[]>('shares.json', []); }
  /** All shares.json writes go through one serialised, atomic (tmp+rename) transaction chain. */
  private mutateShares(fn: (all: Share[]) => Share[]): Promise<Share[]> {
    const run = async () => { const next = fn(await this.shares()); await atomicWriteJson(this.home, 'shares.json', next); return next; };
    const p = this.sharesTxn.then(run, run);
    this.sharesTxn = p.catch(() => {});
    return p;
  }
  /** Own shares are keyed by name (one name -> one version); held shares are keyed by (name, ih). */
  private upsertShare(s: Share) {
    const clean: Share = { name: s.name, ih: s.ih, dir: s.dir, size: s.size, license: s.license, own: s.own };
    return this.mutateShares((all) => [...all.filter((x) => s.own ? !(x.own && x.name === s.name) : !(!x.own && x.name === s.name && x.ih === s.ih)), clean]);
  }
  /** Remove just the own record for `name`, restoring `previous` in its place if given. */
  private restoreOwn(name: string, previous?: Share) {
    return this.mutateShares((all) => { const rest = all.filter((x) => !(x.own && x.name === name)); if (previous) rest.push(previous); return rest; });
  }

  // ---- backing dirs (what a live torrent reads from) -----------------------
  private track(ih: string, dir: string) { let set = this.backing.get(ih); if (!set) this.backing.set(ih, (set = new Set())); set.add(resolvePath(dir)); }
  private untrack(ih: string) { this.backing.delete(ih); }
  /** True when a live torrent in this process is reading from `dir`. Never delete such a dir. */
  isBacking(dir: string): boolean {
    const d = resolvePath(dir);
    for (const set of this.backing.values()) if (set.has(d)) return true;
    for (const ref of this.refs.values()) if (ref.dir && !(ref.torrent as any).destroyed && resolvePath(ref.dir) === d) return true;
    return false;
  }
  backingDirs(ih: string): string[] { return [...(this.backing.get(ih) ?? [])]; }

  /**
   * Reconcile versioned imports (see versions.ts) on start or on demand: each repo is handled
   * under its own lock (repos with a live importer are skipped), `current.json` is the truth,
   * a journaled pending promotion is completed or its share record dropped, and nothing that
   * is current, in progress, pending, or backing a live torrent is ever pruned.
   */
  async recoverImports(): Promise<Recovery> {
    const r = await recoverVersions(this.home, { isLive: (d) => this.isBacking(d), shares: await this.shares() });
    for (const name of r.remove) await this.restoreOwn(name);
    for (const s of r.restore) {
      await this.upsertShare(s);
      // A torrent of ours still reading a non-current version of this repo (only possible when
      // recovery runs inside a live process) is retired, then the repo is pruned again.
      const root = versionsRoot(this.home, s.name) + sep;
      for (const t of [...this.client.torrents]) {
        if (t.infoHash === s.ih) continue;
        if (this.backingDirs(t.infoHash).some((d) => d.startsWith(root))) await this.destroyOwnTorrent(t.infoHash);
      }
      await withRepoLock(this.home, s.name, async () => {
        const ptr = await readPointer(this.home, s.name);
        if (ptr) await pruneVersions(this.home, s.name, { keep: new Set([ptr.version]), isLive: (d) => this.isBacking(d) });
      }).catch(() => {});
    }
    return r;
  }
  follows() { return this.readJson<string[]>('follows.json', []); }
  async follow(pk: string) {
    const c = canonPk(pk);
    if (!c) throw new Error('publisher key must be 64 hex chars');
    const f = new Set(await this.follows()); f.add(c);
    await this.writeJson('follows.json', [...f]);
  }

  // ---- seeding -----------------------------------------------------------

  /** Seed a directory under a torrent name (default: the directory's basename). Returns the torrent once ready. */
  seed(dir: string, o: { torrentName?: string } | string = {}): Promise<Torrent> {
    // The torrent name defaults to the directory's basename (what the catalog lifecycle relies
    // on: distinct catalog dirs must yield distinct on-disk paths under one publisher's cache).
    // Imports pass { torrentName } because their version dirs are named by commit.
    const torrentName = (typeof o === 'object' && o.torrentName) || basename(dir);
    return new Promise((resolve, reject) => {
      const before = new Set(this.client.torrents);
      const t = this.client.seed(dir, { name: torrentName, announce: [], private: false } as any, (t: Torrent) => {
        // webtorrent hands back the existing instance for a known infohash; that one keeps its own backing dir.
        if (!before.has(t)) this.track(t.infoHash, dir);
        resolve(t);
      });
      t.once('error', reject);
    });
  }

  /**
   * Share a directory under your own key: seed it, persist the share, sign its name into the
   * DHT (that is the commit point), then best-effort publish the catalog and (unless
   * keepPrevious) retire the torrent that previously backed this name.
   *
   * Ordering is what makes failure coherent: the previous torrent keeps seeding until the new
   * seed AND the DHT publish have both succeeded; the share record is persisted before the
   * publish and only that record is rolled back if the publish fails; a torrent that already
   * existed before this call (webtorrent returns the existing instance for a known infohash)
   * is never destroyed. A catalog failure after the name is published is returned as
   * `warning` and never thrown: the share is committed at that point.
   */
  async share(dir: string, name: string, license?: string, o: ShareOpts = {}): Promise<Share & { warning?: string }> {
    const share = await this.prepareShare(dir, name, license, o);
    let warning: string | undefined;
    try { await this.publishCatalog(); } catch (e: any) { warning = `catalog publish failed (will retry on serve): ${e?.message ?? e}`; }
    return warning ? { ...share, warning } : share;
  }

  /** seed + persist + publishName. Throws only before anything is committed. */
  async prepareShare(dir: string, name: string, license?: string, o: ShareOpts = {}): Promise<Share> {
    assertPublishable(name, license);
    const before = new Set(this.client.torrents);
    const t = await this.seed(dir, { torrentName: o.torrentName });
    const ownedByUs = !before.has(t);
    const prev = (await this.shares()).find((s) => s.own && s.name === name);
    const share: Share = { name, ih: t.infoHash, dir: o.dir ?? dir, size: t.length, license, own: true };
    let committed = false;
    try {
      await this.upsertShare(share);
      await this.publishName(share);
      committed = true;
    } finally {
      if (!committed) {
        try { await this.restoreOwn(name, prev); }
        finally { if (ownedByUs && !(prev && prev.ih === t.infoHash)) await this.destroyOwnTorrent(t.infoHash); }
      }
    }
    if (!o.keepPrevious && prev && prev.ih !== t.infoHash) await this.stopTorrent(prev.ih, name);
    return share;
  }

  /**
   * Undo a share() the caller has not committed: restore the previous record, drop the new
   * torrent, and make sure the abandoned name is not re-put by us (the DHT record itself
   * expires on its own, ~2h; nothing can unpublish it).
   */
  async unshare(s: Share, previous?: Share): Promise<void> {
    await this.restoreOwn(s.name, previous);
    const held = await this.held();
    if (delete held[`${this.pk}/${s.name}`]) await this.writeJson('records.json', held);
    if (!previous || previous.ih !== s.ih) await this.stopTorrent(s.ih, s.name);
  }

  /** Destroy one of OUR seeded torrents by infohash and forget its backing dirs (catalog torrents use the ref lifecycle below). */
  private async destroyOwnTorrent(ih: string): Promise<void> {
    const t = await (this.client as any).get(ih);
    if (t) await new Promise<void>((r) => t.destroy({}, () => r()));
    this.untrack(ih);
  }

  /** Destroy the torrent for `ih` unless another own share (other than `exceptName`) still needs it. */
  async stopTorrent(ih: string, exceptName?: string): Promise<void> {
    const stillUsed = (await this.shares()).some((s) => s.own && s.ih === ih && s.name !== exceptName);
    if (stillUsed) return;
    await this.destroyOwnTorrent(ih);
  }

  /** Stop seeding whatever currently backs our own share `name` (keeps shares.json until a replacement is written). */
  async stopSharing(name: string): Promise<void> {
    const prev = (await this.shares()).find((s) => s.own && s.name === name);
    if (prev) await this.stopTorrent(prev.ih, name);
  }

  /** Reseed everything we hold and re-put our names (BEP44 items expire after ~2h). */
  async serve(): Promise<Share[]> {
    const shares = await this.shares();
    for (const s of shares) {
      await new Promise<void>((r) => { const t = this.client.add(s.ih, { path: join(s.dir, '..'), announce: [] } as any, () => { this.track(s.ih, s.dir); r(); }); t.once('error', () => r()); });
    }
    await this.republish();
    const t = setInterval(() => void this.republish().catch(() => {}), 50 * 60_000);
    t.unref();
    this.timers.push(t);
    return shares;
  }

  // ---- held records (issue #2) ------------------------------------------
  // Anyone can re-put a signed BEP44 item; only the publisher can mint one.
  // So every node re-puts every record it has resolved, and a name outlives
  // its publisher for as long as anyone who cares is online.

  held() { return this.readJson<Record<string, HeldRecord>>('records.json', {}); }

  private rememberChain: Promise<void> = Promise.resolve();
  private remember(r: HeldRecord): Promise<void> {
    // serialised: get() fires these concurrently and records.json is read-modify-write
    return (this.rememberChain = this.rememberChain.then(async () => {
      const all = await this.held();
      const key = `${r.k}/${r.salt}`;
      if ((all[key]?.seq ?? -1) >= r.seq) return;
      all[key] = r;
      await this.writeJson('records.json', all);
    }).catch(() => {}));
  }

  private putHeld(r: HeldRecord): Promise<void> {
    return new Promise((resolve, reject) => {
      this.dht.put({ k: Buffer.from(r.k, 'hex'), salt: Buffer.from(r.salt), v: bencode.decode(Buffer.from(r.v, 'base64')), sig: Buffer.from(r.sig, 'hex'), seq: r.seq },
        (err: Error | null) => (err ? reject(err) : resolve()));
    });
  }

  /**
   * Keep everything alive: our own names + catalog, then every record we hold.
   * Before re-putting a held record we look for a newer seq so we never push
   * a stale version over a publisher's update. Also walks followed publishers'
   * catalogs so their names get held too. Returns how many records were re-put.
   */
  async republish(): Promise<number> {
    const shares = await this.shares();
    if (shares.some((s) => s.own)) {
      for (const s of shares) if (s.own) await this.publishName(s).catch(() => {});
      await this.publishCatalog().catch(() => {});
    }
    for (const pk of await this.follows()) {
      const entries = await this.catalog(pk).catch(() => [] as CatalogEntry[]);
      for (const e of entries.slice(0, 200)) await this.get(pk, e.name).catch(() => {});
    }
    let n = 0;
    for (const r of Object.values(await this.held())) {
      if (r.k === this.pk) continue; // ours; already re-signed above
      await this.get(r.k, r.salt).catch(() => {}); // refreshes records.json if a newer seq exists
      const latest = (await this.held())[`${r.k}/${r.salt}`] ?? r;
      try { await this.putHeld(latest); n++; } catch (e) { if (process.env.WEBWAY_DEBUG) console.error("re-put failed", r.salt, e); }
    }
    return n;
  }

  // ---- names (BEP44) -----------------------------------------------------

  private seqPath() { return 'seq.json'; }
  private async nextSeq(salt: string): Promise<number> {
    const seqs = await this.readJson<Record<string, number>>(this.seqPath(), {});
    const n = Math.max((seqs[salt] ?? 0) + 1, Math.floor(Date.now() / 1000));
    seqs[salt] = n;
    await this.writeJson(this.seqPath(), seqs);
    return n;
  }

  private put(salt: string, v: unknown, seq: number): Promise<Buffer> {
    return new Promise((resolve, reject) => {
      this.dht.put({ k: this.key.pk, salt: Buffer.from(salt), seq, v, sign: (buf: Buffer) => sign(this.key, buf) },
        (err: Error | null, hash: Buffer) => (err ? reject(err) : resolve(hash)));
    });
  }

  static targetFor(pk: string, salt: string): Buffer {
    return createHash('sha1').update(Buffer.concat([Buffer.from(pk, 'hex'), Buffer.from(salt)])).digest();
  }

  private get(pk: string, salt: string): Promise<any | null> {
    return new Promise((resolve, reject) => {
      this.dht.get(WebwayNode.targetFor(pk, salt), { salt: Buffer.from(salt) }, (err: Error | null, res: any) => {
        if (err) return reject(err);
        if (!res) return resolve(null);
        // bittorrent-dht only hands back mutable items whose signature verified against res.k
        void this.remember({ k: Buffer.from(res.k).toString('hex'), salt, v: Buffer.from(bencode.encode(res.v)).toString("base64"), sig: Buffer.from(res.sig).toString('hex'), seq: res.seq });
        resolve(res.v);
      });
    });
  }

  async publishName(s: Share): Promise<void> {
    const seq = await this.nextSeq(s.name);
    const v: Record<string, unknown> = { ih: Buffer.from(s.ih, 'hex'), n: s.name, sz: s.size };
    if (s.license) v.l = s.license;
    await this.put(s.name, v, seq);
  }

  /** Our catalog: every share we own, as a tiny torrent; the DHT record just points at it. */
  async publishCatalog(): Promise<void> {
    const entries: CatalogEntry[] = (await this.shares()).filter((s) => s.own)
      .map(({ name, ih, size, license }) => ({ name, ih, size, license }));
    const dir = join(this.home, 'catalog');
    await mkdir(dir, { recursive: true });
    // endorse = who we follow; other nodes walk this to widen search (#3)
    const endorse = (await this.follows()).filter((pk) => pk !== this.pk);
    // nodes = some of our routing table so anyone who reads this catalog can bootstrap from it (#4).
    // Never vouch for a node we only recently adopted from someone else's catalog (no transitive laundering).
    const now = Date.now();
    const recentlyAdopted = (addr: string) => { const t = this.adopted.get(addr); return t !== undefined && now - t < ADOPT.reAdvertiseAfterMs; };
    const nodes = advertisableNodes(this.dht.toJSON().nodes ?? [], LIMITS.advertise, this.opts.allowPrivate ?? false, recentlyAdopted);
    await writeFile(join(dir, 'catalog.json'), JSON.stringify({ pk: this.pk, entries, endorse, nodes }, null, 2));
    for (const t of this.client.torrents) if (t.name === 'catalog') await new Promise<void>((r) => t.destroy({}, () => r()));
    const t = await this.seed(dir, 'catalog');
    const seq = await this.nextSeq('catalog');
    await this.put('catalog', { ih: Buffer.from(t.infoHash, 'hex') }, seq);
  }

  /** Resolve webway://<pk>/<name>, a magnet, or a bare infohash to an infohash + metadata. */
  async resolve(ref: string): Promise<{ ih: string; name: string; size?: number; license?: string; pk?: string }> {
    if (/^[0-9a-f]{40}$/i.test(ref)) return { ih: ref.toLowerCase(), name: ref };
    const m = /^magnet:.*xt=urn:btih:([0-9a-f]{40})/i.exec(ref);
    if (m) return { ih: m[1].toLowerCase(), name: m[1] };
    const w = /^(?:webway:\/\/)?([0-9a-f]{64})\/(.+)$/i.exec(ref);
    if (!w) throw new Error(`unrecognised ref: ${ref} (want webway://<pk>/<name>, magnet, or infohash)`);
    const [, pk, name] = w;
    const v = await this.get(pk.toLowerCase(), name);
    if (!v) throw new Error(`no signed record for ${name} under ${pk.slice(0, 12)}… (publisher offline > 2h and nobody re-put it?)`);
    return { ih: Buffer.from(v.ih).toString('hex'), name: String(v.n), size: Number(v.sz), license: v.l ? String(v.l) : undefined, pk };
  }

  /** Download a model into ~/.webway/models/<name>, verifying every piece, and keep seeding it. */
  async fetch(ref: string, onProgress?: (t: Torrent) => void): Promise<Share> {
    const r = await this.resolve(ref);
    const path = join(this.modelsDir(), ...r.name.split('/'));
    await mkdir(path, { recursive: true });
    const t = await new Promise<Torrent>((resolve, reject) => {
      const t = this.client.add(r.ih, { path, announce: [] } as any);
      t.once('error', reject);
      t.once('done', () => { this.track(t.infoHash, torrentRoot(t, path)); resolve(t); });
      if (onProgress) { const i = setInterval(() => onProgress(t), 1000); t.once('done', () => clearInterval(i)); t.once('error', () => clearInterval(i)); }
    });
    const share: Share = { name: r.name, ih: t.infoHash, dir: torrentRoot(t, path), size: t.length, license: r.license, own: false };
    await this.upsertShare(share);
    return share;
  }

  // ---- catalogs (issue #3) ----------------------------------------------
  // Transitive search exposes this path to publishers the user never chose, so
  // every step is bounded: each caller has an absolute deadline covering DHT
  // lookup + acquisition + metadata + download + file read; torrent size is
  // checked before the body downloads; entries/endorsements/results are capped.
  //
  // Torrent lifecycle is one record per infohash (TorrentRef): `owned` means we
  // started the download and may destroy it; `readers` are in-flight loads;
  // `retainedBy` are publishers whose *current* catalog it is. A torrent is
  // destroyed only when owned && readers === 0 && retainedBy.size === 0, and
  // always by its stored object, never by a fresh lookup of the hash (an
  // external reseed of the same hash is never ours to delete). Destroy and
  // reacquire are serialised per infohash.

  static readonly CATALOG_MAX_BYTES = 1 << 20;
  static readonly CATALOG_MAX_ENTRIES = 5000;
  static readonly CATALOG_MAX_ENDORSE = 100;
  static readonly SEARCH_MAX_RESULTS = 1000;
  static readonly SEARCH_MAX_DEPTH = 5;
  static readonly SEARCH_MAX_PUBLISHERS = 500;
  static readonly CATALOG_TIMEOUT_MAX_MS = 600_000;
  static readonly SEARCH_TIMEOUT_MAX_MS = 3_600_000;
  static readonly CATALOG_CACHE_MAX_MAX = 100_000;
  static readonly CATALOG_TORRENTS_MAX_MAX = 100_000;

  private catalogCache = new Map<string, Catalog>(); // `${pk}/${ih}` -> parsed catalog (insertion-ordered; LRU)
  private catalogInflight = new Map<string, { promise: Promise<Catalog>; waiters: number; ctl: AbortController; settled: boolean; aborted: boolean }>();
  private gen = 0; // generation counter for owned download directories
  private refs = new Map<string, TorrentRef>(); // ih -> lifecycle record
  private ihTails = new Map<string, Promise<void>>(); // per-ih serialisation of destroy/reacquire
  private current = new Map<string, TorrentRef>(); // pk -> ref of its current catalog torrent
  /** Catalog torrents we started downloading (cache misses that were not reusable locally); exposed for tests. */
  catalogFetches = 0;
  /** Catalog torrents refused for exceeding CATALOG_MAX_BYTES; exposed for tests. */
  catalogRefused = 0;
  /** Lifecycle errors that happened off the critical path (retirement); exposed for tests/logging. */
  lifecycleErrors: Error[] = [];
  get catalogCacheSize() { return this.catalogCache.size; }
  /** Owned catalog torrents currently alive. */
  get catalogTorrentCount() { return [...this.refs.values()].filter((r) => r.owned && !(r.torrent as any).destroyed).length; }

  /** Fetch a publisher's catalog torrent and return its entries. */
  async catalog(rawPk: string): Promise<CatalogEntry[]> {
    const pk = canonPk(rawPk);
    if (!pk) throw new Error('publisher key must be 64 hex chars');
    return (await this.catalogFull(pk)).entries;
  }

  /** Per-publisher adoption accounting (validated, case-variants merged). */
  async adoptState(): Promise<Record<string, AdoptState>> { return (await this.loadAdopt()).publishers; }
  private async loadAdopt(): Promise<AdoptFile> { return sanitizeAdoptFile(await this.readJson<unknown>('dht-adopt.json', {})); }

  /**
   * Add catalog-carried DHT nodes to our routing table, rationed (#4 review).
   * One serialised transaction per call (concurrent reads cannot double-spend), one
   * pass over at most ADOPT.inspect raw entries: parse, filter (public IPv4 literals
   * only unless allowPrivate; no hostnames, no IPv6), dedupe within the read (Set) and
   * across reads (persisted per publisher), then budget: ADOPT.perRead per call,
   * ADOPT.perPublisher per publisher key ever, ADOPT.perSubnetPerPublisher per /24 per
   * publisher, ADOPT.perSession per process; once the routing table holds >=
   * ADOPT.tableFull nodes only never-seen addresses are considered. Addresses already
   * in our routing table were learned independently: skipped, no budget, no provenance.
   * Stops as soon as a cap or budget is hit. Returns the addresses handed to the DHT
   * (which pings before inserting).
   */
  adoptNodes(nodes: unknown, rawPk: unknown): Promise<string[]> {
    const pk = canonPk(rawPk);
    if (!Array.isArray(nodes) || !pk || nodes.length === 0) return Promise.resolve([]);
    const run = this.adoptChain.then(() => this.adoptTx(nodes, pk), () => this.adoptTx(nodes, pk));
    this.adoptChain = run.catch(() => {});
    return run;
  }

  private async adoptTx(nodes: unknown[], pk: string): Promise<string[]> {
    if (this.stopping) return [];
    const file = await this.loadAdopt();
    const st: AdoptState = file.publishers[pk] ?? { n: 0, seen: [], subnets: {} };
    const seenBefore = new Set(st.seen);
    const tableFull = (this.dht?.nodes?.count?.() ?? 0) >= ADOPT.tableFull;
    const inTable = new Set<string>((this.dht?.toJSON?.().nodes ?? []).map((x: any) => `${x.host}:${x.port}`));
    const inRead = new Set<string>();
    const admitted: string[] = [];
    const limit = Math.min(nodes.length, ADOPT.inspect);
    for (let i = 0; i < limit; i++) {
      if (admitted.length >= ADOPT.perRead) break;
      if (st.n >= ADOPT.perPublisher || this.adoptedThisSession >= ADOPT.perSession) break;
      const n = nodes[i];
      const e = typeof n === 'string' ? parseHostPort(n) : undefined;
      if (!e || !usable(e) || e.family !== 4) continue;
      if (!this.opts.allowPrivate && isPrivateHost(e.host)) continue;
      const s = formatHostPort(e);
      if (inRead.has(s) || inTable.has(s) || seenBefore.has(s)) continue;
      inRead.add(s);
      const sub = subnetKey(e.host);
      if ((st.subnets[sub] ?? 0) >= ADOPT.perSubnetPerPublisher) continue;
      if (tableFull && this.adopted.has(s)) continue;
      st.n++; st.seen.push(s); st.subnets[sub] = (st.subnets[sub] ?? 0) + 1; this.adoptedThisSession++;
      this.adopted.set(s, Date.now());
      admitted.push(s);
    }
    if (admitted.length) {
      file.publishers[pk] = st;
      file.adopted = Object.fromEntries(this.adopted);
      await this.writeJson('dht-adopt.json', file);
      if (this.stopping || !this.dht || this.dht.destroyed) return admitted;
      for (const s of admitted) { const a = parseHostPort(s)!; this.dht.addNode({ host: a.host, port: a.port }); }
    }
    return admitted;
  }

  /**
   * Fetch a publisher's catalog (entries + endorsed publishers), bounded by an
   * absolute per-caller deadline (`deadlineMs`, default opts.catalogTimeoutMs,
   * 20s). Never throws for a missing/unreachable/oversized/malformed catalog:
   * returns an empty catalog. Parsed catalogs are cached per pk+infohash (LRU,
   * opts.catalogCacheMax entries; 0 disables the cache). Concurrent loads of the
   * same key share one underlying load; each caller still leaves at its own
   * deadline, and the load is cancelled only once no caller is waiting.
   */
  async catalogFull(rawPk: string, deadlineMs?: number): Promise<Catalog> {
    const empty = emptyCatalog();
    const budget = Math.max(0, deadlineMs ?? this.opts.catalogTimeoutMs ?? 20_000);
    const deadline = Date.now() + budget;
    const pk = canonPk(rawPk);
    if (!pk) return empty;
    let v: any;
    try { v = await withDeadline(this.get(pk, 'catalog'), deadline, 'catalog record lookup'); } catch (e) { debug(`catalog ${pk.slice(0, 8)}: lookup failed: ${(e as Error).message}`); return empty; }
    if (!v || !(v.ih instanceof Uint8Array)) { debug(`catalog ${pk.slice(0, 8)}: no record`); return empty; }
    const ih = Buffer.from(v.ih).toString('hex');
    if (!/^[0-9a-f]{40}$/.test(ih)) return empty;
    const key = `${pk}/${ih}`;
    const cached = this.catalogCache.get(key);
    if (cached) {
      this.catalogCache.delete(key); this.catalogCache.set(key, cached); // LRU touch
      const live = this.current.get(pk);
      if (live && live.ih === ih) live.lastUse = Date.now(); // keep a hot publisher's torrent hot too
      return cached;
    }
    let inflight = this.catalogInflight.get(key);
    if (!inflight || inflight.aborted) {
      const ctl = new AbortController();
      const entry = { promise: null as unknown as Promise<Catalog>, waiters: 0, ctl, settled: false, aborted: false };
      entry.promise = this.loadCatalog(pk, ih, ctl.signal).finally(() => {
        entry.settled = true;
        if (this.catalogInflight.get(key) === entry) this.catalogInflight.delete(key);
      });
      entry.promise.catch(() => {}); // observed by waiters; never unhandled
      this.catalogInflight.set(key, entry);
      inflight = entry;
    }
    inflight.waiters++;
    try {
      return await withDeadline(inflight.promise, deadline, 'catalog load');
    } catch (e) {
      debug(`catalog ${pk.slice(0, 8)}/${ih.slice(0, 8)}: load failed: ${(e as Error).message}`);
      return empty;
    } finally {
      inflight.waiters--;
      if (inflight.waiters === 0 && !inflight.settled && !inflight.aborted) {
        // nobody is waiting any more: cancel, and never let a newcomer join this doomed load
        inflight.aborted = true;
        inflight.ctl.abort();
        if (this.catalogInflight.get(key) === inflight) this.catalogInflight.delete(key);
      }
    }
  }

  /** Resolve once every queued destroy/reacquire has settled (retirement runs off the critical path). */
  async lifecycleIdle(): Promise<void> {
    while (this.ihTails.size) await Promise.all([...this.ihTails.values()]);
  }

  /** Run `fn` after every earlier operation on this infohash has settled. */
  private serial<T>(ih: string, fn: () => Promise<T>): Promise<T> {
    const prev = this.ihTails.get(ih) ?? Promise.resolve();
    const run = prev.then(fn);
    const tail = run.then(() => {}, () => {});
    this.ihTails.set(ih, tail);
    void tail.then(() => { if (this.ihTails.get(ih) === tail) this.ihTails.delete(ih); });
    return run;
  }

  /**
   * Take a reader reference on the torrent for `ih`: reuse one the client
   * already has (a seed, a model download, another publisher's identical
   * catalog) and never own it, or start a download we do own.
   */
  private acquire(pk: string, ih: string, signal: AbortSignal): Promise<TorrentRef> {
    return this.serial(ih, async () => {
      if (signal.aborted) throw new Error('aborted');
      let ref = this.refs.get(ih);
      if (ref && (ref.torrent as any).destroyed) {
        // stale record: detach every publisher still pointing at it so its cleanup never targets the replacement
        for (const rpk of [...ref.retainedBy]) { if (this.current.get(rpk) === ref) this.current.delete(rpk); }
        ref.retainedBy.clear();
        this.refs.delete(ih);
        this.maybeDestroy(ref); // no-op destroy of the dead object; removes its own generation dir
        ref = undefined;
      }
      if (!ref) {
        const existing: Torrent | undefined = await (this.client as any).get(ih);
        if (existing) {
          ref = { ih, torrent: existing, owned: false, readers: 0, retainedBy: new Set(), lastUse: Date.now() };
        } else {
          this.catalogFetches++;
          debug(`catalog download ${ih.slice(0, 8)} for ${pk.slice(0, 8)} (refs=${this.refs.size})`);
          const dir = join(this.home, 'catalogs', pk, ih, String(++this.gen)); // generation-specific: cleanup of an old ref can never touch a newer download
          await mkdir(dir, { recursive: true });
          const torrent = this.client.add(ih, { path: dir, announce: [] } as any);
          ref = { ih, torrent, owned: true, dir, readers: 0, retainedBy: new Set(), lastUse: Date.now() };
        }
        this.refs.set(ih, ref);
      }
      ref.readers++;
      ref.lastUse = Date.now();
      return ref;
    });
  }

  private release(ref: TorrentRef): void {
    ref.readers--;
    this.maybeDestroy(ref);
    this.capTorrents(); // a torrent that just went idle may now be evictable
  }

  /** Make `ref` publisher `pk`'s current catalog torrent; the previous one loses that retention. */
  private retain(pk: string, ref: TorrentRef): void {
    const prev = this.current.get(pk);
    if (prev === ref) return;
    if (prev) { prev.retainedBy.delete(pk); this.maybeDestroy(prev); }
    ref.retainedBy.add(pk);
    ref.lastUse = Date.now();
    this.current.set(pk, ref);
    this.capTorrents();
  }

  /** Drop `pk`'s retention of its current catalog torrent (cache eviction). */
  private retire(pk: string, ih?: string): void {
    const ref = this.current.get(pk);
    if (!ref || (ih && ref.ih !== ih)) return;
    this.current.delete(pk);
    ref.retainedBy.delete(pk);
    this.maybeDestroy(ref);
  }

  /** Keep at most opts.catalogTorrentsMax owned catalog torrents, evicting least recently used idle ones. */
  private capTorrents(): void {
    const max = this.opts.catalogTorrentsMax ?? 200;
    const owned = [...this.refs.values()].filter((r) => r.owned && !(r.torrent as any).destroyed);
    if (owned.length <= max) return;
    owned.sort((a, b) => a.lastUse - b.lastUse);
    let excess = owned.length - max;
    for (const r of owned) { // least recently used first; skip busy ones and keep scanning until enough idle ones are picked
      if (excess <= 0) break;
      if (r.readers > 0) continue;
      for (const pk of [...r.retainedBy]) { if (this.current.get(pk) === r) this.current.delete(pk); r.retainedBy.delete(pk); }
      this.maybeDestroy(r);
      excess--;
    }
  }

  /**
   * Destroy an owned torrent once nothing uses it. Borrowed torrents are merely
   * forgotten. Off the critical path: errors are collected, never thrown.
   */
  private maybeDestroy(ref: TorrentRef): void {
    if (ref.readers > 0 || ref.retainedBy.size > 0) return;
    if (!ref.owned) { if (this.refs.get(ref.ih) === ref) this.refs.delete(ref.ih); return; }
    void this.serial(ref.ih, async () => {
      if (ref.readers > 0 || ref.retainedBy.size > 0) return; // re-acquired while queued
      if (this.refs.get(ref.ih) === ref) this.refs.delete(ref.ih);
      await this.destroyTorrent(ref.torrent, true);
      if (ref.dir) {
        await rm(ref.dir, { recursive: true, force: true });
        await rmdir(dirname(ref.dir)).catch(() => {}); // drop the <ih> dir if this was its last generation
        await rmdir(dirname(dirname(ref.dir))).catch(() => {}); // ...and the <pk> dir if now empty
      }
    }).catch((e) => { this.lifecycleErrors.push(e instanceof Error ? e : new Error(String(e))); });
  }

  private async loadCatalog(pk: string, ih: string, signal: AbortSignal): Promise<Catalog> {
    const key = `${pk}/${ih}`;
    const ref = await this.acquire(pk, ih, signal);
    const tor = ref.torrent;
    try {
      // 1. metadata (so we know the size) before any body bytes matter
      await waitFor(tor, () => tor.files.length > 0, 'metadata', signal);
      if (tor.length > WebwayNode.CATALOG_MAX_BYTES) {
        this.catalogRefused++;
        throw new Error(`catalog torrent ${ih} is ${tor.length} bytes (> ${WebwayNode.CATALOG_MAX_BYTES})`);
      }
      // 2. body
      await waitFor(tor, () => tor.done, 'done', signal);
      // 3. locate catalog.json through the torrent's own file manifest, never a directory listing
      const file = tor.files.find((f: { path: string; name: string }) => f.name === 'catalog.json');
      const cat: Catalog = file ? parseCatalog(await readFile(join(tor.path, file.path), { encoding: 'utf8', signal }), pk) : emptyCatalog();
      // 4. this is now pk's current catalog torrent; the previous one is retired off the critical path
      this.retain(pk, ref);
      // 5. bootstrap hints (#4): rationed adoption; a failure here never spoils the catalog itself
      if (cat.nodes?.length) await this.adoptNodes(cat.nodes, pk).catch((e) => { this.lifecycleErrors.push(e instanceof Error ? e : new Error(String(e))); });
      const max = this.opts.catalogCacheMax ?? 200;
      if (max > 0) {
        this.catalogCache.set(key, cat);
        while (this.catalogCache.size > max) {
          const evicted = this.catalogCache.keys().next().value!;
          this.catalogCache.delete(evicted);
          const [epk, eih] = evicted.split('/');
          this.retire(epk, eih);
        }
      }
      return cat;
    } finally {
      this.release(ref);
    }
  }

  private destroyTorrent(t: Torrent, destroyStore: boolean): Promise<void> {
    return new Promise((r) => { try { if ((t as any).destroyed) return r(); t.destroy({ destroyStore } as any, () => r()); } catch { r(); } });
  }

  /**
   * Search the web of publishers: BFS from your follow list along each catalog's
   * `endorse` list. depth 0 = only publishers you follow; each hop widens to the
   * publishers they endorse. Bounded by depth (<= SEARCH_MAX_DEPTH), maxPublishers
   * (<= SEARCH_MAX_PUBLISHERS), SEARCH_MAX_RESULTS and an overall deadline
   * (opts.searchTimeoutMs, default 120s). Cycles, self and unreachable publishers
   * are skipped; a slow publisher costs at most one catalog timeout.
   */
  async search(q: string, opts: SearchOpts = {}): Promise<SearchHit[]> {
    const depth = checkInt('depth', opts.depth === undefined ? 2 : opts.depth, WebwayNode.SEARCH_MAX_DEPTH);
    const maxPublishers = checkInt('maxPublishers', opts.maxPublishers === undefined ? 50 : opts.maxPublishers, WebwayNode.SEARCH_MAX_PUBLISHERS);
    const needle = String(q).toLowerCase();
    const deadline = Date.now() + Math.max(0, this.opts.searchTimeoutMs ?? 120_000);
    const queued = new Set<string>([this.pk]); // everything ever enqueued (plus self): never enqueue twice
    const seen = new Set<string>(); // `${pk}/${ih}`
    const out: SearchHit[] = [];
    const finish = (hits: SearchHit[]) => hits.sort((a, b) => a.hops - b.hops || a.name.localeCompare(b.name));
    let frontier: string[] = [];
    for (const pk of await this.follows()) if (!queued.has(pk) && queued.size - 1 < maxPublishers) { queued.add(pk); frontier.push(pk); }
    for (let hops = 0; hops <= depth && frontier.length; hops++) {
      const next: string[] = [];
      for (const pk of frontier) {
        const left = deadline - Date.now();
        if (left <= 0) return finish(out);
        const cat = await this.catalogFull(pk, Math.min(left, this.opts.catalogTimeoutMs ?? 20_000));
        for (const e of cat.entries) {
          if (out.length >= WebwayNode.SEARCH_MAX_RESULTS) return finish(out);
          const k = `${pk}/${e.ih}`;
          if (seen.has(k) || !e.name.toLowerCase().includes(needle)) continue;
          seen.add(k);
          out.push({ ...e, pk, hops });
        }
        if (hops === depth) continue; // final depth: do not expand
        for (const epk of cat.endorse) {
          if (queued.size - 1 >= maxPublishers) break; // publisher budget spent
          if (queued.has(epk)) continue;
          queued.add(epk); next.push(epk);
        }
      }
      frontier = next;
    }
    return finish(out);
  }
}

/** Reject anything that is not a safe non-negative integer within [0, max]. */
export function checkInt(name: string, v: unknown, max: number): number {
  if (typeof v !== 'number' || !Number.isSafeInteger(v) || v < 0 || v > max) {
    throw new RangeError(`${name} must be an integer in [0, ${max}], got ${String(v)}`);
  }
  return v;
}

/** Validate an untrusted catalog.json body; bad entries are dropped, good ones kept. */
export function parseCatalog(text: string, pk: string): Catalog {
  let j: any;
  try { j = JSON.parse(text); } catch { return emptyCatalog(); }
  if (!j || typeof j !== 'object' || Array.isArray(j)) return emptyCatalog();
  const entries: CatalogEntry[] = [];
  if (Array.isArray(j.entries)) {
    for (const e of j.entries) {
      if (entries.length >= WebwayNode.CATALOG_MAX_ENTRIES) break;
      if (!e || typeof e !== 'object') continue;
      if (typeof e.name !== 'string' || !e.name || e.name.length > 512) continue;
      if (typeof e.ih !== 'string' || !/^[0-9a-f]{40}$/i.test(e.ih)) continue;
      if (typeof e.size !== 'number' || !Number.isFinite(e.size) || e.size < 0) continue;
      if (e.license !== undefined && typeof e.license !== 'string') continue;
      const entry: CatalogEntry = { name: e.name, ih: e.ih.toLowerCase(), size: e.size };
      if (typeof e.license === 'string') entry.license = e.license;
      entries.push(entry);
    }
  }
  const endorse: string[] = [];
  if (Array.isArray(j.endorse)) {
    const set = new Set<string>();
    for (const x of j.endorse) {
      if (endorse.length >= WebwayNode.CATALOG_MAX_ENDORSE) break;
      if (typeof x !== 'string' || !/^[0-9a-f]{64}$/i.test(x)) continue;
      const k = x.toLowerCase();
      if (k === pk || set.has(k)) continue;
      set.add(k); endorse.push(k);
    }
  }
  // nodes: pass through at most ADOPT.inspect raw string entries (short ones); adoptNodes() does the real validation + rationing.
  const nodes: string[] = [];
  if (Array.isArray(j.nodes)) {
    for (const x of j.nodes) {
      if (nodes.length >= ADOPT.inspect) break;
      if (typeof x === 'string' && x.length <= 64) nodes.push(x);
    }
  }
  return nodes.length ? { entries, endorse, nodes } : { entries, endorse };
}

function debug(msg: string): void {
  if (process.env.WEBWAY_DEBUG) console.error(`[webway] ${msg}`);
}

/** Race `p` against an absolute deadline (ms since epoch). The underlying work is not cancelled here. */
function withDeadline<T>(p: Promise<T>, deadline: number, what: string): Promise<T> {
  const ms = deadline - Date.now();
  if (ms <= 0) return Promise.reject(new Error(`${what}: deadline already passed`));
  return new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new Error(`${what} timed out`)), ms);
    p.then((v) => { clearTimeout(t); resolve(v); }, (e) => { clearTimeout(t); reject(e); });
  });
}

/**
 * Resolve once `ready()` holds, re-checking on `event`; reject if the torrent
 * errors or closes first, or when `signal` aborts. Every listener it installs
 * is removed on every exit path, so repeated timeouts never accumulate listeners.
 */
function waitFor(tor: Torrent, ready: () => boolean, event: string, signal: AbortSignal): Promise<void> {
  const t = tor as any;
  if (signal.aborted) return Promise.reject(new Error('aborted'));
  if (ready()) return Promise.resolve();
  if (t.destroyed) return Promise.reject(new Error('torrent closed'));
  return new Promise((resolve, reject) => {
    const off = () => { t.off(event, check); t.off('error', fail); t.off('close', closed); signal.removeEventListener('abort', aborted); };
    const check = () => { if (ready()) { off(); resolve(); } };
    const fail = () => { off(); reject(new Error('torrent error')); };
    const closed = () => { off(); reject(new Error('torrent closed')); };
    const aborted = () => { off(); reject(new Error('aborted')); };
    t.on(event, check); t.on('error', fail); t.on('close', closed); signal.addEventListener('abort', aborted, { once: true });
  });
}
