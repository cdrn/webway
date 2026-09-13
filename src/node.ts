import WebTorrent, { type Torrent } from 'webtorrent';
import { createHash } from 'node:crypto';
import { mkdir, readFile, writeFile, readdir } from 'node:fs/promises';
import { join, basename } from 'node:path';
import { homedir } from 'node:os';
import { loadOrCreate, sign, verify, type Keypair } from './keys.ts';

/**
 * A webway node = a BitTorrent client + a Mainline DHT node + a publisher key.
 *
 * Resilience properties, and where each comes from:
 *  - no central index:        Mainline DHT (BEP5) for peers, BEP44 for names
 *  - unforgeable content:     infohash is the content
 *  - unforgeable names:       webway://<ed25519 pk>/<name> is a BEP44 mutable
 *                             item signed by the publisher; DHT nodes reject bad sigs
 *  - no single bootstrap:     builtin routers + persisted routing table + --peer
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
export interface CatalogEntry { name: string; ih: string; size: number; license?: string }
export interface Share { name: string; ih: string; dir: string; size: number; license?: string; own: boolean }

export interface NodeOpts {
  home?: string;
  bootstrap?: string[] | false;
  torrentPort?: number;
  dhtPort?: number;
  peers?: string[]; // extra DHT nodes host:port
  nat?: boolean; // UPnP/NAT-PMP port mapping (default on)
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

  constructor(opts: NodeOpts = {}) {
    this.opts = opts;
    this.home = opts.home ?? process.env.WEBWAY_HOME ?? join(homedir(), '.webway');
  }

  get pk() { return this.key.pk.toString('hex'); }
  get dht(): any { return (this.client as any).dht; }
  modelsDir() { return join(this.home, 'models'); }

  async start(): Promise<this> {
    await mkdir(this.modelsDir(), { recursive: true });
    this.key = await loadOrCreate(join(this.home, 'key.json'));
    const saved = await this.readJson<{ nodes?: any[] }>('dht.json', {});
    // Bootstrap set = builtin routers + nodes we knew last session + anything passed on the CLI.
    // (k-rpc treats a non-empty `nodes` as a replacement for `bootstrap`, so we merge by hand.)
    const remembered = (saved.nodes ?? []).map((n: any) => `${n.host}:${n.port}`).slice(0, 50);
    const bootstrap = this.opts.bootstrap === false ? false
      : [...(this.opts.bootstrap ?? EXTRA_BOOTSTRAP), ...remembered, ...(this.opts.peers ?? [])];
    this.client = new WebTorrent({
      torrentPort: this.opts.torrentPort ?? 0,
      dhtPort: this.opts.dhtPort ?? 0,
      dht: { verify, bootstrap },
      natUpnp: this.opts.nat ?? true,
      natPmp: this.opts.nat ?? true,
      tracker: false, // DHT + PEX only; nothing to subpoena
    } as any);
    await new Promise<void>((r) => this.dht.once('listening', r));
    for (const p of this.opts.peers ?? []) this.dht.addNode(this.parseAddr(p));
    // Wait (bounded) for the routing table to populate so puts/gets have somewhere to go.
    if (bootstrap !== false) await Promise.race([new Promise<void>((r) => this.dht.once('ready', r)), new Promise<void>((r) => setTimeout(r, 15_000).unref())]);
    // Persist the routing table so we can rejoin even if every bootstrap router is gone.
    const persist = () => this.writeJson('dht.json', { nodes: this.dht.toJSON().nodes }).catch(() => {});
    this.timers.push(setInterval(persist, 60_000));
    this.timers[0].unref();
    return this;
  }

  private parseAddr(s: string) { const i = s.lastIndexOf(':'); return { host: s.slice(0, i), port: Number(s.slice(i + 1)) }; }

  async stop(): Promise<void> {
    for (const t of this.timers) clearInterval(t);
    try { await this.writeJson('dht.json', { nodes: this.dht?.toJSON().nodes ?? [] }); } catch {}
    await new Promise<void>((r) => this.client.destroy(() => r()));
  }

  // ---- persistence -------------------------------------------------------

  private async readJson<T>(f: string, dflt: T): Promise<T> {
    try { return JSON.parse(await readFile(join(this.home, f), 'utf8')); } catch { return dflt; }
  }
  private async writeJson(f: string, v: unknown) {
    await mkdir(this.home, { recursive: true });
    await writeFile(join(this.home, f), JSON.stringify(v, null, 2));
  }
  shares() { return this.readJson<Share[]>('shares.json', []); }
  private async upsertShare(s: Share) {
    const all = (await this.shares()).filter((x) => x.ih !== s.ih);
    all.push(s);
    await this.writeJson('shares.json', all);
  }
  follows() { return this.readJson<string[]>('follows.json', []); }
  async follow(pk: string) {
    if (!/^[0-9a-f]{64}$/.test(pk)) throw new Error('publisher key must be 64 hex chars');
    const f = new Set(await this.follows()); f.add(pk);
    await this.writeJson('follows.json', [...f]);
  }

  // ---- seeding -----------------------------------------------------------

  /** Seed a directory. Returns the torrent once it is ready to serve. */
  seed(dir: string, name: string): Promise<Torrent> {
    return new Promise((resolve, reject) => {
      const t = this.client.seed(dir, { name: basename(dir), announce: [], private: false } as any, (t: Torrent) => resolve(t));
      t.once('error', reject);
    });
  }

  /** Share a directory under your own key: seed it, sign its name into the DHT, update your catalog. */
  async share(dir: string, name: string, license?: string): Promise<Share> {
    const t = await this.seed(dir, name);
    const share: Share = { name, ih: t.infoHash, dir, size: t.length, license, own: true };
    await this.upsertShare(share);
    await this.publishName(share);
    await this.publishCatalog();
    return share;
  }

  /** Reseed everything we hold and re-put our names (BEP44 items expire after ~2h). */
  async serve(): Promise<Share[]> {
    const shares = await this.shares();
    for (const s of shares) {
      await new Promise<void>((r) => { const t = this.client.add(s.ih, { path: join(s.dir, '..'), announce: [] } as any, () => r()); t.once('error', () => r()); });
    }
    const republish = async () => {
      for (const s of shares) if (s.own) await this.publishName(s).catch(() => {});
      await this.publishCatalog().catch(() => {});
    };
    await republish();
    const t = setInterval(() => void republish(), 50 * 60_000);
    t.unref();
    this.timers.push(t);
    return shares;
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
    await writeFile(join(dir, 'catalog.json'), JSON.stringify({ pk: this.pk, entries }, null, 2));
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
      t.once('done', () => resolve(t));
      if (onProgress) { const i = setInterval(() => onProgress(t), 1000); t.once('done', () => clearInterval(i)); t.once('error', () => clearInterval(i)); }
    });
    const share: Share = { name: r.name, ih: t.infoHash, dir: torrentRoot(t, path), size: t.length, license: r.license, own: false };
    await this.upsertShare(share);
    return share;
  }

  /** Fetch a publisher's catalog torrent and return its entries. */
  async catalog(pk: string): Promise<CatalogEntry[]> {
    const v = await this.get(pk, 'catalog');
    if (!v) return [];
    const ih = Buffer.from(v.ih).toString('hex');
    const dir = join(this.home, 'catalogs', pk);
    await mkdir(dir, { recursive: true });
    const existing = await (this.client as any).get(ih);
    if (existing) await new Promise<void>((r) => existing.destroy({}, () => r()));
    const t = await new Promise<Torrent>((resolve, reject) => {
      const t = this.client.add(ih, { path: dir, announce: [] } as any);
      t.once('error', reject); t.once('done', () => resolve(t));
    });
    const root = torrentRoot(t, dir);
    const files = await readdir(root);
    if (!files.includes('catalog.json')) return [];
    const j = JSON.parse(await readFile(join(root, 'catalog.json'), 'utf8'));
    return j.entries as CatalogEntry[];
  }

  /** Search across every followed publisher's catalog. */
  async search(q: string): Promise<(CatalogEntry & { pk: string })[]> {
    const out: (CatalogEntry & { pk: string })[] = [];
    const needle = q.toLowerCase();
    for (const pk of await this.follows()) {
      const entries = await this.catalog(pk).catch(() => [] as CatalogEntry[]);
      for (const e of entries) if (e.name.toLowerCase().includes(needle)) out.push({ ...e, pk });
    }
    return out;
  }
}
