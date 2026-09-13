import {
  createPublicClient, createWalletClient, http, keccak256, toBytes, toHex, getAddress, encodeFunctionData, decodeFunctionResult,
  type Address, type Hex, type PublicClient, type Chain,
} from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { sign, type Keypair } from './keys.ts';

/**
 * On-chain registry (issue #9): a permanent, global index of webway names.
 *
 * A publisher (ed25519 pk) binds the Ethereum account that publishes for it
 * by submitting an ed25519 signature over
 *   "webway-bind:<chainId>:<0x lowercase address>:<epoch>"
 * which the contract verifies ON-CHAIN (pure-Solidity Ed25519 + SHA-512).
 * owner[pk] = (account, epoch); each new binding needs a higher epoch, so a
 * re-bind from a fresh account revokes a compromised one and only the key
 * holder can ever change the owner. The client does no binding verification
 * of its own: ownerOf(pk) is authoritative because the chain checked the
 * signature before storing it. Pre-flight uses the contract's own verifier
 * (checkBinding) through eth_call; noble is used only to produce signatures.
 *
 * Freshness: every read happens at one snapshot {height, hash}. The height is
 * the highest one that at least minAgree endpoints can serve (the minAgree-th
 * largest head, minus SNAPSHOT_LAG); endpoints that cannot serve it drop out
 * instead of dragging it down. Every eth_call is pinned to the block HASH
 * (EIP-1898), so a fork flip between calls cannot mix state. Answers must
 * agree byte-for-byte across at least minAgree endpoints. "Owner" therefore
 * means owner as of that snapshot: about SNAPSHOT_LAG blocks plus quorum lag
 * behind the best head.
 */

export const REGISTRY_ABI = [
  { type: 'function', name: 'bind', stateMutability: 'nonpayable', inputs: [{ name: 'pk', type: 'bytes32' }, { name: 'sig', type: 'bytes' }, { name: 'epoch', type: 'uint64' }], outputs: [] },
  { type: 'function', name: 'checkBinding', stateMutability: 'view', inputs: [{ name: 'pk', type: 'bytes32' }, { name: 'addr', type: 'address' }, { name: 'epoch', type: 'uint64' }, { name: 'sig', type: 'bytes' }], outputs: [{ name: '', type: 'bool' }] },
  { type: 'function', name: 'bindingMessage', stateMutability: 'view', inputs: [{ name: 'addr', type: 'address' }, { name: 'epoch', type: 'uint64' }], outputs: [{ name: '', type: 'bytes' }] },
  { type: 'function', name: 'publish', stateMutability: 'nonpayable', inputs: [{ name: 'name', type: 'string' }, { name: 'infohash', type: 'bytes20' }, { name: 'license', type: 'string' }, { name: 'seq', type: 'uint64' }], outputs: [] },
  { type: 'function', name: 'setNodes', stateMutability: 'nonpayable', inputs: [{ name: 'nodes', type: 'string[]' }], outputs: [] },
  { type: 'function', name: 'ownerOf', stateMutability: 'view', inputs: [{ name: 'pk', type: 'bytes32' }], outputs: [{ name: 'addr', type: 'address' }, { name: 'epoch', type: 'uint64' }, { name: 'set', type: 'bool' }] },
  { type: 'function', name: 'resolve', stateMutability: 'view', inputs: [{ name: 'addr', type: 'address' }, { name: 'nameHash', type: 'bytes32' }], outputs: [{ name: 'infohash', type: 'bytes20' }, { name: 'license', type: 'string' }, { name: 'seq', type: 'uint64' }] },
  { type: 'function', name: 'updatedAt', stateMutability: 'view', inputs: [{ name: 'addr', type: 'address' }, { name: 'nameHash', type: 'bytes32' }], outputs: [{ name: '', type: 'uint64' }] },
  { type: 'function', name: 'nodesOf', stateMutability: 'view', inputs: [{ name: 'addr', type: 'address' }], outputs: [{ name: '', type: 'string[]' }] },
  { type: 'event', name: 'Bound', inputs: [{ name: 'pk', type: 'bytes32', indexed: true }, { name: 'addr', type: 'address', indexed: true }, { name: 'epoch', type: 'uint64', indexed: false }] },
  { type: 'event', name: 'Published', inputs: [{ name: 'addr', type: 'address', indexed: true }, { name: 'nameHash', type: 'bytes32', indexed: true }, { name: 'name', type: 'string', indexed: false }, { name: 'infohash', type: 'bytes20', indexed: false }, { name: 'license', type: 'string', indexed: false }, { name: 'seq', type: 'uint64', indexed: false }] },
  { type: 'event', name: 'NodesSet', inputs: [{ name: 'addr', type: 'address', indexed: true }] },
  { type: 'error', name: 'BadSignatureLength', inputs: [] },
  { type: 'error', name: 'BadSignature', inputs: [] },
  { type: 'error', name: 'EpochNotIncreasing', inputs: [{ name: 'have', type: 'uint64' }, { name: 'got', type: 'uint64' }] },
  { type: 'error', name: 'BadName', inputs: [] },
  { type: 'error', name: 'BadLicense', inputs: [] },
  { type: 'error', name: 'BadNodes', inputs: [] },
  { type: 'error', name: 'SeqNotIncreasing', inputs: [{ name: 'have', type: 'uint64' }, { name: 'got', type: 'uint64' }] },
  { type: 'error', name: 'ModexpUnavailable', inputs: [] },
] as const;

/** Ethereum mainnet is the canonical registry (no sequencer, no upgrade keys). `address` stays undefined until deployed. */
export const MAINNET_REGISTRY: RegistryConfig = {
  chainId: 1,
  address: undefined,
  rpcs: ['https://ethereum-rpc.publicnode.com', 'https://eth.llamarpc.com', 'https://rpc.ankr.com/eth', 'https://cloudflare-eth.com'],
};

export const DEFAULT_MIN_AGREE = 2;
export const SNAPSHOT_LAG = 2n;
export const MAX_HEAD_LAG = 64n;
export const MAX_U64 = (1n << 64n) - 1n;

export interface RegistryConfig { chainId: number; address: Address | undefined; rpcs: string[]; minAgree?: number }

export interface SnapshotRef { height: bigint; hash: Hex }
export interface Owner { addr: Address; epoch: bigint }
export interface OwnerAt extends Owner, SnapshotRef {}
export interface ChainRecord extends SnapshotRef { ih: string; license?: string; seq: bigint; addr: Address; epoch: bigint }
export interface Verified extends SnapshotRef { owner: Owner | null; record: ChainRecord | null }
interface Snapshot extends SnapshotRef { endpoints: number[]; excluded: Record<string, string> }

/** Credential-free label for an RPC endpoint: scheme + host only. Display only; never a key. */
export function sanitizeUrl(u: string): string {
  try { const p = new URL(u); return `${p.protocol}//${p.host}`; } catch { return '<invalid url>'; }
}

export function validChainId(v: unknown): v is number {
  return typeof v === 'number' && Number.isSafeInteger(v) && v > 0;
}

export class RpcDisagreement extends Error {
  fn: string; answers: Record<string, string>;
  constructor(fn: string, answers: Record<string, string>) {
    super(`RPCs disagree on ${fn}: ${Object.entries(answers).map(([u, a]) => `${u} → ${a}`).join(' | ')}`);
    this.fn = fn; this.answers = answers;
  }
}
export class AllRpcsFailed extends Error {
  fn: string; errors: Record<string, string>; got: number; need: number;
  constructor(fn: string, errors: Record<string, string>, got: number, need: number) {
    super(`insufficient quorum for ${fn}: ${got}/${need} endpoints answered${Object.keys(errors).length ? ` (${Object.entries(errors).map(([u, e]) => `${u}: ${e}`).join(' | ')})` : ''}`);
    this.fn = fn; this.errors = errors; this.got = got; this.need = need;
  }
}
export class BindingRejected extends Error {
  constructor(detail: string) { super(`binding rejected by the contract's verifier (checkBinding): ${detail}`); }
}

// ---- binding (client side: only for producing the signature the contract verifies) ----

export function bindingMessage(chainId: number, address: string, epoch: bigint): string {
  if (!validChainId(chainId)) throw new Error('chainId must be a positive safe integer');
  if (typeof epoch !== 'bigint' || epoch < 0n || epoch > MAX_U64) throw new Error('epoch must be a bigint in 0..2^64-1');
  return `webway-bind:${chainId}:${getAddress(address).toLowerCase()}:${epoch}`;
}

export function signBinding(kp: Keypair, chainId: number, address: string, epoch: bigint): Buffer {
  return sign(kp, Buffer.from(bindingMessage(chainId, address, epoch), 'utf8'));
}

export const pkHex = (pk: string): Hex => `0x${pk.replace(/^0x/, '').toLowerCase()}` as Hex;
export const nameHash = (name: string): Hex => keccak256(toBytes(name));

// ---- registry client ------------------------------------------------------

function chainFor(chainId: number, rpc: string): Chain {
  return { id: chainId, name: `chain-${chainId}`, nativeCurrency: { name: 'Ether', symbol: 'ETH', decimals: 18 }, rpcUrls: { default: { http: [rpc] } } };
}

/** JSON with bigint support, for byte-for-byte comparison of RPC answers. */
const canon = (v: unknown) => JSON.stringify(v, (_, x) => (typeof x === 'bigint' ? `${x}n` : x));
const ZERO_ADDR = '0x0000000000000000000000000000000000000000';

export class ChainRegistry {
  readonly chainId: number;
  readonly address: Address;
  readonly rpcs: string[];
  readonly minAgree: number;
  private readers: { url: string; label: string; client: PublicClient }[];
  private warnedLag = new Set<number>();

  constructor(cfg: RegistryConfig) {
    if (!cfg.address) throw new Error('registry address not set (pass --registry, set WEBWAY_REGISTRY, or wait for the mainnet deployment)');
    if (!validChainId(cfg.chainId)) throw new Error('chainId must be a positive safe integer');
    if (!cfg.rpcs.length) throw new Error('at least one RPC url is required');
    const rpcs: string[] = [];
    for (const u of cfg.rpcs) {
      let norm: string;
      try { norm = new URL(u).href; } catch { throw new Error(`invalid RPC url ${sanitizeUrl(u)}`); }
      if (rpcs.includes(norm)) throw new Error(`duplicate RPC endpoint ${sanitizeUrl(u)}; each endpoint must be distinct (and, for the quorum to mean anything, an independent provider)`);
      rpcs.push(norm);
    }
    const minAgree = cfg.minAgree ?? DEFAULT_MIN_AGREE;
    if (!Number.isInteger(minAgree) || minAgree < 1) throw new Error('minAgree must be a positive integer');
    if (rpcs.length < minAgree) throw new Error(`minAgree=${minAgree} but only ${rpcs.length} RPC endpoint(s) configured; add endpoints or pass --min-agree 1 to trust a single RPC`);
    this.chainId = cfg.chainId;
    this.address = getAddress(cfg.address);
    this.rpcs = rpcs;
    this.minAgree = minAgree;
    this.readers = rpcs.map((url) => ({ url, label: sanitizeUrl(url), client: createPublicClient({ chain: chainFor(cfg.chainId, url), transport: http(url, { timeout: 10_000, retryCount: 1 }) }) }));
  }

  /** Display label for endpoint i (unique even when two endpoints share a host). */
  private labelOf(i: number): string { return `#${i} ${this.readers[i].label}`; }

  /** Strip every configured URL (and any other URL) out of a provider error; surface decoded custom error names. */
  scrub(e: unknown): string {
    let m = String((e as any)?.shortMessage ?? (e as any)?.message ?? e).split('\n')[0];
    let name: string | undefined;
    for (let cur: any = e, i = 0; cur && i < 10; cur = cur.cause, i++) {
      if (cur?.data?.errorName) { name = cur.data.errorName; break; }
      if (typeof cur?.reason === 'string' && !name) name = cur.reason;
    }
    if (name && !m.includes(name)) m += ` (${name})`;
    for (const r of this.readers) m = m.split(r.url).join(r.label);
    return m.replace(/https?:\/\/[^\s'"`)\]]+/g, (u) => sanitizeUrl(u));
  }

  private async hashAt(i: number, height: bigint): Promise<Hex> {
    const b = await this.readers[i].client.getBlock({ blockNumber: height });
    return b.hash;
  }

  /**
   * Choose the snapshot: drop endpoints on the wrong chain or >MAX_HEAD_LAG
   * blocks from the median head; height = (minAgree-th largest surviving
   * head) - SNAPSHOT_LAG, so the freshest height a quorum can serve; endpoints
   * whose head is below it drop out; every remaining endpoint must report the
   * same hash for it.
   */
  async snapshot(): Promise<Snapshot> {
    const probes = await Promise.allSettled(this.readers.map(async ({ client }) => {
      // cacheTime 0: viem memoises block numbers for ~4s by default, which would make snapshots stale.
      const [cid, head] = await Promise.all([client.getChainId(), client.getBlockNumber({ cacheTime: 0 })]);
      return { cid, head };
    }));
    const excluded: Record<string, string> = {};
    const live: { i: number; head: bigint }[] = [];
    probes.forEach((p, i) => {
      if (p.status === 'rejected') { excluded[this.labelOf(i)] = this.scrub(p.reason); return; }
      if (p.value.cid !== this.chainId) { excluded[this.labelOf(i)] = `chainId ${p.value.cid} != ${this.chainId}`; return; }
      live.push({ i, head: p.value.head });
    });
    if (live.length < this.minAgree) throw new AllRpcsFailed('snapshot', excluded, live.length, this.minAgree);
    const asc = [...live].map((x) => x.head).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    const median = asc.length % 2 ? asc[(asc.length - 1) / 2] : (asc[asc.length / 2 - 1] + asc[asc.length / 2]) / 2n;
    const fresh = live.filter(({ i, head }) => {
      const gap = head > median ? head - median : median - head;
      if (gap <= MAX_HEAD_LAG) return true;
      excluded[this.labelOf(i)] = `head ${head} is ${gap} blocks from the median ${median}`;
      if (!this.warnedLag.has(i)) { this.warnedLag.add(i); console.error(`webway: RPC ${this.readers[i].label} reports head ${head}, ${gap} blocks from the median; excluding it`); }
      return false;
    });
    if (fresh.length < this.minAgree) throw new AllRpcsFailed('snapshot', excluded, fresh.length, this.minAgree);
    const desc = [...fresh].map((x) => x.head).sort((a, b) => (a > b ? -1 : a < b ? 1 : 0));
    const target = desc[this.minAgree - 1];
    const height = target > SNAPSHOT_LAG ? target - SNAPSHOT_LAG : 0n;
    const able = fresh.filter(({ i, head }) => {
      if (head >= height) return true;
      excluded[this.labelOf(i)] = `head ${head} cannot serve snapshot height ${height}`;
      return false;
    });
    const hashes = await Promise.allSettled(able.map(({ i }) => this.hashAt(i, height)));
    const endpoints: number[] = []; const seen: Record<string, string> = {};
    hashes.forEach((h, j) => {
      const i = able[j].i;
      if (h.status === 'rejected') { excluded[this.labelOf(i)] = this.scrub(h.reason); return; }
      endpoints.push(i); seen[this.labelOf(i)] = h.value;
    });
    if (endpoints.length < this.minAgree) throw new AllRpcsFailed('snapshot', excluded, endpoints.length, this.minAgree);
    const distinct = new Set(Object.values(seen));
    if (distinct.size > 1) throw new RpcDisagreement(`block ${height} hash`, seen);
    return { height, hash: [...distinct][0] as Hex, endpoints, excluded };
  }

  /** Snapshot → body. Any failure (quorum, disagreement, unsupported pinning) retries once from a fresh snapshot. */
  private async atSnapshot<T>(body: (snap: Snapshot) => Promise<T>): Promise<T> {
    let lastErr: unknown;
    for (let attempt = 0; attempt < 2; attempt++) {
      try { return await body(await this.snapshot()); } catch (e) { lastErr = e; }
    }
    throw lastErr;
  }

  /**
   * One view, pinned to the snapshot's block HASH (EIP-1898 `{blockHash, requireCanonical}`),
   * on every endpoint of the snapshot. Endpoints that cannot pin by hash drop out of quorum for
   * this read; at least minAgree must answer and all answers must agree pairwise.
   */
  private async readAll<F extends string>(fn: F, args: readonly unknown[], snap: Snapshot): Promise<any> {
    const data = encodeFunctionData({ abi: REGISTRY_ABI, functionName: fn as any, args: args as any });
    const settled = await Promise.allSettled(snap.endpoints.map(async (i) => {
      const raw = await this.readers[i].client.request({
        method: 'eth_call',
        params: [{ to: this.address, data }, { blockHash: snap.hash, requireCanonical: true }],
      } as any) as Hex;
      if (typeof raw !== 'string' || raw === '0x') throw new Error('empty eth_call result');
      return decodeFunctionResult({ abi: REGISTRY_ABI, functionName: fn as any, data: raw });
    }));
    const answers: { i: number; value: any; key: string }[] = []; const bad: Record<string, string> = { ...snap.excluded };
    settled.forEach((r, j) => {
      const i = snap.endpoints[j];
      if (r.status === 'fulfilled') answers.push({ i, value: r.value, key: canon(r.value) });
      else bad[this.labelOf(i)] = this.scrub(r.reason);
    });
    if (answers.length < this.minAgree) throw new AllRpcsFailed(fn, bad, answers.length, this.minAgree);
    for (let x = 1; x < answers.length; x++) {
      if (answers[x].key !== answers[0].key) {
        throw new RpcDisagreement(fn, Object.fromEntries(answers.map((a) => [this.labelOf(a.i), a.key])));
      }
    }
    return answers[0].value;
  }

  // ---- snapshot-internal reads --------------------------------------------

  private async ownerAt(pk: string, s: Snapshot): Promise<Owner | null> {
    const [addr, epoch, set] = await this.readAll('ownerOf', [pkHex(pk)], s) as readonly [Address, bigint, boolean];
    if (!set || addr === ZERO_ADDR) return null;
    return { addr: getAddress(addr), epoch };
  }

  private async recordAt(addr: Address, name: string, s: Snapshot): Promise<{ ih: string; license?: string; seq: bigint } | null> {
    const [ih, license, seq] = await this.readAll('resolve', [getAddress(addr), nameHash(name)], s) as readonly [Hex, string, bigint];
    if (seq === 0n) return null;
    return { ih: ih.slice(2).toLowerCase(), license: license || undefined, seq };
  }

  // ---- public verified reads (always at a fresh snapshot) ----------------

  /** The account pk has bound (verified by the contract), or null if never bound; with the snapshot it was read at. */
  ownerOf(pk: string): Promise<OwnerAt | null> {
    return this.atSnapshot(async (s) => { const o = await this.ownerAt(pk, s); return o ? { ...o, height: s.height, hash: s.hash } : null; });
  }

  resolve(addr: Address, name: string): Promise<({ ih: string; license?: string; seq: bigint } & SnapshotRef) | null> {
    return this.atSnapshot(async (s) => { const r = await this.recordAt(addr, name, s); return r ? { ...r, height: s.height, hash: s.hash } : null; });
  }

  nodesOf(addr: Address): Promise<string[]> {
    return this.atSnapshot(async (s) => [...(await this.readAll('nodesOf', [getAddress(addr)], s) as readonly string[])]);
  }

  /** ownerOf(pk) → resolve(owner, name), both at one snapshot; also reports the snapshot and the owner when there is no record. */
  verified(pk: string, name: string): Promise<Verified> {
    return this.atSnapshot(async (s) => {
      const owner = await this.ownerAt(pk, s);
      const ref = { height: s.height, hash: s.hash };
      if (!owner) return { owner: null, record: null, ...ref };
      const r = await this.recordAt(owner.addr, name, s);
      return { owner, record: r ? { ...r, addr: owner.addr, epoch: owner.epoch, ...ref } : null, ...ref };
    });
  }

  /** The record for webway://pk/name, or null. */
  async resolveVerified(pk: string, name: string): Promise<ChainRecord | null> {
    return (await this.verified(pk, name)).record;
  }

  // ---- latest-block reads through the write endpoint (no quorum; only used to raise our own version floor) ----

  async latestOwner(pk: string): Promise<Owner | null> {
    const [addr, epoch, set] = await this.readers[0].client.readContract({ address: this.address, abi: REGISTRY_ABI, functionName: 'ownerOf', args: [pkHex(pk)] }) as readonly [Address, bigint, boolean];
    return set && addr !== ZERO_ADDR ? { addr: getAddress(addr), epoch } : null;
  }

  async latestSeq(addr: Address, name: string): Promise<bigint> {
    const [, , seq] = await this.readers[0].client.readContract({ address: this.address, abi: REGISTRY_ABI, functionName: 'resolve', args: [getAddress(addr), nameHash(name)] }) as readonly [Hex, string, bigint];
    return seq;
  }

  /** Pre-flight through the contract's own verifier (eth_call checkBinding at latest). */
  async preflightBinding(pk: string, addr: Address, epoch: bigint, sig: Uint8Array | Hex): Promise<boolean> {
    const sigHex = typeof sig === 'string' ? sig : toHex(sig);
    return this.readers[0].client.readContract({ address: this.address, abi: REGISTRY_ABI, functionName: 'checkBinding', args: [pkHex(pk), getAddress(addr), epoch, sigHex] }) as Promise<boolean>;
  }

  // ---- writes ------------------------------------------------------------

  private writer(ethKey: string) {
    const key = (ethKey.startsWith('0x') ? ethKey : `0x${ethKey}`) as Hex;
    const account = privateKeyToAccount(key);
    const url = this.rpcs[0];
    const wallet = createWalletClient({ account, chain: chainFor(this.chainId, url), transport: http(url) });
    return { account, wallet, pub: this.readers[0].client };
  }

  addressOf(ethKey: string): Address { return this.writer(ethKey).account.address; }

  private async send(ethKey: string, functionName: string, args: readonly unknown[]): Promise<Hex> {
    const { account, wallet, pub } = this.writer(ethKey);
    try {
      const { request } = await pub.simulateContract({ account, address: this.address, abi: REGISTRY_ABI, functionName: functionName as any, args: args as any });
      const hash = await wallet.writeContract(request as any);
      const receipt = await pub.waitForTransactionReceipt({ hash });
      if (receipt.status !== 'success') throw new Error(`${functionName} reverted (tx ${hash})`);
      return hash;
    } catch (e) {
      throw new Error(`${functionName} failed: ${this.scrub(e)}`);
    }
  }

  /** Bind pk → the account behind ethKey at `epoch`. Pre-flighted through checkBinding; the contract verifies again on write. */
  async bind(ethKey: string, kp: Keypair, epoch: bigint): Promise<Hex> {
    const { account } = this.writer(ethKey);
    const sig = signBinding(kp, this.chainId, account.address, epoch);
    const pk = kp.pk.toString('hex');
    if (!(await this.preflightBinding(pk, account.address, epoch, sig))) throw new BindingRejected(`pk ${pk.slice(0, 12)}… for ${account.address} epoch ${epoch}`);
    return this.send(ethKey, 'bind', [pkHex(pk), toHex(sig), epoch]);
  }

  publish(ethKey: string, name: string, ih: string, license: string | undefined, seq: bigint): Promise<Hex> {
    if (!/^[0-9a-f]{40}$/i.test(ih)) throw new Error('infohash must be 40 hex chars');
    if (typeof seq !== 'bigint' || seq < 1n || seq > MAX_U64) throw new Error('seq must be a bigint in 1..2^64-1');
    return this.send(ethKey, 'publish', [name, `0x${ih.toLowerCase()}` as Hex, license ?? '', seq]);
  }

  setNodes(ethKey: string, nodes: string[]): Promise<Hex> {
    return this.send(ethKey, 'setNodes', [nodes]);
  }
}

function parseChainId(raw: string, from: string): number {
  if (!/^[1-9]\d{0,15}$/.test(raw)) throw new Error(`${from}: chain id must be a positive decimal integer`);
  const n = Number(raw);
  if (!validChainId(n)) throw new Error(`${from}: chain id out of range`);
  return n;
}

/** Build a ChainRegistry from CLI flags / env / defaults, or undefined if no address is known. */
export function registryFromEnv(opts: { rpcs?: string[]; registry?: string; chainId?: number; minAgree?: number } = {}): ChainRegistry | undefined {
  const address = (opts.registry ?? process.env.WEBWAY_REGISTRY ?? MAINNET_REGISTRY.address) as Address | undefined;
  if (!address) return undefined;
  const rpcs = opts.rpcs?.length ? opts.rpcs : process.env.WEBWAY_RPC ? process.env.WEBWAY_RPC.split(',').map((s) => s.trim()).filter(Boolean) : MAINNET_REGISTRY.rpcs;
  let chainId: number;
  if (opts.chainId !== undefined) { if (!validChainId(opts.chainId)) throw new Error('--chain-id must be a positive safe integer'); chainId = opts.chainId; }
  else if (process.env.WEBWAY_CHAIN_ID) chainId = parseChainId(process.env.WEBWAY_CHAIN_ID, 'WEBWAY_CHAIN_ID');
  else chainId = MAINNET_REGISTRY.chainId;
  const minAgree = opts.minAgree ?? (process.env.WEBWAY_MIN_AGREE ? Number(process.env.WEBWAY_MIN_AGREE) : undefined);
  return new ChainRegistry({ chainId, address, rpcs, minAgree });
}
