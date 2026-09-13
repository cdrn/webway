#!/usr/bin/env node
import { resolve as resolvePath } from 'node:path';
import { pathToFileURL } from 'node:url';
import { realpathSync } from 'node:fs';
import { WebwayNode } from './node.ts';
import { parseSearchOpts } from './args.ts';
import { optsFromFlags, parse, num, bool } from './cliopts.ts';
import { importHf } from './hf.ts';
import { registryFromEnv } from './chain.ts';
export { parse };

const USAGE = `webway — Napster for model weights, on Mainline DHT

  webway id                                 print your publisher key
  webway share <dir> --name <org/model> [--license <spdx>] [--chain]
                                            seed a directory and sign its name into the DHT
  webway import <hf://org/model> [--revision r] [--license <spdx>]
                                            download a HuggingFace repo, then share + sign it (HF_TOKEN for gated)
  webway get <webway://<pk>/<name> | magnet | infohash>
                                            download (verified) into ~/.webway/models and keep seeding
  webway serve                              reseed everything you hold, keep names alive
  webway resolve <ref>                      show what a name currently points at
  webway follow <pk>                        subscribe to a publisher's catalog
  webway search <query> [--depth n] [--max n]
                                            search the web of publishers you follow (default depth 2, max 50)
  webway ls                                 what you hold

  on-chain registry (Ethereum mainnet; needs --registry or WEBWAY_REGISTRY until the deployment lands):
  webway bind [--epoch N]                   link your publisher key to your Ethereum account (the chain verifies your signature; bump epoch to revoke old accounts)
  webway publish-chain <name> [--license l] publish an existing own share to the registry
  webway set-nodes <host:port>...           publish your DHT bootstrap nodes to the registry (public IPv4 literals)
  webway share ... --chain                  share, then publish the same version on chain

  flags: --peer host:port (extra DHT node, repeatable)  --torrent-port N  --dht-port N
         --no-dns (skip DNS TXT seeds)  --dns-domain <d> (seed domain, repeatable)
         --rpc <url> (repeatable; reads are cross-checked at one hash-pinned block)  --min-agree N (default 2; 1 = trust a single RPC)
         --registry <address>  --chain-id N (default 1)  --no-chain
  env:   WEBWAY_HOME (default ~/.webway)  WEBWAY_REGISTRY  WEBWAY_RPC (comma-separated)  WEBWAY_MIN_AGREE  WEBWAY_CHAIN_ID
         WEBWAY_ETH_KEY (hex private key, writes only; never printed)
`;

/** Escape control characters so remote strings (filenames, licenses) cannot drive the terminal. */
export const esc = (s: string) => s.replace(/[\x00-\x1f\x7f-\x9f]/g, (c) => `\\x${c.charCodeAt(0).toString(16).padStart(2, '0')}`);

export const fmt = (n: number) => n >= 1e9 ? `${(n / 1e9).toFixed(2)} GB` : n >= 1e6 ? `${(n / 1e6).toFixed(1)} MB` : `${(n / 1e3).toFixed(0)} kB`;

export const formatImportProgress = (p: { fileIndex: number; fileCount: number; file: string; fileBytes: number; fileTotal?: number }) =>
  `  [${p.fileIndex + 1}/${p.fileCount}] ${esc(p.file)} ${fmt(p.fileBytes)}${p.fileTotal !== undefined ? `/${fmt(p.fileTotal)}` : ''}`;

export const formatShared = (pk: string, s: { name: string; size: number; license?: string; ih: string; seq?: bigint; chainTx?: string }) =>
  `shared ${esc(s.name)} (${fmt(s.size)})${s.license ? ` [${esc(s.license)}]` : ''}${s.seq !== undefined ? ` version ${s.seq}` : ''}\n  webway://${pk}/${esc(s.name)}\n  magnet:?xt=urn:btih:${s.ih}${s.chainTx ? `\n  on chain: tx ${s.chainTx}` : ''}`;

const USAGE_OF: Record<string, string> = {
  share: 'usage: webway share <dir> --name <org/model> [--chain]', import: 'usage: webway import <hf://org/model>', get: 'usage: webway get <ref>', resolve: 'usage: webway resolve <ref>',
  follow: 'usage: webway follow <pk>', search: 'usage: webway search <query>', 'publish-chain': 'usage: webway publish-chain <name> [--license l]', 'set-nodes': 'usage: webway set-nodes <host:port>...', bind: 'usage: webway bind [--epoch N]',
};
const ARGC: Record<string, [number, number]> = {
  id: [0, 0], share: [1, 1], import: [1, 1], get: [1, 1], serve: [0, 0], resolve: [1, 1], follow: [1, 1], search: [1, Infinity], ls: [0, 0],
  bind: [0, 0], 'publish-chain': [1, 1], 'set-nodes': [1, Infinity],
};

/** Validate positional arity for a command; unknown commands and stray arguments are errors. */
export function checkArgs(cmd: string, rest: string[]): void {
  const arity = ARGC[cmd];
  if (!arity) throw new Error(`unknown command: ${esc(cmd)}\n${USAGE}`);
  if (rest.length < arity[0]) throw new Error(USAGE_OF[cmd] ?? `usage: webway ${cmd}`);
  if (rest.length > arity[1]) throw new Error(`unexpected argument: ${esc(rest[arity[1]])}\n${USAGE_OF[cmd] ?? `usage: webway ${cmd}`}`);
}

async function main() {
  // Argument problems are reported before the node (and its DHT) is started.
  const { args, flags } = parse(process.argv.slice(2));
  const [cmd, ...rest] = args;
  if (!cmd || cmd === 'help' || bool(flags, 'help')) { console.log(USAGE); return; }
  checkArgs(cmd, rest);
  if (cmd === 'share' && !flags.name?.[0]) throw new Error(USAGE_OF.share);
  for (const k of ['torrent-port', 'dht-port']) {
    if (flags[k] && !/^\d+$/.test(flags[k][0])) throw new Error(`--${k} must be a port number`);
    num(flags, k, { min: 0, max: 65535 });
  }
  const chain = bool(flags, 'no-chain') ? undefined : registryFromEnv({ rpcs: flags.rpc, registry: flags.registry?.[0], chainId: num(flags, 'chain-id', { min: 1 }), minAgree: num(flags, 'min-agree', { min: 1 }) });
  const opts = { ...optsFromFlags(flags), chain: chain ?? (false as const) };
  // validate search flags before paying for a node start
  const searchOpts = cmd === 'search' ? parseSearchOpts(flags) : {};
  const needChain = () => { if (!chain) throw new Error('no registry configured: pass --registry <address> or set WEBWAY_REGISTRY (mainnet deployment address is TBD)'); return chain; };
  const ethKey = () => { const k = process.env.WEBWAY_ETH_KEY; if (!k) throw new Error('WEBWAY_ETH_KEY is required for on-chain writes'); return k; };
  const useChain = bool(flags, 'chain');
  if (useChain) { needChain(); ethKey(); }
  const epochRaw = flags.epoch?.[0];
  if (epochRaw !== undefined && !/^(0|[1-9]\d{0,19})$/.test(epochRaw)) throw new Error('--epoch must be a non-negative integer (uint64)');
  const node = await new WebwayNode(opts).start();
  const stay = () => { console.log('seeding — ctrl-c to stop'); process.on('SIGINT', () => node.stop().then(() => process.exit(0))); };
  const status = () => setInterval(() => {
    const t = node.client.torrents; const up = t.reduce((a: number, x) => a + x.uploadSpeed, 0); const peers = t.reduce((a: number, x) => a + x.numPeers, 0);
    process.stdout.write(`\r  ${t.length} torrents · ${peers} peers · ↑ ${fmt(up)}/s · dht ${node.dht.nodes.count()} nodes   `);
  }, 2000).unref();
  const warn = (w?: string) => { if (w) console.error(`warning: ${esc(w)}`); };

  switch (cmd) {
    case 'id': console.log(node.pk); await node.stop(); return;
    case 'share': {
      const dir = rest[0]; const name = flags.name![0];
      const s = await node.share(resolvePath(dir), name, flags.license?.[0], useChain ? { ethKey: ethKey() } : {});
      console.log(formatShared(node.pk, s));
      warn(s.warning);
      stay(); status(); return;
    }
    case 'import': {
      let last = '';
      const s = await importHf(node, rest[0], { revision: flags.revision?.[0], license: flags.license?.[0], onProgress: (p) => {
        const line = formatImportProgress(p);
        if (line !== last) { process.stdout.write(`\r${line.padEnd(100)}`); last = line; }
      } });
      console.log('\n' + formatShared(node.pk, s));
      stay(); status(); return;
    }
    case 'get': {
      const s = await node.fetch(rest[0],
        (t) => process.stdout.write(`\r  ${(t.progress * 100).toFixed(1)}% · ${fmt(t.downloaded)}/${fmt(t.length)} · ↓ ${fmt(t.downloadSpeed)}/s · ${t.numPeers} peers   `),
        (r) => { warn(r.warning); console.log(`resolved ${esc(r.name)} → ${r.ih} via ${r.source}`); });
      console.log(`\ndone: ${s.dir}`);
      stay(); status(); return;
    }
    case 'serve': {
      const shares = await node.serve();
      console.log(`serving ${shares.length} shares as ${node.pk}`);
      stay(); status(); return;
    }
    case 'resolve': {
      const r = await node.resolve(rest[0]);
      warn(r.warning);
      console.log({ ...r, name: esc(r.name), seq: r.seq?.toString(), snapshot: r.snapshot ? { height: r.snapshot.height.toString(), hash: r.snapshot.hash } : undefined }); await node.stop(); return;
    }
    case 'bind': {
      const reg = needChain();
      const b = await node.bindChain(ethKey(), epochRaw === undefined ? undefined : BigInt(epochRaw));
      console.log(`bound ${node.pk} → ${b.addr} at epoch ${b.epoch} on chain ${reg.chainId} (tx ${b.tx})`);
      await node.stop(); return;
    }
    case 'publish-chain': {
      const reg = needChain();
      const r = await node.publishToChain(ethKey(), rest[0], flags.license?.[0]);
      console.log(`published ${esc(r.share.name)} → ${r.share.ih} on chain ${reg.chainId} as ${r.addr} (seq ${r.seq}, tx ${r.tx})`);
      await node.stop(); return;
    }
    case 'set-nodes': {
      const reg = needChain();
      const tx = await reg.setNodes(ethKey(), rest);
      console.log(`set ${rest.length} nodes on chain ${reg.chainId} (tx ${tx})`);
      await node.stop(); return;
    }
    case 'follow': { await node.follow(rest[0]); console.log(`following ${rest[0]}`); await node.stop(); return; }
    case 'search': {
      const r = await node.search(rest.join(' '), searchOpts);
      for (const e of r) console.log(`${fmt(e.size).padStart(10)}  ${String(e.hops).padStart(2)} hops  ${esc(e.name).padEnd(40)} ${e.license ? esc(e.license) : '-'}\n                     webway://${e.pk}/${esc(e.name)}`);
      if (!r.length) console.log('nothing found (follow some publishers first: webway follow <pk>)');
      await node.stop(); return;
    }
    case 'ls': { for (const s of await node.shares()) console.log(`${fmt(s.size).padStart(10)}  ${s.own ? '*' : ' '} ${esc(s.name)}  ${s.ih}`); await node.stop(); return; }
    default: await node.stop(); throw new Error(`unknown command: ${esc(cmd)}`);
  }
}

const invokedDirectly = (() => { try { return !!process.argv[1] && import.meta.url === pathToFileURL(realpathSync(process.argv[1])).href; } catch { return false; } })();
if (invokedDirectly) {
  main().catch((e) => { console.error(esc(String(e.message ?? e))); process.exit(1); });
}
