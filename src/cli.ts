#!/usr/bin/env node
import { resolve as resolvePath } from 'node:path';
import { WebwayNode, type NodeOpts } from './node.ts';
import { parseSearchOpts } from './args.ts';

const USAGE = `webway — Napster for model weights, on Mainline DHT

  webway id                                 print your publisher key
  webway share <dir> --name <org/model> [--license <spdx>]
                                            seed a directory and sign its name into the DHT
  webway get <webway://<pk>/<name> | magnet | infohash>
                                            download (verified) into ~/.webway/models and keep seeding
  webway serve                              reseed everything you hold, keep names alive
  webway resolve <ref>                      show what a name currently points at
  webway follow <pk>                        subscribe to a publisher's catalog
  webway search <query> [--depth n] [--max n]
                                            search the web of publishers you follow (default depth 2, max 50)
  webway ls                                 what you hold

  flags: --peer host:port (extra DHT node, repeatable)  --torrent-port N  --dht-port N
  env:   WEBWAY_HOME (default ~/.webway)
`;

function parse(argv: string[]) {
  const args: string[] = []; const flags: Record<string, string[]> = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith('--')) (flags[a.slice(2)] ??= []).push(argv[++i] ?? 'true');
    else args.push(a);
  }
  return { args, flags };
}

const fmt = (n: number) => n >= 1e9 ? `${(n / 1e9).toFixed(2)} GB` : n >= 1e6 ? `${(n / 1e6).toFixed(1)} MB` : `${(n / 1e3).toFixed(0)} kB`;

async function main() {
  const { args, flags } = parse(process.argv.slice(2));
  const [cmd, ...rest] = args;
  if (!cmd || cmd === 'help') { console.log(USAGE); return; }
  const opts: NodeOpts = { peers: flags.peer, torrentPort: Number(flags['torrent-port']?.[0]) || undefined, dhtPort: Number(flags['dht-port']?.[0]) || undefined };
  // validate search flags before paying for a node start
  const searchOpts = cmd === 'search' ? parseSearchOpts(flags) : {};
  const node = await new WebwayNode(opts).start();
  const stay = () => { console.log('seeding — ctrl-c to stop'); process.on('SIGINT', () => node.stop().then(() => process.exit(0))); };
  const status = () => setInterval(() => {
    const t = node.client.torrents; const up = t.reduce((a: number, x) => a + x.uploadSpeed, 0); const peers = t.reduce((a: number, x) => a + x.numPeers, 0);
    process.stdout.write(`\r  ${t.length} torrents · ${peers} peers · ↑ ${fmt(up)}/s · dht ${node.dht.nodes.count()} nodes   `);
  }, 2000).unref();

  switch (cmd) {
    case 'id': console.log(node.pk); await node.stop(); return;
    case 'share': {
      const dir = rest[0]; const name = flags.name?.[0];
      if (!dir || !name) throw new Error('usage: webway share <dir> --name <org/model>');
      const s = await node.share(resolvePath(dir), name, flags.license?.[0]);
      console.log(`shared ${s.name} (${fmt(s.size)})\n  webway://${node.pk}/${s.name}\n  magnet:?xt=urn:btih:${s.ih}`);
      stay(); status(); return;
    }
    case 'get': {
      if (!rest[0]) throw new Error('usage: webway get <ref>');
      const s = await node.fetch(rest[0], (t) => process.stdout.write(`\r  ${(t.progress * 100).toFixed(1)}% · ${fmt(t.downloaded)}/${fmt(t.length)} · ↓ ${fmt(t.downloadSpeed)}/s · ${t.numPeers} peers   `));
      console.log(`\ndone: ${s.dir}`);
      stay(); status(); return;
    }
    case 'serve': {
      const shares = await node.serve();
      console.log(`serving ${shares.length} shares as ${node.pk}`);
      stay(); status(); return;
    }
    case 'resolve': { console.log(await node.resolve(rest[0])); await node.stop(); return; }
    case 'follow': { await node.follow(rest[0]); console.log(`following ${rest[0]}`); await node.stop(); return; }
    case 'search': {
      const r = await node.search(rest.join(' '), searchOpts);
      for (const e of r) console.log(`${fmt(e.size).padStart(10)}  ${String(e.hops).padStart(2)} hops  ${e.name.padEnd(40)} ${e.license ?? '-'}\n                     webway://${e.pk}/${e.name}`);
      if (!r.length) console.log('nothing found (follow some publishers first: webway follow <pk>)');
      await node.stop(); return;
    }
    case 'ls': { for (const s of await node.shares()) console.log(`${fmt(s.size).padStart(10)}  ${s.own ? '*' : ' '} ${s.name}  ${s.ih}`); await node.stop(); return; }
    default: console.log(USAGE); await node.stop();
  }
}

main().catch((e) => { console.error(String(e.message ?? e)); process.exit(1); });
