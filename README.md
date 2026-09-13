# webway

*unstoppable intelligence*

Napster for model weights, minus the part that got Napster shut down.

Napster had one index server. Subpoena it and the network dies. webway has no
server at all: it rides the BitTorrent Mainline DHT (~10M nodes, nobody owns it)
and adds the two things a torrent client is missing for model weights: **names
you can trust** and **discovery without a website**.

```
webway share ./Llama-3.1-8B --name meta/llama-3.1-8b --license llama3.1
  → webway://9f3c…e21a/meta/llama-3.1-8b

webway get webway://9f3c…e21a/meta/llama-3.1-8b        # on any other machine
webway follow 9f3c…e21a && webway search llama
```

## How it resists

| threat | answer |
|---|---|
| index server taken down | there isn't one; peers and names live in Mainline DHT (BEP5 + BEP44) |
| someone swaps the bytes | infohash *is* the content; every piece is hash-verified |
| someone hijacks a name | `webway://<pk>/<name>` is an ed25519-signed mutable item; DHT nodes drop bad signatures |
| bootstrap routers blocked | five builtin routers + persisted routing table + DNS TXT seeds + `--peer` + nodes carried in every catalog + LSD (BEP14) on the LAN |
| publisher goes dark | anyone who downloaded is seeding, and re-puts the signed name record; names outlive publishers |
| trackers subpoenaed | trackers are disabled; discovery is DHT + PEX only |
| NAT | uTP, UPnP/NAT-PMP, PEX via webtorrent |

Content cannot be taken down without taking down Mainline DHT itself, which
would also take down every BitTorrent client on earth.

## What it doesn't do yet

- **Transport obfuscation.** BitTorrent traffic is fingerprintable. An ISP that
  blocks the protocol wholesale needs a pluggable transport (obfs4, or tunnelling
  peer connections over a libp2p/WebRTC layer). Planned, not built.
- **Global search.** There is no global index by design. Search walks a web of
  publishers instead: each catalog carries an `endorse` list (the publishers its
  author follows), and `webway search` does a bounded breadth-first walk from
  your follow list (default 2 hops, 50 publishers; hard maxima 5 and 500). Every
  step is bounded because the walk reaches publishers you never chose: each
  catalog fetch has a deadline (20s), catalogs over 1 MiB are refused before
  download, entries/endorsements/results are capped (5000/100/1000), and a
  malformed catalog costs nothing but its own entries. Catalog torrents are
  reference-counted per infohash (a torrent we did not start is never destroyed;
  one we did is destroyed only when no load and no publisher still uses it) and
  capped at 200 kept alive, least recently used first. Cold start is still
  "someone hands you one key"; from there the web is discoverable.
- **BitTorrent v2.** webtorrent is v1 only, so identical files across model
  versions are not deduplicated in the swarm yet.
- **Key rotation / multi-sig publishers.** One ed25519 key per publisher, in
  `~/.webway/key.json`. Guard it.

## Install

```
git clone https://github.com/ker-ys/webway && cd webway
npm install && npm run build && npm link
```

Needs Node 22+.

## Commands

```
webway id                          your publisher key
webway share <dir> --name <n>      seed + sign name into DHT + update your catalog
webway get <ref>                   download and keep seeding (webway://, magnet, or infohash)
webway serve                       reseed everything you hold, keep names alive
webway resolve <ref>               what a name points at right now
webway follow <pk>                 subscribe to a publisher
webway search <q> [--depth n] [--max n]   walk the web of publishers you follow (2 hops / 50 publishers by default)
webway ls                          what you hold
```

Names expire from the DHT after ~2h unless re-put. Every node re-puts every
signed record it has ever resolved (`webway serve` does this every 50 min),
so a name outlives its publisher for as long as anyone who fetched it is online.
Nobody can forge a record; they can only keep it alive.

## Bootstrap

A fresh node has to find *one* live DHT node. All sources are merged into one
list (in this priority order) and the DHT queries them concurrently:

1. **Builtin routers** — `router.bittorrent.com`, `router.utorrent.com`,
   `dht.transmissionbt.com`, `dht.libtorrent.org`, `dht.aelitis.com`.
2. **Remembered nodes** — up to 50 from the last session's routing table
   (`~/.webway/dht.json`). A node that has been online once never needs the
   routers again.
3. **DNS seeds** — TXT records at `_webway-seeds.<domain>`. No default seed
   domain is configured. Use `--dns-domain <d>` to add an operator-provided
   domain; `--no-dns` skips DNS seeds. Each record holds one or
   more `host:port`, comma or space separated:

   ```
   _webway-seeds.example.org. 300 IN TXT "1.2.3.4:6881, 5.6.7.8:6881"
   ```

   IP literals only: a hostname in a TXT record is ignored, because the DHT
   library would resolve it with its own uncancellable lookup outside our
   deadline.

   DNS never delays startup: the DHT comes up on the other paths and each
   domain's seeds are added the moment that domain answers. Hung queries are
   cancelled after 3 s. Seeds stay retryable: if the routing table is still
   empty after bootstrap they are re-pinged every 30 s, up to five times.
4. **`--peer host:port`** — anything you were handed out of band.

Once online, two more paths keep working even if all four above are blocked:
every publisher's catalog carries up to 20 of their routing-table nodes, which
you adopt when you read it; and BEP14 local service discovery (on by default
in webtorrent) finds peers on your LAN with no DHT at all.

**Every source is rationed.** A seed domain or a publisher is a recommendation,
not an authority, so nothing any one of them says can crowd out what you learned
elsewhere: at most 8 seed domains, 4 KiB / 32 endpoints per domain, 64 DNS
endpoints total; 50 remembered nodes; 128 bootstrap entries in all, hard, with
the builtin routers and your `--peer` values filled first (if those alone exceed
128 the first 128 are kept and a warning is printed). Catalog nodes must be
public IPv4 literals (no hostnames, nothing private / loopback / CGNAT / mapped),
and each publisher may get you to ping at most 20 addresses ever, 4 per /24,
100 per session across all publishers; the accounting lives in
`~/.webway/dht-adopt.json`. A node you adopted from someone's catalog is not
re-advertised in your own for an hour (that timestamp is persisted too), so
recommendations cannot launder themselves through the network or a restart.
State files are written atomically, but a home directory (`~/.webway` /
`WEBWAY_HOME`) must not be shared by concurrent webway processes yet: the
accounting is not locked across processes (issue #10).

**IPv6:** endpoints like `[2001:db8::1]:6881` are parsed but dropped from every
list. The installed DHT stack splits `host:port` on `:` and listens on a udp4
socket, so they cannot work yet; accepting them would only hide that.

## Dev

```
npm test        # unit tests + isolated multi-node DHT round-trips (no real network)
```
