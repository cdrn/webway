# webway

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
| bootstrap routers blocked | five builtin routers + your persisted routing table + `--peer host:port` |
| publisher goes dark | anyone who downloaded is seeding; names stay resolvable while anyone re-puts them |
| trackers subpoenaed | trackers are disabled; discovery is DHT + PEX only |
| NAT | uTP, UPnP/NAT-PMP, PEX via webtorrent |

Content cannot be taken down without taking down Mainline DHT itself, which
would also take down every BitTorrent client on earth.

## What it doesn't do yet

- **Transport obfuscation.** BitTorrent traffic is fingerprintable. An ISP that
  blocks the protocol wholesale needs a pluggable transport (obfs4, or tunnelling
  peer connections over a libp2p/WebRTC layer). Planned, not built.
- **Global search.** There is no global index by design. Search works over the
  catalogs of publishers you follow. A gossip layer where nodes re-share the
  catalogs they know is the next step.
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
webway search <q>                  search followed catalogs
webway ls                          what you hold
```

Names expire from the DHT after ~2h unless re-put, so run `webway serve`
somewhere that stays up. Anyone can re-put a record they hold (it is signed),
so a well-followed model outlives its publisher.

## Dev

```
npm test        # spins up an isolated 4-node DHT and round-trips a model
```
