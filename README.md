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
| DHT unreachable or names expired | the on-chain registry (Ethereum mainnet) is a second, permanent resolution path, read through several RPCs that must agree |
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

## On-chain registry

Storing weights on a chain is a non-starter (a 16 GB model is ~125k blobs that
expire in 18 days). Storing the **index** on one is the opposite: one
transaction buys a name that never expires and a global search feed from
contract events, with no DHT bootstrap needed to resolve it.

**Ethereum mainnet is the canonical registry.** Not an L2: every major rollup
today has a single operator-run sequencer that can refuse your transaction, and
an upgrade multisig that can change the rules under you. For a
censorship-resistance project that is the wrong base layer. The contract and
client are chain-agnostic (the chain id is part of the binding message), so
`--chain-id`, `--registry`, `--rpc` select any deployment.

Cost (forge gas report): `publish()` ~53k gas warm, ~100k the first time a name
is written. `bind()` is ~900k gas because the EVM has no Ed25519 or SHA-512
precompile and the contract verifies the signature itself (`Ed25519.verify`
≈ 830k of that, SHA-512 of the 70-byte message ≈ 136k; worst case ≈ 1.0M); at
10 gwei and $3k ETH that is ~$27–30, paid once per account and again only to
rotate. At 10 gwei and $3k ETH that is
$1.50–$3.50 per publish; at 1 gwei, cents.

`contracts/src/WebwayRegistry.sol`:

- **The chain verifies the binding.** `bind(pk, sig, epoch)` checks, on-chain,
  that `sig` is `pk`'s ed25519 signature over
  `webway-bind:<chainId>:<0x lowercase address>:<epoch>` (RFC 8032 in pure
  Solidity, `contracts/src/Ed25519.sol` + `Sha512.sol`; there is no precompile)
  and only then sets `owner[pk] = (msg.sender, epoch)`. Each new binding must
  carry a strictly higher epoch. Consequences: nothing can be squatted (a
  binding without the key's signature reverts), there is nothing to scan or
  hint (one key, one owner), and **only the key holder can ever change the
  owner**. Revocation is `webway bind` from a fresh account: the old account's
  records stop resolving whatever `seq` they carry.
- `publish(name, infohash, license, seq)` — under `msg.sender`, `seq` strictly
  increasing per name. Emits `Published` for indexers.
- `setNodes([host:port...])` — advertise DHT bootstrap nodes under `msg.sender`
  (clients accept canonical public IPv4 literals only).
- Views: `ownerOf(pk) → (addr, epoch, set)`, `resolve(addr, nameHash)`,
  `nodesOf(addr)`, `bindingMessage(addr, epoch)`.

The client (`src/chain.ts`) resolves `webway://<pk>/<name>` as
`ownerOf(pk) → resolve(owner, name)` at one snapshot. It does no signature
verification of its own: the contract already refused to store anything the
key did not sign, so `ownerOf` is the authority. (The publisher's own DHT
records carry its account and epoch as `a`/`e`; a reader compares them with
`ownerOf` and warns `dht-hint-mismatch` if they differ, e.g. after a re-bind.
They are never used as authority.)

Ed25519 verification is tested against all RFC 8032 §7.1 vectors, 200
signatures generated with `@noble/ed25519`, and 337 negative vectors (bit
flips in R, S, message and key; `S ≥ L`; non-canonical `y ≥ p`; off-curve
points; identity, order-2, order-4 and order-8 points for both A and R; `x = 0`
with the sign bit set), plus direct scalar-multiplication checks for scalars
with bit 252 set ([L−1]B = −B, [k]A + [L−k]A = 0), SHA-512 against 92 vectors
with clean and pre-dirtied memory, and a modexp guard that fails closed if the
precompile is missing or misbehaves. Regenerate with
`node contracts/script/gen-vectors.mjs`. Worst-case verification (longest
binding message, all-ones scalar paths) is bounded at ~1.0M gas.

**Reads never trust one server.** Each read first asks every endpoint for its
chain id and head; endpoints on the wrong chain, or more than 64 blocks from
the **median** head in either direction, are dropped (they do not count toward
quorum, and one inflated or stale head cannot evict the honest ones). The
snapshot height is the freshest one a quorum can serve: the `--min-agree`-th
largest surviving head minus 2; an endpoint whose head is below that drops out
rather than dragging the height down (heads 1000, 1000, 936 → height 998).
Every endpoint must report the **same hash** for that height, and every
`eth_call` is then pinned to that **block hash** (EIP-1898), so a fork flip
between calls cannot mix state; an endpoint that cannot pin by hash drops out
of that read. At least `--min-agree` endpoints (default 2) must answer and all
answers must match byte-for-byte, compared per endpoint (never by display
label). Any failure (quorum, disagreement) retries the whole read once from a
fresh snapshot. Every verified result carries the `{height, hash}` it was read
at.

**Freshness guarantee.** "Owner" and "record" mean *as of the snapshot*: about
2 blocks plus the quorum's own lag behind the best head, never older than the
`--min-agree`-th freshest endpoint minus 2. A re-bind or publish becomes
visible to verified reads once that many blocks have passed.

**Two resolution policies.** `resolveVerified()` (and `webway resolve` with
`--no-dht`-style trust in the chain) answers *only* from the registry at a
snapshot. `resolve()` — what `webway get` uses — is broader: it consults the
DHT first and merges by version as described below, so it can return a DHT
record the chain has never seen, or a newer DHT version of a name the chain
also knows. That is deliberate (the DHT is the live, cheap path); the chain is
the durable one. The merged result still reports the chain snapshot and warns
on any disagreement. The quorum is
never lowered when endpoints fail: three dead RPCs and one lying survivor is a
failure, not a result. Running with one RPC is a trust choice you make
explicitly with `--min-agree 1`. Endpoint URLs appear in errors as scheme+host
only, so a key in the URL path never leaks into logs.

`resolve()` in the node tries the DHT, then the chain. Same infohash on both →
the newer metadata. Different infohashes → the higher `seq` wins; equal `seq` →
chain (immutable, verified) with a `conflict-equal-seq` warning. Size is only
carried across sources when the infohash matches. Warnings are printed before
`webway get` starts downloading.

**One version per update.** `share` allocates a single version number
(persisted, above `now()`, above our own DHT record, and above the owner's and
the writer's chain records read at the latest block) and publishes it to the
DHT and, with `--chain`, to the registry in the same breath. DHT versions are
capped at 2^53−1 before anything is persisted. `webway bind` pre-flights the
signature through the contract's own `checkBinding` view, so what the client
accepts is exactly what the chain accepts.

**Bootstrap from the chain.** In the background at start (and on `follow`, and
when resolving a publisher for the first time), a node pulls the bootstrap
nodes advertised by that publisher's bound account — canonical public IPv4
literals only, at most 20 distinct per publisher — and adds them to its DHT. A
publisher is only marked done after the read succeeds, so a transient RPC
failure is retried later.

```
export WEBWAY_ETH_KEY=0x...            # funded mainnet account; never logged
webway bind                            # once per account: the chain verifies your key's signature (epoch auto-increments)
webway share ./model --name org/m --chain
webway publish-chain org/m             # or publish an existing share (same version counter as the DHT)
webway set-nodes 1.2.3.4:6881 5.6.7.8:6881
webway resolve webway://<pk>/org/m     # DHT, then chain
```

Flags `--rpc <url>` (repeatable), `--min-agree N`, `--registry <address>`,
`--chain-id N` (default 1), or env `WEBWAY_RPC` (comma-separated),
`WEBWAY_MIN_AGREE`, `WEBWAY_REGISTRY`, `WEBWAY_CHAIN_ID`. Default RPCs are four
independent public mainnet endpoints. **The mainnet deployment address is
TBD**; until it lands you must pass `--registry`. Deploy your own with
`cd contracts && forge script script/Deploy.s.sol --rpc-url $RPC --private-key $KEY --broadcast`.

Not yet: light-client verification of RPC answers (Helios / `eth_getProof`),
and serving registry state + proofs peer-to-peer over the swarm itself.

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
webway import <hf://org/model>     download a HuggingFace repo, then share + sign it
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
## Import from HuggingFace

```
webway import hf://meta-llama/Llama-3.1-8B           # HF_TOKEN=... for gated repos
webway import org/model --revision v2 --license mit  # override the card's license
```

Pins the commit the API reports and downloads every file at that commit
(except `.gitattributes`) into an immutable version dir,
`~/.webway/versions/org/model/<commit>/`, verifying sizes and LFS sha256s,
resuming partial files with validated Range requests, and bounding file counts,
path depth, per-file and total bytes, stalls, and oversized streams. Only when
every file has verified is the version promoted: it is seeded and
`webway://<your-key>/org/model` is signed into the DHT, then `current.json` is
written (the commit point) and `~/.webway/models/org/model` is repointed at the
new version, and only then is the previous version retired. Nothing is ever
renamed over the published path, and no directory a live torrent is reading
from is ever deleted; a crash at any step leaves either the old or the new
version fully consistent, and the next start reconciles under the per-repo
lock (a journaled but unfinished promotion is completed when its share record
and content exist, otherwise its local record is dropped; a DHT name record
that was already put simply expires on its own after ~2h, nothing can
unpublish it). A per-repo lock (heartbeated directory; reclaimed only when the
holder is provably dead) refuses concurrent imports of the same model. The license from the model
card travels in the signed record. `HF_TOKEN` is only ever sent to
`huggingface.co`.

## Dev

```
npm test                    # unit tests + isolated multi-node DHT round-trips (no real network); chain tests spin up anvil (skipped if missing)
cd contracts && forge test  # registry + Ed25519/SHA-512 vectors (node contracts/script/gen-vectors.mjs to regenerate)
```
