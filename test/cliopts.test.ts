import { test } from 'node:test';
import assert from 'node:assert/strict';
import { optsFromFlags, parse } from '../src/cliopts.ts';
import { DNS_SEED_DOMAINS } from '../src/bootstrap.ts';

test('parse: positional args, valued flags (repeatable), boolean --no-dns', () => {
  const { args, flags } = parse(['get', 'ref', '--peer', 'a:1', '--peer', 'b:2', '--no-dns', '--dns-domain', 'x.org', '--torrent-port', '7']);
  assert.deepEqual(args, ['get', 'ref']);
  assert.deepEqual(flags.peer, ['a:1', 'b:2']);
  assert.deepEqual(flags['no-dns'], ['true']);
  assert.deepEqual(flags['dns-domain'], ['x.org']);
  assert.deepEqual(flags['torrent-port'], ['7']);
});

test('parse: --no-dns does not swallow the next token', () => {
  const { args, flags } = parse(['--no-dns', 'search', 'llama']);
  assert.deepEqual(args, ['search', 'llama']);
  assert.deepEqual(flags['no-dns'], ['true']);
});

test('optsFromFlags: defaults', () => {
  const o = optsFromFlags({});
  assert.equal(o.dns, true);
  assert.equal(o.peers, undefined);
  assert.equal(o.torrentPort, undefined);
  assert.equal(o.dhtPort, undefined);
});

test('optsFromFlags: --dns-domain ADDS to the defaults (deduped, lowercased)', () => {
  const o = optsFromFlags({ 'dns-domain': ['Example.ORG', 'example.org', ...DNS_SEED_DOMAINS] });
  assert.deepEqual(o.dns, [...DNS_SEED_DOMAINS, 'example.org']);
});

test('optsFromFlags: --no-dns wins over --dns-domain', () => {
  assert.equal(optsFromFlags({ 'no-dns': ['true'], 'dns-domain': ['x.org'] }).dns, false);
});

test('optsFromFlags: ports and peers pass through', () => {
  const o = optsFromFlags({ peer: ['1.2.3.4:1'], 'torrent-port': ['6001'], 'dht-port': ['6002'] });
  assert.deepEqual(o.peers, ['1.2.3.4:1']);
  assert.equal(o.torrentPort, 6001);
  assert.equal(o.dhtPort, 6002);
  assert.equal(optsFromFlags({ 'torrent-port': ['abc'] }).torrentPort, undefined);
});
