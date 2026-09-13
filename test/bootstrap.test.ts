import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  LIMITS, advertisableNodes, canonicalEndpoints, dnsSeeds, isHostname, isPrivateHost, isPublicIpLiteral,
  mergeBootstrap, normalizeHost, parseHostPort, parseNode, parseSeedRecord, startupPeerPings, subnetKey, usable, v6Groups, type TxtResolver,
} from '../src/bootstrap.ts';
import { canonPk, sanitizeAdoptFile } from '../src/node.ts';

test('canonPk: 64 hex, any case -> lowercase; anything else undefined', () => {
  const pk = 'AbCd'.repeat(16);
  assert.equal(canonPk(pk), pk.toLowerCase());
  for (const bad of ['abc', 'g'.repeat(64), 'a'.repeat(63), 'a'.repeat(65), 42, null, undefined]) assert.equal(canonPk(bad), undefined);
});

test('sanitizeAdoptFile: resets only corrupt parts, merges case-variant keys, drops stale/invalid provenance', () => {
  const lo = 'a'.repeat(64), up = 'A'.repeat(64);
  const now = Date.now();
  const f = sanitizeAdoptFile({
    publishers: {
      [lo]: { n: 3, seen: ['1.1.1.1:1', 42, 'junk'], subnets: { '1.1.1': 1, bad: 'x', neg: -1 } },
      [up]: { n: 2, seen: ['2.2.2.2:2', '1.1.1.1:1'], subnets: { '2.2.2': 1 } },
      notakey: { n: 9, seen: [] },
      ['b'.repeat(64)]: 'corrupt',
      ['c'.repeat(64)]: { n: 'nope', seen: ['3.3.3.3:3'] },
    },
    adopted: { '4.4.4.4:4': now - 1000, '5.5.5.5:5': now - 48 * 3600_000, '6.6.6.6:6': 'soon', junk: now, '7.7.7.7:7': now + 60_000 },
  });
  assert.deepEqual(Object.keys(f.publishers).sort(), [lo, 'c'.repeat(64)]);
  assert.equal(f.publishers[lo].n, 5, 'case variants share one budget');
  assert.deepEqual(f.publishers[lo].seen.sort(), ['1.1.1.1:1', '2.2.2.2:2']);
  assert.deepEqual(f.publishers[lo].subnets, { '1.1.1': 1, '2.2.2': 1 });
  assert.deepEqual(f.publishers['c'.repeat(64)], { n: 1, seen: ['3.3.3.3:3'], subnets: {} }, 'bad n reset from seen');
  assert.deepEqual(f.adopted, { '4.4.4.4:4': now - 1000 });
  assert.deepEqual(sanitizeAdoptFile('garbage'), { publishers: {}, adopted: {} });
  assert.deepEqual(sanitizeAdoptFile({ publishers: [], adopted: null }), { publishers: {}, adopted: {} });
});

const fake = (table: Record<string, string[][] | Error | 'hang'>): TxtResolver => async (h) => {
  const v = table[h];
  if (v === undefined) throw new Error('ENOTFOUND');
  if (v instanceof Error) throw v;
  if (v === 'hang') return new Promise(() => {});
  return v;
};

// ---- parsing ----------------------------------------------------------------------------

test('parseHostPort: valid IPv4, hostname, bracketed IPv6', () => {
  assert.deepEqual(parseHostPort('1.2.3.4:6881'), { host: '1.2.3.4', port: 6881, family: 4 });
  assert.deepEqual(parseHostPort('Router.Example.ORG:25401'), { host: 'router.example.org', port: 25401, family: 'name' });
  assert.deepEqual(parseHostPort('[::1]:6881'), { host: '0000:0000:0000:0000:0000:0000:0000:0001', port: 6881, family: 6 });
  assert.deepEqual(parseHostPort('  [2001:DB8::1]:1  '), { host: '2001:0db8:0000:0000:0000:0000:0000:0001', port: 1, family: 6 });
  assert.deepEqual(parseHostPort('1.2.3.4:65535'), { host: '1.2.3.4', port: 65535, family: 4 });
});

test('parseHostPort: rejects junk, bad ports, malformed IPv4, invalid DNS labels', () => {
  const bad = [
    '1.2.3.4', '1.2.3.4:0', '1.2.3.4:70000', '1.2.3.4:abc', '1.2.3.4:65536', '1.2.3.4:-1', '1.2.3.4:1.5', '1.2.3.4:123456',
    '::1:6881', '[1.2.3.4]:6881', '[notv6]:6881', 'ho st:1', '', ':6881', 'a:b:c', 'http://x:1', 'a/b:1',
    '999.999.999.999:6881', '1.2.3:6881', '1.2.3.4.5:6881', '01.2.3.4.:1', '256.1.1.1:1',
    '-bad..name:1', 'bad-.example:1', '-bad.example:1', 'a..b:1', 'under_score.example:1', 'x'.repeat(64) + '.com:1', ('a.'.repeat(127) + 'a:1'),
  ];
  for (const b of bad) assert.equal(parseHostPort(b), undefined, b);
  assert.equal(parseHostPort(undefined as any), undefined);
  assert.equal(parseHostPort(42 as any), undefined);
});

test('isHostname: RFC 1123', () => {
  for (const ok of ['a', 'example.org', 'a-b.c-d.e', 'x'.repeat(63) + '.org', 'trailing.dot.', '1.2.3.4'.replace(/\./g, 'x')]) assert.equal(isHostname(ok), true, ok);
  for (const bad of ['', '-a', 'a-', 'a..b', 'a_b', 'x'.repeat(64), 'a b', ('a.'.repeat(130) + 'a')]) assert.equal(isHostname(bad), false, bad);
});

test('parseNode: structured hosts validated before formatting (corrupt dht.json)', () => {
  assert.deepEqual(parseNode({ host: '1.2.3.4', port: 6881 }), { host: '1.2.3.4', port: 6881, family: 4 });
  for (const bad of [{ host: '127.0.0.1:0', port: 6881 }, { host: '', port: 1 }, { host: '1.2.3.4', port: '6881' }, { host: '1.2.3.4', port: 0 },
    { host: 7, port: 7 }, null, 'str', {}, { host: '999.1.1.1', port: 1 }, { host: '[::1]', port: 1 }, { host: 'a b', port: 1 }])
    assert.equal(parseNode(bad), undefined, JSON.stringify(bad));
  assert.equal(parseNode({ host: '::1', port: 1 })?.family, 6);
});

test('parseSeedRecord: separators, junk, empty', () => {
  assert.deepEqual(parseSeedRecord('1.2.3.4:6881, 5.6.7.8:6881'), ['1.2.3.4:6881', '5.6.7.8:6881']);
  assert.deepEqual(parseSeedRecord('1.2.3.4:6881 5.6.7.8:6881\t9.9.9.9:1\n'), ['1.2.3.4:6881', '5.6.7.8:6881', '9.9.9.9:1']);
  assert.deepEqual(parseSeedRecord(',,1.2.3.4:6881,,junk,,x:0,,'), ['1.2.3.4:6881']);
  assert.deepEqual(parseSeedRecord(''), []);
  assert.deepEqual(parseSeedRecord('v=spf1 -all'), []);
  assert.deepEqual(parseSeedRecord(undefined as any), []);
});

// ---- normalisation / IPv6 -------------------------------------------------------------

test('normalizeHost: case and IPv6 spellings canonicalised', () => {
  assert.equal(normalizeHost('Router.Example.ORG'), 'router.example.org');
  assert.equal(normalizeHost('::1'), '0000:0000:0000:0000:0000:0000:0000:0001');
  assert.equal(normalizeHost('0:0:0:0:0:0:0:1'), normalizeHost('::1'));
  assert.equal(normalizeHost('2001:DB8::1'), normalizeHost('2001:db8:0:0:0:0:0:1'));
  assert.equal(normalizeHost('::ffff:127.0.0.1'), normalizeHost('0:0:0:0:0:ffff:7f00:1'));
  assert.equal(v6Groups('nope'), undefined);
  assert.equal(v6Groups('1.2.3.4'), undefined);
});

test('IPv6 endpoints are recognised but unusable: dropped by canonicalEndpoints and mergeBootstrap', () => {
  const e = parseHostPort('[2001:db8::1]:6881')!;
  assert.equal(e.family, 6);
  assert.equal(usable(e), false);
  assert.deepEqual(canonicalEndpoints(['[2001:db8::1]:6881', '1.2.3.4:1']), ['1.2.3.4:1']);
  assert.deepEqual(mergeBootstrap({ builtin: ['[2001:db8::1]:6881'], peers: ['[::1]:1'], dns: ['[fe80::1]:2'], remembered: ['5.5.5.5:5'] }), ['5.5.5.5:5']);
});

test('canonicalEndpoints: case-insensitive dedupe, junk dropped', () => {
  assert.deepEqual(canonicalEndpoints(['A.org:1', 'a.ORG:1', 'junk', '1.2.3.4:0', '1.2.3.4:2']), ['a.org:1', '1.2.3.4:2']);
});

// ---- classification -----------------------------------------------------------------

test('isPrivateHost: IPv4 ranges incl. CGNAT, docs, multicast, reserved', () => {
  for (const h of ['127.0.0.1', '127.255.255.255', '10.1.2.3', '192.168.0.1', '172.16.0.1', '172.31.255.255', '169.254.1.1', '0.0.0.0', '0.1.2.3',
    '100.64.0.1', '100.127.255.255', '192.0.0.1', '192.0.2.1', '198.18.0.1', '198.19.255.255', '198.51.100.1', '203.0.113.1', '224.0.0.1', '239.1.1.1', '240.0.0.1', '255.255.255.255', 'localhost', 'LOCALHOST', 'foo.localhost'])
    assert.equal(isPrivateHost(h), true, h);
  for (const h of ['1.2.3.4', '172.32.0.1', '172.15.0.1', '8.8.8.8', '100.63.255.255', '100.128.0.1', '192.0.1.1', '192.0.3.1', '198.17.255.255', '198.20.0.1', '223.255.255.255', 'router.bittorrent.com'])
    assert.equal(isPrivateHost(h), false, h);
});

test('isPrivateHost: IPv6 by address bytes (bypasses from review)', () => {
  for (const h of ['::1', '0:0:0:0:0:0:0:1', '::', 'fe80::1', 'fe90::1', 'feb0::1', 'febf:ffff::1', 'fd00::1', 'fc00::1', 'FD12::1',
    '::ffff:127.0.0.1', '0:0:0:0:0:ffff:7f00:1', '::ffff:10.0.0.1', '::ffff:192.168.1.1', '::ffff:100.64.0.1', 'ff02::1', '2001:db8::1', '64:ff9b::10.0.0.1'])
    assert.equal(isPrivateHost(h), true, h);
  for (const h of ['2001:4860:4860::8888', 'fec0::1', '2606:4700::1', '::ffff:8.8.8.8', '2001:db9::1'])
    assert.equal(isPrivateHost(h), false, h);
  assert.equal(isPrivateHost(undefined as any), true);
});

test('isPublicIpLiteral: literals only', () => {
  assert.equal(isPublicIpLiteral('8.8.8.8'), true);
  assert.equal(isPublicIpLiteral('2001:4860:4860::8888'), true);
  assert.equal(isPublicIpLiteral('10.0.0.1'), false);
  assert.equal(isPublicIpLiteral('router.bittorrent.com'), false);
  assert.equal(isPublicIpLiteral('localhost'), false);
});

test('subnetKey: /24', () => {
  assert.equal(subnetKey('1.2.3.4'), '1.2.3');
  assert.equal(subnetKey('1.2.3.250'), '1.2.3');
  assert.equal(subnetKey('1.2.4.4'), '1.2.4');
});

// ---- DNS ------------------------------------------------------------------------------------

test('dnsSeeds: single record', async () => {
  assert.deepEqual(await dnsSeeds(['a.org'], fake({ '_webway-seeds.a.org': [['1.2.3.4:6881']] })), ['1.2.3.4:6881']);
});

test('dnsSeeds: multiple records and multi-chunk records; IPv6 dropped', async () => {
  const r = await dnsSeeds(['a.org'], fake({ '_webway-seeds.a.org': [['1.2.3.4:6881, 5.6.7.8:6881'], ['9.9.9.', '9:6881'], ['[2001:db8::1]:6881']] }));
  assert.deepEqual(r, ['1.2.3.4:6881', '5.6.7.8:6881', '9.9.9.9:6881']);
});

test('dnsSeeds: invalid ports, malformed IPv4 and junk dropped', async () => {
  const r = await dnsSeeds(['a.org'], fake({ '_webway-seeds.a.org': [['1.1.1.1:0 2.2.2.2:70000 3.3.3.3:abc 4.4.4.4 999.9.9.9:1 garbage 5.5.5.5:5']] }));
  assert.deepEqual(r, ['5.5.5.5:5']);
});

test('dnsSeeds: duplicates deduped within and across domains; hostnames in TXT are dropped (IP literals only)', async () => {
  const r = await dnsSeeds(['a.org', 'b.org'], fake({
    '_webway-seeds.a.org': [['1.1.1.1:1, 1.1.1.1:1 Seed.Example:9'], ['2.2.2.2:2']],
    '_webway-seeds.b.org': [['2.2.2.2:2 3.3.3.3:3 seed.example:9 router.bittorrent.com:6881']],
  }));
  assert.deepEqual(r, ['1.1.1.1:1', '2.2.2.2:2', '3.3.3.3:3']);
});

test('dnsSeeds: standalone abort calls the resolver cancel() exactly once and settles', async () => {
  let cancelled = 0;
  const ac = new AbortController();
  const p = dnsSeeds(['hang.org'], { resolveTxt: () => new Promise(() => {}), cancel: () => { cancelled++; } }, 60_000, { signal: ac.signal });
  ac.abort();
  assert.deepEqual(await p, []);
  assert.equal(cancelled, 1);
});

test('startupPeerPings: only peers that survived the merged, capped list; 130 peers -> at most 128', () => {
  const peers = Array.from({ length: 130 }, (_, i) => `30.0.${i >> 8}.${(i & 255) + 1}:3`);
  const merged = mergeBootstrap({ builtin: [], peers, onOverflow: () => {} });
  const pinged = startupPeerPings(merged, peers);
  assert.equal(pinged.length, 128);
  assert.deepEqual(pinged, merged);
  assert.deepEqual(startupPeerPings(['a.org:1'], ['b.org:1', 'junk']), [], 'a peer dropped from the list is not pinged');
  assert.deepEqual(startupPeerPings(false, [...peers, 'junk']).length, 128, 'bootstrap disabled: canonical peers, capped');
  const mixed = mergeBootstrap({ builtin: ['r.org:1'], peers: ['p.org:1', 'junk', '[::1]:1'] });
  assert.deepEqual(startupPeerPings(mixed, ['p.org:1', 'junk', '[::1]:1']), ['p.org:1']);
});

test('dnsSeeds: one failing domain does not poison the others', async () => {
  const r = await dnsSeeds(['bad.org', 'good.org', 'missing.org'], fake({ '_webway-seeds.bad.org': new Error('SERVFAIL'), '_webway-seeds.good.org': [['7.7.7.7:7']] }));
  assert.deepEqual(r, ['7.7.7.7:7']);
});

test('dnsSeeds: resolver throwing (async or sync) -> []', async () => {
  assert.deepEqual(await dnsSeeds(['a.org'], fake({ '_webway-seeds.a.org': new Error('boom') })), []);
  assert.deepEqual(await dnsSeeds(['a.org'], () => { throw new Error('sync boom'); }), []);
});

test('dnsSeeds: hanging resolver -> [] within timeout, cancel() called, others still returned', async () => {
  let cancelled = 0;
  const table = fake({ '_webway-seeds.a.org': 'hang', '_webway-seeds.b.org': [['1.1.1.1:1']] });
  const t0 = Date.now();
  const r = await dnsSeeds(['a.org', 'b.org'], { resolveTxt: table, cancel: () => { cancelled++; } }, 50);
  assert.deepEqual(r, ['1.1.1.1:1']);
  assert.ok(Date.now() - t0 < 1000, 'timeout honoured');
  assert.equal(cancelled, 1);
});

test('dnsSeeds: late rejection after timeout is swallowed', async () => {
  let reject!: (e: Error) => void;
  const r = await dnsSeeds(['a.org'], () => new Promise<string[][]>((_, rej) => { reject = rej; }), 20);
  assert.deepEqual(r, []);
  reject(new Error('late'));
  await new Promise((res) => setTimeout(res, 10)); // no unhandled rejection
});

test('dnsSeeds: empty / invalid domain list -> [] without calling resolver', async () => {
  let calls = 0;
  const spy: TxtResolver = async () => { calls++; return []; };
  assert.deepEqual(await dnsSeeds([], spy), []);
  assert.deepEqual(await dnsSeeds(['-bad', '', 42 as any, 'a b'], spy), []);
  assert.equal(calls, 0);
});

test('dnsSeeds: resolver returning undefined/odd shapes -> []', async () => {
  assert.deepEqual(await dnsSeeds(['a.org'], (async () => undefined) as any), []);
  assert.deepEqual(await dnsSeeds(['a.org'], (async () => [undefined, [], [null], 'str', [42]]) as any), []);
});

test('dnsSeeds: queries the _webway-seeds label under each domain, lowercased, deduped, max 8 domains', async () => {
  const seen: string[] = [];
  const domains = ['A.org', 'a.org', ...Array.from({ length: 10 }, (_, i) => `d${i}.net`)];
  await dnsSeeds(domains, async (h) => { seen.push(h); return []; });
  assert.equal(seen.length, LIMITS.dnsDomains);
  assert.equal(seen[0], '_webway-seeds.a.org');
  assert.deepEqual(new Set(seen).size, seen.length);
});

test('dnsSeeds: 1,000-entry TXT -> 32 per domain (across records), 64 total', async () => {
  // spread over many records so no single record breaks the 4 KiB budget
  const eps = Array.from({ length: 1000 }, (_, i) => `10.${(i >> 8) & 255}.${i & 255}.1:6881`);
  const records: string[][] = [];
  for (let i = 0; i < eps.length; i += 100) records.push([eps.slice(i, i + 100).join(' ')]);
  const r = await dnsSeeds(['a.org'], fake({ '_webway-seeds.a.org': records }));
  assert.equal(r.length, LIMITS.dnsEndpointsPerDomain);
  const three = Object.fromEntries(['a', 'b', 'c'].map((d) => [`_webway-seeds.${d}.org`, [[Array.from({ length: 40 }, (_, i) => `${d === 'a' ? 1 : d === 'b' ? 2 : 3}.0.${i}.1:1`).join(' ')]]]));
  const all = await dnsSeeds(['a.org', 'b.org', 'c.org'], fake(three));
  assert.equal(all.length, LIMITS.dnsEndpointsTotal);
  // a record over 4 KiB is dropped whole
  const padded = [[' '.repeat(LIMITS.dnsBytesPerDomain + 10) + '7.7.7.7:7']];
  assert.deepEqual(await dnsSeeds(['a.org'], fake({ '_webway-seeds.a.org': padded })), []);
  // and a second record after an exhausted budget is not read
  const two = [['x'.repeat(LIMITS.dnsBytesPerDomain)], ['8.8.8.8:8']];
  assert.deepEqual(await dnsSeeds(['a.org'], fake({ '_webway-seeds.a.org': two })), []);
});

// ---- merge ---------------------------------------------------------------------------

test('mergeBootstrap: order preserved (builtin, remembered, dns, peers), deduped across sources', () => {
  const r = mergeBootstrap({ builtin: ['r1:1', 'r2:2'], remembered: ['m1:1', 'R1:1'], dns: ['d1:1', 'm1:1'], peers: ['p1:1', 'd1:1', 'r2:2'] });
  assert.deepEqual(r, ['r1:1', 'r2:2', 'm1:1', 'd1:1', 'p1:1']);
});

test('mergeBootstrap: remembered capped at 50, dns at 64, total at 128', () => {
  const remembered = Array.from({ length: 80 }, (_, i) => `10.0.0.${i + 1}:${i + 1}`);
  const r = mergeBootstrap({ builtin: ['r.org:1'], remembered });
  assert.equal(r.length, 51);
  assert.equal(r[50], '10.0.0.50:50');
  const dns = Array.from({ length: 100 }, (_, i) => `20.0.${i >> 8}.${(i & 255) + 1}:2`);
  assert.equal(mergeBootstrap({ builtin: [], dns }).length, LIMITS.dnsEndpointsTotal);
  const under = mergeBootstrap({ builtin: ['r.org:1'], remembered, dns, peers: ['p.org:1'] });
  assert.equal(under.length, 1 + 50 + 64 + 1, 'below the cap nothing is dropped');
  assert.equal(under[0], 'r.org:1');
  assert.equal(under[under.length - 1], 'p.org:1');
  const builtin = Array.from({ length: 10 }, (_, i) => `b${i}.org:1`);
  const peers = Array.from({ length: 10 }, (_, i) => `p${i}.org:1`);
  const all = mergeBootstrap({ builtin, remembered, dns, peers });
  assert.equal(all.length, LIMITS.bootstrapTotal);
  assert.deepEqual(all.slice(0, 10), builtin);
  assert.deepEqual(all.slice(-10), peers);
  assert.equal(all.filter((e) => e.startsWith('10.')).length, 50, 'remembered kept in full');
  assert.equal(all.filter((e) => e.startsWith('20.')).length, LIMITS.bootstrapTotal - 20 - 50, 'dns absorbs the cap');
});

test('mergeBootstrap: builtin and peers are prioritised under pressure, but 128 is a hard cap (warned once)', () => {
  const builtin = Array.from({ length: 10 }, (_, i) => `b${i}.org:1`);
  const peers = Array.from({ length: 100 }, (_, i) => `30.0.${i >> 8}.${(i & 255) + 1}:3`);
  const remembered = Array.from({ length: 50 }, (_, i) => `10.0.0.${i + 1}:1`);
  const dns = Array.from({ length: 64 }, (_, i) => `20.0.0.${i + 1}:2`);
  const r = mergeBootstrap({ builtin, remembered, dns, peers });
  assert.equal(r.length, 128);
  for (const b of builtin) assert.ok(r.includes(b), b);
  for (const p of peers) assert.ok(r.includes(p), p);
  assert.equal(r.filter((e) => e.startsWith('10.')).length, 18, 'remembered gets the 18 slots left');
  assert.ok(!r.some((e) => e.startsWith('20.')));
  // prioritised sources alone exceed the cap: first 128 kept, overflow reported
  const many = Array.from({ length: 130 }, (_, i) => `30.0.${i >> 8}.${(i & 255) + 1}:3`);
  let dropped = -1;
  const hard = mergeBootstrap({ builtin: ['b.org:1'], peers: many, remembered, dns, onOverflow: (n) => { dropped = n; } });
  assert.equal(hard.length, LIMITS.bootstrapTotal);
  assert.equal(dropped, 3);
  assert.equal(hard[0], 'b.org:1');
  assert.ok(!hard.some((e) => e.startsWith('10.') || e.startsWith('20.')));
  assert.equal(mergeBootstrap({ builtin: [], peers: many.slice(0, 128) }).length, 128, 'exactly at the cap: no overflow');
});

test('canonicalisation: single trailing dot stripped for hostnames and seed domains', () => {
  assert.equal(normalizeHost('Seed.Example.'), 'seed.example');
  assert.equal(normalizeHost('.'), '.');
  assert.deepEqual(parseHostPort('seed.example.:1'), { host: 'seed.example', port: 1, family: 'name' });
  assert.equal(parseHostPort('seed.example..:1'), undefined, 'two dots is not a name');
  assert.deepEqual(canonicalEndpoints(['seed.example:1', 'seed.example.:1', 'SEED.example.:1']), ['seed.example:1']);
  assert.equal(isHostname('example.org.'), true);
  assert.equal(isPrivateHost('localhost.'), true);
});

test('dnsSeeds: trailing-dot domain variants collapse into one query', async () => {
  const seen: string[] = [];
  await dnsSeeds(['a.org', 'a.org.', 'A.ORG.'], async (h) => { seen.push(h); return []; });
  assert.deepEqual(seen, ['_webway-seeds.a.org']);
});

test('dnsSeeds: byte budget never cuts a token (4085 spaces + 8.8.8.8:6881)', async () => {
  const rec = ' '.repeat(4085) + '8.8.8.8:6881'; // 4097 bytes: over budget by one, dropped whole
  const r = await dnsSeeds(['a.org'], fake({ '_webway-seeds.a.org': [[rec]] }));
  assert.deepEqual(r, []);
  assert.ok(!r.includes('8.8.8.8:688'));
  const fits = ' '.repeat(4084) + '8.8.8.8:6881'; // exactly 4096 bytes
  assert.deepEqual(await dnsSeeds(['a.org'], fake({ '_webway-seeds.a.org': [[fits]] })), ['8.8.8.8:6881']);
  // budget is bytes, not chars: multibyte padding counts fully
  const multi = 'é'.repeat(2048) + ' 9.9.9.9:9'; // 4096 bytes of é + token -> over budget
  assert.deepEqual(await dnsSeeds(['a.org'], fake({ '_webway-seeds.a.org': [[multi]] })), []);
  // a second record after the budget is exhausted is not read, but an earlier fitting one is kept
  const two = [['1.1.1.1:1 ' + 'x'.repeat(4080)], ['8.8.8.8:8']];
  assert.deepEqual(await dnsSeeds(['a.org'], fake({ '_webway-seeds.a.org': two })), ['1.1.1.1:1']);
});

test('dnsSeeds: IPv6 and duplicates do not consume the per-domain cap (32 v6 + 1 v4 -> v4 survives)', async () => {
  const v6 = Array.from({ length: 32 }, (_, i) => `[2001:db8::${i + 1}]:1`);
  const r = await dnsSeeds(['a.org'], fake({ '_webway-seeds.a.org': [[[...v6, '8.8.8.8:8'].join(' ')]] }));
  assert.deepEqual(r, ['8.8.8.8:8']);
  const dups = Array.from({ length: 40 }, () => '7.7.7.7:7');
  assert.deepEqual(await dnsSeeds(['a.org'], fake({ '_webway-seeds.a.org': [[[...dups, '6.6.6.6:6'].join(' ')]] })), ['7.7.7.7:7', '6.6.6.6:6']);
});

test('dnsSeeds: per-domain emission — a fast domain is delivered before a hanging one times out', async () => {
  const events: { seeds: string[]; domain: string; at: number }[] = [];
  const t0 = Date.now();
  const p = dnsSeeds(['fast.org', 'hang.org'], fake({ '_webway-seeds.fast.org': [['1.1.1.1:1']], '_webway-seeds.hang.org': 'hang' }), 300,
    { onDomain: (seeds, domain) => events.push({ seeds, domain, at: Date.now() - t0 }) });
  await new Promise((r) => setTimeout(r, 50));
  assert.equal(events.length, 1, 'fast domain emitted while the other is still pending');
  assert.deepEqual(events[0].seeds, ['1.1.1.1:1']);
  assert.equal(events[0].domain, 'fast.org');
  assert.ok(events[0].at < 100);
  assert.deepEqual(await p, ['1.1.1.1:1']);
  assert.ok(Date.now() - t0 >= 250, 'overall promise waited for the hanging domain timeout');
  // cross-domain dedupe at emission time
  const ev2: string[][] = [];
  await dnsSeeds(['a.org', 'b.org'], fake({ '_webway-seeds.a.org': [['1.1.1.1:1 2.2.2.2:2']], '_webway-seeds.b.org': [['2.2.2.2:2 3.3.3.3:3']] }), 1000, { onDomain: (s) => ev2.push(s) });
  assert.deepEqual(ev2.flat().sort(), ['1.1.1.1:1', '2.2.2.2:2', '3.3.3.3:3']);
});

test('dnsSeeds: abort signal settles the promise promptly, clears timers, emits nothing afterwards', async () => {
  const ac = new AbortController();
  const emitted: string[][] = [];
  const t0 = Date.now();
  const p = dnsSeeds(['hang.org'], fake({ '_webway-seeds.hang.org': 'hang' }), 60_000, { signal: ac.signal, onDomain: (s) => emitted.push(s) });
  setTimeout(() => ac.abort(), 20);
  assert.deepEqual(await p, []);
  assert.ok(Date.now() - t0 < 1000, 'settled on abort, not on the 60s timer');
  assert.deepEqual(emitted, []);
  assert.deepEqual(await dnsSeeds(['a.org'], fake({ '_webway-seeds.a.org': [['1.1.1.1:1']] }), 100, { signal: AbortSignal.abort() }), [], 'pre-aborted');
});

test('mergeBootstrap: dns=false, missing sources, junk', () => {
  assert.deepEqual(mergeBootstrap({ builtin: ['r.org:1'], dns: false }), ['r.org:1']);
  assert.deepEqual(mergeBootstrap({ builtin: [] }), []);
  assert.deepEqual(mergeBootstrap({ builtin: [], peers: ['p.org:1', 'junk', '1.2.3.4:0'] }), ['p.org:1']);
});

// ---- advertising ---------------------------------------------------------------------

test('advertisableNodes: structured validation, IPv4 only, private filter, dedupe, cap, exclude', () => {
  const nodes = [
    { host: '127.0.0.1', port: 1 }, { host: '1.2.3.4', port: 6881 }, { host: '1.2.3.4', port: 6881 },
    { host: '2001:db8::1', port: 2 }, { host: '2606:4700::1', port: 2 }, { host: '5.5.5.5', port: 0 }, { host: '6.6.6.6', port: 70000 },
    null as any, { host: 7 as any, port: 7 }, { host: '127.0.0.1:0', port: 6881 }, { host: '', port: 1 }, { host: '999.1.1.1', port: 1 },
    { host: '100.64.0.1', port: 1 }, { host: 'host.example', port: 1 }, { host: '8.8.8.8', port: 8 },
  ];
  assert.deepEqual(advertisableNodes(nodes), ['1.2.3.4:6881', '8.8.8.8:8']);
  assert.deepEqual(advertisableNodes(nodes, 20, true), ['127.0.0.1:1', '1.2.3.4:6881', '100.64.0.1:1', '8.8.8.8:8']);
  assert.deepEqual(advertisableNodes(nodes, 1), ['1.2.3.4:6881']);
  assert.deepEqual(advertisableNodes(nodes, 20, false, (a) => a === '1.2.3.4:6881'), ['8.8.8.8:8']);
  const many = Array.from({ length: 30 }, (_, i) => ({ host: `9.9.9.${i}`, port: 9 }));
  assert.equal(advertisableNodes(many).length, LIMITS.advertise);
  assert.deepEqual(advertisableNodes(undefined as any), []);
  assert.deepEqual(advertisableNodes('nope' as any), []);
});
