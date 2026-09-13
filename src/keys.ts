import * as ed from '@noble/ed25519';
import { createHash, randomBytes } from 'node:crypto';
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { dirname } from 'node:path';

// noble v3 needs a sync sha512 for sign()/verify(); use node's.
ed.hashes.sha512 = (m: Uint8Array) => new Uint8Array(createHash('sha512').update(m).digest());

export interface Keypair { pk: Buffer; sk: Buffer }

export function generate(): Keypair {
  const sk = Buffer.from(randomBytes(32));
  return { pk: Buffer.from(ed.getPublicKey(sk)), sk };
}

export function sign(kp: Keypair, msg: Uint8Array): Buffer {
  return Buffer.from(ed.sign(msg, kp.sk));
}

/** Sync verify in the shape bittorrent-dht expects: (sig, msg, pk) => boolean. */
export function verify(sig: Uint8Array, msg: Uint8Array, pk: Uint8Array): boolean {
  try { return ed.verify(sig, msg, pk); } catch { return false; }
}

export async function loadOrCreate(path: string): Promise<Keypair> {
  try {
    const j = JSON.parse(await readFile(path, 'utf8'));
    return { pk: Buffer.from(j.pk, 'hex'), sk: Buffer.from(j.sk, 'hex') };
  } catch (e: any) {
    if (e.code !== 'ENOENT') throw e;
    const kp = generate();
    await mkdir(dirname(path), { recursive: true });
    await writeFile(path, JSON.stringify({ pk: kp.pk.toString('hex'), sk: kp.sk.toString('hex') }), { mode: 0o600 });
    return kp;
  }
}
