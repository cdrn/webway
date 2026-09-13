// Child-process probe for issue #8: two nodes exchange a torrent over uTP/TCP, both stop,
// and the process must then exit on its own. Prints the ms between the last stop() resolving
// and process exit; the parent test asserts that number stays small.
import { mkdtemp, mkdir, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { WebwayNode } from '../../src/node.ts';

const root = await mkdtemp(join(tmpdir(), 'webway-exit-'));
const modelDir = join(root, 'src', 'm');
await mkdir(modelDir, { recursive: true });
await writeFile(join(modelDir, 'w.bin'), randomBytes(512 * 1024));

const router = await new WebwayNode({ home: join(root, 'router'), bootstrap: false, nat: false, dns: false }).start();
const boot = [`127.0.0.1:${router.dht.address().port}`];
const pub = await new WebwayNode({ home: join(root, 'pub'), bootstrap: boot, nat: false, dns: false }).start();
const alice = await new WebwayNode({ home: join(root, 'alice'), bootstrap: boot, nat: false, dns: false }).start();

const share = await pub.share(modelDir, 'acme/m');
await alice.fetch(share.ih); // a real peer connection, so uTP connections exist at teardown

// Stop everyone at once: this is the pattern that left libutp waiting ~30 s for FINs.
await Promise.all([alice.stop(), pub.stop(), router.stop()]);
const stoppedAt = Date.now();
process.on('exit', () => process.stdout.write(`exit-after-stop-ms=${Date.now() - stoppedAt}\n`));
