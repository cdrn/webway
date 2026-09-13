import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));

// Issue #8: after node.stop() the process must exit on its own, promptly. utp-native used to
// hold the event loop for ~30 s (libutp waiting for FINs from peers that were torn down at the
// same time) through a native handle that no handle inspector can see, so the only honest test
// is a real child process: two nodes trade a torrent, everyone stops, measure time-to-exit.
// On the unfixed code this measures ~31,000 ms.
test('process exits by itself within 3s of the last stop() (uTP peers torn down together)', async () => {
  const probe = join(here, 'helpers', 'exit-probe.ts');
  const { out, err, code, ms } = await new Promise<{ out: string; err: string; code: number | null; ms: number }>((resolve) => {
    const t0 = Date.now();
    const child = spawn(process.execPath, ['--experimental-strip-types', probe], { stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '', err = '';
    child.stdout.on('data', (d) => (out += d));
    child.stderr.on('data', (d) => (err += d));
    child.on('exit', (code) => resolve({ out, err, code, ms: Date.now() - t0 }));
  });
  const m = /exit-after-stop-ms=(\d+)/.exec(out);
  assert.ok(m, `probe did not report an exit time (code ${code}, ${ms}ms)\n${err.split('\n').filter((l) => !/ExperimentalWarning|trace-warnings/.test(l)).join('\n')}`);
  const afterStop = Number(m[1]);
  assert.equal(code, 0, `probe exit code ${code}\n${err}`);
  assert.ok(afterStop < 3000, `process lingered ${afterStop}ms after stop()`);
  assert.ok(!/UNCAUGHT|Error: UTP_ECONNRESET/.test(err), `late uncaught error during teardown:\n${err}`);
});
