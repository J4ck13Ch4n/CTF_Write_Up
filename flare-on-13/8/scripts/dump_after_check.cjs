'use strict';
// Run check(<b64>) and dump the whole wasm linear memory to a file.
// usage: node dump_after_check.cjs <b64> <outfile>
const fs = require('node:fs');
const path = require('node:path');
const EXT = path.resolve(__dirname, '..', 'ext');
require(path.join(EXT, 'wasm_exec.js'));

async function main() {
  const go = new globalThis.Go();
  const wasmPath = process.env.WASM || path.join(EXT, 'main.wasm');
  const bytes = fs.readFileSync(wasmPath);
  const { instance } = await WebAssembly.instantiate(bytes, go.importObject);
  go.run(instance);
  let t = 0;
  while (typeof globalThis.check !== 'function') {
    if (++t > 3000) { console.error('no check'); process.exit(2); }
    await new Promise(r => setTimeout(r, 10));
  }
  await new Promise(r => setTimeout(r, 300));
  const b64 = process.argv[2] || '';
  let res;
  try { res = globalThis.check(b64); } catch (e) { res = 'THREW ' + e.message; }
  console.error('check =>', JSON.stringify(String(res)));
  await new Promise(r => setTimeout(r, 100));
  const mem = new Uint8Array(go.mem.buffer);
  const out = process.argv[3];
  if (out) fs.writeFileSync(out, Buffer.from(mem));
  console.error('mem size', mem.length, '->', out);
  process.exit(0);
}
main();
