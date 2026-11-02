// Node harness: load ext/main.wasm with ext/wasm_exec.js and call globalThis.check
// Usage: node scripts/run_wasm.cjs <input-string>
'use strict';
const fs = require('node:fs');
const path = require('node:path');

const EXT = path.resolve(__dirname, '..', 'ext');
require(path.join(EXT, 'wasm_exec.js')); // installs globalThis.Go

async function main() {
  const go = new globalThis.Go();
  const bytes = fs.readFileSync(path.join(EXT, 'main.wasm'));
  const { instance } = await WebAssembly.instantiate(bytes, go.importObject);
  go.run(instance); // do not await: Go program stays alive in the js event loop

  // wait until globalThis.check is installed
  let tries = 0;
  while (typeof globalThis.check !== 'function') {
    if (++tries > 1000) {
      console.error('globalThis.check never appeared. globals:', Object.keys(globalThis).filter(k => !k.startsWith('_')));
      process.exit(2);
    }
    await new Promise(r => setTimeout(r, 10));
  }
  console.error('[harness] globalThis.check ready:', globalThis.check.toString().slice(0, 200));

  const args = process.argv.slice(2);
  const input = args.length ? args[0] : '';

  let res;
  try {
    res = globalThis.check(input);
  } catch (e) {
    console.error('check() threw:', e && e.stack ? e.stack : e);
    process.exit(3);
  }
  console.log('check(' + JSON.stringify(input) + ') =>', res, '(typeof ' + typeof res + ')');
  if (res === true) console.log('*** ACCEPTED ***');
  process.exit(0);
}

main();
