// electron-builder beforePack hook: reconstruct assets/lighter_signer.wasm
// from the gzip shipped in the repo (assets/lighter_signer.wasm.gz).
//
// Why: the raw Go WASM signer is ~12.8 MB, which is too large to sync into
// this releases repo through the Replit GitHub connector proxy (its request
// body cap rejects the blob with HTTP 413). The gzip is ~3.6 MB and passes,
// so the repo carries only the .gz and this hook inflates it on the CI
// runner right before electron-builder packs the asar (build.files includes
// assets/** but excludes the .gz). Runs once per target — idempotent.
'use strict';
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

module.exports = async function prepareWasm() {
  const dir = path.join(__dirname, '..', 'assets');
  const gz = path.join(dir, 'lighter_signer.wasm.gz');
  const out = path.join(dir, 'lighter_signer.wasm');
  if (fs.existsSync(out)) return;               // dev checkout / second target
  if (!fs.existsSync(gz)) {
    throw new Error('prepare-wasm: neither lighter_signer.wasm nor its .gz exists');
  }
  fs.writeFileSync(out, zlib.gunzipSync(fs.readFileSync(gz)));
  console.log('prepare-wasm: inflated lighter_signer.wasm (' +
              fs.statSync(out).size + ' bytes)');
};
