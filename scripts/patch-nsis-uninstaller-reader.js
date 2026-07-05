#!/usr/bin/env node
// Patches app-builder-lib so the NSIS uninstaller can be extracted with the
// pure-JS UninstallerReader instead of executing the 32-bit installer stub
// under wine. Needed ONLY when building the NSIS target in the Replit Linux
// sandbox, where 32-bit code cannot execute (gVisor). Windows / normal Linux
// with wine do NOT need this.
//
// Usage:
//   node scripts/patch-nsis-uninstaller-reader.js   (after npm install)
//   NSIS_UNINSTALLER_READER=1 npm run build:win:installer
'use strict';

const fs = require('fs');
const path = require('path');

const target = path.join(
  __dirname, '..', 'node_modules', 'app-builder-lib', 'out', 'targets', 'nsis', 'NsisTarget.js'
);

const src = fs.readFileSync(target, 'utf8');

if (src.includes('NSIS_UNINSTALLER_READER')) {
  console.log('Already patched.');
  process.exit(0);
}

// Each entry: [needle, replacement]. The first matching anchor is used —
// covers both old (execWine) and new (WineVmManager) app-builder-lib layouts.
const anchors = [
  [
    `        else {
            await (0, wine_1.execWine)(installerPath, null, [], { env: { __COMPAT_LAYER: "RunAsInvoker" } });
        }`,
    `        else if (process.env.NSIS_UNINSTALLER_READER === "1") {
            // Local patch: sandbox cannot execute 32-bit code via wine; extract
            // the uninstaller with the pure-JS reader (same path as macOS Catalina).
            await nsisUtil_1.UninstallerReader.exec(installerPath, uninstallerPath);
        }
        else {
            await (0, wine_1.execWine)(installerPath, null, [], { env: { __COMPAT_LAYER: "RunAsInvoker" } });
        }`,
  ],
  [
    `        else {
            const wineVm = new WineVm_1.WineVmManager((_a = packager.config.toolsets) === null || _a === void 0 ? void 0 : _a.wine);
            await wineVm.exec(installerPath, [], { env: { __COMPAT_LAYER: "RunAsInvoker" } });
        }`,
    `        else if (process.env.NSIS_UNINSTALLER_READER === "1") {
            // Local patch: sandbox cannot execute 32-bit code via wine; extract
            // the uninstaller with the pure-JS reader (same path as macOS Catalina).
            await nsisUtil_1.UninstallerReader.exec(installerPath, uninstallerPath);
        }
        else {
            const wineVm = new WineVm_1.WineVmManager((_a = packager.config.toolsets) === null || _a === void 0 ? void 0 : _a.wine);
            await wineVm.exec(installerPath, [], { env: { __COMPAT_LAYER: "RunAsInvoker" } });
        }`,
  ],
];

const hit = anchors.find(([needle]) => src.includes(needle));
if (!hit) {
  console.error('Patch anchor not found — app-builder-lib layout changed; patch manually.');
  process.exit(1);
}

fs.writeFileSync(target, src.replace(hit[0], hit[1]));
console.log('Patched', target);
