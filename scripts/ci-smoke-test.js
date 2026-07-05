#!/usr/bin/env node
// Windows-only CI smoke test for the auto-update pipeline. Runs on a real
// windows-latest runner (it CANNOT run in the Replit Linux sandbox — that is the
// whole point). It proves the exact failure class that once bricked a user's
// install ("old removed, new not installed") can no longer ship silently:
//
//   1. Silently install the current version's setup.exe.
//   2. Assert the app exe AND the uninstaller exist in the per-user install dir,
//      and the registered version matches.
//   3. Build the NEXT version's setup.exe and silently install it OVER the first
//      one (simulates a real electron-updater in-place upgrade).
//   4. Assert the install replaced cleanly — new version registered, app exe
//      still present.
//   5. Silently run the uninstaller and assert a clean removal (install dir and
//      registry entry gone).
//
// Any failed assertion exits non-zero → the CI job fails.
'use strict';

const { execFileSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const PKG = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
const PRODUCT = PKG.build.productName; // "A Trader's Tool"
const BASE_VER = PKG.version;
const NEXT_VER = bumpPatch(BASE_VER);

const DIST = path.join(ROOT, 'dist');
const DIST_NEXT = path.join(ROOT, 'dist-next');

function bumpPatch(v) {
  const m = String(v).split('.').map((n) => parseInt(n, 10));
  if (m.length !== 3 || m.some(isNaN)) {
    throw new Error(`Cannot bump non-semver version "${v}"`);
  }
  return `${m[0]}.${m[1]}.${m[2] + 1}`;
}

function log(msg) { console.log(`[smoke] ${msg}`); }
function fail(msg) { console.error(`[smoke] FAIL: ${msg}`); process.exit(1); }

// Run a PowerShell command, return trimmed stdout.
function ps(command) {
  return execFileSync(
    'powershell',
    ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', command],
    { encoding: 'utf8', stdio: ['ignore', 'pipe', 'inherit'] }
  ).trim();
}

// Run a command, streaming output; throw on non-zero exit.
// shell:true is required on Windows so `npx` resolves to `npx.cmd` (otherwise
// execFileSync throws ENOENT — it won't append the .cmd extension itself).
function run(cmd, args, opts) {
  log(`$ ${cmd} ${args.join(' ')}`);
  execFileSync(cmd, args, Object.assign({ stdio: 'inherit', cwd: ROOT, shell: true }, opts || {}));
}

const setupName = (ver) => `A-Traders-Tool-${ver}-setup.exe`;

// Look up the app's Windows uninstall registry entry (per-user install →
// HKCU; also check HKLM/WOW6432Node defensively). Returns null if absent.
function registryEntry() {
  const script = `
    $paths = @(
      'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall',
      'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall',
      'HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall'
    )
    $e = Get-ChildItem $paths -ErrorAction SilentlyContinue |
      ForEach-Object { Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue } |
      Where-Object { $_.DisplayName -eq "${PRODUCT}" } |
      Select-Object -First 1 DisplayName,DisplayVersion,InstallLocation,QuietUninstallString,UninstallString
    if ($e) { $e | ConvertTo-Json -Compress } else { '' }
  `;
  const out = ps(script);
  if (!out) return null;
  try { return JSON.parse(out); } catch (e) { return null; }
}

// Silent install: NSIS oneClick installer supports /S. Start-Process -Wait waits
// for the installer stub to finish; the freshly-installed app may auto-launch, so
// we kill it afterwards to keep the runner clean.
function silentInstall(setupExe) {
  if (!fs.existsSync(setupExe)) fail(`installer not found: ${setupExe}`);
  ps(`Start-Process -FilePath "${setupExe}" -ArgumentList '/S' -Wait`);
  killApp();
}

function killApp() {
  try {
    ps(`Stop-Process -Name "${PRODUCT}" -Force -ErrorAction SilentlyContinue`);
  } catch (e) { /* not running — fine */ }
}

// Silent uninstall via the NSIS uninstaller exe (/S). It copies itself to %TEMP%
// and finishes asynchronously; callers should poll for the install dir to vanish.
function silentUninstall(uninstExe, installDir) {
  killApp();
  ps(`Start-Process -FilePath "${uninstExe}" -ArgumentList '/S' -Wait`);
}

// Poll until predicate() is true or timeout. Returns true on success.
function waitFor(predicate, timeoutMs, everyMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (predicate()) return true;
    ps(`Start-Sleep -Milliseconds ${everyMs || 1000}`);
  }
  return predicate();
}

// Poll for the uninstall registry entry to appear (optionally with a specific
// DisplayVersion). NSIS silent installs commit the registry write after the
// launcher process returns, so a single immediate lookup races the installer.
// Returns the entry object once matched, or the last-seen value on timeout.
function waitForRegistry(expectedVer, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  let e = registryEntry();
  while (Date.now() < deadline) {
    if (e && (!expectedVer || e.DisplayVersion === expectedVer)) return e;
    ps('Start-Sleep -Milliseconds 2000');
    e = registryEntry();
  }
  return e;
}

// Diagnostics: dump every registered uninstall DisplayName/Version so a naming
// mismatch (vs the exact PRODUCT string) is visible in the log immediately.
function dumpUninstallEntries() {
  const script = `
    $paths = @(
      'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall',
      'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall',
      'HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall'
    )
    Get-ChildItem $paths -ErrorAction SilentlyContinue |
      ForEach-Object { Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue } |
      Where-Object { $_.DisplayName } |
      Select-Object DisplayName,DisplayVersion |
      ConvertTo-Json -Compress
  `;
  try { return ps(script) || '(none)'; } catch (e) { return '(dump failed: ' + e.message + ')'; }
}

function main() {
  if (process.platform !== 'win32') {
    fail('this smoke test must run on Windows (windows-latest CI runner)');
  }

  log(`product="${PRODUCT}" base=${BASE_VER} next=${NEXT_VER}`);

  // Make sure any stale registration from a previous run is gone.
  const stale = registryEntry();
  if (stale && stale.InstallLocation) {
    const staleUninst = path.join(stale.InstallLocation, `Uninstall ${PRODUCT}.exe`);
    if (fs.existsSync(staleUninst)) {
      log('removing stale prior install…');
      try { silentUninstall(staleUninst, stale.InstallLocation); } catch (e) { /* best effort */ }
    }
  }

  // --- 1. base installer must already be built by the workflow ---
  const baseSetup = path.join(DIST, setupName(BASE_VER));
  if (!fs.existsSync(baseSetup)) {
    log('base installer missing — building it');
    run('npx', ['electron-builder', '--win', 'nsis', '--publish', 'never']);
  }

  // --- 2. build the NEXT version installer for the upgrade test ---
  log(`building next-version installer (${NEXT_VER}) into dist-next/`);
  const pkgPath = path.join(ROOT, 'package.json');
  const pkgBackup = fs.readFileSync(pkgPath, 'utf8');
  try {
    const bumped = JSON.parse(pkgBackup);
    bumped.version = NEXT_VER;
    fs.writeFileSync(pkgPath, JSON.stringify(bumped, null, 2) + '\n');
    run('npx', ['electron-builder', '--win', 'nsis', '--publish', 'never',
      '-c.directories.output=dist-next']);
  } finally {
    fs.writeFileSync(pkgPath, pkgBackup); // always restore the real version
  }
  const nextSetup = path.join(DIST_NEXT, setupName(NEXT_VER));
  if (!fs.existsSync(nextSetup)) fail(`next installer not built: ${nextSetup}`);

  // --- 3. install base, assert app + uninstaller present, version correct ---
  log('installing base version silently…');
  silentInstall(baseSetup);

  let entry = waitForRegistry(BASE_VER, 120000);
  if (!entry) {
    log(`registered uninstall entries: ${dumpUninstallEntries()}`);
    fail('no uninstall registry entry after base install');
  }
  if (!entry.InstallLocation) fail('registry entry has no InstallLocation');
  const installDir = entry.InstallLocation;
  const appExe = path.join(installDir, `${PRODUCT}.exe`);
  const uninstExe = path.join(installDir, `Uninstall ${PRODUCT}.exe`);

  if (!waitFor(() => fs.existsSync(appExe), 30000, 1500)) fail(`app exe missing after install: ${appExe}`);
  if (!waitFor(() => fs.existsSync(uninstExe), 30000, 1500)) fail(`uninstaller missing after install: ${uninstExe}`);
  if (entry.DisplayVersion !== BASE_VER) {
    fail(`registered version ${entry.DisplayVersion} != base ${BASE_VER}`);
  }
  log(`base install OK → ${installDir} (v${entry.DisplayVersion})`);

  // --- 4. install next OVER it, assert clean in-place replace ---
  log('installing next version over the base (simulated auto-update)…');
  silentInstall(nextSetup);

  entry = waitForRegistry(NEXT_VER, 120000);
  if (!entry) fail('no registry entry after in-place update');
  if (!waitFor(() => fs.existsSync(appExe), 30000, 1500)) fail(`app exe missing after update: ${appExe}`);
  if (entry.DisplayVersion !== NEXT_VER) {
    fail(`after update, registered version ${entry.DisplayVersion} != next ${NEXT_VER}`);
  }
  log(`in-place update OK → v${entry.DisplayVersion}`);

  // --- 5. uninstall, assert clean removal ---
  log('uninstalling silently…');
  if (!fs.existsSync(uninstExe)) fail(`uninstaller missing before uninstall: ${uninstExe}`);
  silentUninstall(uninstExe, installDir);
  // The NSIS uninstaller copies itself to %TEMP% and finishes asynchronously.
  const gone = waitFor(() => !fs.existsSync(appExe) && registryEntry() === null, 60000, 1500);
  if (!gone) {
    fail(`uninstall did not clean up (appExe exists=${fs.existsSync(appExe)}, registry=${registryEntry() ? 'present' : 'gone'})`);
  }
  log('uninstall OK — install dir and registry entry removed');

  log('ALL CHECKS PASSED ✔');
}

try {
  main();
} catch (e) {
  fail(e && e.stack ? e.stack : String(e));
}
