// ---------------------------------------------------------------------------
// Device API-key vault (keyvault.js) — per-panel-user, per-venue exchange API
// keys stored ON THIS DEVICE via Electron safeStorage (OS keychain-backed).
// Keys saved here NEVER travel to the server: the renderer reads a blob back
// only at arm time and hands it straight to the native trading store
// (attTrade.setCreds) — the same one-shot handoff the server release uses.
//
// Namespacing: entries are keyed "user|venue" with the panel-reported session
// username (same trust path as every other att:* usage — the shell already
// trusts the top-level app-origin frame; list/get only ever return the
// requesting user's own slots, so a shared machine's other accounts stay
// invisible in normal operation).
//
// Everything above module.exports.createKeyVault's closure is PURE (no
// electron / fs) so it node-unit-tests without a shell.
// ---------------------------------------------------------------------------
'use strict';

const fs = require('fs');
const path = require('path');

// --- pure helpers -----------------------------------------------------------

// Normalize + validate the vault slot name. Users come from the panel session
// (lowercase account names); venues from the fixed venue registry. Refuse
// anything shaped oddly so a hostile string can never smuggle a separator.
function kvUserNorm(user) {
  const u = String(user == null ? '' : user).trim().toLowerCase();
  return (/^[a-z0-9_.@-]{1,64}$/.test(u)) ? u : '';
}
function kvVenueNorm(venue) {
  const v = String(venue == null ? '' : venue).trim().toLowerCase();
  // Optional per-account suffix "#aN" (extra exchange accounts store under
  // additive "venue#aN" slots — e.g. "bybit#a2"). '#' stays refused anywhere
  // else so a hostile string still can't smuggle a separator.
  return (/^[a-z0-9_-]{1,32}(?:#a[0-9]{1,4})?$/.test(v)) ? v : '';
}
function kvSlot(user, venue) {
  const u = kvUserNorm(user), v = kvVenueNorm(venue);
  return (u && v) ? u + '|' + v : '';
}
// Validate an incoming creds blob (same field limits as the native store).
// Returns the normalized payload or null.
function kvCredsNorm(creds) {
  if (!creds || typeof creds !== 'object') return null;
  const key = String(creds.key || ''), secret = String(creds.secret || '');
  // Kraken dual-pair creds: key/secret = spot pair, additive key2/secret2 =
  // futures pair (separate keys — spot keys can't sign the futures API).
  // Valid when at least ONE complete pair is present.
  const key2 = String(creds.key2 || ''), secret2 = String(creds.secret2 || '');
  const dual = !!(creds.krv || key2 || secret2);
  if (dual) {
    if ((!!key !== !!secret) || (!!key2 !== !!secret2)
        || (!key && !key2)
        || key.length > 200 || secret.length > 500
        || key2.length > 200 || secret2.length > 500) return null;
  } else if (!key || !secret || key.length > 200 || secret.length > 500) {
    return null;
  }
  const out = { key: key, secret: secret };
  if (dual) { out.krv = 1; out.key2 = key2; out.secret2 = secret2; }
  if (creds.passphrase) out.pass = String(creds.passphrase).slice(0, 200);
  else if (creds.pass) out.pass = String(creds.pass).slice(0, 200);
  return out;
}
// Parse the on-disk vault file content. Returns the entries map (never null).
function kvParse(raw) {
  try {
    const d = JSON.parse(raw);
    return (d && typeof d === 'object' && d.entries && typeof d.entries === 'object')
      ? d.entries : {};
  } catch (e) { return {}; }
}
// One user's presence listing from an entries map (no secret material).
function kvListFor(entries, user) {
  const u = kvUserNorm(user);
  const out = {};
  if (!u) return out;
  for (const slot of Object.keys(entries)) {
    const i = slot.indexOf('|');
    if (i < 0 || slot.slice(0, i) !== u) continue;
    const r = entries[slot];
    if (!r || typeof r !== 'object' || !r.b64) continue;
    const e = { present: true, tail: String(r.tail || ''), ts: r.ts || 0 };
    // Dual-pair marker (Kraken spot+futures blobs): lets a plan decide
    // whether the copy carries the second pair WITHOUT a get() — old
    // entries simply lack the field (unknown, not false).
    if (r.has2) e.has2 = true;
    out[slot.slice(i + 1)] = e;
  }
  return out;
}

// --- runtime (electron-side) -------------------------------------------------
function createKeyVault(opts) {
  const ipcMain = opts.ipcMain;
  const safeStorage = opts.safeStorage;
  const senderOk = opts.senderOk;              // top-level app-origin frame gate
  const userDataDir = opts.userDataDir;        // function → app.getPath('userData')

  const vaultFile = () => path.join(userDataDir(), 'key_vault.json');

  function loadAll() {
    try { return kvParse(fs.readFileSync(vaultFile(), 'utf8')); } catch (e) { return {}; }
  }
  function saveAll(entries) {
    try {
      fs.writeFileSync(vaultFile(), JSON.stringify({ v: 1, entries: entries }));
      return true;
    } catch (e) { return false; }
  }

  function vaultSet(user, venue, creds) {
    if (!safeStorage || !safeStorage.isEncryptionAvailable()) {
      return { ok: false, error: 'encryption-unavailable' };
    }
    const slot = kvSlot(user, venue);
    if (!slot) return { ok: false, error: 'bad-slot' };
    const payload = kvCredsNorm(creds);
    if (!payload) return { ok: false, error: 'bad-creds' };
    let b64;
    try {
      b64 = safeStorage.encryptString(JSON.stringify(payload)).toString('base64');
    } catch (e) { return { ok: false, error: 'encrypt-failed' }; }
    const entries = loadAll();
    entries[slot] = {
      b64: b64,
      tail: (payload.key || payload.key2 || '').length >= 4
        ? (payload.key || payload.key2 || '').slice(-4)
        : (payload.key || payload.key2 || ''),
      ts: Math.floor(Date.now() / 1000),
    };
    // Dual-pair marker for list(): a Kraken blob carrying BOTH pairs.
    if (payload.key2 && payload.secret2) entries[slot].has2 = true;
    if (!saveAll(entries)) return { ok: false, error: 'persist-failed' };
    return { ok: true, tail: entries[slot].tail };
  }

  function vaultGet(user, venue) {
    const slot = kvSlot(user, venue);
    if (!slot || !safeStorage) return null;
    const r = loadAll()[slot];
    if (!r || !r.b64) return null;
    try {
      const d = JSON.parse(safeStorage.decryptString(Buffer.from(r.b64, 'base64')));
      if (!d) return null;
      // Valid: a plain pair, or a Kraken dual blob with ≥1 complete pair.
      if (!((d.key && d.secret) || (d.key2 && d.secret2))) return null;
      return d;                                     // {key, secret, pass?}
    } catch (e) { return null; }
  }

  function vaultDel(user, venue) {
    const slot = kvSlot(user, venue);
    if (!slot) return { ok: false, error: 'bad-slot' };
    const entries = loadAll();
    delete entries[slot];
    saveAll(entries);
    return { ok: true };
  }

  function vaultList(user) {
    return {
      ok: true,
      venues: kvListFor(loadAll(), user),
      encryptionAvailable: !!(safeStorage && safeStorage.isEncryptionAvailable()),
    };
  }

  ipcMain.handle('att:keyvault-set', (event, user, venue, creds) => {
    if (!senderOk(event)) return { ok: false, error: 'forbidden' };
    return vaultSet(user, venue, creds);
  });
  ipcMain.handle('att:keyvault-get', (event, user, venue) => {
    if (!senderOk(event)) return null;
    return vaultGet(user, venue);
  });
  ipcMain.handle('att:keyvault-del', (event, user, venue) => {
    if (!senderOk(event)) return { ok: false, error: 'forbidden' };
    return vaultDel(user, venue);
  });
  ipcMain.handle('att:keyvault-list', (event, user) => {
    if (!senderOk(event)) return { ok: false, error: 'forbidden' };
    return vaultList(user);
  });

  return { vaultSet, vaultGet, vaultDel, vaultList };
}

module.exports = { kvUserNorm, kvVenueNorm, kvSlot, kvCredsNorm, kvParse, kvListFor, createKeyVault };
