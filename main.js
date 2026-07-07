'use strict';

const { app, BrowserWindow, Tray, Menu, shell, session, nativeImage, ipcMain } = require('electron');
const path = require('path');
const fs = require('fs');
const net = require('net');

let autoUpdater = null;
try {
  autoUpdater = require('electron-updater').autoUpdater;
} catch (e) {
  // electron-updater not installed (e.g. dev run) — updates simply disabled
}

const APP_URL = 'https://atraderstool.com';
const APP_HOST = 'atraderstool.com';
const PARTITION = 'persist:atraderstool';
// Public releases page — the manual-recovery escape hatch surfaced when an
// auto-update ever errors, so a user is one click from the latest installer
// instead of stuck on a half-updated app. Matches build.publish (owner/repo).
const RELEASES_URL = 'https://github.com/arturbarbaneagra/att-desktop-releases/releases/latest';

// Features that can be popped out into their own OS window. Each id matches the
// panel's showTab()/?feature=<id> name. Keep in lockstep with POPOUT_FEATURES in
// panel.html.
const FEATURE_IDS = [
  'main', 'terminal', 'mywallets', 'wallets', 'splashes', 'arbs', 'oracle', 'marklast',
  'indexlast', 'stockarb', 'biglimits', 'screener', 'listings',
];
// Scratch Terminal windows: throwaway DOM/chart workspaces, each in its OWN window.
// The user can open ANY NUMBER of them, so their ids are dynamic ('terminal_scratch'
// legacy, or 'terminal_scratch_<n>') rather than a fixed list — isScratchFeatureId
// recognizes the whole family. Like feature windows they are reopened-on-launch when
// they were open at last quit (registerFeatureWindow persists bounds + open), but
// they have no ⧉ launcher of their own (opened from the panel's workspace-tab bar).
// Kept OUT of FEATURE_IDS because the family is open-ended; recognition is by
// predicate. Lockstep with _scratchIdOf / POPOUT_FEATURES in panel.html.
function isScratchFeatureId(f) {
  return typeof f === 'string' && /^terminal_scratch(_\d+)?$/.test(f);
}
// Open-on-demand Terminal SECTION pop-outs ("Your trades" / "Phemex markets").
// They ARE recognized as feature URLs so window.open spawns a proper new OS
// window (createFeatureWindow) instead of navigating the current window in place.
// Kept OUT of FEATURE_IDS so they are never spawned UNPROMPTED on a fresh install,
// but reopenFeatureWindows DOES restore them when they were open at last quit (the
// user asked that these windows survive a restart and stay where they were put) —
// registerFeatureWindow persists their bounds + open flag like any feature window.
// Lockstep with the terminal_trades / terminal_watchlist entries in POPOUT_FEATURES
// (panel.html).
const SECTION_FEATURE_IDS = ['terminal_trades', 'terminal_watchlist'];

let mainWindow = null;
let tray = null;
let isQuitting = false;
// id -> BrowserWindow for every open feature pop-out window.
const featureWindows = new Map();
let updateStatus = 'idle'; // idle | checking | downloading | ready | disabled | error
let updateVersion = null;
// True once an update was found and download started — used so a bare, transient
// check-for-update network hiccup stays silent (idle) while a genuine
// download/apply failure surfaces the manual-recovery bar (status 'error').
let updateInFlight = false;
// Throttle focus-driven update checks so switching between windows doesn't spam
// the release feed (see browser-window-focus handler).
let lastCheckTs = 0;
// Re-entrancy guard for raiseAppWindows() (belt-and-suspenders — moveTop() does
// not itself fire browser-window-focus, but keep it so a windowing hiccup can
// never loop us back into the focus handler mid-raise).
let raisingWindows = false;

// ---------------------------------------------------------------------------
// Simple JSON settings (window bounds, feature-window layout)
// ---------------------------------------------------------------------------
const settingsPath = () => path.join(app.getPath('userData'), 'settings.json');

function loadSettings() {
  try {
    return JSON.parse(fs.readFileSync(settingsPath(), 'utf8'));
  } catch (e) {
    return {};
  }
}

function saveSettings(patch) {
  const cur = loadSettings();
  const next = Object.assign({}, cur, patch);
  try {
    fs.writeFileSync(settingsPath(), JSON.stringify(next, null, 2));
  } catch (e) {
    // non-fatal
  }
  return next;
}

// ---------------------------------------------------------------------------
// Single instance lock
// ---------------------------------------------------------------------------
const gotLock = app.requestSingleInstanceLock();
if (!gotLock) {
  app.quit();
} else {
  app.on('second-instance', () => {
    if (mainWindow) {
      if (!mainWindow.isVisible()) mainWindow.show();
      if (mainWindow.isMinimized()) mainWindow.restore();
      mainWindow.focus();
    }
  });
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function isAppOrigin(url) {
  try {
    const u = new URL(url);
    return u.hostname === APP_HOST || u.hostname.endsWith('.' + APP_HOST);
  } catch (e) {
    return false;
  }
}

// Show the offline fallback page. `retryUrl` is the app URL the window was trying
// to reach (e.g. a ?feature=<id> URL) — it is passed to fallback.html so the
// Retry button / auto-retry return to that exact URL, not the root panel.
function showFallback(win, retryUrl) {
  const target = (retryUrl && isAppOrigin(retryUrl)) ? retryUrl : APP_URL;
  // Tell the fallback page whether a proxy is active so it can offer a
  // "Disable proxy & retry" escape hatch (a bad proxy can black out all traffic).
  const cfg = getProxyConfig();
  const query = { retry: target };
  if (cfg && cfg.enabled) query.proxy = cfg.scheme + '://' + cfg.host + ':' + cfg.port;
  win.loadFile(path.join(__dirname, 'fallback.html'), { query }).catch(() => {});
}

// ---------------------------------------------------------------------------
// Feature pop-out windows (each feature in its own OS window, persisted layout)
// ---------------------------------------------------------------------------
function featureIdFromUrl(url) {
  try {
    const f = new URL(url).searchParams.get('feature');
    // Recognize the persisted feature windows, the transient section pop-outs, AND
    // dynamic scratch windows so window.open spawns a real new window for any of
    // them. Feature windows + scratch windows are reopened on launch when they were
    // open at last quit; section pop-outs likewise (see reopenFeatureWindows).
    return (FEATURE_IDS.includes(f) || SECTION_FEATURE_IDS.includes(f) || isScratchFeatureId(f)) ? f : null;
  } catch (e) {
    return null;
  }
}

// Merge a patch into settings.featureWindows[id] (bounds / open flag).
function saveFeatureWindowState(id, patch) {
  const cur = loadSettings();
  const fw = Object.assign({}, cur.featureWindows || {});
  fw[id] = Object.assign({}, fw[id], patch);
  saveSettings({ featureWindows: fw });
}

function featureWindowState(id) {
  return (loadSettings().featureWindows || {})[id] || {};
}

// Per-window zoom persistence. `id` null → the MAIN window (settings.zoom); a
// feature id → settings.featureWindows[id].zoom. Stored in settings.json
// (userData) so a window's zoom survives app restart, app update, and PC restart.
function savedZoomFor(id) {
  const s = loadSettings();
  const z = id ? ((s.featureWindows || {})[id] || {}).zoom : s.zoom;
  return (typeof z === 'number' && z > 0) ? z : 1;
}

function saveZoomFor(id, factor) {
  const f = (typeof factor === 'number' && factor > 0) ? factor : 1;
  if (id) saveFeatureWindowState(id, { zoom: f });
  else saveSettings({ zoom: f });
}

// Push the saved zoom to a freshly-loaded window so it restores after each load.
function pushZoom(win, id) {
  if (!win || win.isDestroyed()) return;
  try { win.webContents.send('att:zoom-apply', savedZoomFor(id)); } catch (e) { /* non-fatal */ }
}

// Map an IPC sender back to its window id: null = main window, a string = feature
// id, undefined = unknown (ignored). Lets att:zoom-changed persist to the right key.
function windowIdForSender(sender) {
  if (mainWindow && !mainWindow.isDestroyed() && sender === mainWindow.webContents) return null;
  for (const [id, w] of featureWindows.entries()) {
    if (w && !w.isDestroyed() && w.webContents === sender) return id;
  }
  return undefined;
}

// BrowserWindow options shared by every feature window (same login partition,
// security + look as the main window). `bounds` seeds size/position.
function featureWindowOptions(bounds) {
  const b = bounds || {};
  return {
    width: b.width || 900,
    height: b.height || 800,
    x: typeof b.x === 'number' ? b.x : undefined,
    y: typeof b.y === 'number' ? b.y : undefined,
    minWidth: 380,
    minHeight: 320,
    autoHideMenuBar: true,
    backgroundColor: '#0d1117',
    icon: path.join(__dirname, 'assets', 'icon.png'),
    title: "A Trader's Tool",
    webPreferences: {
      partition: PARTITION,
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      spellcheck: false,
    },
  };
}

// Shared window-open handler used by BOTH the main window and feature windows:
//  - app-origin URL with ?feature=<id>: focus the existing feature window, or
//    allow a new one (Electron creates it; did-create-window registers it).
//  - other app-origin window.open: load in the SAME window (no new tab).
//  - external links: open in the default browser.
function makeWindowOpenHandler(win) {
  return ({ url }) => {
    if (isAppOrigin(url)) {
      const id = featureIdFromUrl(url);
      if (id) {
        const existing = featureWindows.get(id);
        if (existing && !existing.isDestroyed()) {
          if (existing.isMinimized()) existing.restore();
          existing.show();
          existing.focus();
          return { action: 'deny' };
        }
        // Create the feature window on the INDEPENDENT path (no opener/owner
        // relationship) so clicking one window never raises the whole app group
        // above other apps. Deny the window.open so Electron makes no owned child.
        createFeatureWindow(id);
        return { action: 'deny' };
      }
      if (win && !win.isDestroyed()) win.loadURL(url);
      return { action: 'deny' };
    }
    if (/^https?:/i.test(url)) shell.openExternal(url);
    return { action: 'deny' };
  };
}

// Apply the same navigation lock + offline fallback + window-open handling to any
// window (main or feature). Permission handlers live on the shared session.
function wireWindowNav(win) {
  win.webContents.setWindowOpenHandler(makeWindowOpenHandler(win));

  win.webContents.on('will-navigate', (event, url) => {
    if (!isAppOrigin(url) && !url.startsWith('file:')) {
      event.preventDefault();
      if (/^https?:/i.test(url)) shell.openExternal(url);
    }
  });

  win.webContents.on('did-fail-load', (event, errorCode, errorDesc, validatedURL, isMainFrame) => {
    if (!isMainFrame) return;
    if (errorCode === -3) return; // ERR_ABORTED (in-page nav etc.)
    showFallback(win, validatedURL);
  });

  // Games-style fullscreen escape hatch (MANDATORY): F11 toggles fullscreen and
  // Esc exits it at the MAIN-PROCESS level, so a user can never be trapped with
  // the taskbar/Start button hidden even if the renderer button is broken or
  // off-screen. Handled here (before-input-event) so it works in every window.
  win.webContents.on('before-input-event', (event, input) => {
    if (input.type !== 'keyDown') return;
    if (input.key === 'F11') {
      event.preventDefault();
      try { win.setFullScreen(!win.isFullScreen()); } catch (e) { /* non-fatal */ }
    } else if (input.key === 'Escape' && win.isFullScreen()) {
      event.preventDefault();
      try { win.setFullScreen(false); } catch (e) { /* non-fatal */ }
    }
  });

  // Reflect the REAL fullscreen state back to the renderer button (covers the
  // panel toggle, tray toggle, F11/Esc, and any OS-driven change), and re-push
  // it after each (re)load so the button label is right on Ctrl+R / offline retry.
  const notifyFullscreen = () => {
    try { win.webContents.send('att:fullscreen-changed', win.isFullScreen()); } catch (e) { /* non-fatal */ }
  };
  win.on('enter-full-screen', notifyFullscreen);
  win.on('leave-full-screen', notifyFullscreen);
  win.webContents.on('did-finish-load', notifyFullscreen);
}

// Permission allowlist for the shared app session (set once; all windows on the
// PARTITION share it): notifications + clipboard for the app origin only.
function setupSession() {
  const ses = session.fromPartition(PARTITION);
  const allowed = ['notifications', 'clipboard-read', 'clipboard-sanitized-write'];
  ses.setPermissionRequestHandler((webContents, permission, callback, details) => {
    const originOk = details && details.requestingUrl
      ? isAppOrigin(details.requestingUrl)
      : (webContents ? isAppOrigin(webContents.getURL()) : false);
    callback(allowed.includes(permission) && originOk);
  });
  ses.setPermissionCheckHandler((webContents, permission, requestingOrigin) => {
    return allowed.includes(permission) && isAppOrigin(requestingOrigin);
  });
}

// Track a feature window: apply saved maximize, persist bounds/open, dedupe.
function registerFeatureWindow(win, id) {
  featureWindows.set(id, win);
  saveFeatureWindowState(id, { open: true });

  const st = featureWindowState(id);
  if (st.bounds && st.bounds.maximized) win.maximize();

  wireWindowNav(win);

  // Re-push the update state after every (re)load so a pop-out opened AFTER an
  // update was already downloaded (or reloaded via Ctrl+R) still shows the bar —
  // the preload starts each load with a hidden bar.
  win.webContents.on('did-finish-load', pushUpdateState);
  win.webContents.on('did-finish-load', () => pushZoom(win, id));

  const persistBounds = () => {
    if (!win || win.isDestroyed()) return;
    // Same guard as the main window: never capture whole-screen bounds while a
    // pop-out is fullscreened (F11), or they'd clobber its real windowed size.
    if (win.isFullScreen()) return;
    if (win.isMaximized()) {
      saveFeatureWindowState(id, {
        bounds: Object.assign({}, featureWindowState(id).bounds, { maximized: true }),
      });
    } else {
      const b = win.getBounds();
      saveFeatureWindowState(id, {
        bounds: { x: b.x, y: b.y, width: b.width, height: b.height, maximized: false },
      });
    }
  };
  win.on('resize', persistBounds);
  win.on('move', persistBounds);
  win.on('maximize', persistBounds);
  win.on('unmaximize', persistBounds);

  // A user-closed feature window must NOT reopen next launch; but on app quit we
  // keep open:true so the whole arrangement is restored. isQuitting tells them
  // apart. Feature windows never minimize to tray — default close destroys them.
  win.on('close', () => {
    if (!isQuitting) saveFeatureWindowState(id, { open: false });
  });
  win.on('closed', () => {
    if (featureWindows.get(id) === win) featureWindows.delete(id);
  });
}

// Create a feature window directly (used to reopen saved windows on launch).
function createFeatureWindow(id) {
  const existing = featureWindows.get(id);
  if (existing && !existing.isDestroyed()) {
    if (existing.isMinimized()) existing.restore();
    existing.show();
    existing.focus();
    return;
  }
  const win = new BrowserWindow(featureWindowOptions(featureWindowState(id).bounds));
  registerFeatureWindow(win, id);
  win.loadURL(APP_URL + '/?feature=' + id).catch(() => showFallback(win, APP_URL + '/?feature=' + id));
}

// On launch, reopen every feature window that was open when the app last quit.
function reopenFeatureWindows() {
  const fw = loadSettings().featureWindows || {};
  Object.keys(fw).forEach((id) => {
    if ((FEATURE_IDS.includes(id) || SECTION_FEATURE_IDS.includes(id) || isScratchFeatureId(id)) && fw[id] && fw[id].open) createFeatureWindow(id);
  });
}

// ---------------------------------------------------------------------------
// Network proxy (desktop-only; routes ALL app traffic through a local proxy)
// ---------------------------------------------------------------------------
// A user in a geo-blocked region can point the whole desktop app at a local
// SOCKS5/HTTP proxy (e.g. a Shadowsocks client at 127.0.0.1:2080). This is the
// clean fix for the browser-direct Phemex market-data WebSocket (Terminal DOM),
// which a plain browser page cannot tunnel but Electron can via the session
// proxy. Applied to BOTH the app-partition session (all windows) AND the default
// session (the auto-updater uses that one). socks5:// resolves DNS remotely (the
// local DNS may be blocked too); bypass rules are left empty so nothing skips the
// tunnel (Chromium auto-excludes loopback, so reaching the proxy itself is safe).
// No proxy authentication: Chromium has no SOCKS auth and a local client needs none.
const PROXY_SCHEMES = ['socks5', 'http'];

// Normalized, validated view of the persisted proxy config, or null if none/bad.
function getProxyConfig() {
  const p = loadSettings().proxy;
  if (!p || typeof p !== 'object') return null;
  const scheme = String(p.scheme || '').toLowerCase();
  const host = String(p.host || '').trim();
  const port = Number(p.port);
  if (!PROXY_SCHEMES.includes(scheme)) return null;
  if (!host) return null;
  if (!Number.isInteger(port) || port < 1 || port > 65535) return null;
  return { enabled: !!p.enabled, scheme, host, port };
}

// Renderer/tray-safe view of the current state. No secrets exist here (SOCKS auth
// is intentionally unsupported), so this is simply the full config.
function publicProxyState() {
  const cfg = getProxyConfig();
  if (!cfg) return { enabled: false, scheme: 'socks5', host: '', port: null };
  return { enabled: cfg.enabled, scheme: cfg.scheme, host: cfg.host, port: cfg.port };
}

// Validate a renderer-supplied config. Never trust a raw proxy-rules string from
// the page — accept only {scheme, host, port} and build the rules ourselves.
function normalizeProxyInput(input) {
  if (!input || typeof input !== 'object') throw new Error('bad input');
  const scheme = String(input.scheme || '').toLowerCase();
  if (!PROXY_SCHEMES.includes(scheme)) throw new Error('scheme');
  const host = String(input.host || '').trim();
  if (!host || /[\s/@]/.test(host)) throw new Error('host');
  const port = Number(input.port);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('port');
  return { enabled: true, scheme, host, port };
}

function proxyRulesFromConfig(cfg) {
  return cfg.scheme + '://' + cfg.host + ':' + cfg.port;
}

function proxyTargetSessions() {
  const list = [];
  try { list.push(session.defaultSession); } catch (e) { /* non-fatal */ }
  try { list.push(session.fromPartition(PARTITION)); } catch (e) { /* non-fatal */ }
  return list;
}

// Apply (or clear) the proxy on every session. Called once BEFORE the first
// window loads and again on every runtime change.
async function applyProxyToSessions(cfg) {
  const rules = (cfg && cfg.enabled) ? proxyRulesFromConfig(cfg) : '';
  for (const ses of proxyTargetSessions()) {
    try {
      if (rules) await ses.setProxy({ proxyRules: rules, proxyBypassRules: '' });
      else await ses.setProxy({ mode: 'direct' });
    } catch (e) { /* non-fatal */ }
  }
}

// Reload every live window so its connections (incl. WebSockets) re-open through
// the new proxy. A window sitting on the offline fallback is sent back to the app.
function reloadAllWindows() {
  const wins = [mainWindow, ...featureWindows.values()].filter((w) => w && !w.isDestroyed());
  wins.forEach((w) => {
    try {
      const url = w.webContents.getURL();
      if (url && url.startsWith('file:')) w.loadURL(APP_URL).catch(() => {});
      else w.webContents.reloadIgnoringCache();
    } catch (e) { /* non-fatal */ }
  });
}

// Persist + apply + drop connections + reload. `cfg.enabled` decides whether the
// saved host/port is activated or just turned off (host/port are kept so a later
// Enable works without re-typing).
async function setProxyAndReconnect(cfg) {
  saveSettings({ proxy: cfg });
  await applyProxyToSessions(cfg && cfg.enabled ? cfg : null);
  for (const ses of proxyTargetSessions()) {
    try { await ses.closeAllConnections(); } catch (e) { /* non-fatal */ }
  }
  reloadAllWindows();
  refreshTrayMenu();
}

// Pre-flight reachability probe: a raw, direct TCP connect to the proxy host:port
// (NOT through any session proxy — net.createConnection ignores Electron proxies),
// so we learn whether the local proxy client is actually listening BEFORE we apply
// and reload every window into a possible black-out. Never throws. Returns:
//   { reachable: true }                    — connected within the timeout
//   { reachable: false, definitive: true } — nothing listening / bad address
//   { reachable: false, definitive: false } — no clear answer (slow / timed out)
// A non-definitive result must be treated as fail-open by callers (a working-but-
// slow proxy is never blocked).
function proxyTcpProbe(host, port, timeoutMs) {
  return new Promise((resolve) => {
    let done = false;
    let sock = null;
    const finish = (res) => {
      if (done) return;
      done = true;
      try { if (sock) sock.destroy(); } catch (e) { /* non-fatal */ }
      resolve(res);
    };
    try {
      sock = net.createConnection({ host: host, port: port });
    } catch (e) {
      resolve({ reachable: false, definitive: false });
      return;
    }
    sock.setTimeout(timeoutMs > 0 ? timeoutMs : 2500);
    sock.once('connect', () => finish({ reachable: true, definitive: true }));
    sock.once('timeout', () => finish({ reachable: false, definitive: false }));
    sock.once('error', (err) => {
      const code = (err && err.code) || '';
      // These mean the target is genuinely unreachable (nothing listening / the
      // host or address is bad) — a definitive "your proxy isn't there". Anything
      // else (transient network hiccup) stays inconclusive → fail-open.
      const definitive = ['ECONNREFUSED', 'EHOSTUNREACH', 'ENOTFOUND', 'EADDRNOTAVAIL', 'ENETUNREACH'].includes(code);
      finish({ reachable: false, definitive: definitive });
    });
  });
}

// IPC sender gate: only a top-level frame on the app origin may get/set; the
// file:// offline fallback may additionally clear (its "Disable proxy & retry").
function proxySenderKind(event) {
  try {
    const f = event.senderFrame;
    if (!f || f.parent) return null; // must be a top-level frame
    const url = String(f.url || '');
    if (isAppOrigin(url)) return 'app';
    if (url.startsWith('file:')) return 'fallback';
  } catch (e) { /* non-fatal */ }
  return null;
}

ipcMain.handle('att:proxy-get', (event) => {
  if (!proxySenderKind(event)) return null;
  return publicProxyState();
});

ipcMain.handle('att:proxy-set', async (event, input) => {
  if (proxySenderKind(event) !== 'app') return { ok: false, error: 'forbidden' };
  let cfg;
  try { cfg = normalizeProxyInput(input); } catch (e) { return { ok: false, error: 'invalid' }; }
  await setProxyAndReconnect(cfg);
  return { ok: true, proxy: publicProxyState() };
});

// Pre-flight reachability check the panel runs BEFORE saving/enabling a proxy, so
// a typo or a stopped local proxy client is caught up front instead of dumping
// the user onto the offline screen. Direct TCP connect, short timeout. The result
// is advisory only — the panel still lets the user apply on an inconclusive check.
ipcMain.handle('att:proxy-test', async (event, input) => {
  if (proxySenderKind(event) !== 'app') return { ok: false, error: 'forbidden' };
  let cfg;
  try { cfg = normalizeProxyInput(input); } catch (e) { return { ok: false, error: 'invalid' }; }
  const res = await proxyTcpProbe(cfg.host, cfg.port, 2500);
  return {
    ok: true,
    reachable: !!res.reachable,
    definitive: !!res.definitive,
    host: cfg.host,
    port: cfg.port,
  };
});

ipcMain.handle('att:proxy-clear', async (event) => {
  const kind = proxySenderKind(event);
  if (kind !== 'app' && kind !== 'fallback') return { ok: false, error: 'forbidden' };
  const cur = getProxyConfig();
  const next = cur
    ? { enabled: false, scheme: cur.scheme, host: cur.host, port: cur.port }
    : { enabled: false };
  await setProxyAndReconnect(next);
  return { ok: true, proxy: publicProxyState() };
});

// Tray escape hatches: enable the saved config, disable it, or open the settings
// card in the panel. These stay available even when a bad proxy blacks out all
// network traffic, so the user is never permanently locked out.
function trayEnableProxy() {
  const cfg = getProxyConfig();
  if (!cfg || !cfg.host) { openProxySettings(); return; }
  setProxyAndReconnect({ enabled: true, scheme: cfg.scheme, host: cfg.host, port: cfg.port });
}

function trayDisableProxy() {
  const cur = getProxyConfig();
  const next = cur
    ? { enabled: false, scheme: cur.scheme, host: cur.host, port: cur.port }
    : { enabled: false };
  setProxyAndReconnect(next);
}

function openProxySettings() {
  if (!mainWindow) createWindow();
  if (mainWindow && !mainWindow.isDestroyed()) {
    if (!mainWindow.isVisible()) mainWindow.show();
    if (mainWindow.isMinimized()) mainWindow.restore();
    mainWindow.focus();
    try { mainWindow.webContents.send('att:proxy-open-settings'); } catch (e) { /* non-fatal */ }
  }
}

// ---------------------------------------------------------------------------
// Auto-update (electron-updater; NSIS installer builds only)
// ---------------------------------------------------------------------------
// The portable exe cannot self-update (there is nothing installed to replace),
// and unpackaged dev runs have no update feed — both are silently skipped.
// Failures (feed unreachable, placeholder repo, offline) are swallowed: the
// shell must never bother the user because an update check failed.
function isPortableBuild() {
  return !!process.env.PORTABLE_EXECUTABLE_DIR;
}

function updatesSupported() {
  return !!autoUpdater && app.isPackaged && !isPortableBuild();
}

function setupAutoUpdater() {
  if (!updatesSupported()) {
    updateStatus = 'disabled';
    return;
  }

  autoUpdater.autoDownload = true;
  autoUpdater.autoInstallOnAppQuit = true; // silent: installs on next quit
  autoUpdater.allowPrerelease = false;
  // Force FULL, sha512-verified downloads (electron-updater always verifies the
  // finished file against latest.yml). Differential/blockmap patching can splice
  // a corrupt installer from a stale/mismatched blockmap — the exact class of
  // failure that bricked an install ("old removed, new not installed"). A full
  // download is a few MB more but can never assemble a bad setup.exe.
  autoUpdater.disableDifferentialDownload = true;

  // Optional feed override from settings.json, e.g.
  //   { "updateFeed": { "provider": "github", "owner": "me", "repo": "att-releases" } }
  // Lets the owner repoint an already-shipped build without rebuilding.
  const s = loadSettings();
  if (s.updateFeed && typeof s.updateFeed === 'object') {
    try {
      autoUpdater.setFeedURL(s.updateFeed);
    } catch (e) {
      // bad override — fall back to the baked-in feed
    }
  }

  autoUpdater.on('checking-for-update', () => {
    updateStatus = 'checking';
    refreshTrayMenu();
    pushUpdateState();
  });
  autoUpdater.on('update-available', (info) => {
    updateStatus = 'downloading';
    updateInFlight = true;
    updateVersion = info && info.version ? info.version : null;
    refreshTrayMenu();
    pushUpdateState();
  });
  autoUpdater.on('update-not-available', () => {
    updateStatus = 'idle';
    updateInFlight = false;
    updateVersion = null;
    refreshTrayMenu();
    pushUpdateState();
  });
  autoUpdater.on('update-downloaded', (info) => {
    updateStatus = 'ready';
    updateInFlight = false;
    updateVersion = info && info.version ? info.version : updateVersion;
    refreshTrayMenu();
    pushUpdateState();
    if (tray) {
      try {
        tray.setToolTip("A Trader's Tool — update ready (installs on quit)");
      } catch (e) { /* non-fatal */ }
    }
  });
  autoUpdater.on('error', () => {
    // A bare check-for-update hiccup (feed briefly unreachable) stays silent so a
    // transient network blip never nags the user — the web app keeps working. But
    // once an update is in flight (found + downloading), a failure is a genuine
    // dead-end risk, so surface the non-blocking manual-recovery bar.
    if (updateInFlight) {
      updateStatus = 'error';
      updateInFlight = false;
    } else {
      updateStatus = 'idle';
    }
    refreshTrayMenu();
    pushUpdateState();
  });

  checkForUpdatesQuiet();
  // Re-check every hour while the app stays running in the tray.
  setInterval(checkForUpdatesQuiet, 60 * 60 * 1000);

  // Also check when any window gains focus, throttled to at most once per ~10min
  // so hopping between windows doesn't spam the GitHub feed. checkForUpdatesQuiet
  // already early-returns while downloading/ready, so an in-flight download is
  // never restarted.
  app.on('browser-window-focus', () => {
    raiseAppWindows(BrowserWindow.getFocusedWindow());
    if (Date.now() - lastCheckTs < 10 * 60 * 1000) return;
    checkForUpdatesQuiet();
  });
}

function checkForUpdatesQuiet() {
  if (!updatesSupported()) return;
  if (updateStatus === 'downloading' || updateStatus === 'ready') return;
  lastCheckTs = Date.now();
  // Rejections here are handled by the autoUpdater 'error' event (which decides,
  // via updateInFlight, whether to stay silent or surface recovery). Swallow so
  // an unhandled rejection can't crash the shell; don't set state here.
  try {
    autoUpdater.checkForUpdates().catch(() => {});
  } catch (e) { /* non-fatal — 'error' event covers state */ }
}

function updateMenuLabel() {
  if (!updatesSupported()) return null;
  switch (updateStatus) {
    case 'checking': return 'Checking for updates…';
    case 'downloading': return 'Downloading update' + (updateVersion ? ' ' + updateVersion : '') + '…';
    case 'ready': return 'Restart to update' + (updateVersion ? ' to ' + updateVersion : '');
    default: return 'Check for updates';
  }
}

// Push the current update state to EVERY live window's renderer (main window +
// all feature pop-outs). Each preload builds/toggles the slim top "Update
// available" bar generically, so a user working only in a pop-out still sees it.
// Guarded so a destroyed/absent window is a safe no-op.
function pushUpdateState() {
  const payload = { status: updateStatus, version: updateVersion };
  const wins = [mainWindow, ...featureWindows.values()];
  wins.forEach((win) => {
    if (!win || win.isDestroyed()) return;
    try {
      win.webContents.send('att:update-state', payload);
    } catch (e) { /* non-fatal */ }
  });
}

// macOS-style app activation: when ANY app window gains focus (i.e. the user
// returns to the app from another program), raise every OTHER open app window to
// the foreground so the whole monitoring layout surfaces together, above other
// apps. moveTop() changes z-order WITHOUT stealing focus or activating a window,
// so within-app ordering is preserved (the clicked/focused window stays frontmost
// and keeps focus; the siblings sit right behind it). This does NOT reintroduce
// the pre-#192 owner/pinning relationship — windows remain independently movable;
// we only lift them together on activation.
//
// Minimized or hidden (tray) windows the user deliberately tucked away are left
// as-is — only already-visible windows are raised. Guarded against re-entrancy
// and wrapped in try/catch so a windowing error can never crash the shell.
function raiseAppWindows(focused) {
  if (raisingWindows) return;
  raisingWindows = true;
  try {
    const wins = [mainWindow, ...featureWindows.values()].filter(
      (w) => w && !w.isDestroyed()
    );
    wins.forEach((w) => {
      if (w === focused) return;
      if (!w.isVisible() || w.isMinimized()) return;
      try { w.moveTop(); } catch (e) { /* non-fatal */ }
    });
    // Ensure the focused window ends on top of the freshly-raised siblings.
    if (focused && !focused.isDestroyed()) {
      try { focused.moveTop(); } catch (e) { /* non-fatal */ }
    }
  } catch (e) {
    // never let a windowing hiccup crash the shell
  } finally {
    raisingWindows = false;
  }
}

// The in-window bar's click routes here. Only a fully downloaded update can be
// installed (quitAndInstall is invalid before that) — any other state no-ops.
ipcMain.handle('att:install-update', () => {
  if (updateStatus !== 'ready' || !autoUpdater) return false;
  isQuitting = true;
  try {
    autoUpdater.quitAndInstall(true, true);
  } catch (e) {
    app.quit(); // installs on quit via autoInstallOnAppQuit
  }
  return true;
});

// Manual-recovery escape hatch: the in-window error bar routes here so a failed
// auto-update never dead-ends a user — one click opens the releases page in the
// browser where they can grab the latest setup.exe / portable exe by hand.
ipcMain.handle('att:open-releases', () => {
  try {
    shell.openExternal(RELEASES_URL);
    return true;
  } catch (e) {
    return false;
  }
});

// A window reports its zoom factor on every change; persist it under that
// window's id (main → settings.zoom, feature → featureWindows[id].zoom) so it
// survives restart/update/PC-restart. Unknown senders are ignored.
ipcMain.on('att:zoom-changed', (event, factor) => {
  const id = windowIdForSender(event.sender);
  if (id === undefined) return;
  saveZoomFor(id, factor);
});

// ---------------------------------------------------------------------------
// Restart + games-style fullscreen (renderer bridge → window.attApp)
// ---------------------------------------------------------------------------
// The bridge exposes only parameterless/boolean calls; the main process owns all
// behavior (no renderer-supplied data). Fullscreen acts on the SENDER's window
// (default main), so a feature pop-out toggles itself.
function senderWindow(event) {
  try {
    const w = BrowserWindow.fromWebContents(event.sender);
    if (w && !w.isDestroyed()) return w;
  } catch (e) { /* non-fatal */ }
  return mainWindow;
}

// Restart the whole app cleanly. isQuitting is flipped first so the main
// window's close handler / feature-window bookkeeping behave as on a normal quit
// (arrangement restored on relaunch).
ipcMain.handle('att:app-restart', () => {
  isQuitting = true;
  try { app.relaunch(); } catch (e) { /* non-fatal */ }
  app.quit();
  return true;
});

// setFullScreen(true) on Windows gives borderless fullscreen that COVERS the
// taskbar/Start button — the games-style behavior requested. Returns the new
// state so the button can update immediately (the enter/leave events also fire).
ipcMain.handle('att:toggle-fullscreen', (event) => {
  const win = senderWindow(event);
  if (!win || win.isDestroyed()) return false;
  const next = !win.isFullScreen();
  try { win.setFullScreen(next); } catch (e) { return win.isFullScreen(); }
  return next;
});

ipcMain.handle('att:get-fullscreen', (event) => {
  const win = senderWindow(event);
  return !!(win && !win.isDestroyed() && win.isFullScreen());
});

// ---------------------------------------------------------------------------
// Window
// ---------------------------------------------------------------------------
function createWindow() {
  const settings = loadSettings();
  const bounds = settings.bounds || {};

  mainWindow = new BrowserWindow({
    width: bounds.width || 1400,
    height: bounds.height || 900,
    x: bounds.x,
    y: bounds.y,
    minWidth: 900,
    minHeight: 600,
    autoHideMenuBar: true,
    backgroundColor: '#0d1117',
    icon: path.join(__dirname, 'assets', 'icon.png'),
    title: "A Trader's Tool — v" + app.getVersion(),
    webPreferences: {
      partition: PARTITION,
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      spellcheck: false,
    },
  });

  if (bounds.maximized) mainWindow.maximize();
  // Fullscreen is a SESSION-ONLY toggle (F11 / Esc / tray) — deliberately NOT
  // persisted or auto-restored. Auto-restoring it on every launch trapped users
  // who toggled it once into always-fullscreen; the window must instead reopen
  // where it last was (bounds/maximize above). Any stale `fullscreen` flag left
  // in an older settings.json is simply ignored now.

  // The loaded panel sets its own document.title, which would override the
  // BrowserWindow title. Re-append the build version on every page-title change
  // so the main window's title bar always shows the running version.
  mainWindow.webContents.on('page-title-updated', (event, pageTitle) => {
    event.preventDefault();
    mainWindow.setTitle(pageTitle + ' — v' + app.getVersion());
  });

  // Re-push the update state after every (re)load so a Ctrl+R / offline-retry
  // re-shows the bar if an update is still pending (the preload is rebuilt on
  // each load and starts with a hidden bar).
  mainWindow.webContents.on('did-finish-load', pushUpdateState);
  mainWindow.webContents.on('did-finish-load', () => pushZoom(mainWindow, null));

  // Shared window-open handler (feature pop-outs + same-window app nav + external
  // links), navigation origin lock, and offline fallback. Permission handlers
  // live on the shared session (setupSession, called once at startup).
  wireWindowNav(mainWindow);

  // A ?feature=<id> window.open from the panel spawns a new window; register it
  // as a managed feature window (bounds persistence, dedupe, reopen-on-launch).
  mainWindow.webContents.on('did-create-window', (childWindow, details) => {
    const id = featureIdFromUrl(details && details.url ? details.url : '');
    if (id) registerFeatureWindow(childWindow, id);
  });

  // Persist bounds
  const persistBounds = () => {
    if (!mainWindow) return;
    // Never capture bounds while fullscreen — they'd be the whole-screen size and
    // would clobber the user's real windowed position/size for the next launch.
    if (mainWindow.isFullScreen()) return;
    if (mainWindow.isMaximized()) {
      saveSettings({ bounds: Object.assign({}, loadSettings().bounds, { maximized: true }) });
    } else {
      const b = mainWindow.getBounds();
      saveSettings({ bounds: { x: b.x, y: b.y, width: b.width, height: b.height, maximized: false } });
    }
  };
  mainWindow.on('resize', persistBounds);
  mainWindow.on('move', persistBounds);
  mainWindow.on('maximize', persistBounds);
  mainWindow.on('unmaximize', persistBounds);

  // Closing the main window quits the whole app (and every feature window with
  // it). isQuitting is flipped first so feature windows keep open:true and the
  // whole arrangement is restored on the next launch.
  mainWindow.on('close', () => {
    isQuitting = true;
    app.quit();
  });

  mainWindow.on('closed', () => {
    mainWindow = null;
  });

  mainWindow.loadURL(APP_URL).catch(() => showFallback(mainWindow));
}

// ---------------------------------------------------------------------------
// Tray
// ---------------------------------------------------------------------------
function buildTrayMenu() {
  const loginSettings = app.getLoginItemSettings();

  const updateLabel = updateMenuLabel();
  const updateItems = updateLabel
    ? [
        {
          label: updateLabel,
          enabled: updateStatus !== 'checking' && updateStatus !== 'downloading',
          click: () => {
            if (updateStatus === 'ready') {
              isQuitting = true;
              try {
                autoUpdater.quitAndInstall(true, true);
              } catch (e) {
                app.quit(); // installs on quit via autoInstallOnAppQuit
              }
            } else {
              checkForUpdatesQuiet();
            }
          },
        },
        { type: 'separator' },
      ]
    : [];

  const proxyState = publicProxyState();
  const proxyDesc = proxyState.enabled
    ? (proxyState.scheme + '://' + proxyState.host + ':' + proxyState.port)
    : 'off';
  const proxyItem = {
    label: 'Network proxy',
    submenu: [
      { label: proxyState.enabled ? ('On — ' + proxyDesc) : 'Off', enabled: false },
      { type: 'separator' },
      { label: 'Enable proxy', enabled: !proxyState.enabled, click: () => trayEnableProxy() },
      { label: 'Disable proxy', enabled: proxyState.enabled, click: () => trayDisableProxy() },
      { type: 'separator' },
      { label: 'Proxy settings…', click: () => openProxySettings() },
    ],
  };

  return Menu.buildFromTemplate([
    ...updateItems,
    proxyItem,
    { type: 'separator' },
    {
      label: 'Show / Hide',
      click: () => {
        if (!mainWindow) return;
        if (mainWindow.isVisible() && !mainWindow.isMinimized()) {
          mainWindow.hide();
        } else {
          mainWindow.show();
          mainWindow.focus();
        }
      },
    },
    // Fullscreen toggle + Restart — discoverable here and an extra escape hatch
    // (the tray stays reachable even when fullscreen hides the taskbar).
    {
      label: (mainWindow && !mainWindow.isDestroyed() && mainWindow.isFullScreen())
        ? 'Exit fullscreen' : 'Fullscreen',
      click: () => {
        if (!mainWindow || mainWindow.isDestroyed()) return;
        try { mainWindow.setFullScreen(!mainWindow.isFullScreen()); } catch (e) { /* non-fatal */ }
        refreshTrayMenu();
      },
    },
    {
      label: 'Restart',
      click: () => {
        isQuitting = true;
        try { app.relaunch(); } catch (e) { /* non-fatal */ }
        app.quit();
      },
    },
    { type: 'separator' },
    {
      label: 'Launch on startup',
      type: 'checkbox',
      checked: loginSettings.openAtLogin,
      click: (item) => {
        app.setLoginItemSettings({ openAtLogin: item.checked });
        refreshTrayMenu();
      },
    },
    { type: 'separator' },
    {
      label: 'Quit',
      click: () => {
        isQuitting = true;
        app.quit();
      },
    },
  ]);
}

function refreshTrayMenu() {
  if (tray) tray.setContextMenu(buildTrayMenu());
}

function createTray() {
  const trayIcon = nativeImage.createFromPath(path.join(__dirname, 'assets', 'tray.png'));
  tray = new Tray(trayIcon);
  tray.setToolTip("A Trader's Tool");
  tray.setContextMenu(buildTrayMenu());
  tray.on('double-click', () => {
    if (mainWindow) {
      mainWindow.show();
      mainWindow.focus();
    }
  });
}

// ---------------------------------------------------------------------------
// App lifecycle
// ---------------------------------------------------------------------------
app.whenReady().then(async () => {
  app.setAppUserModelId('com.atraderstool.desktop'); // Windows notifications attribution
  setupSession();
  // Apply the saved proxy BEFORE the first window loads so the initial page load
  // (and the auto-updater on the default session) already goes through the tunnel.
  await applyProxyToSessions(getProxyConfig());
  createWindow();
  reopenFeatureWindows();   // restore feature windows that were open at last quit
  createTray();
  setupAutoUpdater();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('before-quit', () => {
  isQuitting = true;
});

app.on('window-all-closed', () => {
  // Keep alive in tray unless quitting
  if (isQuitting) app.quit();
});
