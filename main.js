'use strict';

const { app, BrowserWindow, Tray, Menu, shell, session, nativeImage, ipcMain, safeStorage } = require('electron');
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
  'indexlast', 'stockarb', 'biglimits', 'screener', 'listings', 'hld',
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
const SECTION_FEATURE_IDS = ['terminal_trades', 'terminal_watchlist', 'terminal_alerts'];
// Sniffing-session + snoop pop-outs (#1794): DYNAMIC id families like scratch —
// sniff_win_<encoded-session-id> (one window per sniffing session) and
// snoop_win_<hash> (one window per snooped wallet+coin). Open-ended families →
// recognized by predicate, kept OUT of FEATURE_IDS. Both are restored at launch
// when open at last quit (a sniff session that no longer exists renders an
// honest "session ended" note the user closes). User-closing ANY window of
// these families deletes its per-id saved state outright (session/wallet ids
// are transient — keeping open:false rows + bounds forever would grow settings
// without bound; see registerFeatureWindow). Lockstep with _sniffPopFid /
// _snoopPopFid + _popoutFeatureId in panel.html.
function isSniffWinFeatureId(f) {
  return typeof f === 'string' && /^sniff_win_[A-Za-z0-9_-]{1,100}$/.test(f);
}
function isSnoopWinFeatureId(f) {
  return typeof f === 'string' && /^snoop_win_[0-9a-f]{8}$/.test(f);
}
function isDynFeatureId(f) {
  return isSniffWinFeatureId(f) || isSnoopWinFeatureId(f);
}
// Backstop cap for the dynamic families: the panel enforces its own cap with a
// user-facing toast BEFORE window.open (localStorage alive roster); this guard
// only refuses runaway window creation if that ever fails.
const DYN_FEATURE_WIN_CAP = 8;
function dynFeatureWinCount() {
  let n = 0;
  for (const [id, w] of featureWindows) {
    if (isDynFeatureId(id) && w && !w.isDestroyed()) n += 1;
  }
  return n;
}

// ---------------------------------------------------------------------------
// Admin-only diagnostic logger (#1786) — see diag_log.js. `diag` stays null
// for regular users (fail closed: settings.diag.admin must ALREADY be true
// from a prior admin session — no role known = no logger, no files). dlog()
// is the zero-overhead guard every call site rides.
// ---------------------------------------------------------------------------
const { createDiagLogger } = require('./diag_log');
let diag = null;
function dlog(win, cat, ev, data) {
  if (diag) diag.log(win, cat, ev, data);
}
function diagDir() {
  return path.join(app.getPath('userData'), 'logs');
}
function diagSettings() {
  const d = loadSettings().diag;
  return (d && typeof d === 'object') ? d : {};
}
// Construct the logger for this launch — ONLY when a prior session proved the
// user is admin AND the toggle isn't off. Toggle changes take effect next
// launch by design (the file covers a whole launch or none of it).
function initDiag() {
  const d = diagSettings();
  if (!(d.admin === true && d.enabled !== false)) return;
  try { diag = createDiagLogger({ dir: diagDir() }); } catch (e) { diag = null; }
}

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
    return (FEATURE_IDS.includes(f) || SECTION_FEATURE_IDS.includes(f) || isScratchFeatureId(f) || isDynFeatureId(f)) ? f : null;
  } catch (e) {
    return null;
  }
}

// Raw ?feature=<id> value from a URL when the id is NOT in the known sets above.
// Used ONLY by the user-initiated window.open path (makeWindowOpenHandler) so a
// panel feature added AFTER this shell version shipped still opens as a real
// standalone window instead of replacing the window the user clicked from.
// Reopen-on-launch (reopenFeatureWindows) deliberately does NOT use this — it
// filters on the known id sets, so an unknown id is never spawned unprompted at
// boot. The id shape is sanity-checked because it becomes a settings key.
function rawFeatureIdFromUrl(url) {
  try {
    const f = new URL(url).searchParams.get('feature');
    return (typeof f === 'string' && /^[A-Za-z0-9_-]{1,64}$/.test(f)) ? f : null;
  } catch (e) {
    return null;
  }
}

// Delete a feature window's saved record entirely (dynamic-family ids only —
// per-session ids must not pile up as dead settings rows; #1794).
function removeFeatureWindowState(id) {
  const cur = loadSettings();
  const fw = Object.assign({}, cur.featureWindows || {});
  delete fw[id];
  saveSettings({ featureWindows: fw });
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

// Diag window tag for a BrowserWindow: 'main', a feature id, or 'wc<N>'.
function diagWinId(win) {
  if (win === mainWindow) return 'main';
  for (const [id, w] of featureWindows.entries()) {
    if (w === win) return id;
  }
  try { return 'wc' + win.webContents.id; } catch (e) { return 'win'; }
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

// Windows-only overlay title bar (#1793): titleBarStyle 'hidden' +
// titleBarOverlay keeps the NATIVE min/max/close caption buttons (drawn by the
// OS, double-click-to-maximize etc. all native) while letting the page own the
// rest of the bar — the panel renders a slim drag strip with an in-bar Restart
// button (windowControlsOverlay API). Other platforms keep the fully native
// frame exactly as before (empty object = zero change), and pages that don't
// render a strip (login, offline fallback) carry their own CSS drag region.
const TITLEBAR_OVERLAY_HEIGHT = 32;
function titleBarOpts() {
  if (process.platform !== 'win32') return {};
  return {
    titleBarStyle: 'hidden',
    titleBarOverlay: { color: '#0d1117', symbolColor: '#c9d1d9', height: TITLEBAR_OVERLAY_HEIGHT },
  };
}

// BrowserWindow options shared by every feature window (same login partition,
// security + look as the main window). `bounds` seeds size/position.
function featureWindowOptions(bounds) {
  const b = bounds || {};
  return {
    ...titleBarOpts(),
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
      // Terminal pop-outs run live DOM boards/charts on secondary monitors —
      // Chromium must never throttle their rAF/timers when the window is
      // occluded or unfocused (the main window keeps the default: throttling
      // an occluded main window is desirable battery behavior, and the rAF
      // loop already gates on document.hidden panel-side).
      backgroundThrottling: false,
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
          // Deep-linked reopen (e.g. sniff-row 📊 → ?feature=hld&hv=…&haddr=…&hcoin=…):
          // re-navigate the EXISTING window to the new URL so clicking 📊 on a
          // second wallet actually loads it (single window per feature — bounds
          // slot stays unique). A plain ?feature=<id> open (nav ⧉) keeps the old
          // focus-only behavior — no pointless reload of a live window.
          try {
            let extra = false;
            new URL(url).searchParams.forEach((v, k) => { if (k !== 'feature') extra = true; });
            if (extra) loadAppUrl(existing, url);   // #1801: watchdog-armed like any app-origin loadURL
          } catch (e) {}
          if (existing.isMinimized()) existing.restore();
          existing.show();
          existing.focus();
          return { action: 'deny' };
        }
        // Create the feature window on the INDEPENDENT path (no opener/owner
        // relationship) so clicking one window never raises the whole app group
        // above other apps. Deny the window.open so Electron makes no owned child.
        // Pass the FULL url so deep-link params (hv/haddr/hcoin) survive the hop —
        // reopen-on-launch still uses the bare ?feature=<id> URL (no stale wallet).
        // Dynamic sniff/snoop families ride a silent backstop cap (the panel
        // already toasted + refused at its own cap before window.open).
        if (isDynFeatureId(id) && dynFeatureWinCount() >= DYN_FEATURE_WIN_CAP) return { action: 'deny' };
        createFeatureWindow(id, url);
        return { action: 'deny' };
      }
      // FUTURE-PROOFING: an app-origin window.open carrying a ?feature=<id> this
      // shell does NOT recognize (a section/feature the panel added after this
      // version shipped) must STILL open a real standalone window — falling
      // through to same-window navigation would replace the window the user
      // clicked from (the v1.5.15 bug: ?feature=terminal_alerts replaced the
      // Terminal window). Same independent createFeatureWindow path, raw id;
      // reopen-on-launch stays strict, so unknown ids never respawn at boot.
      const rawId = rawFeatureIdFromUrl(url);
      if (rawId) {
        createFeatureWindow(rawId, url);
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

  // Launch-scoped first-load retry budget: a transient failure of the INITIAL
  // document load (e.g. the launch connection storm contending through the
  // user's proxy) self-heals with 1-2 automatic retries before settling on the
  // offline fallback. Cleared on the first successful load, so later failures
  // (Ctrl+R while offline etc.) go straight to the fallback as before.
  win.__firstLoadRetriesLeft = 2;

  win.on('closed', () => clearLoadWatchdog(win));   // #1801

  win.webContents.on('will-navigate', (event, url) => {
    if (!isAppOrigin(url) && !url.startsWith('file:')) {
      event.preventDefault();
      if (/^https?:/i.test(url)) shell.openExternal(url);
    }
  });

  win.webContents.on('did-fail-load', (event, errorCode, errorDesc, validatedURL, isMainFrame) => {
    if (!isMainFrame) return;
    clearLoadWatchdog(win);          // #1801: a definitive result — the stall timer must not fire
    launchGateWinDone(win);          // #1801: this window's first load resolved
    if (errorCode === -3) return; // ERR_ABORTED (in-page nav etc.)
    // First-load retry (launch-scoped, see __firstLoadRetriesLeft above): back
    // off 1s then 2.5s. The fallback page must still appear eventually — after
    // the budget is spent this falls through to showFallback (its own escape
    // hatches, incl. "Disable proxy & retry", stay untouched).
    dlog(diagWinId(win), 'win', 'fail-load', { code: errorCode, desc: String(errorDesc || ''), retriesLeft: win.__firstLoadRetriesLeft });
    if (win.__firstLoadRetriesLeft > 0 && isAppOrigin(validatedURL)) {
      win.__firstLoadRetriesLeft -= 1;
      const delay = win.__firstLoadRetriesLeft > 0 ? 1000 : 2500;
      setTimeout(() => {
        if (win.isDestroyed()) return;
        dlog(diagWinId(win), 'win', 'retry-load', { delay });
        loadAppUrl(win, validatedURL);   // #1801: re-arm the stalled-load watchdog on the retry
      }, delay);
      return;
    }
    dlog(diagWinId(win), 'win', 'fallback', {});
    showFallback(win, validatedURL);
  });

  win.webContents.on('did-finish-load', () => {
    clearLoadWatchdog(win);          // #1801
    launchGateWinDone(win);          // #1801
    dlog(diagWinId(win), 'win', 'loaded', {});
  });
  win.webContents.on('render-process-gone', (event, details) => {
    dlog(diagWinId(win), 'win', 'renderer-gone', { reason: details && details.reason, exitCode: details && details.exitCode });
  });

  win.webContents.on('did-finish-load', () => {
    // A successful document load ends the launch retry window.
    win.__firstLoadRetriesLeft = 0;
    maybeReloadLoginRace(win);
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
      return;
    }
    // With the application menu removed (Menu.setApplicationMenu(null)) the
    // default role accelerators are gone, so reload and DevTools are
    // re-registered here explicitly (per window, incl. pop-outs):
    const ctrlOnly = input.control && !input.alt && !input.meta;
    if (ctrlOnly && !input.shift && (input.key === 'r' || input.key === 'R')) {
      event.preventDefault(); // Ctrl+R — normal reload
      try { win.webContents.reload(); } catch (e) { /* non-fatal */ }
    } else if ((ctrlOnly && input.shift && (input.key === 'r' || input.key === 'R')) || input.key === 'F5') {
      event.preventDefault(); // Ctrl+Shift+R / F5 — hard reload
      try { win.webContents.reloadIgnoringCache(); } catch (e) { /* non-fatal */ }
    } else if (input.key === 'F12' || (ctrlOnly && input.shift && (input.key === 'i' || input.key === 'I'))) {
      event.preventDefault(); // F12 / Ctrl+Shift+I — DevTools
      try { win.webContents.toggleDevTools(); } catch (e) { /* non-fatal */ }
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

  // Native-WS teardown: any (re)load orphans the shim's socket ids in the old
  // renderer, so drop every native socket this webContents owns on load-start and
  // on destroy. did-start-loading fires on Ctrl+R / offline-retry / proxy-reload
  // (a no-op on the very first load, when nothing is open yet).
  const wcId = win.webContents.id;
  win.webContents.on('did-start-loading', () => closeNativeSocketsFor(wcId));
  win.webContents.on('destroyed', () => closeNativeSocketsFor(wcId));
}

// Belt-and-braces for the cookie-ready race: if a window's first document
// rendered the LOGIN page while the shared session is actually authenticated
// (session cookie present), reload it once — the reload sends the cookie and
// gets the real panel. A genuinely logged-out user has no session cookie, so
// their login page stays untouched in every window. At most ONE reload per
// window, ever (__loginRaceReloaded), so this can never loop.
function maybeReloadLoginRace(win) {
  if (win.__loginRaceReloaded) return;
  let title = '';
  try {
    if (!isAppOrigin(win.webContents.getURL())) return;
    title = win.webContents.getTitle() || '';
  } catch (e) { return; }
  // The login page is the only app page titled "… — Sign in" (login.html).
  if (!/sign in/i.test(title)) return;
  session.fromPartition(PARTITION).cookies.get({ url: APP_URL }).then((cookies) => {
    if (!cookies.some((c) => c.name === 'sid')) return; // really logged out
    win.__loginRaceReloaded = true;
    if (!win.isDestroyed()) win.webContents.reload();
  }).catch(() => { /* non-fatal */ });
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
    if (isQuitting) return;
    // Dynamic-family ids (sniff/snoop, #1794) are transient: a user close
    // deletes the whole saved record (bounds included) instead of keeping
    // open:false rows for session ids that will never come back.
    if (isDynFeatureId(id)) removeFeatureWindowState(id);
    else saveFeatureWindowState(id, { open: false });
  });
  win.on('closed', () => {
    if (featureWindows.get(id) === win) featureWindows.delete(id);
  });
}

// Create a feature window directly (used to reopen saved windows on launch).
// Optional `url` carries a deep-linked open (e.g. ?feature=hld&hv=…&haddr=…);
// launch-reopen never passes one, so restarts load the bare feature page.
// Optional `loadDelayMs` (launch-reopen only) staggers the INITIAL loadURL so a
// many-window launch doesn't fire every document+asset burst simultaneously
// through the proxy; the window itself is created immediately (bounds/position
// appear at once, painted with the app background color until its turn).
function createFeatureWindow(id, url, loadDelayMs) {
  const existing = featureWindows.get(id);
  if (existing && !existing.isDestroyed()) {
    if (existing.isMinimized()) existing.restore();
    existing.show();
    existing.focus();
    return;
  }
  const win = new BrowserWindow(featureWindowOptions(featureWindowState(id).bounds));
  registerFeatureWindow(win, id);
  dlog(id, 'win', 'create', { delayed: typeof loadDelayMs === 'number' && loadDelayMs > 0 });
  const target = (url && isAppOrigin(url)) ? url : (APP_URL + '/?feature=' + id);
  launchGateTrack(win);   // #1801: no-op unless a proxied launch closed the gate
  const doLoad = () => {
    if (win.isDestroyed()) return;
    loadAppUrl(win, target);
  };
  if (typeof loadDelayMs === 'number' && loadDelayMs > 0) setTimeout(doLoad, loadDelayMs);
  else doLoad();
}

// ---------------------------------------------------------------------------
// Documents-first launch gate (#1801, proxy black-windows fix)
// ---------------------------------------------------------------------------
// With the session proxy ENABLED, a many-window launch + all-tab hydration
// opens a huge simultaneous burst of exchange websockets through one SOCKS
// tunnel; Chromium caps sockets per proxy, so the other windows' DOCUMENT
// fetches queue behind long-lived WS forever → black windows with no
// did-fail-load. Fix: the panel's heavy connection ramp (all-tab hydration)
// waits until every launch-reopened window has fired did-finish-load /
// did-fail-load (or a timeout), signalled over the attApp bridge
// (getLaunchGate/onLaunchGate — parameterless/boolean only). Proxy disabled →
// the gate is NEVER closed, so behavior is byte-identical to today.
const LAUNCH_GATE_TIMEOUT_MS = 25000;
let launchGateOpen = true;      // open by default; closed ONLY for a proxied multi-window launch
let launchGateArmed = false;    // true once reopenFeatureWindows finished registering windows
let launchGateTimer = null;
const launchGatePending = new Set();   // BrowserWindows still owing a first load result

function launchGateBroadcast() {
  const wins = [mainWindow, ...featureWindows.values()];
  for (const w of wins) {
    if (w && !w.isDestroyed()) {
      try { w.webContents.send('att:launch-gate'); } catch (e) { /* non-fatal */ }
    }
  }
}

function launchGateRelease(reason) {
  if (launchGateOpen) return;
  launchGateOpen = true;
  if (launchGateTimer) { clearTimeout(launchGateTimer); launchGateTimer = null; }
  dlog('main', 'app', 'launch-gate-open', { reason, pending: launchGatePending.size });
  launchGatePending.clear();
  launchGateBroadcast();
}

// Called from createWindow/createFeatureWindow while the gate is closed and not
// yet armed — i.e. only for the launch-created windows the gate waits on.
function launchGateTrack(win) {
  if (launchGateOpen || launchGateArmed) return;
  launchGatePending.add(win);
  win.on('closed', () => launchGateWinDone(win));
}

// A window's first document load resolved (finish, fail, stall or close).
function launchGateWinDone(win) {
  if (launchGateOpen) return;
  if (!launchGatePending.delete(win)) return;
  if (launchGateArmed && launchGatePending.size === 0) launchGateRelease('all-loaded');
}

// Close the gate BEFORE any window is created (whenReady) so no load event can
// race the registration. Only when the proxy is enabled AND there are saved-open
// feature windows to reopen — otherwise the gate stays open and nothing changes.
function launchGateMaybeClose() {
  const cfg = getProxyConfig();
  if (!cfg || !cfg.enabled) return;
  const fw = loadSettings().featureWindows || {};
  const anyOpen = Object.keys(fw).some((id) =>
    (FEATURE_IDS.includes(id) || SECTION_FEATURE_IDS.includes(id) || isScratchFeatureId(id) || isDynFeatureId(id)) && fw[id] && fw[id].open);
  if (!anyOpen) return;
  launchGateOpen = false;
  dlog('main', 'app', 'launch-gate-close', {});
}

// Arm after reopenFeatureWindows registered every launch window: from here the
// gate opens when the pending set drains (or the timeout fires — a stalled
// window must never hold every OTHER window's feeds hostage forever).
function launchGateArm() {
  if (launchGateOpen) return;
  launchGateArmed = true;
  dlog('main', 'app', 'launch-gate-armed', { windows: launchGatePending.size });
  if (launchGatePending.size === 0) { launchGateRelease('all-loaded'); return; }
  launchGateTimer = setTimeout(() => { launchGateTimer = null; launchGateRelease('timeout'); }, LAUNCH_GATE_TIMEOUT_MS);
}

// ---------------------------------------------------------------------------
// Stalled-load watchdog (#1801 regression guard): through a saturated proxy an
// app-origin document load can hang firing NEITHER did-finish-load NOR
// did-fail-load — the window sits black forever and the fallback page never
// appears. If neither event lands within the budget: diag-log, stop() the load
// and route into the SAME __firstLoadRetriesLeft ladder as a real failure →
// eventually showFallback ("Disable proxy & retry"). Armed only at app-origin
// loadURL calls (never file:// fallback loads, never in-page navs); cleared on
// finish/fail/destroy.
const LOAD_STALL_MS = 25000;

function clearLoadWatchdog(win) {
  if (win.__loadStallT) { clearTimeout(win.__loadStallT); win.__loadStallT = null; }
}

function armLoadWatchdog(win, url) {
  clearLoadWatchdog(win);
  if (!isAppOrigin(url)) return;
  win.__loadStallT = setTimeout(() => {
    win.__loadStallT = null;
    if (win.isDestroyed()) return;
    dlog(diagWinId(win), 'win', 'load-stalled', { retriesLeft: win.__firstLoadRetriesLeft });
    try { win.webContents.stop(); } catch (e) { /* non-fatal */ }
    launchGateWinDone(win);   // a stalled window must not hold the launch gate
    if (win.__firstLoadRetriesLeft > 0) {
      win.__firstLoadRetriesLeft -= 1;
      const delay = win.__firstLoadRetriesLeft > 0 ? 1000 : 2500;
      setTimeout(() => {
        if (win.isDestroyed()) return;
        dlog(diagWinId(win), 'win', 'retry-load', { delay, stalled: true });
        loadAppUrl(win, url);
      }, delay);
      return;
    }
    dlog(diagWinId(win), 'win', 'fallback', { stalled: true });
    showFallback(win, url);
  }, LOAD_STALL_MS);
}

// Every app-origin loadURL goes through here so the stalled-load watchdog is
// armed exactly at loadURL time (file:// fallback loads bypass this on purpose).
function loadAppUrl(win, url) {
  armLoadWatchdog(win, url);
  win.loadURL(url).catch(() => { clearLoadWatchdog(win); showFallback(win, url); });
}

// On launch, reopen every feature window that was open when the app last quit.
// Initial loads are STAGGERED (300ms apart, after the main window's load) so
// the simultaneous first-document + asset/API bursts of many windows don't
// contend through the user's proxy and fail/half-paint (launch-scoped only —
// user-initiated window.open loads immediately as before).
function reopenFeatureWindows() {
  const fw = loadSettings().featureWindows || {};
  let n = 0;
  Object.keys(fw).forEach((id) => {
    if ((FEATURE_IDS.includes(id) || SECTION_FEATURE_IDS.includes(id) || isScratchFeatureId(id) || isDynFeatureId(id)) && fw[id] && fw[id].open) {
      n += 1;
      createFeatureWindow(id, null, 300 * n);
    }
  });
  launchGateArm();   // #1801: gate opens when every reopened window's first load resolves
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

// Per-venue×market Proxy/Direct route (browser transports): the renderer posts
// its set of DIRECT venue|market tokens over att:route-hosts; the pure helper
// derives the Chromium bypass hosts (proxy wins ties on shared hosts — see
// route_hosts.js). Session-scoped state, default empty (= everything proxied).
let routeBypassHosts = [];

// Apply (or clear) the proxy on every session. Called once BEFORE the first
// window loads and again on every runtime change (config OR route change).
async function applyProxyToSessions(cfg) {
  const rules = (cfg && cfg.enabled) ? proxyRulesFromConfig(cfg) : '';
  const bypass = routeBypassHosts.join(',');
  for (const ses of proxyTargetSessions()) {
    try {
      if (rules) await ses.setProxy({ proxyRules: rules, proxyBypassRules: bypass });
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
  // Proxy config is never a secret (no SOCKS auth exists here), but log only
  // scheme/host/port + enabled anyway (design rule).
  dlog('main', 'net', 'proxy-set', cfg ? { enabled: !!cfg.enabled, scheme: cfg.scheme, host: cfg.host, port: cfg.port } : { enabled: false });
  saveSettings({ proxy: cfg });
  await applyProxyToSessions(cfg && cfg.enabled ? cfg : null);
  for (const ses of proxyTargetSessions()) {
    try { await ses.closeAllConnections(); } catch (e) { /* non-fatal */ }
  }
  // Native market-data sockets bypass the Electron session, so closeAllConnections
  // won't drop them — close them explicitly so they re-open through the new agent
  // when each window reloads below.
  closeAllNativeSockets();
  // Destroy every cached keep-alive HTTP(S) agent too (native trading + WS +
  // bullet fetch), so the next request dials through the NEW egress instead of
  // reusing a warm socket through the old proxy. Also covers proxy disable.
  flushKeepAliveAgents();
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

// Per-venue×market Proxy/Direct route for BROWSER transports: the panel posts
// the venue|market combos the user set to Direct; the pure helper derives the
// Chromium bypass hosts (proxy-wins-ties on shared hosts) and the sessions are
// re-stamped in place. Deliberately NO closeAllConnections / reload here — the
// panel resyncs exactly the flipped market's socket itself, so the rest of the
// app (REST, other feeds) never blinks. No-op while the proxy is disabled
// (state is still stored so an Enable picks it up).
ipcMain.handle('att:route-hosts', async (event, tokens) => {
  if (proxySenderKind(event) !== 'app') return { ok: false, error: 'forbidden' };
  routeBypassHosts = bypassHostsFor(tokens);
  const cfg = getProxyConfig();
  if (cfg && cfg.enabled) await applyProxyToSessions(cfg);
  return { ok: true, hosts: routeBypassHosts.slice() };
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

// ---------------------------------------------------------------------------
// Diagnostic-logger IPC (#1786) — role gate + settings toggle + renderer pipe
// ---------------------------------------------------------------------------
// The panel reports the logged-in role after /api/me. Fail closed both ways:
// admin=true only ever set from an authenticated app-origin page's report;
// a non-admin report clears the flag AND stops any live logger immediately.
ipcMain.on('att:diag-role', (event, isAdmin) => {
  if (proxySenderKind(event) !== 'app') return;
  const d = diagSettings();
  if (isAdmin === true) {
    if (d.admin !== true) saveSettings({ diag: Object.assign({}, d, { admin: true }) });
    refreshTrayMenu();   // "Open log folder" appears for admins
  } else {
    if (d.admin === true) saveSettings({ diag: Object.assign({}, d, { admin: false }) });
    if (diag) { try { diag.close(); } catch (e) { /* non-fatal */ } diag = null; }
    refreshTrayMenu();
  }
});

// Settings-card state for the admin-only "Diagnostic logging" toggle.
ipcMain.handle('att:diag-get', (event) => {
  if (proxySenderKind(event) !== 'app') return null;
  const d = diagSettings();
  return {
    admin: d.admin === true,
    enabled: d.enabled !== false,
    active: !!diag,                      // logging THIS launch?
    dir: diagDir(),
  };
});

// Toggle takes effect NEXT launch (a launch's file covers all of it or none).
ipcMain.handle('att:diag-set-enabled', (event, on) => {
  if (proxySenderKind(event) !== 'app') return { ok: false, error: 'forbidden' };
  const d = diagSettings();
  if (d.admin !== true) return { ok: false, error: 'forbidden' };
  saveSettings({ diag: Object.assign({}, d, { enabled: on === true }) });
  dlog('main', 'app', 'diag-toggle', { on: on === true });
  return { ok: true, enabled: on === true };
});

// Renderer/terminal event pipe: the panel posts key events (WS lifecycle,
// REST-failure breadcrumbs, park/hydrate, /state pacing) here. Sanitization +
// per-key rate limiting happen inside diag.log; payload shape is clamped so a
// renderer can never write arbitrary bulk. Silently a no-op when no logger.
ipcMain.on('att:diag-event', (event, payload) => {
  if (!diag) return;
  if (proxySenderKind(event) !== 'app') return;
  if (!payload || typeof payload !== 'object') return;
  const cat = typeof payload.cat === 'string' ? payload.cat : '';
  const ev = typeof payload.ev === 'string' ? payload.ev : '';
  if (!cat || !ev) return;
  let data = (payload.data && typeof payload.data === 'object') ? payload.data : null;
  const wid = windowIdForSender(event.sender);
  const win = wid === null ? 'main' : (typeof wid === 'string' ? wid : 'wc' + event.sender.id);
  diag.log(win, 'r:' + cat, ev, data);
});

function openDiagFolder() {
  try { fs.mkdirSync(diagDir(), { recursive: true }); } catch (e) { /* non-fatal */ }
  try { shell.openPath(diagDir()); } catch (e) { /* non-fatal */ }
}

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
// Native market-data WebSocket bridge (desktop-only)
// ---------------------------------------------------------------------------
// WHY: Binance silently withholds futures @aggTrade from Chromium (browser AND
// Electron renderer) — the socket stays healthy but the trade stream never
// arrives, so the Terminal's tape/cluster fall back to REST polling (visibly
// laggy). A NATIVE client (like Metascalp) gets the stream fine. So we open the
// Binance market-data sockets in the Node MAIN process (a native runtime, not
// Chromium) and pipe frames to the renderer over IPC via a WebSocket-like shim.
//
// SECURITY: the renderer can NEVER open an arbitrary native socket. Every URL is
// validated against a strict allowlist of Binance market-data hosts (wss only),
// and only a top-level frame on the app origin may open/send/close. This mirrors
// the proxy bridge's "never trust renderer-supplied strings" rule.
const WSNative = (() => { try { return require('ws'); } catch (e) { return null; } })();
const https = require('https');
// Pure KuCoin bullet helpers (separate module so they node-unit-test without
// Electron): bullet-response validation + keepalive clamp + dial-URL builder.
const { KC_BULLET_HOSTS, kcBulletParse, kcDialUrl } = require('./kucoin_bullet');
const { nativeProxyUrl } = require('./proxy_url');
const { routeNorm, bypassHostsFor, nativeWsHeadersFor } = require('./route_hosts');
// Shared keep-alive proxy-agent cache lives in trade_native.js so the native
// WS bridge, the KuCoin bullet fetch, and the native trading HTTPS requests
// all reuse ONE warm agent per proxy config (flushed on proxy change below).
const { sharedKeepAliveAgent, flushKeepAliveAgents } = require('./trade_native');

// Strict allowlist: only Terminal market-data WS hosts (Phemex + Binance + Gate), wss
// only. Anything else is refused so the shim can never be turned into an
// arbitrary-socket primitive. The renderer only picks a transport MODE per
// venue — it never supplies arbitrary hosts.
const NATIVE_WS_HOSTS = new Set([
  'ws.phemex.com',              // Phemex spot + USDT-M perp market data
  'fstream.binance.com',        // USDT-M futures combined streams
  'stream.binance.com',         // spot combined streams (:9443)
  'data-stream.binance.com',    // spot market-data mirror
  'nbstream.binance.com',       // Binance Alpha wsa combined streams (WS only — bapi REST stays browser-side)
  'api.gateio.ws',              // Gate spot market data WS (wss only — REST on this host is NOT reachable via this shim)
  'fx-ws.gateio.ws',            // Gate USDT-futures market data WS
  'ws.bitget.com',              // Bitget spot + USDT-M futures market data WS
  'ws.bitmex.com',              // BitMEX realtime WS (spot + USDT-linear perps)
  'api.hyperliquid.xyz',        // Hyperliquid public market-data WS (/ws)
  'stream.bybit.com',           // Bybit v5 public streams (linear + spot; text JSON)
  'ws.okx.com',                 // OKX public WS (:8443 — host match only, port passes)
  'api.arcus.xyz',              // Arcus futures public WS (/v1/ws; text JSON)
  'indexer.spot.arcus.xyz',     // Arcus spot indexer WS (/ws; text JSON)
  'fstream.asterdex.com',       // AsterDex USDT-M futures combined streams (Binance-family, text)
  'sstream.asterdex.com',       // AsterDex spot combined streams (Binance-family, text)
  'contract.mexc.com',          // MEXC futures push WS (/edge; text JSON — spot stays relay-only)
  'wbs-api.mexc.com',           // MEXC spot WS (/ws; protobuf BINARY frames — decoded in the panel)
  'mainnet.zklighter.elliot.ai', // Lighter zk-rollup /stream WS (text JSON; REST stays browser-side per host route rules)
  'ws.kraken.com',              // Kraken spot WS v2 market data (trading REST rides trade_native)
  'futures.kraken.com',         // Kraken futures ws/v1 market data (trading REST rides trade_native)
]);
function nativeWsUrlOk(url) {
  try {
    const u = new URL(String(url || ''));
    if (u.protocol !== 'wss:') return false;
    return NATIVE_WS_HOSTS.has(u.hostname);
  } catch (e) { return false; }
}

// id -> { ws, wcId }. One entry per live native socket, tagged with its owning
// webContents so a reload / navigation / window-close tears down its sockets.
const nativeSockets = new Map();
let nativeSockSeq = 1;

// Build the outbound proxy agent from the SAME persisted desktop proxy config as
// the Chromium session (native sockets bypass Electron's session proxy, so they
// must tunnel themselves). The URL comes from the pure nativeProxyUrl helper
// (socks5 → socks5h so DNS resolves AT the proxy, matching Chromium's remote
// DNS). Returns:
//   { agent: undefined }  — no proxy enabled → direct dialing is fine
//   { agent: <Agent> }    — proxy enabled, agent built → tunnel through it
//   { refuse: true }      — proxy enabled but NO agent could be built (module
//                           missing / constructor threw). Callers must REFUSE
//                           the open ('unavailable') instead of dialing direct:
//                           the renderer shim then fails over to the browser
//                           WebSocket, which rides the Chromium session proxy —
//                           data stays tunneled instead of silently leaking.
function nativeWsAgent() {
  const cfg = getProxyConfig();
  const proxyUrl = nativeProxyUrl(cfg);
  if (!proxyUrl) {
    // Unknown scheme with proxy enabled must also refuse (never dial direct).
    if (cfg && cfg.enabled) return { refuse: true };
    return { agent: undefined };
  }
  // Shared keep-alive agent (trade_native's cache): WS dials + the KuCoin
  // bullet fetch reuse the SAME warm agent as the native trading requests —
  // one SOCKS/TLS handshake per proxy config, not per dial. null → refuse.
  const ag = sharedKeepAliveAgent(cfg.scheme, proxyUrl);
  if (ag) return { agent: ag };
  return { refuse: true };
}

// Route-aware agent pick for one native connection. route comes from the
// renderer, already collapsed by routeNorm(): 'direct' is an EXPLICIT
// per-venue×market user choice to skip the tunnel for market data, so it
// returns a bare { agent: undefined } (no refuse path — direct is the point).
// Anything else behaves exactly like nativeWsAgent() (proxy, fail-closed).
function nativeWsAgentFor(route) {
  if (routeNorm(route) === 'direct') return { agent: undefined };
  return nativeWsAgent();
}

// Only a top-level frame on the app origin may drive native sockets.
function nativeWsSenderOk(event) {
  try {
    const f = event.senderFrame;
    if (!f || f.parent) return false;
    return isAppOrigin(String(f.url || ''));
  } catch (e) { return false; }
}

function closeNativeSocket(id) {
  const rec = nativeSockets.get(id);
  if (!rec) return;
  nativeSockets.delete(id);
  // KuCoin-native sockets carry a main-owned keepalive timer — always stop it.
  if (rec.kaT) { try { clearInterval(rec.kaT); } catch (e) { /* non-fatal */ } rec.kaT = null; }
  const ws = rec.ws;
  // Stop forwarding this socket's frames to the renderer, but keep a no-op
  // 'error' listener attached while we tear it down. Closing/terminating a
  // socket that is still CONNECTING makes `ws` emit an 'error' ("WebSocket was
  // closed before the connection was established"). removeAllListeners() strips
  // the open-time error handler, so without re-attaching one that error would
  // have NO listener and Node re-throws it as an uncaught exception — crashing
  // the whole main process (the exact crash seen when a board is closed or the
  // transport switch live-reconnects before the handshake completes).
  try { ws.removeAllListeners(); } catch (e) { /* non-fatal */ }
  try { ws.on('error', () => { /* swallow teardown-race errors */ }); } catch (e) { /* non-fatal */ }
  try {
    if (ws.readyState === 0 /* CONNECTING */) ws.terminate(); // abort the pending handshake
    else ws.close();
  } catch (e) { /* non-fatal */ }
}

// Tear down every native socket owned by a webContents (reload / nav / close).
function closeNativeSocketsFor(wcId) {
  for (const [id, rec] of nativeSockets.entries()) {
    if (rec.wcId === wcId) closeNativeSocket(id);
  }
}

// Tear down ALL native sockets (proxy change → force a clean reconnect through
// the new agent, mirroring session.closeAllConnections()).
function closeAllNativeSockets() {
  for (const id of Array.from(nativeSockets.keys())) closeNativeSocket(id);
}

// Open a validated native socket. Returns { ok, id } to the shim; frames stream
// back over the per-window 'att:ws-event' channel keyed by id.
ipcMain.handle('att:ws-open', (event, url, route) => {
  if (!WSNative) return { ok: false, error: 'unavailable' };
  if (!nativeWsSenderOk(event)) return { ok: false, error: 'forbidden' };
  if (!nativeWsUrlOk(url)) return { ok: false, error: 'blocked' };
  const wc = event.sender;
  const wcId = wc.id;
  const ag = nativeWsAgentFor(route);
  if (ag.refuse) return { ok: false, error: 'unavailable' };
  const id = nativeSockSeq++;
  let ws;
  try {
    ws = new WSNative(String(url), {
      agent: ag.agent,
      handshakeTimeout: 15000,
      perMessageDeflate: false,
      // Per-host browser-like handshake headers (nbstream bot-walls bare
      // dials on some network paths — see route_hosts.nativeWsHeadersFor).
      headers: nativeWsHeadersFor(url),
    });
  } catch (e) {
    return { ok: false, error: 'open-failed' };
  }
  nativeSockets.set(id, { ws, wcId });
  const emit = (msg) => {
    try { if (!wc.isDestroyed()) wc.send('att:ws-event', msg); } catch (e) { /* non-fatal */ }
  };
  const diagHost = (() => { try { return new URL(String(url)).hostname; } catch (e) { return ''; } })();
  const diagT0 = Date.now();
  ws.on('open', () => { dlog('main', 'ws', 'open', { k: diagHost, id, host: diagHost, ms: Date.now() - diagT0, route: ag.agent ? 'proxy' : 'direct' }); emit({ id, type: 'open' }); });
  // via = the path MAIN actually applied (not what the renderer requested):
  // an agent means the tunnel is really in use; no agent means the dial goes
  // over the plain internet (proxy off / explicit Direct). A refused open
  // never reaches here — the panel's confirmed-transport label reads this.
  const via = { transport: 'native', route: ag.agent ? 'proxy' : 'direct' };
  ws.on('message', (data, isBinary) => {
    // Text feeds forward verbatim as strings. Binary frames (MEXC spot WS
    // is protobuf) forward base64-tagged — the PANEL owns the decode; the
    // shell stays a dumb transport.
    if (isBinary) {
      let b = '';
      try { b = Buffer.from(data).toString('base64'); } catch (e) { return; }
      emit({ id, type: 'message', data: b, binary: true });
      return;
    }
    let s = '';
    try { s = data.toString('utf8'); } catch (e) { return; }
    emit({ id, type: 'message', data: s });
  });
  ws.on('close', (code, reason) => {
    nativeSockets.delete(id);
    let r = '';
    try { r = reason ? reason.toString('utf8') : ''; } catch (e) { r = ''; }
    dlog('main', 'ws', 'close', { k: diagHost, id, host: diagHost, code });
    emit({ id, type: 'close', code: code, reason: r });
  });
  ws.on('error', (err) => {
    dlog('main', 'ws', 'error', { k: diagHost, id, host: diagHost, msg: (err && err.message) || 'error' });
    emit({ id, type: 'error', message: (err && err.message) || 'error' });
  });
  return { ok: true, id, via };
});

// POST the KuCoin bullet-public endpoint through the SAME proxy agent the
// native sockets use (the token dance must originate from the same egress IP
// as the dial or KuCoin may reject the token). Resolves to kcBulletParse's
// verdict; rejects on transport failure/timeout.
function kcBulletFetch(mkt, route) {
  return new Promise((resolve, reject) => {
    const ag = nativeWsAgentFor(route);
    // Proxy enabled but no agent → refuse rather than fetch the bullet direct
    // (a direct bullet + proxied dial mismatch is useless anyway).
    if (ag.refuse) { reject(new Error('proxy-unavailable')); return; }
    const req = https.request(KC_BULLET_HOSTS[mkt] + '/api/v1/bullet-public', {
      method: 'POST',
      agent: ag.agent,
      timeout: 10000,
      headers: { 'content-length': 0 },
    }, (res) => {
      let buf = '';
      res.setEncoding('utf8');
      res.on('data', (d) => { if (buf.length < 65536) buf += d; });
      res.on('end', () => resolve(kcBulletParse(buf)));
    });
    req.on('timeout', () => { try { req.destroy(new Error('timeout')); } catch (e) { /* non-fatal */ } });
    req.on('error', reject);
    req.end();
  });
}

// Open a KuCoin market-data socket the MetaScalp way: main does the
// bullet-public token dance and dials the returned wss endpoint directly.
// The renderer names ONLY the market ('spot'|'futures') — it can never supply
// a URL (the bullet endpoint host varies per token, so the fixed-host
// allowlist can't cover KuCoin; kcBulletParse's wss + *.kucoin.com check is
// the equivalent gate). Frames stream back over the same 'att:ws-event'
// channel; main owns the app-level keepalive (KuCoin drops ~18s-idle sockets)
// and swallows its own natka-* pongs so the renderer's RTT ping stays honest.
ipcMain.handle('att:ws-open-kucoin', async (event, market, route) => {
  if (!WSNative) return { ok: false, error: 'unavailable' };
  if (!nativeWsSenderOk(event)) return { ok: false, error: 'forbidden' };
  const mkt = market === 'futures' ? 'futures' : (market === 'spot' ? 'spot' : null);
  if (!mkt) return { ok: false, error: 'blocked' };
  const wc = event.sender;
  const wcId = wc.id;
  // Proxy enabled but no agent buildable → refuse up front ('unavailable' so
  // the renderer shim fails over to the browser WebSocket, which rides the
  // Chromium session proxy) — never bullet-fetch or dial direct.
  if (nativeWsAgentFor(route).refuse) return { ok: false, error: 'unavailable' };
  let bullet;
  try { bullet = await kcBulletFetch(mkt, route); } catch (e) { return { ok: false, error: 'bullet-failed' }; }
  if (!bullet || !bullet.ok) return { ok: false, error: 'bullet-failed' };
  // The webContents may have reloaded/closed while the bullet was in flight —
  // never register a socket for a dead owner.
  if (wc.isDestroyed()) return { ok: false, error: 'gone' };
  // Re-check at dial time (the proxy config may have changed while the bullet
  // was in flight) — never dial direct past an enabled proxy.
  const ag = nativeWsAgentFor(route);
  if (ag.refuse) return { ok: false, error: 'unavailable' };
  const id = nativeSockSeq++;
  const connectId = 'att' + Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
  let ws;
  try {
    ws = new WSNative(kcDialUrl(bullet.endpoint, bullet.token, connectId), {
      agent: ag.agent,
      handshakeTimeout: 15000,
      perMessageDeflate: false,
    });
  } catch (e) {
    return { ok: false, error: 'open-failed' };
  }
  const rec = { ws, wcId, kaT: null };
  nativeSockets.set(id, rec);
  const emit = (msg) => {
    try { if (!wc.isDestroyed()) wc.send('att:ws-event', msg); } catch (e) { /* non-fatal */ }
  };
  let kaN = 0;
  ws.on('open', () => {
    // Main-owned app-level keepalive at the bullet-advertised cadence.
    rec.kaT = setInterval(() => {
      try { if (ws.readyState === 1) ws.send(JSON.stringify({ id: 'natka-' + (++kaN), type: 'ping' })); } catch (e) { /* non-fatal */ }
    }, bullet.pingMs);
    emit({ id, type: 'open' });
  });
  ws.on('message', (data, isBinary) => {
    if (isBinary) return;
    let s = '';
    try { s = data.toString('utf8'); } catch (e) { return; }
    // Swallow OUR keepalive pongs (id natka-*) — everything else (incl. the
    // renderer's own RTT pongs) pipes verbatim.
    if (s.indexOf('natka-') !== -1) {
      try {
        const m = JSON.parse(s);
        if (m && m.type === 'pong' && String(m.id || '').indexOf('natka-') === 0) return;
      } catch (e) { /* not JSON — fall through and forward */ }
    }
    emit({ id, type: 'message', data: s });
  });
  ws.on('close', (code, reason) => {
    if (rec.kaT) { try { clearInterval(rec.kaT); } catch (e) { /* non-fatal */ } rec.kaT = null; }
    nativeSockets.delete(id);
    let r = '';
    try { r = reason ? reason.toString('utf8') : ''; } catch (e) { r = ''; }
    emit({ id, type: 'close', code: code, reason: r });
  });
  ws.on('error', (err) => {
    emit({ id, type: 'error', message: (err && err.message) || 'error' });
  });
  // Same confirmed-path echo as att:ws-open: ag is the agent used at DIAL time.
  return { ok: true, id, via: { transport: 'native', route: ag.agent ? 'proxy' : 'direct' } };
});

// Forward an outbound text frame verbatim to the owning native socket.
ipcMain.on('att:ws-send', (event, payload) => {
  if (!nativeWsSenderOk(event)) return;
  const id = payload && payload.id;
  const rec = nativeSockets.get(id);
  if (!rec || rec.wcId !== event.sender.id) return;
  try {
    if (rec.ws.readyState === 1 /* OPEN */) rec.ws.send(String(payload.data == null ? '' : payload.data));
  } catch (e) { /* non-fatal */ }
});

// Close a native socket on the renderer's request.
ipcMain.on('att:ws-close', (event, payload) => {
  if (!nativeWsSenderOk(event)) return;
  const id = payload && payload.id;
  const rec = nativeSockets.get(id);
  if (!rec || rec.wcId !== event.sender.id) return;
  closeNativeSocket(id);
});

// ---------------------------------------------------------------------------
// Native trading transport (trade_native.js) — creds in safeStorage, orders
// signed and sent from the main process. Reuses the native-WS sender gate
// (top-level app-origin frames only) and the same proxy-agent discipline.
// ---------------------------------------------------------------------------
const { createTradeNative } = require('./trade_native');
createTradeNative({
  ipcMain,
  safeStorage,
  getProxyConfig,
  senderOk: nativeWsSenderOk,
  userDataDir: () => app.getPath('userData'),
  // Diagnostic tap (#1786): no-op unless the admin logger is live. trade_native
  // only ever passes pre-shaped, secret-free summaries (host/path/status/ms —
  // never headers, bodies, queries or creds); diag.log sanitizes again anyway.
  diag: (cat, ev, data) => dlog('main', cat, ev, data),
});

// ---------------------------------------------------------------------------
// Device API-key vault (keyvault.js) — per-panel-user exchange keys stored on
// THIS machine via safeStorage; keys saved here never touch the server. Same
// sender gate + userData dir discipline as the native trading store.
// ---------------------------------------------------------------------------
const { createKeyVault } = require('./keyvault');
createKeyVault({
  ipcMain,
  safeStorage,
  senderOk: nativeWsSenderOk,
  userDataDir: () => app.getPath('userData'),
});

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

// #1801 documents-first launch gate: current state for the panel's hydration
// hold. Boolean-only — no renderer-supplied data (attApp security rule).
ipcMain.handle('att:get-launch-gate', () => launchGateOpen === true);

// ---------------------------------------------------------------------------
// Window
// ---------------------------------------------------------------------------
function createWindow() {
  const settings = loadSettings();
  const bounds = settings.bounds || {};

  mainWindow = new BrowserWindow({
    ...titleBarOpts(),
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

  launchGateTrack(mainWindow);   // #1801: main window's document counts toward the gate too
  loadAppUrl(mainWindow, APP_URL);
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

  // Admin-only (#1786): quick access to the diagnostic log folder. Shown only
  // once a prior admin session set the flag — regular users never see it.
  const diagItems = diagSettings().admin === true
    ? [{ label: 'Open log folder', click: () => openDiagFolder() }, { type: 'separator' }]
    : [];

  return Menu.buildFromTemplate([
    ...updateItems,
    proxyItem,
    ...diagItems,
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
  // No application menu, ever: kills the ALT-revealed File/Edit/View/Window/Help
  // bar in EVERY window (main, feature pop-outs, floats) and the Alt+key
  // accelerator entry points. Shortcuts users rely on that the default menu used
  // to provide (Ctrl+R reload, F12/Ctrl+Shift+I DevTools) are re-registered in
  // wireWindowNav's before-input-event handler; F11 fullscreen and Ctrl+wheel
  // zoom were already custom. The tray context menu (buildTrayMenu) is separate
  // and unaffected. Clipboard/undo work natively in inputs without a menu.
  Menu.setApplicationMenu(null);
  app.setAppUserModelId('com.atraderstool.desktop'); // Windows notifications attribution
  // Diagnostic logger first, so every subsequent launch step is captured.
  initDiag();
  if (diag) {
    const cfg = getProxyConfig();
    dlog('main', 'app', 'start', {
      version: app.getVersion(),
      packaged: app.isPackaged,
      portable: isPortableBuild(),
      proxy: cfg ? { enabled: cfg.enabled, scheme: cfg.scheme, host: cfg.host, port: cfg.port } : null,
    });
  }
  setupSession();
  // Apply the saved proxy BEFORE the first window loads so the initial page load
  // (and the auto-updater on the default session) already goes through the tunnel.
  await applyProxyToSessions(getProxyConfig());
  // Cookie-ready gate: Electron loads the persisted cookie store from disk
  // asynchronously — a window whose first loadURL fires before it's ready sends
  // an UNAUTHENTICATED document request and gets the login page even though the
  // user is logged in. Any resolved cookies.get() proves the store is loaded,
  // so await one read on the app partition before creating ANY window. The
  // result itself doesn't gate anything — a genuinely logged-out user (no
  // session cookie) must still load and see the login page normally.
  const cookieGateT0 = Date.now();
  try { await session.fromPartition(PARTITION).cookies.get({ url: APP_URL }); } catch (e) { /* non-fatal */ }
  dlog('main', 'app', 'cookie-gate', { ms: Date.now() - cookieGateT0 });
  launchGateMaybeClose();   // #1801: BEFORE any window exists, so no load event races the gate
  createWindow();
  dlog('main', 'win', 'create-main', {});
  reopenFeatureWindows();   // restore feature windows that were open at last quit (arms the gate)
  createTray();
  setupAutoUpdater();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('before-quit', () => {
  isQuitting = true;
  dlog('main', 'app', 'quit', {});
  if (diag) { try { diag.close(); } catch (e) { /* non-fatal */ } }
});

app.on('window-all-closed', () => {
  // Keep alive in tray unless quitting
  if (isQuitting) app.quit();
});
