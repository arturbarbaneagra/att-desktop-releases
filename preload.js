'use strict';

// The desktop shell is a dumb window around atraderstool.com — no app logic
// lives here and nothing is exposed to the page (contextIsolation is on, the
// web Notification API works natively through Electron without any bridge).
//
// The one exception: a slim, shell-owned "Update available" bar across the top
// of the MAIN window. main.js pushes the electron-updater state over IPC and
// this preload builds/toggles the bar entirely in its isolated world (the
// website never sees it). The preload runs on every page load, so the bar
// survives Ctrl+R / offline-retry reloads; main.js re-pushes the state on
// did-finish-load. Feature pop-out windows never receive the IPC message, so
// they never get a bar.

const { ipcRenderer, webFrame, contextBridge } = require('electron');

// ---------------------------------------------------------------------------
// Network-proxy bridge (validated, minimal; app panel + offline fallback page)
// ---------------------------------------------------------------------------
// The panel's "Network proxy" card reads/sets/clears the desktop proxy over the
// existing IPC channels. The page never passes a raw proxy-rules string — only
// {scheme, host, port}; the main process validates and builds the rules itself.
// Its presence (window.attProxy) is also how the panel tells it's running inside
// a desktop build new enough to support the feature.
let _proxyOpenSettingsCb = null;
try {
  contextBridge.exposeInMainWorld('attProxy', {
    get: () => ipcRenderer.invoke('att:proxy-get'),
    set: (cfg) => ipcRenderer.invoke('att:proxy-set', {
      scheme: cfg && cfg.scheme,
      host: cfg && cfg.host,
      port: cfg && cfg.port,
    }),
    // Pre-flight reachability probe (direct TCP connect in the main process); the
    // panel calls this BEFORE set() so it can warn about a stopped/mistyped proxy.
    test: (cfg) => ipcRenderer.invoke('att:proxy-test', {
      scheme: cfg && cfg.scheme,
      host: cfg && cfg.host,
      port: cfg && cfg.port,
    }),
    clear: () => ipcRenderer.invoke('att:proxy-clear'),
    // The tray "Proxy settings…" item asks the panel to open the Desktop App tab.
    onOpenSettings: (cb) => { _proxyOpenSettingsCb = (typeof cb === 'function') ? cb : null; },
  });
} catch (e) { /* non-fatal — bridge unavailable, panel falls back to the notice */ }

ipcRenderer.on('att:proxy-open-settings', () => {
  try { if (_proxyOpenSettingsCb) _proxyOpenSettingsCb(); } catch (e) { /* non-fatal */ }
});

// ---------------------------------------------------------------------------
// App control bridge (Restart + games-style fullscreen) — window.attApp
// ---------------------------------------------------------------------------
// Slim, shell-owned API: only parameterless / boolean calls (no renderer-supplied
// data), matching the proxy card's security rule — the main process owns all
// behavior. Its presence (window.attApp) is also how the panel tells it's running
// inside a desktop build new enough to show the Restart + Fullscreen buttons.
let _fullscreenChangeCb = null;
let _updateStateCb = null;   // titlebar Restart button accent (#1793)
let _launchGateCb = null;    // #1801 documents-first launch gate open signal
try {
  contextBridge.exposeInMainWorld('attApp', {
    restart: () => ipcRenderer.invoke('att:app-restart'),
    toggleFullscreen: () => ipcRenderer.invoke('att:toggle-fullscreen'),
    getFullscreen: () => ipcRenderer.invoke('att:get-fullscreen'),
    onFullscreenChange: (cb) => { _fullscreenChangeCb = (typeof cb === 'function') ? cb : null; },
    // #1801 documents-first launch gate: with the session proxy enabled the
    // shell holds the panel's heavy connection ramp (all-tab hydration) until
    // every launch-reopened window's document load resolved. Parameterless /
    // boolean only, per the bridge's security rule. Missing on older shells —
    // the panel must treat absence as "no gating".
    getLaunchGate: () => ipcRenderer.invoke('att:get-launch-gate'),
    // #1894 atomic cross-window sound claim: first window to claim an event
    // id (serialized in main via sendSync) plays it; every other window gets
    // false. Returns null on bridge failure so the panel can fall back to
    // its localStorage latch. String id only — no renderer data flows back.
    sndClaim: (id) => {
      try { return ipcRenderer.sendSync('att:snd-claim', String(id || '')) === true; }
      catch (e) { return null; }
    },
    // #2197 non-blocking claim: same serialized first-wins registry in main,
    // consulted via ASYNC invoke so the renderer never blocks on a busy main
    // process (the sendSync above froze windows 300-430ms during Binance fill
    // bursts). Resolves true (won) / false (lost) / null (bridge failure —
    // panel keeps its optimistic latch decision). String id only.
    sndClaimAsync: (id) => {
      try {
        return ipcRenderer.invoke('att:snd-claim-async', String(id || ''))
          .then((r) => (r === true ? true : (r === false ? false : null)), () => null);
      } catch (e) { return Promise.resolve(null); }
    },
    onLaunchGate: (cb) => { _launchGateCb = (typeof cb === 'function') ? cb : null; },
    // Update-state mirror for the in-titlebar Restart button (#1793): the panel
    // accents the button ("restart to update") when a downloaded update is
    // pending. Same payload main.js pushes for the shell-owned update bar;
    // status/version only — no renderer-supplied data flows back.
    onUpdateState: (cb) => { _updateStateCb = (typeof cb === 'function') ? cb : null; },
  });
} catch (e) { /* non-fatal — bridge unavailable, panel simply hides the buttons */ }

ipcRenderer.on('att:fullscreen-changed', (_e, isFull) => {
  try { if (_fullscreenChangeCb) _fullscreenChangeCb(!!isFull); } catch (e) { /* non-fatal */ }
});

ipcRenderer.on('att:launch-gate', () => {
  try { if (_launchGateCb) _launchGateCb(); } catch (e) { /* non-fatal */ }
});

// ---------------------------------------------------------------------------
// Admin diagnostic logger bridge (#1786) — window.attDiag
// ---------------------------------------------------------------------------
// Slim pipe for the admin-only per-launch diagnostic log. The MAIN process
// owns gating (fail closed on role), sanitization and rate limiting; this
// bridge only forwards. role() is how the panel reports the logged-in session
// role after /api/me; log() pipes key panel events (WS lifecycle, REST-failure
// breadcrumbs, park/hydrate, /state pacing) — a no-op when no logger is live.
try {
  contextBridge.exposeInMainWorld('attDiag', {
    role: (isAdmin) => { try { ipcRenderer.send('att:diag-role', isAdmin === true); } catch (e) { /* non-fatal */ } },
    get: () => ipcRenderer.invoke('att:diag-get'),
    setEnabled: (on) => ipcRenderer.invoke('att:diag-set-enabled', on === true),
    log: (cat, ev, data) => {
      try { ipcRenderer.send('att:diag-event', { cat: String(cat), ev: String(ev), data: data }); } catch (e) { /* non-fatal */ }
    },
  });
} catch (e) { /* non-fatal — bridge unavailable, panel simply skips diag */ }

// ---------------------------------------------------------------------------
// Native market-data WebSocket bridge — window.attNativeWS
// ---------------------------------------------------------------------------
// Slim, validated bridge over the main-process native sockets. The page builds a
// WebSocket-like shim on top of these primitives and uses it for Terminal DOM
// connections whose venue is set to "native" (Phemex and/or Binance — Binance
// futures @aggTrade is silently withheld by Chromium; the Node runtime gets it).
// The main process validates every URL against a Terminal market-data host
// allowlist and refuses anything else. Its presence (window.attNativeWS) is how
// the panel detects a native-WS-capable build — same pattern as attProxy / attApp.
let _nativeWsCb = null;
try {
  contextBridge.exposeInMainWorld('attNativeWS', {
    // Returns a Promise<{ok, id}> — id keys all later send/close + inbound events.
    // route ('proxy'|'direct') is the optional per-venue×market ROUTE choice;
    // main validates it (anything unknown collapses to 'proxy', fail-closed).
    // ident (#2216) is the panel's conn identity ('venue|market|aid'), logged
    // with the socket's lifecycle lines in the admin diag file. Diagnostics
    // only — main validates the URL/route exactly as before and never routes
    // on this string.
    open: (url, route, ident) => ipcRenderer.invoke('att:ws-open', String(url || ''), String(route || ''), String(ident || '')),
    // KuCoin direct dial: the renderer names ONLY the market ('spot'|'futures');
    // main does the bullet-public token dance itself and validates the returned
    // wss endpoint (its host varies per token, so the fixed allowlist can't
    // cover it). Presence of this method gates the panel's KuCoin Native button.
    openKucoin: (market, route) => ipcRenderer.invoke('att:ws-open-kucoin', String(market || ''), String(route || '')),
    // Per-venue×market Proxy/Direct route for BROWSER transports: posts the
    // venue|market combos set to Direct; main rebuilds the session bypass
    // rules from its static host map. Presence of THIS method gates the
    // panel's Route switch row (older builds simply never show it).
    setRouteHosts: (tokens) => ipcRenderer.invoke('att:route-hosts',
      Array.isArray(tokens) ? tokens.map((t) => String(t || '')) : []),
    send: (id, data) => ipcRenderer.send('att:ws-send', { id: id, data: String(data == null ? '' : data) }),
    close: (id, code, reason) => ipcRenderer.send('att:ws-close', { id: id, code: code, reason: reason }),
    // Single fan-out dispatcher; the page routes {id, type, ...} to its shims.
    onEvent: (cb) => { _nativeWsCb = (typeof cb === 'function') ? cb : null; },
  });
} catch (e) { /* non-fatal — bridge unavailable, panel keeps browser WS + REST fallback */ }

ipcRenderer.on('att:ws-event', (_e, msg) => {
  try { if (_nativeWsCb) _nativeWsCb(msg); } catch (e) { /* non-fatal */ }
});

// ---------------------------------------------------------------------------
// Native trading bridge — window.attTrade
// ---------------------------------------------------------------------------
// The renderer NEVER sees API keys: setCreds forwards the one-shot creds blob
// (fetched by the page from the authed server endpoint) straight into the main
// process, which stores it via Electron safeStorage; exec sends an order
// INTENT that main validates/builds/signs itself. Presence of window.attTrade
// is how the panel detects a native-trading-capable build (same pattern as
// attNativeWS). No cross-transport fallback: a failed native call surfaces
// {ok:false, message} and the page reports it — it never re-sends via server.
try {
  contextBridge.exposeInMainWorld('attTrade', {
    setCreds: (venue, creds) => ipcRenderer.invoke('att:trade-creds-set', String(venue || ''), creds),
    wipeCreds: (venue) => ipcRenderer.invoke('att:trade-creds-wipe', String(venue || '')),
    status: () => ipcRenderer.invoke('att:trade-creds-status'),
    exec: (intent) => ipcRenderer.invoke('att:trade-exec', intent),
    // #1867 Kraken push channel: the shell broadcasts every ledger mutation
    // ('att:ledger-push') the moment its WS session applies it. Presence of
    // this method is the panel's capability probe — old shells simply lack
    // it and the panel stays on the polled display path.
    // #2234: registering also SUBSCRIBES this window to the lane, so main can
    // skip windows that never listen (they used to pay a structured clone per
    // push). The payload arrives pre-serialized — the panel unpacks both the
    // string and the legacy object shape.
    onLedgerPush: (cb) => {
      try { ipcRenderer.send('att:ledger-sub'); } catch (e) { /* old shell */ }
      ipcRenderer.on('att:ledger-push', (e, p) => { try { cb(p); } catch (err) { /* page handler */ } });
    },
    // Capability list (#1713): the panel probes this to decide which NEW
    // shell-backed axes to offer (absent on old shells → axes stay hidden →
    // server path, graceful degradation). Presence-of-method stays the probe
    // for the pre-#1713 features.
    caps: ['acct:bybit', 'acct:phemex', 'acct:binance', 'acct:okx', 'acct:gate', 'acct:bitget', 'acct:mexc', 'acct:kucoin', 'acct:bitmex', 'acct:kraken', 'acct:asterdex', 'cat:phemex', 'cat:kucoin', 'cat:gate', 'cat:bitmex', 'cat:kraken', 'cat:mexc', 'cat:mexc2', 'cat:arcus', 'cat:http', 'lblot:binance', 'lblot:kraken', 'lblot:hyperliquid', 'lblot:bybit', 'lblot:gate', 'lblotri'],
  });
} catch (e) { /* non-fatal — bridge unavailable, panel keeps Server trading */ }

// ---------------------------------------------------------------------------
// Device API-key vault bridge — window.attKeyVault
// ---------------------------------------------------------------------------
// Per-panel-user exchange API keys stored ONLY on this machine (safeStorage).
// get() returns the decrypted blob to the page purely as an arm-time handoff
// into attTrade.setCreds — identical trust surface to the server release path.
// Presence of window.attKeyVault is how the panel detects a vault-capable
// shell build; older shells simply lack it and the panel degrades gracefully.
try {
  contextBridge.exposeInMainWorld('attKeyVault', {
    set: (user, venue, creds) => ipcRenderer.invoke('att:keyvault-set', String(user || ''), String(venue || ''), creds),
    get: (user, venue) => ipcRenderer.invoke('att:keyvault-get', String(user || ''), String(venue || '')),
    del: (user, venue) => ipcRenderer.invoke('att:keyvault-del', String(user || ''), String(venue || '')),
    list: (user) => ipcRenderer.invoke('att:keyvault-list', String(user || '')),
  });
} catch (e) { /* non-fatal — vault unavailable, panel keeps Server keys */ }

// ---------------------------------------------------------------------------
// Ctrl+scroll page zoom (shell-owned, every window shares this preload)
// ---------------------------------------------------------------------------
// Electron disables Chromium's default Ctrl+wheel zoom, so nothing happens
// today. Re-implement it here via webFrame.setZoomFactor. The `!e.defaultPrevented`
// guard means the shell zoom never double-fires over the panel's own Ctrl+wheel
// handlers (Terminal DOM board + splash chart zoom already preventDefault their
// own areas). Ctrl+0 resets to 100%.
const ZOOM_MIN = 0.5;
const ZOOM_MAX = 2.5;
const ZOOM_STEP = 0.1;

function clampZoom(z) {
  return Math.min(ZOOM_MAX, Math.max(ZOOM_MIN, z));
}

// A window's zoom factor is PERSISTED per-window: every change is reported to the
// main process (att:zoom-changed), which stores it in settings.json (userData —
// survives app restart, app update, and PC restart) keyed by window id. On each
// (re)load the main process pushes the saved factor back (att:zoom-apply). Restore
// goes through webFrame (the SAME per-frame path as live zoom) so windows stay
// independent — one window's zoom never bleeds into another.
function reportZoom(f) {
  try { ipcRenderer.send('att:zoom-changed', f); } catch (e) { /* non-fatal */ }
}

function applyZoom(f) {
  const z = clampZoom(f);
  webFrame.setZoomFactor(z);
  reportZoom(z);
  return z;
}

function setupZoom() {
  // Restore the saved zoom pushed by the main process after each (re)load. This
  // is a bare set (no re-report) — the value already came from persistence.
  ipcRenderer.on('att:zoom-apply', (_e, f) => {
    try {
      webFrame.setZoomFactor(clampZoom((typeof f === 'number' && f > 0) ? f : 1));
    } catch (e) { /* non-fatal */ }
  });

  window.addEventListener('wheel', (e) => {
    if (!e.ctrlKey || e.defaultPrevented) return;
    e.preventDefault();
    const cur = webFrame.getZoomFactor();
    const dir = e.deltaY < 0 ? 1 : -1;
    const next = clampZoom(Math.round((cur + dir * ZOOM_STEP) * 100) / 100);
    applyZoom(next);
  }, { passive: false });

  window.addEventListener('keydown', (e) => {
    if ((e.ctrlKey || e.metaKey) && (e.key === '0' || e.code === 'Digit0' || e.code === 'Numpad0')) {
      e.preventDefault();
      applyZoom(1);
    }
  });
}

const BAR_ID = '__att_update_bar__';
const DISMISS_KEY = '__att_update_dismissed__';
let bar = null;

// Dismissal (✕) is stored per update STATE (`status:version`) in sessionStorage:
//  - a different status or version → a different key → the bar reappears
//    ("next state change", e.g. dismiss while downloading, show again when ready),
//  - sessionStorage survives Ctrl+R (same run) but is cleared on next launch,
//    so a dismissed bar stays hidden across reloads yet returns next launch.
function stateKey(status, version) {
  return String(status) + ':' + (version || '');
}
function getDismissed() {
  try { return sessionStorage.getItem(DISMISS_KEY); } catch (e) { return null; }
}
function setDismissed(key) {
  try {
    if (key) sessionStorage.setItem(DISMISS_KEY, key);
    else sessionStorage.removeItem(DISMISS_KEY);
  } catch (e) { /* non-fatal */ }
}

function ensureBar() {
  if (bar && document.body.contains(bar)) return bar;

  bar = document.createElement('div');
  bar.id = BAR_ID;
  Object.assign(bar.style, {
    position: 'fixed',
    top: '0',
    left: '0',
    right: '0',
    zIndex: '2147483647',
    height: '30px',
    lineHeight: '30px',
    display: 'none',
    boxSizing: 'border-box',
    padding: '0 12px',
    font: '600 13px/30px -apple-system, "Segoe UI", Roboto, Arial, sans-serif',
    color: '#ffffff',
    background: '#238636',
    textAlign: 'center',
    userSelect: 'none',
    boxShadow: '0 1px 4px rgba(0,0,0,0.35)',
  });

  const label = document.createElement('span');
  label.id = BAR_ID + '_label';
  Object.assign(label.style, { display: 'inline-block' });

  const close = document.createElement('span');
  close.textContent = '✕';
  Object.assign(close.style, {
    position: 'absolute',
    right: '10px',
    top: '0',
    height: '30px',
    lineHeight: '30px',
    cursor: 'pointer',
    fontWeight: '700',
    opacity: '0.85',
  });
  close.title = 'Dismiss (the update still installs when you quit)';
  close.addEventListener('click', (e) => {
    e.stopPropagation();
    setDismissed(bar.getAttribute('data-key') || '');
    hideBar();
  });

  bar.appendChild(label);
  bar.appendChild(close);

  bar.addEventListener('click', () => {
    if (bar.getAttribute('data-clickable') !== '1') return;
    // 'releases' → open the download page (recovery after a failed update);
    // anything else → the normal restart-to-install action.
    if (bar.getAttribute('data-action') === 'releases') {
      ipcRenderer.invoke('att:open-releases').catch(() => {});
    } else {
      ipcRenderer.invoke('att:install-update').catch(() => {});
    }
  });

  document.body.appendChild(bar);
  return bar;
}

function hideBar() {
  if (bar) bar.style.display = 'none';
}

// With the Windows overlay title bar (#1793) the page starts BELOW the native
// caption-button strip, so the fixed bar must sit under it, never over the
// native buttons / drag region. 0 on native-framed platforms and in fullscreen.
function ttbTop() {
  try {
    const wco = navigator.windowControlsOverlay;
    if (wco && wco.visible && typeof wco.getTitlebarAreaRect === 'function') {
      const r = wco.getTitlebarAreaRect();
      if (r && r.height > 0) return Math.round(r.height);
    }
  } catch (e) { /* non-fatal */ }
  return 0;
}

function showBar(text, clickable, key, opts) {
  const o = opts || {};
  const b = ensureBar();
  b.style.top = ttbTop() + 'px';
  const label = document.getElementById(BAR_ID + '_label');
  if (label) label.textContent = text;
  b.setAttribute('data-clickable', clickable ? '1' : '0');
  b.setAttribute('data-action', o.action || 'install');
  b.setAttribute('data-key', key || '');
  // green = ready to install, amber = update error (manual recovery),
  // blue = passive info (downloading).
  b.style.background = o.bg || (clickable ? '#238636' : '#1f6feb');
  b.style.cursor = clickable ? 'pointer' : 'default';
  b.style.display = 'block';
}

function applyState(state) {
  const status = state && state.status;
  const version = (state && state.version) || null;
  const vtxt = version ? 'v' + version : '';
  const key = stateKey(status, version);

  // A dismissal only suppresses the exact state it was dismissed at; any change
  // of status/version yields a new key and the bar returns. Stale dismissals
  // (for a state we're no longer in) are cleared so they can't linger.
  if (getDismissed() && getDismissed() !== key) setDismissed(null);

  if (status === 'downloading') {
    if (getDismissed() === key) { hideBar(); return; }
    // Info-only (quitAndInstall isn't valid until the update is downloaded).
    showBar('⬇ Downloading update ' + (vtxt || '') + '…', false, key);
    return;
  }
  if (status === 'ready') {
    if (getDismissed() === key) { hideBar(); return; }
    showBar('⭯ Update to ' + (vtxt || 'a new version') +
            ' available — click to restart & update', true, key);
    return;
  }
  if (status === 'error') {
    // Non-blocking manual-recovery hatch: an auto-update failed, so give the
    // user a one-click path to the latest installer instead of a dead end.
    // Dismissible; the web app keeps working regardless.
    if (getDismissed() === key) { hideBar(); return; }
    showBar('⚠ Update couldn\u2019t be applied automatically — click to download the latest version',
            true, key, { action: 'releases', bg: '#9e6a03' });
    return;
  }
  // idle | checking | not-available | disabled → nothing pending.
  hideBar();
}

function start() {
  try { setupZoom(); } catch (e) { /* non-fatal */ }
  ipcRenderer.on('att:update-state', (_event, state) => {
    try { applyState(state); } catch (e) { /* non-fatal */ }
  });
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', start, { once: true });
} else {
  start();
}
