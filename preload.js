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

function showBar(text, clickable, key, opts) {
  const o = opts || {};
  const b = ensureBar();
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
