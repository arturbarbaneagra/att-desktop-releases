'use strict';

// ---------------------------------------------------------------------------
// Admin-only desktop diagnostic logger (#1786)
// ---------------------------------------------------------------------------
// One JSONL file per app launch under <userData>/logs/att-YYYYMMDD-HHMMSS.log,
// so the admin can hand a launch's file back after a fix and a bug report is
// precisely diagnosable. Constructed ONLY when the persisted admin flag is set
// (main.js gates on settings.diag — fail closed: no role known = no logger),
// so regular users pay zero overhead and get zero files.
//
// Line shape: {"ts":<epoch ms>,"w":"<window id>","c":"<category>","e":"<event>",...data}
//
// HARD SANITIZATION RULE: no API keys / secrets / signatures / cookies /
// session tokens / auth headers ever reach the file. diagSanitize is the ONE
// shared sanitizer (node-tested) applied to every payload, main-proc and
// renderer-piped alike. Wallet addresses are truncated to 0xABCD…; long
// strings are clipped; secret-shaped KEY NAMES are redacted wholesale.
//
// Rotation: at construction keep the newest DIAG_KEEP_FILES-1 old launches and
// enforce DIAG_TOTAL_CAP bytes across the folder (oldest deleted first).
// Runtime caps: per-event-key rate limit (a flapping feed cannot blow the file
// up) + a per-launch byte cap (past it, one final "capped" line, then silence).
// The per-key allowance is admin-tunable without a build (settings.diag.rlMax,
// read at launch); the BYTE cap is the real ceiling whatever it is set to.
//
// Pure helpers (diagSanitize, diagLine, rate-limit math) are exported for the
// node tests; only createDiagLogger touches the filesystem.

const fs = require('fs');
const path = require('path');

const DIAG_KEEP_FILES = 10;                 // launches kept (incl. the new one)
const DIAG_TOTAL_CAP = 50 * 1024 * 1024;    // folder-wide byte cap
const DIAG_FILE_CAP = 10 * 1024 * 1024;     // per-launch byte cap
// #2340: default events per key per window. 30/min could not survive an active
// trading burst — one 13-minute field session lost 15,203 lines to THIS
// throttle (not to any venue), and the densest keys are exactly the evidence a
// forensic read needs. The per-launch byte cap below is the real ceiling, so
// raising this trades "silent per-key loss all session" for "full detail until
// the file cap, then one honest capped marker".
const DIAG_RL_MAX = 300;
const DIAG_RL_WINDOW_MS = 60 * 1000;        // rate-limit window
// Bounds for the admin-configurable allowance (settings.diag.rlMax): a typo
// must not silence the log nor uncap the limiter outright.
const DIAG_RL_MAX_MIN = 1;
const DIAG_RL_MAX_LIMIT = 5000;
const DIAG_STR_MAX = 400;                   // max chars for any logged string

// Key names whose VALUES must never be written (case-insensitive substring
// match). Covers API keys/secrets, signatures, cookies, session/auth tokens,
// passphrases, private keys and seeds. "sig" is matched as a word-ish prefix
// so e.g. "signal" fields survive but "sig"/"signature"/"sigHex" are redacted.
const DIAG_SECRET_KEY_RE = /(secret|token|cookie|auth|passw|passphrase|priv|mnemonic|seed|credential|apikey|api_key|session)/i;
const DIAG_SECRET_KEY_EXACT_RE = /^(key|creds|sid|sig|sign|signature|sighex|jwt|bearer|nonce_sig|key2|secret2)$/i;

function diagKeyIsSecret(k) {
  const s = String(k || '');
  return DIAG_SECRET_KEY_RE.test(s) || DIAG_SECRET_KEY_EXACT_RE.test(s);
}

// Truncate 0x… hex addresses/hashes ANYWHERE inside a string: 0xABCD…
// (first 4 hex chars kept). Applies to 0x-strings of 12+ hex chars so plain
// small hex numbers stay readable.
function diagTruncAddr(s) {
  return String(s).replace(/0x[0-9a-fA-F]{12,}/g, (m) => m.slice(0, 6) + '\u2026');
}

// One shared sanitizer for every payload written to the file. Depth-limited,
// cycle-safe; arrays clipped to 50 entries. Strings: address-truncated then
// length-clipped. Secret-shaped keys → '[redacted]' regardless of value type.
function diagSanitize(v, depth) {
  const d = depth === undefined ? 0 : depth;
  if (v === null || v === undefined) return v;
  const t = typeof v;
  if (t === 'string') {
    let s = diagTruncAddr(v);
    if (s.length > DIAG_STR_MAX) s = s.slice(0, DIAG_STR_MAX) + '\u2026';
    return s;
  }
  if (t === 'number' || t === 'boolean') return v;
  if (t === 'function' || t === 'symbol' || t === 'bigint') return String(t);
  if (d >= 4) return '[deep]';
  if (Array.isArray(v)) {
    const out = [];
    for (let i = 0; i < v.length && i < 50; i++) out.push(diagSanitize(v[i], d + 1));
    if (v.length > 50) out.push('[+' + (v.length - 50) + ']');
    return out;
  }
  if (t === 'object') {
    const out = {};
    let n = 0;
    for (const k of Object.keys(v)) {
      if (++n > 40) { out['[more]'] = true; break; }
      out[k] = diagKeyIsSecret(k) ? '[redacted]' : diagSanitize(v[k], d + 1);
    }
    return out;
  }
  return String(v);
}

// Build one JSONL line (sanitized). win/cat/ev are clipped strings; data is an
// optional flat-ish object merged in AFTER the reserved fields.
function diagLine(tsMs, win, cat, ev, data) {
  const rec = {
    ts: tsMs,
    w: String(win == null ? '' : win).slice(0, 40),
    c: String(cat == null ? '' : cat).slice(0, 24),
    e: String(ev == null ? '' : ev).slice(0, 48),
  };
  if (data && typeof data === 'object') {
    const s = diagSanitize(data);
    for (const k of Object.keys(s)) {
      if (k === 'ts' || k === 'w' || k === 'c' || k === 'e') continue;
      rec[k] = s[k];
    }
  }
  return JSON.stringify(rec);
}

// File name for one launch. Local time, matches the design's att-YYYYMMDD-HHMMSS.
function diagFileName(dt) {
  const p = (n, w) => String(n).padStart(w || 2, '0');
  return 'att-' + dt.getFullYear() + p(dt.getMonth() + 1) + p(dt.getDate()) +
         '-' + p(dt.getHours()) + p(dt.getMinutes()) + p(dt.getSeconds()) + '.log';
}

// Rotation: keep the newest keepFiles-1 existing att-*.log (the new launch
// makes keepFiles), then delete oldest-first until the remaining total size
// fits totalCap. Returns names deleted (for tests). Never throws.
function diagRotate(dir, keepFiles, totalCap) {
  const deleted = [];
  let names;
  try { names = fs.readdirSync(dir).filter((n) => /^att-\d{8}-\d{6}(-\d+)?\.log$/.test(n)); }
  catch (e) { return deleted; }
  // Lexicographic sort == chronological for this fixed-width name shape.
  names.sort();
  const kill = (n) => {
    try { fs.unlinkSync(path.join(dir, n)); deleted.push(n); } catch (e) { /* non-fatal */ }
  };
  while (names.length > Math.max(0, keepFiles - 1)) kill(names.shift());
  let total = 0;
  const sizes = names.map((n) => {
    let sz = 0;
    try { sz = fs.statSync(path.join(dir, n)).size; } catch (e) { /* non-fatal */ }
    total += sz;
    return sz;
  });
  let i = 0;
  while (total > totalCap && i < names.length) {
    total -= sizes[i];
    kill(names[i]);
    i += 1;
  }
  return deleted;
}

// Per-event-key rate limiter state machine (pure — injected clock, node-tested).
// Key = cat|ev|k (k is an optional caller-chosen sub-key, e.g. a conn key or
// host). Allows the configured max per rolling window; the first suppressed
// event emits ONE marker ({e:'rl', rk, dropped, max}) when the window rolls
// over. The marker's key field is `rk`, NOT `key`: the sanitizer redacts
// secret-shaped names wholesale and `key` is one of them, so the one line whose
// job is to name the flooding event used to redact its own subject (#2340).
// #1864: events exempt from the rate limiter — each must be provably
// self-bounded where it is emitted (kr_ws_lag: one per minute per scope).
const DIAG_RL_EXEMPT = { kr_ws_lag: 1 };

// PURE: resolve the per-key allowance from admin config (settings.diag.rlMax),
// so the cap is tunable without shipping a build. Read once at construction —
// like the enabled toggle, a change takes effect on the NEXT launch (a file
// covers a whole launch under one cap or none of it). Absent, unparseable,
// zero/negative → the shipped default; absurd values clamp to DIAG_RL_MAX_LIMIT
// so a stray hand-edit can never disable the limiter.
function diagRlMaxFrom(raw) {
  const n = typeof raw === 'string' ? Number(raw.trim()) : raw;
  if (typeof n !== 'number' || !isFinite(n)) return DIAG_RL_MAX;
  const v = Math.floor(n);
  if (v < DIAG_RL_MAX_MIN) return DIAG_RL_MAX;
  return Math.min(v, DIAG_RL_MAX_LIMIT);
}

function diagRateLimiter(maxPerWindow, windowMs) {
  const max = maxPerWindow > 0 ? maxPerWindow : DIAG_RL_MAX;
  const win = windowMs > 0 ? windowMs : DIAG_RL_WINDOW_MS;
  const st = {};   // key → { t0, n, dropped }
  // returns: {ok:true} — write it; {ok:false} — drop silently;
  //          {ok:true, note:{rk,dropped,max}} — write it, PLUS a rollover marker.
  return function allow(key, now) {
    let s = st[key];
    if (!s || now - s.t0 >= win) {
      const note = (s && s.dropped > 0) ? { rk: key, dropped: s.dropped, max: max } : null;
      s = st[key] = { t0: now, n: 1, dropped: 0 };
      return note ? { ok: true, note: note } : { ok: true };
    }
    if (s.n < max) { s.n += 1; return { ok: true }; }
    s.dropped += 1;
    return { ok: false };
  };
}

// The runtime logger. opts: { dir (required), now? () → ms, keepFiles?,
// totalCap?, fileCap? }. Construction rotates, mkdirs and opens the stream;
// any failure yields a no-op logger (diagnostics must never break the shell).
function createDiagLogger(opts) {
  const dir = opts.dir;
  const now = typeof opts.now === 'function' ? opts.now : Date.now;
  const fileCap = opts.fileCap > 0 ? opts.fileCap : DIAG_FILE_CAP;
  const allow = diagRateLimiter(opts.rlMax, opts.rlWindowMs);
  let stream = null;
  let file = null;
  let written = 0;
  let capped = false;
  try {
    fs.mkdirSync(dir, { recursive: true });
    // Rotate with the ACTIVE launch's capacity reserved: old files may keep at
    // most totalCap - fileCap bytes, so even after this launch grows to its
    // full per-file cap the folder never exceeds the aggregate budget.
    const totalCap = opts.totalCap > 0 ? opts.totalCap : DIAG_TOTAL_CAP;
    diagRotate(dir, opts.keepFiles > 0 ? opts.keepFiles : DIAG_KEEP_FILES,
               Math.max(0, totalCap - fileCap));
    let name = diagFileName(new Date(now()));
    // Two launches within the same second (crash loop): suffix instead of append.
    if (fs.existsSync(path.join(dir, name))) {
      name = name.replace(/\.log$/, '-' + (now() % 1000) + '.log');
    }
    file = path.join(dir, name);
    // Pre-create synchronously so the launch file exists even if the process
    // dies before the stream's lazy open (crash-loop forensics).
    fs.closeSync(fs.openSync(file, 'a'));
    stream = fs.createWriteStream(file, { flags: 'a' });
    stream.on('error', () => { stream = null; });
  } catch (e) {
    stream = null;
  }

  // ~space reserved for the final "capped" marker line, so writing it can
  // never itself push the file past fileCap.
  const CAP_MARKER_RESERVE = 128;

  function writeLine(line) {
    if (!stream || capped) return;
    // Count ENCODED bytes (unicode crumbs are multi-byte), incl. the newline.
    const bytes = Buffer.byteLength(line, 'utf8') + 1;
    if (written + bytes > fileCap - CAP_MARKER_RESERVE) {
      capped = true;
      const marker = JSON.stringify({ ts: now(), w: 'main', c: 'app', e: 'capped', bytes: written }) + '\n';
      written += Buffer.byteLength(marker, 'utf8');
      try { stream.write(marker); } catch (e) { /* non-fatal */ }
      return;
    }
    written += bytes;
    try { stream.write(line + '\n'); } catch (e) { /* non-fatal */ }
  }

  return {
    dir: dir,
    file: file,
    // win: window id ('main', a feature id, or 'wc<N>'); cat/ev: short tags;
    // data: optional object (sanitized); data.k (if present) extends the
    // rate-limit key so per-connection floods are limited per connection.
    log: function (win, cat, ev, data) {
      if (!stream || capped) return;
      const t = now();
      // #1864: limiter-exempt events (already self-bounded at the source —
      // e.g. kr_ws_lag emits at most once per minute per scope). A burst of
      // OTHER events on the same cat can otherwise consume the shared window
      // and drop the one lag sample the session forensics need.
      if (DIAG_RL_EXEMPT[ev]) { writeLine(diagLine(t, win, cat, ev, data)); return; }
      const key = cat + '|' + ev + '|' + String((data && data.k) || '');
      const a = allow(key, t);
      if (!a.ok) return;
      // #2340: `rk`, never `key` — a field literally named `key` is redacted by
      // the sanitizer's secret-name rule, which blanked the very subject this
      // marker exists to report. The rule itself stays untouched.
      if (a.note) writeLine(diagLine(t, 'main', 'diag', 'rl', { rk: a.note.rk, dropped: a.note.dropped, max: a.note.max }));
      writeLine(diagLine(t, win, cat, ev, data));
    },
    close: function () {
      try { if (stream) stream.end(); } catch (e) { /* non-fatal */ }
      stream = null;
    },
  };
}

module.exports = {
  createDiagLogger,
  diagSanitize,
  diagLine,
  diagRotate,
  diagRateLimiter,
  diagRlMaxFrom,
  diagFileName,
  diagKeyIsSecret,
  diagTruncAddr,
  DIAG_KEEP_FILES,
  DIAG_TOTAL_CAP,
  DIAG_FILE_CAP,
  DIAG_RL_MAX,
  DIAG_RL_MAX_MIN,
  DIAG_RL_MAX_LIMIT,
  DIAG_RL_WINDOW_MS,
  DIAG_RL_EXEMPT,
};
